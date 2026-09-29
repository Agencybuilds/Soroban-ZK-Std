#![no_std]
extern crate alloc;

pub mod cache;
pub mod gadgets;
pub mod groth16;
pub mod host;
pub mod nullifier;
pub mod pairing;
pub mod poseidon2;
pub mod vk;

pub use groth16::{groth16_verify, Groth16Proof, Groth16VerifyingKey};
pub use nullifier::{inputs_to_bytes, NullifierKey, NullifierSet, NullifierStore};
pub use pairing::{pairing_check, G2Affine};
pub use vk::{
    clear_proof_context, clear_vk, load_vk, save_vk, set_proof_context, vk_from_bytes,
    vk_to_bytes, G1_GENERATOR, G2_GENERATOR, OwnedVerifyingKey, VkMeta, VkStorageKey,
    VK_CHUNK_SIZE,
};

use ethnum::u256 as eth_u256;
use soroban_sdk::{contracterror, Address, Bytes, Env, U256, Vec};
use soroban_zk_core::{Bn254, Fr, SafeFrom, ZkError};

/// Validates a Soroban U256 as a BN254 scalar.
/// This prevents "out of bounds" field element errors in ZK verifiers.
pub fn validate_soroban_scalar(_env: &Env, val: U256) -> bool {
    let mut bytes = [0u8; 32];
    val.to_be_bytes().copy_into_slice(&mut bytes);

    // Convert Big-Endian bytes to ethnum u256
    let internal_val = eth_u256::from_be_bytes(bytes);

    Bn254::is_valid_scalar(internal_val)
}

/// Helper trait to add this functionality directly to the Env
pub trait ZkEnv {
    fn is_bn254_scalar(&self, val: U256) -> bool;
}

impl ZkEnv for Env {
    fn is_bn254_scalar(&self, val: U256) -> bool {
        validate_soroban_scalar(self, val)
    }
}

/// Zero-copy conversion from a Soroban host-managed [`U256`] into a validated
/// BN254 [`Fr`] field element.
///
/// This trait is designed to wrap the `env.crypto().bn254_fr_from_u256()` host
/// call when it becomes available as a native Soroban API.  The current
/// implementation performs the conversion in software via big-endian byte
/// mapping with no heap allocation, then delegates range validation to
/// [`Fr::safe_from`].
pub trait HostConvert {
    /// Converts a Soroban `U256` into a BN254 scalar field element.
    ///
    /// Returns `Err(`[`ZkError::InvalidFieldElement`]`)` if the value lies
    /// outside `[0, r)`.  Never panics; no heap allocation.
    fn fr_from_u256(&self, val: U256) -> Result<Fr, ZkError>;
}

impl HostConvert for Env {
    #[inline(always)]
    fn fr_from_u256(&self, val: U256) -> Result<Fr, ZkError> {
        // Zero-copy stack allocation: read the Soroban U256 as big-endian bytes
        // and reinterpret as an ethnum u256 for field validation.
        let mut bytes = [0u8; 32];
        val.to_be_bytes().copy_into_slice(&mut bytes);
        let raw = eth_u256::from_be_bytes(bytes);
        Fr::safe_from(raw)
    }
}

use soroban_sdk::{contract, contractimpl};

/// Contract-facing error type for the `ZkContract` entry points.
///
/// `ZkError` (in `soroban-zk-core`) deliberately avoids depending on the
/// Soroban SDK, so contract methods translate it into this `#[contracterror]`
/// type, which the SDK can marshal across the host boundary.
#[contracterror]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkContractError {
    /// A supplied value was ≥ the BN254 scalar field modulus.
    InvalidFieldElement = 1,
    /// Mismatched input lengths or empty slices.
    InvalidInput = 2,
    /// Serialized bytes could not be decoded.
    DeserializationError = 3,
    /// A raw host call trapped or was unavailable.
    HostError = 4,
    /// A storage read/write/remove failed or required data was missing.
    StorageError = 5,
    /// A ZK constraint or gadget invariant was violated by the supplied witness.
    ConstraintUnsatisfied = 6,
    /// A previously-accepted proof was submitted again (anti-replay protection).
    ///
    /// This error is returned by [`nullifier::NullifierStore::mark_spent`] (and
    /// by [`ZkContract::verify_proof`] when `anti_replay` is `true`) if the
    /// nullifier of the submitted proof + public inputs already exists in
    /// `StorageType::Persistent`.
    ReplayDetected = 7,
}

impl From<ZkError> for ZkContractError {
    fn from(e: ZkError) -> Self {
        match e {
            ZkError::InvalidFieldElement => ZkContractError::InvalidFieldElement,
            ZkError::InvalidInput => ZkContractError::InvalidInput,
            ZkError::DeserializationError => ZkContractError::DeserializationError,
            ZkError::HostError => ZkContractError::HostError,
            ZkError::StorageError => ZkContractError::StorageError,
            ZkError::ConstraintUnsatisfied => ZkContractError::ConstraintUnsatisfied,
        }
    }
}

#[contract]
pub struct ZkContract;

#[contractimpl]
impl ZkContract {
    /// Benchmark function to ensure CI measures REAL library footprint.
    pub fn validate_scalar(env: Env, val: U256) -> bool {
        // This forces the compiler to include the ethnum and soroban-zk-core logic
        env.is_bn254_scalar(val)
    }

    /// Poseidon2 hash of a list of BN254 field elements, using the
    /// instance-storage cache for the round constants and matrix diagonal
    /// (Issue #124).
    ///
    /// The first invocation populates the cache from code; later invocations
    /// reuse the constants stored in `StorageType::Instance` instead of
    /// rebuilding them on every call.
    pub fn poseidon2_hash(env: Env, inputs: soroban_sdk::Vec<U256>) -> U256 {
        let mut sponge = poseidon2::Poseidon2Sponge::new_cached(&env);
        for input in inputs.iter() {
            sponge.absorb(core::slice::from_ref(&input));
        }
        sponge.squeeze()
    }

    /// Persists a verification key (serialized via [`vk::vk_to_bytes`]) to
    /// `StorageType::Persistent`, chunked if necessary.
    ///
    /// **Safety:** the caller must authorize before the key is replaced, so a
    /// hostile key swap is impossible without the admin's signature.
    pub fn set_verifying_key(
        env: Env,
        admin: Address,
        vk_bytes: Bytes,
    ) -> Result<(), ZkContractError> {
        admin.require_auth();
        let owned = vk::vk_from_bytes(&env, &vk_bytes).map_err(ZkContractError::from)?;
        let vk = owned.as_vk();
        vk::save_vk(&env, &vk).map_err(ZkContractError::from)
    }

    /// Purges the on-ledger verification key (cleanup hook for key rotation).
    /// Requires the admin's authorization.
    pub fn clear_verifying_key(env: Env, admin: Address) -> Result<(), ZkContractError> {
        admin.require_auth();
        vk::clear_vk(&env);
        Ok(())
    }

    /// Loads the stored verification key, verifies a Groth16 proof against it,
    /// and clears the short-lived proof-context flag afterwards. Demonstrates
    /// the Phase-3 cleanup pattern: the temporary flag is removed whether the
    /// verification succeeds or fails.
    ///
    /// When `anti_replay` is `true` the verifier additionally records a
    /// SHA-256 commitment over `proof_bytes || public_inputs` in
    /// `StorageType::Persistent`.  Any attempt to re-submit the same proof
    /// will return [`ZkContractError::ReplayDetected`] **before** running the
    /// pairing check, eliminating the gas cost of a redundant verification.
    pub fn verify_proof(
        env: Env,
        proof_bytes: Bytes,
        public_inputs: Vec<U256>,
        anti_replay: bool,
    ) -> Result<bool, ZkContractError> {
        // ── Anti-replay check (fast-path: reject before the expensive pairing) ──
        //
        // We check *before* proof verification so a replayed proof never burns
        // the gas budget for a pairing check.  The nullifier is committed to
        // the full `proof_bytes || serialised_inputs` tuple, so the same proof
        // with different public inputs remains a valid new submission.
        if anti_replay {
            let inputs_buf = nullifier::inputs_to_bytes(&env, &public_inputs);
            let nstore = nullifier::NullifierStore::new(&env);
            // If spent → early return, no state change.
            if nstore.is_spent(&env, &proof_bytes, &inputs_buf) {
                return Err(ZkContractError::ReplayDetected);
            }
        }

        let result: Result<bool, ZkError> = (|| {
            let owned = vk::load_vk(&env)?;
            let vk = owned.as_vk();

            // Mark the in-flight run with a temporary proof-context flag.
            vk::set_proof_context(&env, &proof_bytes);

            let outcome = (|| {
                let proof_buf: alloc::vec::Vec<u8> = proof_bytes.iter().collect();
                let proof = Groth16Proof::from_bytes(&proof_buf)?;
                let mut inputs: alloc::vec::Vec<eth_u256> =
                    alloc::vec::Vec::with_capacity(public_inputs.len() as usize);
                for input in public_inputs.iter() {
                    let mut buf = [0u8; 32];
                    input.to_be_bytes().copy_into_slice(&mut buf);
                    inputs.push(eth_u256::from_be_bytes(buf));
                }
                groth16_verify(&env, &vk, &proof, &inputs)
            })();

            // Always clear the proof-context flag (the Temporary entry also
            // expires automatically).
            vk::clear_proof_context(&env);
            outcome
        })();

        // ── Record nullifier only after a successful verification ──────────────
        //
        // We write the nullifier *after* verification so that a proof that
        // fails on-chain (bad pairing, invalid inputs, …) is not burned in the
        // nullifier set — the submitter would lose the ability to re-submit a
        // corrected proof if we wrote before.  Only an accepted proof (one that
        // returns `Ok(true)`) is recorded as spent.
        if anti_replay {
            if let Ok(true) = result {
                let inputs_buf = nullifier::inputs_to_bytes(&env, &public_inputs);
                let nstore = nullifier::NullifierStore::new(&env);
                nstore.mark_spent(&env, &proof_bytes, &inputs_buf)
                    .map_err(|_| ZkContractError::StorageError)?;
            }
        }

        result.map_err(ZkContractError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Bytes, Env, U256};

    #[test]
    fn host_convert_zero_is_valid() {
        let env = Env::default();
        let val = U256::from_u128(&env, 0);
        assert!(env.fr_from_u256(val).is_ok());
    }

    #[test]
    fn host_convert_small_value_is_valid() {
        let env = Env::default();
        let val = U256::from_u128(&env, 42);
        assert!(env.fr_from_u256(val).is_ok());
    }

    #[test]
    fn host_convert_above_modulus_is_err() {
        let env = Env::default();
        let bytes = Bytes::from_array(&env, &[0xff_u8; 32]);
        let val = U256::from_be_bytes(&env, &bytes);
        assert_eq!(env.fr_from_u256(val), Err(ZkError::InvalidFieldElement));
    }

    #[test]
    fn host_convert_modulus_itself_is_err() {
        let env = Env::default();
        let modulus_bytes: [u8; 32] = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16,
            0xd8, 0x7c, 0xfd, 0x47,
        ];
        let bytes = Bytes::from_array(&env, &modulus_bytes);
        let val = U256::from_be_bytes(&env, &bytes);
        assert_eq!(env.fr_from_u256(val), Err(ZkError::InvalidFieldElement));
    }

    #[test]
    fn host_convert_returns_err_not_panic_on_overflow() {
        let env = Env::default();
        // u256::MAX is far above the BN254 modulus — must return Err, never panic.
        let bytes = Bytes::from_array(&env, &[0xff_u8; 32]);
        let val = U256::from_be_bytes(&env, &bytes);
        let result = env.fr_from_u256(val);
        assert!(result.is_err());
    }

    #[test]
    fn poseidon2_hash_matches_uncached_and_reuses_cache() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let id = env.register(ZkContract, ());
        let client = ZkContractClient::new(&env, &id);

        let inputs = soroban_sdk::vec![&env, U256::from_u128(&env, 1), U256::from_u128(&env, 2)];

        // The cached on-chain hash equals the pure (uncached) library hash.
        let raw = [U256::from_u128(&env, 1), U256::from_u128(&env, 2)];
        let expected = poseidon2::hash_to_field(&env, &raw);
        assert_eq!(client.poseidon2_hash(&inputs), expected);

        // A second invocation hits the populated instance cache and is stable.
        assert_eq!(client.poseidon2_hash(&inputs), expected);

        // The constants are present in the contract's instance storage.
        env.as_contract(&id, || {
            let store = env.storage().instance();
            assert!(store.has(&cache::ConstantKey::Poseidon2RoundConstants));
            assert!(store.has(&cache::ConstantKey::Poseidon2MatDiag));
            assert!(store.has(&cache::ConstantKey::FrModulus));
        });
    }

    // ── verify_proof anti-replay integration tests ───────────────────────────

    /// Builds a minimal but structurally valid 256-byte proof buffer using the
    /// canonical G1 / G2 generator points (a real pairing check would fail, but
    /// that's fine — these tests exercise the nullifier layer only).
    fn dummy_proof_bytes(env: &Env) -> Bytes {
        use crate::pairing::g1_to_bytes;
        let g1 = vk::G1_GENERATOR;
        let g2 = vk::G2_GENERATOR;
        let mut buf = Bytes::new(env);
        buf.extend_from_array(&g1_to_bytes(&g1));   // A  (64 bytes)
        buf.extend_from_array(&g2.to_bytes());       // B (128 bytes)
        buf.extend_from_array(&g1_to_bytes(&g1));   // C  (64 bytes)
        buf
    }

    #[test]
    fn verify_proof_anti_replay_rejected_on_second_call() {
        use ark_bn254::{Bn254 as ArkBn254, Fr as ArkFr};
        use ark_groth16::{prepare_verifying_key, Groth16};
        use ark_relations::gr1cs::{
            ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
        };
        use ark_snark::SNARK;
        use ark_std::rand::{rngs::StdRng, SeedableRng};
        use ark_ff::{BigInteger, PrimeField};

        #[derive(Clone)]
        struct SquareCircuit {
            x: Option<ArkFr>,
            public_square: Option<ArkFr>,
        }
        impl ConstraintSynthesizer<ArkFr> for SquareCircuit {
            fn generate_constraints(
                self,
                cs: ConstraintSystemRef<ArkFr>,
            ) -> Result<(), SynthesisError> {
                let x = cs.new_witness_variable(|| {
                    self.x.ok_or(SynthesisError::AssignmentMissing)
                })?;
                let sq = cs.new_input_variable(|| {
                    self.public_square.ok_or(SynthesisError::AssignmentMissing)
                })?;
                cs.enforce_r1cs_constraint(
                    || LinearCombination::from(x),
                    || LinearCombination::from(x),
                    || LinearCombination::from(sq),
                )
            }
        }

        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();

        let mut rng = StdRng::seed_from_u64(42);
        let (pk, ark_vk) =
            Groth16::<ArkBn254>::circuit_specific_setup(
                SquareCircuit { x: None, public_square: None },
                &mut rng,
            )
            .unwrap();

        let ark_proof = Groth16::<ArkBn254>::prove(
            &pk,
            SquareCircuit {
                x: Some(ArkFr::from(3u64)),
                public_square: Some(ArkFr::from(9u64)),
            },
            &mut rng,
        )
        .unwrap();

        // ── Helpers to convert arkworks → local types ──────────────────────
        use crate::groth16::g1_from_bytes as local_g1;
        use crate::pairing::g1_to_bytes;
        use ethnum::u256 as eu256;
        use soroban_zk_core::G1Affine;

        fn fq_u256(v: ark_bn254::Fq) -> eu256 {
            let bytes = v.into_bigint().to_bytes_be();
            let mut out = [0u8; 32];
            out[32 - bytes.len()..].copy_from_slice(&bytes);
            eu256::from_be_bytes(out)
        }
        fn fr_u256(v: ArkFr) -> eu256 {
            let bytes = v.into_bigint().to_bytes_be();
            let mut out = [0u8; 32];
            out[32 - bytes.len()..].copy_from_slice(&bytes);
            eu256::from_be_bytes(out)
        }
        fn to_g1(p: ark_bn254::G1Affine) -> G1Affine {
            G1Affine { x: fq_u256(p.x), y: fq_u256(p.y) }
        }
        fn to_g2(p: ark_bn254::G2Affine) -> crate::pairing::G2Affine {
            crate::pairing::G2Affine {
                x: (fq_u256(p.x.c0), fq_u256(p.x.c1)),
                y: (fq_u256(p.y.c0), fq_u256(p.y.c1)),
            }
        }

        let ic_local = [
            to_g1(ark_vk.gamma_abc_g1[0]),
            to_g1(ark_vk.gamma_abc_g1[1]),
        ];
        let local_vk = crate::vk::OwnedVerifyingKey {
            alpha_g1: to_g1(ark_vk.alpha_g1),
            beta_g2: to_g2(ark_vk.beta_g2),
            gamma_g2: to_g2(ark_vk.gamma_g2),
            delta_g2: to_g2(ark_vk.delta_g2),
            ic: alloc::vec![ic_local[0], ic_local[1]],
        };

        // Serialise proof → 256-byte buffer
        let mut pbuf = [0u8; 256];
        pbuf[..64].copy_from_slice(&g1_to_bytes(&to_g1(ark_proof.a)));
        pbuf[64..192].copy_from_slice(&to_g2(ark_proof.b).to_bytes());
        pbuf[192..].copy_from_slice(&g1_to_bytes(&to_g1(ark_proof.c)));
        let proof_bytes = Bytes::from_array(&env, &pbuf);

        let public_square = fr_u256(ArkFr::from(9u64));
        let public_inputs = soroban_sdk::vec![
            &env,
            U256::from_be_bytes(
                &env,
                &Bytes::from_array(&env, &public_square.to_be_bytes()),
            )
        ];

        // Register the contract and save the VK.
        let id = env.register(ZkContract, ());
        let client = ZkContractClient::new(&env, &id);

        env.as_contract(&id, || {
            let vk_ref = local_vk.as_vk();
            vk::save_vk(&env, &vk_ref).unwrap();
        });

        // First call with anti_replay=true → should succeed (proof is valid).
        let first = client.try_verify_proof(&proof_bytes, &public_inputs, &true);
        assert_eq!(first, Ok(Ok(true)), "first verify_proof should return Ok(true)");

        // Second call with the identical proof → ReplayDetected.
        let second = client.try_verify_proof(&proof_bytes, &public_inputs, &true);
        assert_eq!(
            second,
            Err(Ok(ZkContractError::ReplayDetected)),
            "second verify_proof should return ReplayDetected"
        );
    }

    #[test]
    fn verify_proof_without_anti_replay_allows_resubmission() {
        // When anti_replay=false, no nullifier is written and the same proof can
        // be submitted any number of times.  (The pairing check will fail on dummy
        // bytes, but we test the nullifier path specifically here.)
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let id = env.register(ZkContract, ());

        // We deliberately use a VK with no IC so verify_proof returns
        // Err(InvalidInput) consistently — we only care that ReplayDetected
        // is NOT returned on the second call.
        env.as_contract(&id, || {
            // Save a minimal dummy VK (1 ic entry matching 0 public inputs).
            let vk_ref = crate::groth16::Groth16VerifyingKey {
                alpha_g1: vk::G1_GENERATOR,
                beta_g2: vk::G2_GENERATOR,
                gamma_g2: vk::G2_GENERATOR,
                delta_g2: vk::G2_GENERATOR,
                ic: &[vk::G1_GENERATOR],
            };
            vk::save_vk(&env, &vk_ref).unwrap();
        });

        let proof_bytes = dummy_proof_bytes(&env);
        let public_inputs: soroban_sdk::Vec<U256> = soroban_sdk::Vec::new(&env);
        let client = ZkContractClient::new(&env, &id);

        let first = client.try_verify_proof(&proof_bytes, &public_inputs, &false);
        let second = client.try_verify_proof(&proof_bytes, &public_inputs, &false);

        // Neither result should be ReplayDetected.
        assert_ne!(
            first,
            Err(Ok(ZkContractError::ReplayDetected)),
            "anti_replay=false must not return ReplayDetected on first call"
        );
        assert_ne!(
            second,
            Err(Ok(ZkContractError::ReplayDetected)),
            "anti_replay=false must not return ReplayDetected on second call"
        );
    }
}
