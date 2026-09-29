//! PLONK KZG Evaluation Proof Verifier (Stellar Integration Layer).
//!
//! This module wires the pure-math [`kzg_eval_proof_points`] function from
//! `soroban-zk-core` to the Soroban `bn254_multi_pairing_check` host function
//! via the existing [`pairing_check`] abstraction.
//!
//! ## Protocol
//!
//! The final KZG check in PLONK verification reduces to a two-pair equation:
//!
//! ```text
//! e(W_ζ + u·W_{ζω},  [τ]₂)
//! · e(-(ζ·W_ζ + u·ζω·W_{ζω} + F - [E]₁),  G₂)
//! == 1
//! ```
//!
//! where:
//! - `[τ]₂` is the SRS G2 element (the trusted-setup key)
//! - `G₂` is the BN254 G2 generator
//! - `F` is the batched polynomial commitment (see [`KzgEvalProofInputs`])
//! - `[E]₁` is the batched evaluation encoded as a G1 point
//!
//! [`kzg_eval_proof_points`] handles all G1 arithmetic and returns the two
//! G1 points for the equation above.  This module pairs them against the
//! appropriate G2 points using the Soroban host's native pairing engine.
//!
//! ## Security Notes
//!
//! - All input scalars are validated against the BN254 scalar field modulus
//!   before any curve operation (inside [`kzg_eval_proof_points`]).
//! - G1 points coming from the proof (`w_zeta`, `w_zeta_omega`, and the
//!   commitments) **must** be validated by the caller before constructing
//!   [`KzgEvalProofInputs`].  Use [`crate::host::g1_from_host_bytes`] or
//!   check [`soroban_zk_core::Bn254::is_valid_g1_subgroup`] directly.
//! - G2 points (`srs_g2`, generator) are validated inside [`pairing_check`].

use soroban_sdk::Env;
use soroban_zk_core::{kzg_eval_proof_points, Bn254, G1Affine, KzgEvalProofInputs, ZkError};

use crate::pairing::{pairing_check, G2Affine};

/// Negates a G1Affine point: `(x, y) -> (x, -y mod Fq)`.
///
/// Returns the identity unchanged.
#[inline(always)]
fn neg_g1(p: G1Affine) -> G1Affine {
    use ethnum::u256;
    if p.x == u256::from(0u8) && p.y == u256::from(0u8) {
        p
    } else {
        G1Affine {
            x: p.x,
            y: Bn254::sub_fq(u256::from(0u8), p.y),
        }
    }
}

/// Verifies the batched KZG evaluation proofs for PLONK at `ζ` and `ζω`.
///
/// This is the entry point for the "opening check" step of a PLONK verifier.
/// It performs the full two-pair pairing equation using the Soroban
/// `bn254_multi_pairing_check` host function (CAP-0075).
///
/// # Arguments
///
/// * `env` – Soroban execution environment (needed for the pairing host call).
/// * `inputs` – All evaluations, commitments, and opening proofs (see
///   [`KzgEvalProofInputs`]).
/// * `srs_g2` – The SRS G2 element `[τ]₂` from the trusted setup.  In
///   practice this is stored in the verifying key.
///
/// # Returns
///
/// * `Ok(true)` if the pairing equation holds (proof accepted).
/// * `Ok(false)` if the pairing equation fails (proof rejected).
/// * `Err(ZkError::InvalidInput)` / `Err(ZkError::InvalidFieldElement)` on
///   malformed inputs (propagated from [`kzg_eval_proof_points`]).
/// * `Err(ZkError::HostError)` if the host pairing call fails unexpectedly.
///
/// # Gas Guidance
///
/// This call performs exactly two pairings via `bn254_multi_pairing_check`.
/// At Protocol 25 rates each pair costs ~40 M instructions; total budget for
/// this call is ~80 M instructions.  The G1 scalar-mul operations in
/// [`kzg_eval_proof_points`] add roughly 10–30 M depending on the batch size.
///
/// # Example
///
/// ```rust,ignore
/// use soroban_zk_std::plonk_kzg::verify_plonk_kzg;
/// use soroban_zk_core::KzgEvalProofInputs;
/// use soroban_zk_std::pairing::G2Affine;
///
/// let accepted = verify_plonk_kzg(&env, &inputs, srs_g2)?;
/// assert!(accepted, "proof verification failed");
/// ```
pub fn verify_plonk_kzg(
    env: &Env,
    inputs: &KzgEvalProofInputs<'_>,
    srs_g2: G2Affine,
) -> Result<bool, ZkError> {
    // 1. Compute the two G1 points from the batched polynomial arithmetic.
    let (lhs, rhs) = kzg_eval_proof_points(inputs)?;

    // 2. The G2 generator (BN254 standard generator).
    let g2_gen = G2Affine::generator();

    // 3. Check:  e(lhs, srs_g2) · e(neg(rhs), G2_gen) == 1
    //
    //    Equivalent to:  e(lhs, srs_g2) == e(rhs, G2_gen)
    //    which is the standard form of the KZG pairing check.
    //
    //    We negate `rhs` and pass both pairs to the multi-pairing engine so
    //    the product lands on the identity in GT:
    //
    //        e(lhs, srs_g2) · e(-rhs, G2_gen) = 1
    pairing_check(env, &[(lhs, srs_g2), (neg_g1(rhs), g2_gen)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethnum::u256;
    use soroban_sdk::Env;
    use soroban_zk_core::G1Affine;

    // ─── helpers ────────────────────────────────────────────────────────────

    fn g1_gen() -> G1Affine {
        G1Affine {
            x: u256::from(1u8),
            y: u256::from(2u8),
        }
    }

    fn g2_gen() -> G2Affine {
        G2Affine::generator()
    }

    // ─── unit tests ─────────────────────────────────────────────────────────

    /// Calling `verify_plonk_kzg` with well-formed inputs must not panic and
    /// must return a `bool` (true or false) rather than an error.
    ///
    /// Note: Because the fixture is *not* a valid proof, the pairing will
    /// return `false`.  We only assert the absence of errors here.
    #[test]
    fn verify_plonk_kzg_completes_without_error_for_valid_inputs() {
        let env = Env::default();
        let commitments = [g1_gen()];
        let evaluations = [u256::from(3u8)];

        let inputs = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: g1_gen(),
            w_zeta_omega: g1_gen(),
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: u256::from(13u8),
            omega: u256::from(17u8),
        };

        // A random G2 point used as the mock SRS element.
        let srs_g2 = g2_gen();

        // Must return Ok(bool) — not panic, not Err.
        match verify_plonk_kzg(&env, &inputs, srs_g2) {
            Ok(_accepted) => { /* pass — result is mathematically undefined for dummy data */ }
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    }

    /// `verify_plonk_kzg` must propagate `ZkError::InvalidInput` when the
    /// commitment and evaluation slices have different lengths.
    #[test]
    fn verify_plonk_kzg_propagates_invalid_input_error() {
        let env = Env::default();
        let commitments = [g1_gen()];
        let evaluations = [u256::from(1u8), u256::from(2u8)]; // wrong length

        let inputs = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: g1_gen(),
            w_zeta_omega: g1_gen(),
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: u256::from(13u8),
            omega: u256::from(17u8),
        };

        assert_eq!(
            verify_plonk_kzg(&env, &inputs, g2_gen()),
            Err(ZkError::InvalidInput)
        );
    }

    /// `verify_plonk_kzg` must propagate `ZkError::InvalidFieldElement` when
    /// any challenge scalar is ≥ the BN254 scalar field modulus.
    #[test]
    fn verify_plonk_kzg_propagates_field_element_error() {
        let env = Env::default();
        let commitments = [g1_gen()];
        let evaluations = [u256::from(3u8)];

        let inputs = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(5u8),
            w_zeta: g1_gen(),
            w_zeta_omega: g1_gen(),
            v: u256::from(7u8),
            u: u256::from(11u8),
            zeta: Bn254::FR_MODULUS, // out-of-range zeta
            omega: u256::from(17u8),
        };

        assert_eq!(
            verify_plonk_kzg(&env, &inputs, g2_gen()),
            Err(ZkError::InvalidFieldElement)
        );
    }

    /// Structural test: verify the full call chain reaches the pairing engine.
    /// With u = 0 and carefully chosen inputs, we confirm no panic/error occurs.
    /// See inline comments for the mathematical reasoning.
    #[test]
    fn verify_plonk_kzg_trivial_self_cancelling_proof() {
        let env = Env::default();

        // With u = 0: lhs = W_ζ
        // With zeta = 0: zeta*W_ζ = identity
        // F = C_0 = G1_gen, [E]_1 = eval_0 * G1_gen = 1 * G1_gen = G1_gen
        // → F - [E]_1 = G1_gen - G1_gen = identity
        // → rhs = identity
        //
        // Pairing check: e(G1_gen, srs_g2) · e(-identity, G2_gen) = e(G1_gen, srs_g2) ≠ 1
        // So the proof is NOT accepted — but no error should be returned.
        let commitments = [g1_gen()];
        let evaluations = [u256::from(1u8)];

        let inputs = KzgEvalProofInputs {
            commitments: &commitments,
            evaluations_at_zeta: &evaluations,
            commitment_at_zeta_omega: g1_gen(),
            evaluation_at_zeta_omega: u256::from(0u8),
            w_zeta: g1_gen(),
            w_zeta_omega: g1_gen(),
            v: u256::from(1u8),
            u: u256::from(0u8),
            zeta: u256::from(0u8),
            omega: u256::from(1u8),
        };

        let result = verify_plonk_kzg(&env, &inputs, g2_gen());
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }
}
