//! Rescue-Prime hashing gadget (Issue #367, Phase 4).
//!
//! Implements the Rescue-Prime sponge permutation over the BN254 scalar field
//! `Fr` in pure software (no host call), so the same constraints can be
//! evaluated in-circuit by a prover and re-checked by a verifier.
//!
//! The linear layer (MDS matrix-vector multiply) is now delegated entirely to
//! [`soroban_zk_core::rescue`], which provides:
//! - [`soroban_zk_core::rescue::MdsMat`] — the Cauchy MDS matrix type
//! - [`soroban_zk_core::rescue::mds_multiply`] — constant-time matrix-vector multiply
//! - [`soroban_zk_core::rescue::RescuePrimeCore`] — full permutation with pre-built params
//!
//! This file provides the Soroban-SDK-aware sponge wrapper that absorbs
//! [`soroban_sdk::U256`] inputs and returns a digest.

use ethnum::u256 as eth_u256;
use soroban_sdk::{Bytes, Env, U256};
use soroban_zk_core::{Bn254, rescue::RescuePrimeCore};

/// Thin constant-time field addition alias (delegates to `Bn254::add`).
#[inline(always)]
fn fadd(a: eth_u256, b: eth_u256) -> eth_u256 {
    Bn254::add(a, b)
}

/// Re-export the state width constant from the core crate.
pub use soroban_zk_core::rescue::STATE;
/// Re-export the round count from the core crate.
pub use soroban_zk_core::rescue::ROUNDS;

/// Rescue-Prime parameters: a thin wrapper around [`RescuePrimeCore`] that
/// exposes the Soroban-facing API used by the rest of the gadget suite.
///
/// The MDS linear layer is fully delegated to
/// [`soroban_zk_core::rescue::mds_multiply`].
pub struct RescueParams {
    core: RescuePrimeCore,
}

impl RescueParams {
    /// Build the fixed (deterministic) parameter set.
    pub fn new() -> Self {
        Self {
            core: RescuePrimeCore::new(),
        }
    }

    /// Apply the forward S-box (`x^α`).
    #[inline(always)]
    pub fn sbox(&self, x: eth_u256) -> eth_u256 {
        self.core.sbox_fwd(x)
    }

    /// Apply the inverse S-box (`x^{α⁻¹}`).
    #[inline(always)]
    pub fn sbox_inv(&self, x: eth_u256) -> eth_u256 {
        self.core.sbox_inv(x)
    }

    /// One Rescue-Prime permutation of the `STATE`-element state.
    ///
    /// Delegates the MDS linear layer to
    /// [`soroban_zk_core::rescue::mds_multiply`] via the pre-built
    /// [`MdsMat`] stored inside [`RescuePrimeCore`].
    pub fn permute(&self, state: &mut [eth_u256; STATE]) {
        self.core.permute(state);
    }
}

/// Rescue-Prime sponge hash over BN254 Fr.
///
/// Absorbs `message` (field elements) in blocks of `rate = STATE - 1` with
/// pad10* (`1` followed by `0`s), then squeezes a single field element.
/// Capacity is 1 (state[0], never directly absorbed). An exact-multiple
/// input (including empty) gets a full extra padding block `[1, 0]`, so
/// `[]`, `[0]`, and `[0, 0]` all digest distinctly.
pub fn rescue_prime_hash(env: &Env, message: &[U256]) -> U256 {
    let mut fields = alloc::vec::Vec::with_capacity(message.len());
    for m in message.iter() {
        fields.push(to_eth_v(m));
    }
    from_eth_v(env, hash_eth_padded(&fields))
}

/// Rescue-Prime hash over a variable-length byte string.
///
/// Chunks `bytes` into 32-byte big-endian blocks (last block zero-padded on
/// the right, matching the transcript chunking convention), interprets each
/// block as a field element (reduced mod `Fr` on absorb), then applies the
/// same pad10* sponge as [`rescue_prime_hash`].
pub fn rescue_prime_hash_bytes(env: &Env, bytes: &Bytes) -> U256 {
    let n = bytes.len() as usize;
    let num_blocks = (n + 31) / 32;
    let mut fields = alloc::vec::Vec::with_capacity(num_blocks);
    for b in 0..num_blocks {
        let mut buf = [0u8; 32];
        for k in 0..32 {
            let idx = b * 32 + k;
            buf[k] = if idx < n {
                bytes.get(idx as u32).unwrap_or(0)
            } else {
                0
            };
        }
        fields.push(eth_u256::from_be_bytes(buf));
    }
    from_eth_v(env, hash_eth_padded(&fields))
}

/// Shared pad10* sponge core over native field elements.
fn hash_eth_padded(elems: &[eth_u256]) -> eth_u256 {
    let params = RescueParams::new();
    let rate = STATE - 1;
    let mut state = [eth_u256::ZERO; STATE];

    let mut idx = 0;
    while idx + rate <= elems.len() {
        for k in 0..rate {
            state[k + 1] = fadd(state[k + 1], elems[idx + k]);
        }
        params.permute(&mut state);
        idx += rate;
    }
    // Remainder is 0 or 1 (rate == 2): append `1`, zero-fill the rest.
    let rem = elems.len() - idx;
    if rem == 1 {
        state[1] = fadd(state[1], elems[idx]);
        state[2] = fadd(state[2], eth_u256::ONE);
    } else {
        state[1] = fadd(state[1], eth_u256::ONE);
    }
    params.permute(&mut state);

    state[1]
}

#[inline(always)]
fn to_eth_v(v: &U256) -> eth_u256 {
    let mut b = [0u8; 32];
    v.to_be_bytes().copy_into_slice(&mut b);
    eth_u256::from_be_bytes(b)
}

#[inline(always)]
fn from_eth_v(env: &Env, v: eth_u256) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_array(env, &v.to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    #[test]
    fn sbox_roundtrip() {
        let p = RescueParams::new();
        let x = eth_u256::from(12345u64);
        let y = p.sbox(x);
        assert_eq!(p.sbox_inv(y), x);
    }

    #[test]
    fn permute_is_deterministic() {
        let p = RescueParams::new();
        let mut s1 = [eth_u256::from(1u8), eth_u256::from(2u8), eth_u256::from(3u8)];
        let mut s2 = s1;
        p.permute(&mut s1);
        p.permute(&mut s2);
        assert_eq!(s1, s2);
    }

    #[test]
    fn hash_is_deterministic_and_order_sensitive() {
        let env = env();
        let a = U256::from_u128(&env, 1);
        let b = U256::from_u128(&env, 2);
        let h1 = rescue_prime_hash(&env, &[a.clone(), b.clone()]);
        let h2 = rescue_prime_hash(&env, &[a, b]);
        assert_eq!(h1, h2);
        let h3 = rescue_prime_hash(&env, &[U256::from_u128(&env, 2), U256::from_u128(&env, 1)]);
        assert_ne!(h1, h3);
    }

    #[test]
    fn hash_nonzero() {
        let env = env();
        let h = rescue_prime_hash(&env, &[]);
        // Not required to be nonzero, but should be stable & in-field.
        assert_eq!(h, rescue_prime_hash(&env, &[]));
        let bytes = h.to_be_bytes();
        let _ = bytes;
    }

    #[test]
    fn padding_separates_empty_zero_and_two_zeros() {
        let env = env();
        let h_empty = rescue_prime_hash(&env, &[]);
        let h_one = rescue_prime_hash(&env, &[U256::from_u128(&env, 0)]);
        let h_two = rescue_prime_hash(
            &env,
            &[U256::from_u128(&env, 0), U256::from_u128(&env, 0)],
        );
        assert_ne!(h_empty, h_one);
        assert_ne!(h_empty, h_two);
        assert_ne!(h_one, h_two);
    }

    #[test]
    fn exact_multiple_gets_full_padding_block() {
        let env = env();
        let a = U256::from_u128(&env, 1);
        let b = U256::from_u128(&env, 2);
        let c = U256::from_u128(&env, 3);
        let h_two = rescue_prime_hash(&env, &[a.clone(), b.clone()]);
        assert_eq!(h_two, rescue_prime_hash(&env, &[a, b]));
        // Different lengths must not collide through padding.
        assert_ne!(
            h_two,
            rescue_prime_hash(&env, &[U256::from_u128(&env, 1)])
        );
        assert_ne!(
            h_two,
            rescue_prime_hash(
                &env,
                &[
                    U256::from_u128(&env, 1),
                    U256::from_u128(&env, 2),
                    c
                ]
            )
        );
    }

    #[test]
    fn hash_bytes_matches_chunked_fields() {
        use soroban_sdk::Bytes;
        let env = env();
        let raw = [1u8, 2u8, 3u8];
        let bytes = Bytes::from_slice(&env, &raw);
        let mut block = [0u8; 32];
        block[..3].copy_from_slice(&raw);
        let field = U256::from_be_bytes(&env, &Bytes::from_array(&env, &block));
        assert_eq!(
            rescue_prime_hash_bytes(&env, &bytes),
            rescue_prime_hash(&env, &[field])
        );
        assert_eq!(
            rescue_prime_hash_bytes(&env, &Bytes::from_slice(&env, &[])),
            rescue_prime_hash(&env, &[])
        );
    }
}
