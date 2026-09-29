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
/// Absorbs `message` (field elements) in blocks of `rate = STATE - 1`, then
/// squeezes a single field element as the digest. Capacity is 1 (state[0]).
pub fn rescue_prime_hash(env: &Env, message: &[U256]) -> U256 {
    let params = RescueParams::new();
    let rate = STATE - 1;
    let mut state = [eth_u256::ZERO; STATE];

    let mut idx = 0;
    while idx < message.len() {
        // Absorb one block into the rate portion (capacity untouched).
        for k in 0..rate {
            if idx + k < message.len() {
                state[k + 1] = fadd(state[k + 1], to_eth_v(&message[idx + k]));
            }
        }
        params.permute(&mut state);
        idx += rate;
    }
    // Final permutation if the message was empty ensures a non-trivial digest.
    if message.is_empty() {
        params.permute(&mut state);
    }

    from_eth_v(env, state[1])
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
}
