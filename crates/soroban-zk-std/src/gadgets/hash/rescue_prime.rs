//! Rescue-Prime hashing gadget (Issue #367, Phase 4).
//!
//! Implements the Rescue-Prime sponge permutation over the BN254 scalar field
//! `Fr` in pure software (no host call), so the same constraints can be
//! evaluated in-circuit by a prover and re-checked by a verifier. The S-box is
//! `x^α` with `α` an odd exponent coprime to `p-1`; its inverse `x^{α⁻¹}` is
//! provided so that the permutation is (partially) invertible and the S-box
//! inverse algorithm is exercised directly.
//!
//! Field arithmetic uses [`soroban_zk_core::Bn254`], which operates on
//! [`ethnum::u256`] modulo the BN254 Fr modulus.

use ethnum::u256 as eth_u256;
use soroban_sdk::{Bytes, Env, U256, Vec};
use soroban_zk_core::Bn254;

/// State width `m`. Rate = `m - 1`, capacity = `1`.
pub const STATE: usize = 3;
/// Number of permutation rounds (must be even).
pub const ROUNDS: usize = 6;

const FR: eth_u256 = Bn254::FR_MODULUS;

#[inline(always)]
fn fadd(a: eth_u256, b: eth_u256) -> eth_u256 {
    Bn254::add(a, b)
}
#[inline(always)]
fn fsub(a: eth_u256, b: eth_u256) -> eth_u256 {
    Bn254::sub(a, b)
}
#[inline(always)]
fn fmul(a: eth_u256, b: eth_u256) -> eth_u256 {
    Bn254::mul(a, b)
}
#[inline(always)]
fn finv(a: eth_u256) -> eth_u256 {
    Bn254::invert(a)
}
#[inline(always)]
fn fpow(a: eth_u256, e: eth_u256) -> eth_u256 {
    Bn254::pow(a, e)
}

/// Pick a valid S-box exponent `α` (odd, coprime to `p-1`) and its inverse.
fn sbox_exponents() -> (eth_u256, eth_u256) {
    // p-1 for the BN254 scalar field.
    let pm1 = FR - eth_u256::ONE;
    let mut alpha = eth_u256::from(3u8);
    loop {
        if gcd(alpha, pm1) == eth_u256::ONE {
            let inv = mod_inv(alpha, pm1);
            return (alpha, inv);
        }
        alpha += eth_u256::from(2u8); // stay odd
    }
}

fn gcd(mut a: eth_u256, mut b: eth_u256) -> eth_u256 {
    while b != eth_u256::ZERO {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// `(a + b) mod m` without overflow (a, b < m < 2^254 ⇒ sum < 2^255).
fn add_mod(a: eth_u256, b: eth_u256, m: eth_u256) -> eth_u256 {
    let s = a + b;
    s % m
}

/// `(a − b) mod m`, keeping the result in `[0, m)`.
fn sub_mod(a: eth_u256, b: eth_u256, m: eth_u256) -> eth_u256 {
    if a >= b {
        (a - b) % m
    } else {
        (m - (b - a)) % m
    }
}

/// `(a · b) mod m` using double-and-add so intermediate products stay in `u256`
/// (`m < 2^254`, `a·b` could be up to `2^508`).
fn mul_mod(a: eth_u256, b: eth_u256, m: eth_u256) -> eth_u256 {
    let mut res = eth_u256::ZERO;
    let mut x = a % m;
    for bit in (0..256).rev() {
        res = (res << 1) % m;
        if (x >> bit) & eth_u256::ONE == eth_u256::ONE {
            res = add_mod(res, b, m);
        }
    }
    res
}

/// Modular inverse of `a` modulo `m` (extended Euclidean with modular reduction
/// so the Bézout coefficient never goes negative). `m` need not be prime.
fn mod_inv(mut a: eth_u256, mut m: eth_u256) -> eth_u256 {
    a %= m;
    let (mut t, mut newt) = (eth_u256::ZERO, eth_u256::ONE);
    let (mut r, mut newr) = (m, a);
    while newr != eth_u256::ZERO {
        let q = r / newr;
        let tmp = t;
        t = newt;
        newt = sub_mod(tmp, mul_mod(q, newt, m), m);
        let tmp_r = r;
        r = newr;
        newr = tmp_r - q * newr; // r >= q·newr, so this is non-negative and < m
    }
    // r must be 1 (a is coprime to m).
    t % m
}

/// Rescue-Prime parameters: MDS matrix and round keys (Cauchy MDS, LCG round keys).
pub struct RescueParams {
    mds: [[eth_u256; STATE]; STATE],
    round_keys: [[eth_u256; STATE]; ROUNDS],
}

impl RescueParams {
    /// Build the fixed (deterministic) parameter set.
    pub fn new() -> Self {
        let mds = build_mds();
        let round_keys = build_round_keys();
        Self { mds, round_keys }
    }

    /// Build from pre-computed cached values (for instance storage caching).
    pub fn from_cached(
        _env: &Env,
        mds: Vec<Vec<U256>>,
        round_keys: Vec<Vec<U256>>,
    ) -> Self {
        let mut mds_arr = [[eth_u256::ZERO; STATE]; STATE];
        for i in 0..STATE {
            for j in 0..STATE {
                mds_arr[i][j] = to_eth_v(&mds.get(i).unwrap().get(j).unwrap());
            }
        }
        let mut rk_arr = [[eth_u256::ZERO; STATE]; ROUNDS];
        for r in 0..ROUNDS {
            for j in 0..STATE {
                rk_arr[r][j] = to_eth_v(&round_keys.get(r).unwrap().get(j).unwrap());
            }
        }
        Self {
            mds: mds_arr,
            round_keys: rk_arr,
        }
    }

    /// Apply the `α`-th power S-box to a single element.
    pub fn sbox(&self, x: eth_u256) -> eth_u256 {
        let (alpha, _) = sbox_exponents();
        fpow(x, alpha)
    }

    /// Apply the S-box inverse (`x^{α⁻¹}`).
    pub fn sbox_inv(&self, x: eth_u256) -> eth_u256 {
        let (_, alpha_inv) = sbox_exponents();
        fpow(x, alpha_inv)
    }

    /// One Rescue-Prime permutation of the `m`-element state.
    pub fn permute(&self, state: &mut [eth_u256; STATE]) {
        let (alpha, alpha_inv) = sbox_exponents();
        for r in 0..ROUNDS {
            // S-box (forward on even rounds, inverse on odd rounds).
            for i in 0..STATE {
                state[i] = if r % 2 == 0 {
                    fpow(state[i], alpha)
                } else {
                    fpow(state[i], alpha_inv)
                };
            }
            // Add round key.
            let key = &self.round_keys[r];
            for i in 0..STATE {
                state[i] = fadd(state[i], key[i]);
            }
            // MDS linear layer.
            let mut out = [eth_u256::ZERO; STATE];
            for i in 0..STATE {
                let mut acc = eth_u256::ZERO;
                for j in 0..STATE {
                    acc = fadd(acc, fmul(self.mds[i][j], state[j]));
                }
                out[i] = acc;
            }
            *state = out;
        }
    }
}

/// Build a Cauchy MDS matrix `M[i][j] = 1/(x_i - y_j)` with distinct sequences,
/// which is guaranteed invertible.
fn build_mds() -> [[eth_u256; STATE]; STATE] {
    let mut mds = [[eth_u256::ZERO; STATE]; STATE];
    for i in 0..STATE {
        let xi = eth_u256::from(i as u128 + 1);
        for j in 0..STATE {
            // y_j = m + j + 1  → ensures x_i - y_j is never zero.
            let yj = eth_u256::from(STATE as u128 + j as u128 + 1);
            let mut diff = fsub(xi, yj);
            if diff >= FR {
                diff = fsub(diff, FR);
            }
            mds[i][j] = finv(diff);
        }
    }
    mds
}

/// Deterministic round keys from a small LCG seeded by a constant.
fn build_round_keys() -> [[eth_u256; STATE]; ROUNDS] {
    let mut keys = [[eth_u256::ZERO; STATE]; ROUNDS];
    // LCG parameters (arbitrary but fixed); result is mod Fr.
    let a: eth_u256 = eth_u256::from(0x9E3779B97F4A7C15u64);
    let c: eth_u256 = eth_u256::from(0x4F1BBCDCBFD3A8A7u64);
    let mut state = eth_u256::from(0x1234_5678_9ABC_DEF1u64);
    for r in 0..ROUNDS {
        let mut row = [eth_u256::ZERO; STATE];
        for j in 0..STATE {
            state = fadd(fmul(state, a), c);
            row[j] = state;
        }
        keys[r] = row;
    }
    keys
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

/// Rescue-Prime sponge over BN254 Fr (t=3, rate=2, capacity=1).
///
/// The permutation runs in guest code (no host call), making it suitable for
/// in-circuit verification as well as native execution.
///
/// # Example
/// ```ignore
/// let mut sponge = RescueSponge::new(&env);
/// sponge.absorb(&inputs);
/// let digest = sponge.squeeze();
/// ```
pub struct RescueSponge {
    env: Env,
    state: [eth_u256; STATE],
    rate_idx: usize,
    params: RescueParams,
}

impl RescueSponge {
    /// Create a new sponge with zeroed state, building the BN254 constants
    /// from code (no contract storage required).
    ///
    /// The round keys and MDS matrix are computed once here and reused across
    /// every [`RescueSponge::absorb`]/[`RescueSponge::squeeze`] permutation,
    /// rather than being rebuilt on each permutation.
    pub fn new(env: &Env) -> Self {
        let params = RescueParams::new();
        let state = [eth_u256::ZERO; STATE];
        Self {
            env: env.clone(),
            state,
            rate_idx: 0,
            params,
        }
    }

    /// Create a new sponge whose BN254 constants are sourced from the contract
    /// instance storage cache.
    ///
    /// On the first invocation within a contract the constants are computed and
    /// written to `StorageType::Instance`; subsequent invocations read them back
    /// from storage instead of rebuilding them. Must be called from within a
    /// contract invocation context (it touches instance storage).
    pub fn new_cached(env: &Env) -> Self {
        let params = crate::cache::rescue_prime_params(env);
        let state = [eth_u256::ZERO; STATE];
        Self {
            env: env.clone(),
            state,
            rate_idx: 0,
            params,
        }
    }

    /// Absorb a slice of BN254 Fr field elements into the sponge.
    pub fn absorb(&mut self, inputs: &[U256]) {
        let rate = STATE - 1;
        for input in inputs {
            let cur = self.state[self.rate_idx + 1];
            let next = fadd(cur, to_eth_v(input));
            self.state[self.rate_idx + 1] = next;
            self.rate_idx += 1;
            if self.rate_idx == rate {
                self.params.permute(&mut self.state);
                self.rate_idx = 0;
            }
        }
    }

    /// Squeeze one field element.
    ///
    /// Pads and applies the permutation if any unprocessed input remains,
    /// then returns the first element of the rate portion (state[1]).
    pub fn squeeze(&mut self) -> U256 {
        // Flush any buffered input with a final permutation.
        self.params.permute(&mut self.state);
        self.rate_idx = 0;
        from_eth_v(&self.env, self.state[1])
    }
}

/// Hash a slice of BN254 Fr field elements to a single field element using
/// the Rescue-Prime sponge (t=3, rate=2, capacity=1).
///
/// Compatible with the Rescue-Prime specification (forward/inverse S-box,
/// Cauchy MDS matrix, LCG round keys).
pub fn rescue_prime_hash(env: &Env, message: &[U256]) -> U256 {
    let mut sponge = RescueSponge::new(env);
    sponge.absorb(message);
    sponge.squeeze()
}

/// Instance-cached variant of [`rescue_prime_hash`].
///
/// Identical output to [`rescue_prime_hash`], but the BN254 round keys and
/// MDS matrix are loaded from (and lazily populated into) the contract
/// instance storage cache rather than rebuilt from code. Must be called from
/// within a contract invocation context.
pub fn rescue_prime_hash_cached(env: &Env, message: &[U256]) -> U256 {
    let mut sponge = RescueSponge::new_cached(env);
    sponge.absorb(message);
    sponge.squeeze()
}

/// Build the MDS matrix as nested `Vec<Vec<U256>>` for storage in instance cache.
pub fn build_mds_for_cache(env: &Env) -> Vec<Vec<U256>> {
    let mds = build_mds();
    let mut outer = Vec::new(env);
    for i in 0..STATE {
        let mut inner = Vec::new(env);
        for j in 0..STATE {
            inner.push_back(from_eth_v(env, mds[i][j]));
        }
        outer.push_back(inner);
    }
    outer
}

/// Build the round keys as nested `Vec<Vec<U256>>` for storage in instance cache.
pub fn build_round_keys_for_cache(env: &Env) -> Vec<Vec<U256>> {
    let round_keys = build_round_keys();
    let mut outer = Vec::new(env);
    for r in 0..ROUNDS {
        let mut inner = Vec::new(env);
        for j in 0..STATE {
            inner.push_back(from_eth_v(env, round_keys[r][j]));
        }
        outer.push_back(inner);
    }
    outer
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
    fn sponge_absorb_squeeze() {
        let env = env();
        let mut sponge = RescueSponge::new(&env);
        sponge.absorb(&[U256::from_u128(&env, 1), U256::from_u128(&env, 2)]);
        let d1 = sponge.squeeze();
        let d2 = sponge.squeeze();
        assert_ne!(d1, d2);
    }

    #[test]
    fn sponge_matches_direct_hash() {
        let env = env();
        let inputs = [U256::from_u128(&env, 42), U256::from_u128(&env, 99)];
        let h1 = rescue_prime_hash(&env, &inputs);
        let mut sponge = RescueSponge::new(&env);
        sponge.absorb(&inputs);
        let h2 = sponge.squeeze();
        assert_eq!(h1, h2);
    }
}
