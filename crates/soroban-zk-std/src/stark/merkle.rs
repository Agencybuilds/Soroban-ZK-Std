//! Soroban-optimized Merkle authentication (Issue #366, Phase 3).
//!
//! Verification streams a fixed-size [`MerklePath`] of sibling hashes and folds
//! them with the leaf via the **native SHA-256 host binding** (`env.crypto()`.
//! sha256`, a single CAP-0075 host call per level). No guest Wasm heap is
//! touched: the only storage is the `siblings` array, bounded by `MAX_DEPTH`.
//!
//! **Sparse Merkle Tree (SMT) support** (Issue #459).
//!
//! A Sparse Merkle Tree is a full binary tree of fixed depth (typically 256)
//! where the vast majority of leaves are empty (default value). Only non-empty
//! leaves are stored explicitly. The authentication path for a leaf only includes
//! non-empty siblings; missing siblings are implicitly the precomputed "empty
//! hash" for that level. This enables O(log N) verification with O(k) storage
//! where k is the number of non-empty nodes on the path.
//!
//! Gas model: each tree level costs exactly one host `sha256` call. For a tree
//! of `2^d` leaves the verifier pays `d` host calls — this is the dominant, and
//! minimal, cost of the STARK Merkle check.
//!
//! **Localized hashing gas profile.** A standard STARK Merkle check walks one
//! authentication path of length `d` (the trace-domain log-size, e.g. `d = 20`
//! for a 1M-row trace). Each `sha256` host call is a single CAP-0075 metered
//! instruction; the Wasm-side work is just 64 bytes of array copies plus one
//! `BytesN` conversion per level. Total verifier cost is therefore
//! `O(d)` host calls and `O(d·64)` bytes of linear-memory traffic — no
//! guest heap allocation, independent of trace width. Doubling the trace length
//! adds exactly one more `sha256` call per query.

use soroban_sdk::{Bytes, BytesN, Env, Vec};
use ethnum::u256;
use alloc::collections::BTreeMap;

use crate::stark::field::Felt;

/// Maximum tree depth supported by a [`MerklePath`] (covers `2^32` leaves).
pub const MAX_DEPTH: u32 = 32;

/// An authentication path: the sibling hashes (raw 32-byte digests) from leaf to
/// root, plus the leaf index so folding can decide left/right ordering.
pub struct MerklePath {
    pub siblings: [[u8; 32]; MAX_DEPTH as usize],
    pub depth: u32,
    pub index: u64,
}

/// SHA-256 of an arbitrary byte slice (a Merkle leaf or inner-node input).
#[inline(always)]
pub fn hash(env: &Env, data: &Bytes) -> BytesN<32> {
    BytesN::from_array(env, &env.crypto().sha256(data).to_array())
}

/// Merkle leaf for a single Goldilocks element (its 8-byte big-endian encoding).
#[inline(always)]
pub fn felt_leaf(env: &Env, f: Felt) -> BytesN<32> {
    let b = f.to_bytes();
    hash(env, &Bytes::from_slice(env, &b))
}

/// Hash two 32-byte digests into their parent node, returning raw bytes.
#[inline(always)]
fn sha_pair(l: &[u8; 32], r: &[u8; 32], env: &Env) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(l);
    buf[32..].copy_from_slice(r);
    env.crypto().sha256(&Bytes::from_array(env, &buf)).to_array()
}

#[inline(always)]
fn sha_pair_bn(env: &Env, l: &BytesN<32>, r: &BytesN<32>) -> BytesN<32> {
    let a = l.to_array();
    let b = r.to_array();
    BytesN::from_array(env, &sha_pair(&a, &b, env))
}

impl MerklePath {
    /// Recompute the root this path authenticates to, given the leaf digest.
    pub fn compute_root(&self, env: &Env, leaf: &BytesN<32>) -> BytesN<32> {
        let mut cur = leaf.to_array();
        let mut idx = self.index;
        for i in 0..self.depth as usize {
            let sib = self.siblings[i];
            let (l, r) = if idx & 1 == 0 { (cur, sib) } else { (sib, cur) };
            cur = sha_pair(&l, &r, env);
            idx >>= 1;
        }
        BytesN::from_array(env, &cur)
    }

    /// Verify that `leaf` sits at `index` in the tree with Merkle `root`.
    pub fn verify(&self, env: &Env, leaf: &BytesN<32>, root: &BytesN<32>) -> bool {
        &self.compute_root(env, leaf) == root
    }
}

/// Build the Merkle root over a list of leaf digests (prover-side helper / test
/// fixture). Uses a host-backed `Vec` of digests — no guest Wasm heap.
pub fn merkle_root(env: &Env, leaves: &Vec<BytesN<32>>) -> BytesN<32> {
    let mut level: Vec<BytesN<32>> = Vec::new(env);
    for l in leaves.iter() {
        level.push_back(l);
    }
    while level.len() > 1 {
        let mut next: Vec<BytesN<32>> = Vec::new(env);
        let n = level.len();
        let mut i = 0;
        while i < n {
            next.push_back(sha_pair_bn(env, &level.get(i).unwrap(), &level.get(i + 1).unwrap()));
            i += 2;
        }
        level = next;
    }
    level.get(0).unwrap()
}

/// Open a Merkle proof for `leaves[index]` (prover-side helper / test fixture).
pub fn open(env: &Env, leaves: &Vec<BytesN<32>>, index: u32) -> MerklePath {
    let mut level: Vec<BytesN<32>> = Vec::new(env);
    for l in leaves.iter() {
        level.push_back(l);
    }
    let mut path = MerklePath {
        siblings: [[0u8; 32]; MAX_DEPTH as usize],
        depth: 0,
        index: index as u64,
    };
    let mut idx = index;
    let mut depth = 0u32;
    while level.len() > 1 {
        let sib_idx = (idx ^ 1) as usize;
        path.siblings[depth as usize] = level.get(sib_idx as u32).unwrap().to_array();
        let mut next: Vec<BytesN<32>> = Vec::new(env);
        let n = level.len();
        let mut i = 0;
        while i < n {
            next.push_back(sha_pair_bn(env, &level.get(i).unwrap(), &level.get(i + 1).unwrap()));
            i += 2;
        }
        level = next;
        idx >>= 1;
        depth += 1;
    }
    path.depth = depth;
    path
}

/// Maximum depth for a Sparse Merkle Tree (256-bit key space).
pub const SMT_MAX_DEPTH: u32 = 256;

/// Precomputed empty hashes for each level of a Sparse Merkle Tree.
/// `EMPTY_HASHES[0]` = hash of empty leaf (H(0)).
/// `EMPTY_HASHES[i]` = H(EMPTY_HASHES[i-1], EMPTY_HASHES[i-1]).
pub struct EmptyHashes {
    hashes: [[u8; 32]; SMT_MAX_DEPTH as usize + 1],
}

impl EmptyHashes {
    /// Compute and return the singleton empty-hash array for the given depth.
    /// The empty leaf is defined as SHA-256(0x00) (32 zero bytes).
    pub fn new(env: &Env) -> Self {
        let mut hashes = [[0u8; 32]; SMT_MAX_DEPTH as usize + 1];
        // Level 0: hash of 32 zero bytes (empty leaf)
        hashes[0] = env.crypto().sha256(&Bytes::from_array(env, &[0u8; 32])).to_array();
        // Level i: hash of (level i-1, level i-1)
        for i in 1..=SMT_MAX_DEPTH as usize {
            hashes[i] = sha_pair(&hashes[i - 1], &hashes[i - 1], env);
        }
        Self { hashes }
    }

    /// Get the empty hash for a specific level (0 = leaf level).
    #[inline(always)]
    pub fn get(&self, level: u32) -> &[u8; 32] {
        &self.hashes[level as usize]
    }

    /// Get the empty root for a tree of the given depth.
    #[inline(always)]
    pub fn root(&self, depth: u32) -> &[u8; 32] {
        &self.hashes[depth as usize]
    }
}

/// A sparse Merkle authentication path.
///
/// Only non-empty siblings are stored explicitly. A bitmap indicates which
/// levels have a non-empty sibling. Missing siblings default to the precomputed
/// empty hash for that level.
pub struct SparseMerklePath {
    /// Bitmap: bit i is 1 if `siblings[siblings_index[i]]` is the sibling for level i.
    pub bitmap: u256,
    /// Non-empty sibling hashes, packed contiguously.
    pub siblings: [[u8; 32]; SMT_MAX_DEPTH as usize],
    /// Number of non-empty siblings (popcount of bitmap).
    pub sibling_count: u32,
    /// Tree depth (typically 256).
    pub depth: u32,
    /// Leaf index (256-bit key).
    pub index: u256,
}

impl SparseMerklePath {
    /// Recompute the root this sparse path authenticates to.
    pub fn compute_root(&self, env: &Env, leaf: &BytesN<32>, empty_hashes: &EmptyHashes) -> BytesN<32> {
        let mut cur = leaf.to_array();
        let mut idx = self.index;
        let mut sib_idx = 0u32;

        for level in 0..self.depth as usize {
            let is_right = (idx & u256::from(1u64)) != u256::from(0u64);
            idx >>= 1;

            let sib = if (self.bitmap >> level) & u256::from(1u64) != u256::from(0u64) {
                // Non-empty sibling provided in the path
                let s = self.siblings[sib_idx as usize];
                sib_idx += 1;
                s
            } else {
                // Empty sibling: use precomputed empty hash for this level
                *empty_hashes.get(level as u32)
            };

            let (l, r) = if is_right { (sib, cur) } else { (cur, sib) };
            cur = sha_pair(&l, &r, env);
        }

        BytesN::from_array(env, &cur)
    }

    /// Verify that `leaf` sits at `index` in the SMT with Merkle `root`.
    pub fn verify(&self, env: &Env, leaf: &BytesN<32>, root: &BytesN<32>, empty_hashes: &EmptyHashes) -> bool {
        &self.compute_root(env, leaf, empty_hashes) == root
    }
}

/// Build the empty hashes and SMT root from a map of non-empty leaves (prover-side helper).
///
/// `leaves` is a sorted vector of (index, leaf_hash) pairs. Indices must be unique and in range [0, 2^depth).
pub fn smt_root(env: &Env, leaves: &Vec<(u256, BytesN<32>)>, depth: u32, empty_hashes: &EmptyHashes) -> BytesN<32> {
    if leaves.is_empty() {
        return BytesN::from_array(env, empty_hashes.root(depth));
    }

    // Build a map for quick lookup
    use alloc::collections::BTreeMap;
    let mut leaf_map: BTreeMap<u256, [u8; 32]> = BTreeMap::new();
    for (idx, hash) in leaves.iter() {
        leaf_map.insert(idx, hash.to_array());
    }

    // Recursively build the tree from bottom up
    fn build_level(
        env: &Env,
        nodes: &BTreeMap<u256, [u8; 32]>,
        level: u32,
        empty_hashes: &EmptyHashes,
    ) -> BTreeMap<u256, [u8; 32]> {
        if level == 0 {
            return nodes.clone();
        }

        let mut parent_map: BTreeMap<u256, [u8; 32]> = BTreeMap::new();
        let empty_hash = empty_hashes.get(level - 1);

        for (idx, hash) in nodes {
            let parent_idx = idx >> 1;
            let is_right = (idx & u256::from(1u64)) != u256::from(0u64);
            let sibling_idx = if is_right { idx - u256::from(1u64) } else { idx + u256::from(1u64) };

            let (left, right) = if is_right {
                let sib = nodes.get(&sibling_idx).copied().unwrap_or(*empty_hash);
                (sib, *hash)
            } else {
                let sib = nodes.get(&sibling_idx).copied().unwrap_or(*empty_hash);
                (*hash, sib)
            };

            let parent_hash = sha_pair(&left, &right, env);
            parent_map.insert(parent_idx, parent_hash);
        }

        build_level(env, &parent_map, level - 1, empty_hashes)
    }

    let root_map = build_level(env, &leaf_map, depth, empty_hashes);
    let root_hash = root_map.get(&u256::from(0u64)).copied().unwrap_or(*empty_hashes.root(depth));
    BytesN::from_array(env, &root_hash)
}

/// Open a Sparse Merkle proof for the leaf at `index` (prover-side helper).
///
/// Returns a `SparseMerklePath` containing only non-empty siblings.
pub fn smt_open(
    env: &Env,
    leaves: &Vec<(u256, BytesN<32>)>,
    index: u256,
    depth: u32,
    empty_hashes: &EmptyHashes,
) -> SparseMerklePath {
    use alloc::collections::BTreeMap;
    let mut leaf_map: BTreeMap<u256, [u8; 32]> = BTreeMap::new();
    for (idx, hash) in leaves.iter() {
        leaf_map.insert(idx, hash.to_array());
    }

    let mut path = SparseMerklePath {
        bitmap: u256::from(0u64),
        siblings: [[0u8; 32]; SMT_MAX_DEPTH as usize],
        sibling_count: 0,
        depth,
        index,
    };

    let mut idx = index;
    let mut sib_idx = 0u32;

    for level in 0..depth as usize {
        let is_right = (idx & u256::from(1u64)) != u256::from(0u64);
        let sibling_idx = if is_right { idx - u256::from(1u64) } else { idx + u256::from(1u64) };

        if let Some(sib_hash) = leaf_map.get(&sibling_idx) {
            // Non-empty sibling found
            path.bitmap |= u256::from(1u64) << level;
            path.siblings[sib_idx as usize] = *sib_hash;
            sib_idx += 1;
        }
        // else: sibling is empty, bitmap bit stays 0

        idx >>= 1;

        // Build parent level for next iteration
        let mut parent_map: BTreeMap<u256, [u8; 32]> = BTreeMap::new();
        let empty_hash = empty_hashes.get(level as u32);

        for (node_idx, hash) in &leaf_map {
            let parent_idx = node_idx >> 1;
            let node_is_right = (node_idx & u256::from(1u64)) != u256::from(0u64);
            let node_sibling_idx = if node_is_right { node_idx - u256::from(1u64) } else { node_idx + u256::from(1u64) };

            let (left, right) = if node_is_right {
                let sib = leaf_map.get(&node_sibling_idx).copied().unwrap_or(*empty_hash);
                (sib, *hash)
            } else {
                let sib = leaf_map.get(&node_sibling_idx).copied().unwrap_or(*empty_hash);
                (*hash, sib)
            };

            let parent_hash = sha_pair(&left, &right, env);
            parent_map.insert(parent_idx, parent_hash);
        }

        leaf_map = parent_map;
    }

    path.sibling_count = sib_idx;
    path
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::Env;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    #[test]
    fn valid_path_verifies_and_corrupted_fails() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..8u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);

        let idx = 3u32;
        let path = open(&env, &leaves, idx);
        let leaf = felt_leaf(&env, Felt::new(idx as u64));
        assert!(path.verify(&env, &leaf, &root), "valid path must verify");

        let bad_leaf = felt_leaf(&env, Felt::new(99));
        assert!(!path.verify(&env, &bad_leaf, &root), "corrupted leaf must fail");

        let mut bad_path = path.clone_struct();
        bad_path.siblings[0] = felt_leaf(&env, Felt::new(123)).to_array();
        assert!(!bad_path.verify(&env, &leaf, &root), "corrupted sibling must fail");
    }

    #[test]
    fn different_root_rejected() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..4u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let path = open(&env, &leaves, 0);
        let leaf = felt_leaf(&env, Felt::new(0));
        let wrong = BytesN::from_array(&env, &[0xab; 32]);
        assert!(!path.verify(&env, &leaf, &wrong));
    }
}

#[cfg(test)]
impl MerklePath {
    /// Copy a path so a test can mutate one sibling (no `Copy` on the struct).
    fn clone_struct(&self) -> MerklePath {
        MerklePath {
            siblings: self.siblings,
            depth: self.depth,
            index: self.index,
        }
    }
}
