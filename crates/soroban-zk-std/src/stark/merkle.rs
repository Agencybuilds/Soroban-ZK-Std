//! Soroban-optimized Merkle authentication (Issue #366, Phase 3).
//!
//! Verification streams a fixed-size [`MerklePath`] of sibling hashes and folds
//! them with the leaf via the **native SHA-256 host binding** (`env.crypto().
//! sha256`, a single CAP-0075 host call per level). No guest Wasm heap is
//! touched: the only storage is the `siblings` array, bounded by `MAX_DEPTH`.
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

use crate::stark::field::Felt;
use alloc::vec::Vec as AllocVec;

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

/// Batch verify multiple Merkle paths to avoid re-hashing shared intermediate nodes.
/// Re-uses intermediate nodes where paths intersect.
pub fn verify_batch(
    env: &Env,
    leaves: &Vec<BytesN<32>>,
    paths: &Vec<MerklePath>,
    root: &BytesN<32>,
) -> bool {
    if leaves.len() != paths.len() {
        return false;
    }
    if leaves.len() == 0 {
        return true;
    }

    let depth = paths.get(0).unwrap().depth;

    let mut current_level: AllocVec<(u64, [u8; 32], u32)> = AllocVec::new();
    for i in 0..leaves.len() {
        let p = paths.get(i).unwrap();
        if p.depth != depth {
            return false; // All paths must have the same depth
        }
        current_level.push((p.index, leaves.get(i).unwrap().to_array(), i));
    }

    // Sort by index to group siblings together
    current_level.sort_unstable_by_key(|k| k.0);

    // Ensure no duplicate indices
    for i in 1..current_level.len() {
        if current_level[i - 1].0 == current_level[i].0 {
            return false;
        }
    }

    for d in 0..depth {
        let mut next_level: AllocVec<(u64, [u8; 32], u32)> = AllocVec::with_capacity(current_level.len());
        let mut i = 0;
        while i < current_level.len() {
            let (idx, hash, path_id) = current_level[i];
            let parent_idx = idx >> 1;

            if i + 1 < current_level.len() && current_level[i + 1].0 == (idx ^ 1) {
                // Sibling is present in the batch
                let sibling_hash = current_level[i + 1].1;
                let (l, r) = if idx & 1 == 0 { (hash, sibling_hash) } else { (sibling_hash, hash) };
                let parent_hash = sha_pair(&l, &r, env);
                next_level.push((parent_idx, parent_hash, path_id));
                i += 2;
            } else {
                // Sibling not in batch, use the one from the path
                let p = paths.get(path_id).unwrap();
                let sibling_hash = p.siblings[d as usize];
                let (l, r) = if idx & 1 == 0 { (hash, sibling_hash) } else { (sibling_hash, hash) };
                let parent_hash = sha_pair(&l, &r, env);
                next_level.push((parent_idx, parent_hash, path_id));
                i += 1;
            }
        }
        current_level = next_level;
    }

    if current_level.len() != 1 {
        return false;
    }

    let final_hash = current_level[0].1;
    &BytesN::from_array(env, &final_hash) == root
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

    #[test]
    fn batch_verifies_valid_paths() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..8u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);

        let idx0 = 2u32;
        let idx1 = 3u32; // sibling to idx0
        let idx2 = 5u32;
        
        let path0 = open(&env, &leaves, idx0);
        let path1 = open(&env, &leaves, idx1);
        let path2 = open(&env, &leaves, idx2);
        
        let mut batch_leaves = Vec::new(&env);
        batch_leaves.push_back(felt_leaf(&env, Felt::new(idx0 as u64)));
        batch_leaves.push_back(felt_leaf(&env, Felt::new(idx1 as u64)));
        batch_leaves.push_back(felt_leaf(&env, Felt::new(idx2 as u64)));
        
        let mut batch_paths = Vec::new(&env);
        batch_paths.push_back(path0);
        batch_paths.push_back(path1);
        batch_paths.push_back(path2);
        
        assert!(verify_batch(&env, &batch_leaves, &batch_paths, &root), "batch verify should succeed");
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
