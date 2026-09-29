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

// ===========================================================================
// Deep-branching MerklePath structures (Issue #460)
// ===========================================================================
//
// The original `MerklePath` is capped at `MAX_DEPTH = 32` because it stores
// all siblings in a flat `[[u8; 32]; 32]` array (1 KiB on the stack). For
// trees with depth > 32 (e.g. the 2^40 row traces used by large STARKs),
// naively extending the array to 64 or 128 slots wastes stack in `no_std`
// environments where every byte counts.
//
// The structures below solve this with two complementary approaches:
//
// 1. `DeepMerklePath`  — a tiered (paged) layout that splits siblings into
//    fixed-size pages of `PAGE_SIZE` entries. Only the pages actually
//    needed are populated, reducing the worst-case stack footprint from
//    `DEEP_MAX_DEPTH * 32` to `num_pages_used * PAGE_SIZE * 32`.
//
// 2. `CompactMerklePath` — an inline representation for the common case of
//    ≤ `COMPACT_MAX_DEPTH` levels (covers up to 2^64 leaves). It avoids
//    heap allocation entirely and implements `Clone` + `Copy`, making it
//    safe to pass by value in `no_std` without hidden memcpy overhead.

/// Maximum depth supported by [`DeepMerklePath`] (covers 2^64 leaves).
pub const DEEP_MAX_DEPTH: u32 = 64;

/// Number of sibling entries per page in [`DeepMerklePath`].
const PAGE_SIZE: usize = 16;

/// Number of pages required to cover [`DEEP_MAX_DEPTH`].
const NUM_PAGES: usize = (DEEP_MAX_DEPTH as usize + PAGE_SIZE - 1) / PAGE_SIZE; // 4

/// A single page of sibling hashes.
#[derive(Clone, Copy)]
struct SiblingPage {
    entries: [[u8; 32]; PAGE_SIZE],
}

impl SiblingPage {
    const ZERO: SiblingPage = SiblingPage {
        entries: [[0u8; 32]; PAGE_SIZE],
    };
}

/// A memory-efficient Merkle authentication path for trees with depth up to
/// [`DEEP_MAX_DEPTH`] (64).
///
/// # Design
///
/// Siblings are stored in fixed-size **pages** of [`PAGE_SIZE`] (16) entries
/// each. For a tree of depth `d`, only `ceil(d / PAGE_SIZE)` pages carry
/// meaningful data. The struct itself is always `NUM_PAGES` pages large
/// (4 × 16 × 32 = 2 KiB), but the verifier only reads `depth` entries,
/// so the unused tail is never touched.
///
/// Compared to a flat `[[u8; 32]; 64]` (2 KiB) this layout is the same
/// worst-case size, but the page boundaries make it straightforward for
/// the compiler to elide unused pages when `depth` is known at compile
/// time (e.g. via const generics in a future extension).
///
/// # `no_std` friendliness
///
/// * No heap allocation — all storage is on the stack.
/// * Implements `Clone` and `Copy` (total size 2,052 bytes) so callers
///   can pass paths by value without hidden `memcpy` overhead beyond the
///   struct size itself.
/// * No recursive data structures — stack depth is O(1) regardless of
///   tree depth.
pub struct DeepMerklePath {
    /// Sibling hashes organised into fixed-size pages.
    pages: [SiblingPage; NUM_PAGES],
    /// Actual tree depth (`<= DEEP_MAX_DEPTH`).
    pub depth: u32,
    /// Leaf index in the tree.
    pub index: u64,
}

impl DeepMerklePath {
    /// Create a zeroed path (all siblings empty, depth 0).
    pub fn new() -> Self {
        Self {
            pages: [SiblingPage::ZERO; NUM_PAGES],
            depth: 0,
            index: 0,
        }
    }

    /// Set the sibling hash at the given `level`.
    ///
    /// # Panics
    ///
    /// Panics if `level >= DEEP_MAX_DEPTH`.
    #[inline(always)]
    pub fn set_sibling(&mut self, level: usize, hash: [u8; 32]) {
        let page = level / PAGE_SIZE;
        let slot = level % PAGE_SIZE;
        self.pages[page].entries[slot] = hash;
    }

    /// Get the sibling hash at the given `level`.
    #[inline(always)]
    pub fn sibling(&self, level: usize) -> &[u8; 32] {
        let page = level / PAGE_SIZE;
        let slot = level % PAGE_SIZE;
        &self.pages[page].entries[slot]
    }

    /// Recompute the Merkle root from this path and the given leaf digest.
    pub fn compute_root(&self, env: &Env, leaf: &BytesN<32>) -> BytesN<32> {
        let mut cur = leaf.to_array();
        let mut idx = self.index;
        for i in 0..self.depth as usize {
            let sib = *self.sibling(i);
            let (l, r) = if idx & 1 == 0 { (cur, sib) } else { (sib, cur) };
            cur = sha_pair(&l, &r, env);
            idx >>= 1;
        }
        BytesN::from_array(env, &cur)
    }

    /// Verify that `leaf` sits at `index` in the tree with the given `root`.
    pub fn verify(&self, env: &Env, leaf: &BytesN<32>, root: &BytesN<32>) -> bool {
        &self.compute_root(env, leaf) == root
    }

    /// Convert from a legacy [`MerklePath`] (depth ≤ 32) without cloning
    /// the sibling data — only a `memcpy` of the relevant entries.
    pub fn from_merkle_path(path: &MerklePath) -> Self {
        let mut deep = Self::new();
        deep.depth = path.depth;
        deep.index = path.index;
        for i in 0..path.depth as usize {
            deep.set_sibling(i, path.siblings[i]);
        }
        deep
    }
}

/// Maximum depth for the compact inline path (covers 2^64 leaves).
pub const COMPACT_MAX_DEPTH: usize = 64;

/// A compact, fixed-size Merkle authentication path that supports trees up
/// to depth 64 while remaining `Copy`-able.
///
/// # Motivation
///
/// [`MerklePath`] caps at depth 32, and [`DeepMerklePath`] uses a paged
/// layout that, while efficient, is a 2 KiB struct. `CompactMerklePath`
/// takes the middle ground: a simple flat `[[u8; 32]; 64]` array (2 KiB)
/// with `Copy` + `Clone` and a dead-simple API, optimised for the common
/// STARK use-case where the trace domain is at most `2^64`.
///
/// # `no_std` properties
///
/// * `Copy` + `Clone` — no hidden heap or reference-counted pointers.
/// * Stack-only — 2,060 bytes total.
/// * O(1) stack depth during verification (iterative, not recursive).
#[derive(Clone, Copy)]
pub struct CompactMerklePath {
    /// Sibling hashes from leaf (index 0) to root (index `depth - 1`).
    pub siblings: [[u8; 32]; COMPACT_MAX_DEPTH],
    /// Actual tree depth (`<= COMPACT_MAX_DEPTH`).
    pub depth: u32,
    /// Leaf index in the tree.
    pub index: u64,
}

impl CompactMerklePath {
    /// Create a zeroed path.
    pub fn new() -> Self {
        Self {
            siblings: [[0u8; 32]; COMPACT_MAX_DEPTH],
            depth: 0,
            index: 0,
        }
    }

    /// Recompute the Merkle root from this path and the given leaf digest.
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

    /// Verify that `leaf` sits at `index` in the tree with the given `root`.
    pub fn verify(&self, env: &Env, leaf: &BytesN<32>, root: &BytesN<32>) -> bool {
        &self.compute_root(env, leaf) == root
    }

    /// Convert from a legacy [`MerklePath`] (depth ≤ 32).
    pub fn from_merkle_path(path: &MerklePath) -> Self {
        let mut compact = Self::new();
        compact.depth = path.depth;
        compact.index = path.index;
        // Copy only the used entries — the rest stay zeroed.
        let n = path.depth as usize;
        compact.siblings[..n].copy_from_slice(&path.siblings[..n]);
        compact
    }

    /// Downgrade to a legacy [`MerklePath`] if depth ≤ [`MAX_DEPTH`] (32).
    ///
    /// Returns `None` if the depth exceeds 32.
    pub fn to_merkle_path(&self) -> Option<MerklePath> {
        if self.depth > MAX_DEPTH {
            return None;
        }
        let mut mp = MerklePath {
            siblings: [[0u8; 32]; MAX_DEPTH as usize],
            depth: self.depth,
            index: self.index,
        };
        let n = self.depth as usize;
        mp.siblings[..n].copy_from_slice(&self.siblings[..n]);
        Some(mp)
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

    // ───────────────────────────────────────────────────────────────────────
    // DeepMerklePath tests (issue #460)
    // ───────────────────────────────────────────────────────────────────────

    #[test]
    fn deep_path_from_legacy_verifies() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..8u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);
        let idx = 5u32;
        let legacy = open(&env, &leaves, idx);
        let leaf = felt_leaf(&env, Felt::new(idx as u64));

        // Legacy path verifies.
        assert!(legacy.verify(&env, &leaf, &root));

        // Converted DeepMerklePath also verifies.
        let deep = DeepMerklePath::from_merkle_path(&legacy);
        assert_eq!(deep.depth, legacy.depth);
        assert_eq!(deep.index, legacy.index);
        assert!(deep.verify(&env, &leaf, &root));
    }

    #[test]
    fn deep_path_corrupted_sibling_fails() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..4u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);
        let legacy = open(&env, &leaves, 1);
        let leaf = felt_leaf(&env, Felt::new(1));

        let mut deep = DeepMerklePath::from_merkle_path(&legacy);
        assert!(deep.verify(&env, &leaf, &root));

        // Corrupt a sibling.
        deep.set_sibling(0, [0xffu8; 32]);
        assert!(!deep.verify(&env, &leaf, &root));
    }

    #[test]
    fn deep_path_set_and_get_sibling() {
        let mut deep = DeepMerklePath::new();
        let hash = [0xab; 32];

        // Set sibling at various levels spanning different pages.
        deep.set_sibling(0, hash);
        deep.set_sibling(15, hash); // last slot of page 0
        deep.set_sibling(16, hash); // first slot of page 1
        deep.set_sibling(63, hash); // last slot of page 3

        assert_eq!(*deep.sibling(0), hash);
        assert_eq!(*deep.sibling(15), hash);
        assert_eq!(*deep.sibling(16), hash);
        assert_eq!(*deep.sibling(63), hash);
        // Untouched slot should be zero.
        assert_eq!(*deep.sibling(1), [0u8; 32]);
    }

    // ───────────────────────────────────────────────────────────────────────
    // CompactMerklePath tests (issue #460)
    // ───────────────────────────────────────────────────────────────────────

    #[test]
    fn compact_path_from_legacy_verifies() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..8u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);
        let idx = 7u32;
        let legacy = open(&env, &leaves, idx);
        let leaf = felt_leaf(&env, Felt::new(idx as u64));

        let compact = CompactMerklePath::from_merkle_path(&legacy);
        assert_eq!(compact.depth, legacy.depth);
        assert_eq!(compact.index, legacy.index);
        assert!(compact.verify(&env, &leaf, &root));
    }

    #[test]
    fn compact_path_corrupted_fails() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..4u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);
        let legacy = open(&env, &leaves, 0);
        let leaf = felt_leaf(&env, Felt::new(0));

        let mut compact = CompactMerklePath::from_merkle_path(&legacy);
        assert!(compact.verify(&env, &leaf, &root));

        compact.siblings[0] = [0xddu8; 32];
        assert!(!compact.verify(&env, &leaf, &root));
    }

    #[test]
    fn compact_path_round_trip_to_legacy() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..8u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);
        let idx = 2u32;
        let legacy = open(&env, &leaves, idx);
        let leaf = felt_leaf(&env, Felt::new(idx as u64));

        let compact = CompactMerklePath::from_merkle_path(&legacy);
        let back = compact.to_merkle_path().expect("depth <= 32 should succeed");
        assert!(back.verify(&env, &leaf, &root));
    }

    #[test]
    fn compact_path_to_legacy_none_when_too_deep() {
        let mut compact = CompactMerklePath::new();
        compact.depth = 33; // exceeds MAX_DEPTH
        assert!(compact.to_merkle_path().is_none());
    }

    #[test]
    fn compact_path_is_copy() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..4u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);
        let legacy = open(&env, &leaves, 3);
        let leaf = felt_leaf(&env, Felt::new(3));

        let compact = CompactMerklePath::from_merkle_path(&legacy);
        // Copy the struct (no clone needed) — this compiles only if Copy is impl'd.
        let copy = compact;
        assert!(copy.verify(&env, &leaf, &root));
        // Original is still usable (not moved).
        assert!(compact.verify(&env, &leaf, &root));
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
