/// STARK verifier & FRI proximity-testing primitives (Issue #366).
///
/// This module implements the verifier-side building blocks for STARK proofs:
//.
/// * [`field`] — the Goldilocks prime field (`p = 2^64 − 2^32 + 1`) with high
///   2-adicity, used for the FRI Reed–Solomon domain.
/// * [`aet`] — Algebraic Execution Trace configuration and boundary/transition
///   constraint checks.
/// * [`fri`] — FRI folding loops, layer commitment, and deep-FRI composition.
/// * [`merkle`] — Soroban-optimized Merkle authentication over the native
///   SHA-256 host binding.
/// * [`transcript`] — Fiat-Shamir transcript over SHA-256.

pubmod aet;
pubmod field;
pubmod fri;
pubmod merkle;
pubmod transcript;
