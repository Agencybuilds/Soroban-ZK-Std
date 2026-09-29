// SPDX-License-Identifier: Apache-2.0

//! SHA-256 padding — implementation has been moved to `soroban-zk-core`.
//!
//! See [`soroban_zk_core::sha256_padding`] for the full API and documentation.
//!
//! This file exists only for backwards-compatibility; new code should depend
//! directly on `soroban-zk-core` or use the re-exports in the parent `mod.rs`.

pub use soroban_zk_core::sha256_padding::{
    pad_into, pad_message, padded_length, PaddedBlock, BLOCK_SIZE, LENGTH_FIELD_BYTES,
    MAX_INPUT_BYTES, MAX_PADDED_LEN,
};
