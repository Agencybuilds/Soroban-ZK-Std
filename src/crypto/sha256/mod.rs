// SPDX-License-Identifier: Apache-2.0

//! SHA-256 sub-module.
//!
//! Re-exports the padding primitives from `soroban-zk-core` for convenience.
//! The actual implementation lives in [`soroban_zk_core::sha256_padding`] so
//! that it remains dependency-free and `no_std`-compatible.
//!
//! Use this module when you need SHA-256 padding from within a Soroban contract
//! crate that already depends on `soroban-zk-std`.

pub use soroban_zk_core::sha256_padding::{
    pad_into, pad_message, padded_length, PaddedBlock, BLOCK_SIZE, LENGTH_FIELD_BYTES,
    MAX_INPUT_BYTES, MAX_PADDED_LEN,
};
