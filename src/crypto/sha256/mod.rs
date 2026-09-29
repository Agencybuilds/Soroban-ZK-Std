// SPDX-License-Identifier: Apache-2.0
pub use super::padding::{Sha256Padding, Sha256Padder};

/// SHA-256 constants.
pub mod constants {
    pub const BLOCK_SIZE: u8 = 64;
    pub const MAX_INPUT_SIZE: u8 = 64; // 512-bit blocks.
}
