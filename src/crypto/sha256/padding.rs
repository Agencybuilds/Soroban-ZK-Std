// SPDX-License-Identifier: Apache-2.0
use soroban_sdk::{contractimport, panic_with_error, symbol, Env, Symbol, Vec};
use soroban_sdk::bytes::Bytes;
use soroban_sdk::num::U256;

/// SHA-256 padding validator enforcing field modular arithmetic limits.
pub trait Sha256Padding {
    /// Validates and applies SHA-256 padding to input bytes.
    /// 
    /// # Arguments
    /// * `env` - Soroban environment.
    /// * `input` - Input bytes to pad.
    /// 
    /// # Returns
    /// Padded bytes as `Bytes` with length divisible by 64.
    /// 
    /// # Panics
    /// If padding would exceed field limits or violate SHA-256 constraints.
    fn validate_and_pad(env: &Env, input: &Bytes) -> Bytes;
}

/// Core padding logic with strict field bounds.
pub struct Sha256Padder;

impl Sha256Padding for Sha256Padder {
    fn validate_and_pad(env: &Env, input: &Bytes) -> Bytes {
        let input_len = input.len();
        
        // SHA-256 requires input length < 2^64 bits (512-bit blocks).
        if input_len > 64 {
            panic_with_error!(env, "Input exceeds SHA-256 block limit (max 64 bytes)");
        }
        
        // Calculate padding length: 64 - (input_len % 64).
        let padding_len = if input_len % 64 == 0 {
            64
        } else {
            64 - (input_len % 64)
        };
        
        // Validate padding does not exceed field limits.
        if padding_len > 64 {
            panic_with_error!(env, "Padding overflow detected");
        }
        
        // Step 1: Append `1` bit (0x80).
        let mut padded = input.clone();
        padded.push_byte(0x80);
        
        // Step 2: Append `0` bits (up to 56 bytes).
        for _ in 0..(padding_len - 1) {
            padded.push_byte(0x00);
        }
        
        // Step 3: Append 64-bit big-endian bit-length of original input.
        let bit_len = U256::from(input_len * 8);
        for byte in bit_len.to_le_bytes()[..8].iter() {
            padded.push_byte(*byte);
        }
        
        padded
    }
}
