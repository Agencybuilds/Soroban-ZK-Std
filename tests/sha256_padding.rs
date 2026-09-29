// SPDX-License-Identifier: Apache-2.0
use soroban_sdk::{testutils::*, Env};
use soroban_sdk::bytes::Bytes;
use soroban_zk_std::crypto::sha256::{Sha256Padding, Sha256Padder};

#[test]
fn test_sha256_padding_edge_cases() {
    let env = Env::default();
    
    // Test 1: Empty input (pads to 56 bytes + 8-byte length).
    let empty_input = Bytes::new(&env);
    let padded = Sha256Padder::validate_and_pad(&env, &empty_input);
    assert_eq!(padded.len(), 64);
    assert_eq!(padded.last_byte(), Some(0x00)); // Last byte is 0 (64-bit length).
    
    // Test 2: Max input (63 bytes) → pads to 64 bytes.
    let max_input = Bytes::from_vec(&env, vec![0xFF; 63]);
    let padded = Sha256Padder::validate_and_pad(&env, &max_input);
    assert_eq!(padded.len(), 64);
    assert_eq!(padded[63], 0x3F); // 63*8 = 504 → 0x00000000000001F8 (big-endian).
    
    // Test 3: Input requiring zero-padding (e.g., 56 bytes).
    let zero_pad_input = Bytes::from_vec(&env, vec![0xAA; 56]);
    let padded = Sha256Padder::validate_and_pad(&env, &zero_pad_input);
    assert_eq!(padded.len(), 64);
    assert_eq!(padded[56], 0x80); // `1` bit appended.
    assert_eq!(padded[57..64], [0x00; 7]); // Zero-padded.
    
    // Test 4: Panic on overflow (input > 64 bytes).
    let overflow_input = Bytes::from_vec(&env, vec![0x00; 65]);
    let result = Sha256Padder::validate_and_pad(&env, &overflow_input);
    assert!(result.is_none()); // Should panic.
}
