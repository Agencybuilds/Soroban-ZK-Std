// SPDX-License-Identifier: Apache-2.0
use soroban_sdk::{test, Env, Symbol, Vec};
use soroban_zk_std::bulletproofs::range_proof::RangeProof;

#[test]
fn test_64bit_range_validation_edge_cases() {
    let env = Env::default();
    let client = env.test_client();
    
    // Test values
    let zero: u64 = 0;
    let max_u64: u64 = u64::MAX;
    let overflow: u64 = u64::MAX + 1;
    let negative: i64 = -1;
    
    // Valid range proofs should succeed for 0 and max_u64
    let proof_zero = RangeProof::prove(&env, &zero).unwrap();
    assert!(proof_zero.verify(&env, &zero).unwrap());
    
    let proof_max = RangeProof::prove(&env, &max_u64).unwrap();
    assert!(proof_max.verify(&env, &max_u64).unwrap());
    
    // Overflow and negative values should fail verification
    let proof_overflow = RangeProof::prove(&env, &overflow).unwrap_err();
    assert!(matches!(proof_overflow, RangeProofError::OutOfRange));
    
    let proof_negative = RangeProof::prove(&env, &negative).unwrap_err();
    assert!(matches!(proof_negative, RangeProofError::OutOfRange));
    
    // Test range constraints explicitly
    let proof_underflow = RangeProof::prove(&env, &0u64.saturating_sub(1)).unwrap_err();
    assert!(matches!(proof_underflow, RangeProofError::OutOfRange));
    
    // Test with array of boundary values
    let boundary_values: Vec<u64> = vec![0, 1, max_u64.saturating_sub(1), max_u64];
    for value in boundary_values {
        let proof = RangeProof::prove(&env, &value).unwrap();
        assert!(proof.verify(&env, &value).unwrap());
    }
}

#[test]
fn test_range_proof_consistency() {
    let env = Env::default();
    let client = env.test_client();
    
    // Test that proofs are deterministic for same input
    let value = 123456789u64;
    let proof1 = RangeProof::prove(&env, &value).unwrap();
    let proof2 = RangeProof::prove(&env, &value).unwrap();
    
    assert_eq!(proof1, proof2);
    assert!(proof1.verify(&env, &value).unwrap());
}