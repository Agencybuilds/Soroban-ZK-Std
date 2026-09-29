
// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Soroban Contributors

use soroban_sdk::{contractimport, vec, Env, Symbol, Address, Bytes, BytesN};
use soroban_zks::kzg::{KzgProof, VerificationError};
use crate::kzg::batch::{KzgProofBatch, BatchKzgVerifier};

/// Extended KZG verifier with batch support
pub struct ExtendedKzgVerifier;

impl BatchKzgVerifier for ExtendedKzgVerifier {
    fn verify_batch(&self, env: &Env, batch: &KzgProofBatch) -> Result<(), VerificationError> {
        batch.verify_batch(env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_extended_verifier() {
        let env = Env::default();
        let verifier = ExtendedKzgVerifier;
        let client = env.borrow_client();
        let contract_id = Address::generate(&env);

        // Test data
        let proofs = vec![&env, KzgProof::default(&env); 3];
        let inputs = vec![&env, BytesN::from_array(&env, &[0u8; 32]); 3];
        let batch = KzgProofBatch::new(&env, proofs, inputs);

        assert!(verifier.verify_batch(&env, &batch).is_ok());
    }
}