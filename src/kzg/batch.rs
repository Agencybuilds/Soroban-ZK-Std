
// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Soroban Contributors

use soroban_sdk::{contractimport, vec, Env, Symbol, Address, Bytes, BytesN};
use soroban_zks::kzg::{KzgProof, KzgVerifier, VerificationError};

/// Batch wrapper for KZG proofs and public inputs
#[derive(Clone)]
pub struct KzgProofBatch<'a> {
    proofs: Vec<KzgProof<'a>>,
    public_inputs: Vec<BytesN<'a>>,
}

impl<'a> KzgProofBatch<'a> {
    /// Create new batch from proofs and public inputs
    pub fn new(env: &Env, proofs: Vec<KzgProof<'a>>, public_inputs: Vec<BytesN<'a>>) -> Self {
        Self { proofs, public_inputs }
    }

    /// Verify all proofs in batch
    pub fn verify_batch(&self, env: &Env) -> Result<(), VerificationError> {
        for (proof, input) in self.proofs.iter().zip(self.public_inputs.iter()) {
            KzgVerifier::verify(env, proof, input)?;
        }
        Ok(())
    }
}

/// Trait for batch KZG verification
pub trait BatchKzgVerifier {
    fn verify_batch(&self, env: &Env, batch: &KzgProofBatch) -> Result<(), VerificationError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_batch_verification() {
        let env = Env::default();
        let client = env.borrow_client();
        let contract_id = Address::generate(&env);

        // Setup test data
        let proofs = vec![&env, KzgProof::default(&env); 5];
        let inputs = vec![&env, BytesN::from_array(&env, &[0u8; 32]); 5];
        let batch = KzgProofBatch::new(&env, proofs, inputs);

        // Verify batch
        assert!(batch.verify_batch(&env).is_ok());
    }
}