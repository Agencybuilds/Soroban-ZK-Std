// SPDX-License-Identifier: Apache-2.0
use soroban_sdk::storage::StorageDiff;

/// Tracks storage modifications for atomic rollback
pub struct StorageDiffTracker {
    diff: StorageDiff,
    initial_state: Vec<u8>,
}

impl StorageDiffTracker {
    pub fn new() -> Self {
        Self {
            diff: StorageDiff::new(),
            initial_state: Vec::new(),
        }
    }
    
    pub fn revert(&mut self) -> Result<(), String> {
        self.diff.revert()
    }
}