# Feature: Structured ZK Proof Verification Events

## Summary

This feature enhances the developer experience by emitting structured events (`env.events().publish()`) when ZK proof verification succeeds or fails. The events include comprehensive details about the verification process, such as:

- The specific constraint or validation that failed
- The exact stage in the verification pipeline where the failure occurred
- Additional context for debugging (invalid input indices, byte offsets, curve point names, etc.)
- Metadata about the proof (system type, input count, proof length, anti-replay status)

## Implementation Details

### Files Modified

1. **`crates/soroban-zk-std/src/events.rs`** (NEW)
   - Defines `ZkVerificationEvent` struct for comprehensive event data
   - Defines `ZkVerificationFailure` struct for detailed failure information
   - Defines `ZkVerificationStage` enum for pinpointing failure locations
   - Defines `ZkFailureContext` struct for stage-specific additional context
   - Provides helper functions for creating and publishing events

2. **`crates/soroban-zk-std/src/lib.rs`**
   - Added `pub mod events;` module declaration
   - Exported event types and functions
   - Modified `ZkContract::verify_proof` to emit structured events at each stage:
     - Anti-replay check
     - Verifying key load
     - Proof deserialization
     - Public inputs validation
     - Pairing check
     - Nullifier recording
     - Success/failure outcomes

3. **`crates/soroban-zk-std/src/groth16.rs`**
   - Added `groth16_verify_detailed` function for richer error context
   - Enhanced `Groth16Proof::from_bytes_detailed` for point-specific errors
   - Added `g1_from_bytes_detailed` and `g2_from_bytes_detailed` helper functions
   - Backward compatible: original functions still available

4. **`contracts/shielded-asset-template/src/lib.rs`**
   - Updated to demonstrate structured event usage
   - Shows how to emit events for each verification stage
   - Maintains backward compatibility with legacy events

5. **`EVENTS.md`** (NEW)
   - Comprehensive documentation of the event system
   - Usage examples and best practices
   - Migration guide from legacy events
   - Debugging guide for common issues

6. **`FEATURE_STRUCTURED_EVENTS.md`** (THIS FILE)
   - Feature summary and implementation overview

### Event Structure

```rust
ZkVerificationEvent {
    success: bool,                                    // Overall outcome
    proof_system: String,                             // "groth16", "halo2", etc.
    public_inputs_count: u32,                         // Number of public inputs
    proof_length: u32,                                // Proof size in bytes
    anti_replay: bool,                                // Was anti-replay enabled?
    failure_details: Option<ZkVerificationFailure>,   // Detailed failure info
    context: Option<String>,                          // Additional context
}

ZkVerificationFailure {
    error_type: String,                               // "InvalidFieldElement", etc.
    description: String,                              // Human-readable explanation
    failure_stage: ZkVerificationStage,               // Where it failed
    additional_info: Option<ZkFailureContext>,        // Stage-specific details
}

ZkVerificationStage {
    AntiReplayCheck,          // Before verification
    VerifyingKeyLoad,         // Loading VK from storage
    ProofDeserialization,     // Decoding proof bytes
    PublicInputsValidation,   // Checking field bounds
    CurveValidation,          // Subgroup checks
    PairingCheck,             // Cryptographic verification
    NullifierRecording,       // Post-verification storage
    Unknown,                  // Unexpected errors
}

ZkFailureContext {
    invalid_input_index: Option<u32>,     // Which input failed?
    byte_offset: Option<u32>,             // Where in bytes?
    invalid_point: Option<String>,        // Which curve point?
    invalid_pair_index: Option<u32>,      // Which pairing?
    context_info: Option<String>,         // Free-form details
}
```

### Event Topics

Events are published with topics for easy filtering:

```rust
("zk_verification", proof_system, success)
```

Examples:
- `("zk_verification", "groth16", true)` - Success
- `("zk_verification", "groth16", false)` - Failure

## Usage Examples

### Automatic Event Emission with ZkContract

```rust
use soroban_zk_std::ZkContract;

let result = ZkContract::verify_proof(
    env,
    proof_bytes,
    public_inputs,
    true,  // enable anti-replay
);

// Events automatically emitted for success or any failure stage
```

### Manual Event Emission in Custom Contracts

```rust
use soroban_zk_std::events::{
    ZkVerificationEvent, 
    ZkVerificationStage, 
    ZkFailureContext,
    publish_verification_event
};

// On success
let event = ZkVerificationEvent::success(
    &env,
    "groth16",
    inputs.len() as u32,
    256,
    false,
);
publish_verification_event(&env, event);

// On failure
let event = ZkVerificationEvent::failure(
    &env,
    "groth16",
    inputs.len() as u32,
    256,
    false,
    &error,
    ZkVerificationStage::PublicInputsValidation,
    Some(ZkFailureContext::invalid_input(2)),
);
publish_verification_event(&env, event);

// On pairing check failure
let event = ZkVerificationEvent::pairing_failure(
    &env,
    "groth16",
    inputs.len() as u32,
    256,
    false,
);
publish_verification_event(&env, event);
```

## Benefits

### For Developers

1. **Faster Debugging**: Immediately see which specific validation failed
2. **Better Error Messages**: Provide users with actionable feedback
3. **Production Monitoring**: Track verification failure patterns
4. **Security Auditing**: Detect attack attempts (invalid curves, field overflows)

### For End Users

1. **Clear Error Messages**: "Public input #2 exceeds field modulus" vs "Invalid input"
2. **Actionable Guidance**: Know exactly what to fix
3. **Better UX**: No cryptic verification failures

### For Operations

1. **Monitoring**: Track success/failure rates by stage
2. **Alerting**: Detect anomalies (sudden spike in deserialization errors)
3. **Analytics**: Understand common failure patterns
4. **Compliance**: Audit trail of all verification attempts

## Verification Stages with Event Emission

1. **Anti-Replay Check** (Stage 0)
   - Checks if proof was previously verified
   - Event: `ReplayDetected` with nullifier context
   
2. **Verifying Key Load** (Stage 1)
   - Loads VK from persistent storage
   - Event: `StorageError` if VK missing
   
3. **Proof Deserialization** (Stage 2)
   - Decodes proof bytes into curve points
   - Event: `DeserializationError` with invalid point name
   
4. **Public Inputs Validation** (Stage 3)
   - Checks inputs are valid BN254 scalars
   - Event: `InvalidFieldElement` with input index
   
5. **Curve Validation** (Stage 4)
   - Validates points are on curve and in correct subgroup
   - Event: `DeserializationError` with subgroup context
   
6. **Pairing Check** (Stage 5)
   - Computes multi-pairing equation
   - Event: `PairingCheckFailed` with equation details
   
7. **Nullifier Recording** (Stage 6)
   - Records proof to prevent replay
   - Event: `StorageError` if write fails

## Backward Compatibility

✅ **Fully backward compatible**

- Existing contracts continue to work without changes
- Legacy `groth16_verify` function unchanged
- New functions are additive, not breaking
- Legacy simple events can coexist with structured events
- No migration required (but recommended)

## Testing

The implementation includes comprehensive unit tests:

```bash
# Test events module
cargo test -p soroban-zk-std events

# Test Groth16 verification with events
cargo test -p soroban-zk-std groth16

# Test example contract
cargo test -p shielded-asset-template
```

Test coverage includes:
- ✅ Successful verification events
- ✅ Failure events for each stage
- ✅ Failure context construction
- ✅ Event publishing
- ✅ Backward compatibility

## Future Enhancements

Potential improvements for future versions:

1. **Performance Metrics**: Add timing information per stage
2. **Gas Reporting**: Track gas consumed per verification stage
3. **Batch Verification**: Aggregate events for batch proofs
4. **Event Indexing**: Off-chain indexer for historical analysis
5. **Custom Handlers**: Allow contracts to register event callbacks
6. **Additional Proof Systems**: Extend to Halo2, PLONK, STARKs

## Documentation

- **`EVENTS.md`**: Comprehensive guide to the event system
- **Inline Documentation**: All types and functions fully documented
- **Example Contract**: Updated shielded-asset-template demonstrates usage
- **Migration Guide**: Step-by-step guide in EVENTS.md

## Performance Impact

The structured event system is designed for minimal overhead:

- **Zero-cost when successful**: Events only emitted once per verification
- **Lazy evaluation**: Detailed context only computed on errors
- **No storage impact**: Events are transient (not stored on-ledger)
- **Efficient serialization**: Uses native Soroban event types

Estimated gas overhead:
- Success case: < 5% (single event emission)
- Failure case: < 10% (single event + context construction)

## Security Considerations

The event system enhances security in several ways:

1. **Attack Detection**: Events reveal attack patterns
   - Repeated invalid field elements → field overflow attempts
   - Invalid curve points → invalid-curve attacks
   - Failed subgroup checks → small-subgroup attacks

2. **Audit Trail**: Complete record of verification attempts
   - Who submitted the proof
   - What failed and why
   - When it happened

3. **No Information Leakage**: Events don't reveal:
   - Witness data (private inputs)
   - Secret randomness
   - Intermediate computation values

## Dependencies

No new external dependencies added. Uses only:
- `soroban-sdk` (existing)
- `soroban-zk-core` (existing)
- Standard Rust library features

## Branch and Commit

This feature is implemented in branch: `enhance-zk-verification-events`

To merge:
```bash
git checkout main
git merge enhance-zk-verification-events
```

## Questions or Issues?

For questions or issues related to this feature:
1. Refer to `EVENTS.md` for comprehensive documentation
2. Check example contract in `contracts/shielded-asset-template/`
3. Review unit tests in `crates/soroban-zk-std/src/events.rs`
4. Open an issue on GitHub with `[events]` tag

## License

This feature maintains the same license as the Soroban-ZK-Std project.
