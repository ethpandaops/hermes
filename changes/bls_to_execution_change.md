# BLS to Execution Change Validation Analysis

## 1. Validation Specification Requirements

According to `/validation-specs/pubsub/bls_to_execution_change.md`, the `bls_to_execution_change` topic validation requires:

### MUST Requirements:

1. **[IGNORE]** `current_epoch >= CAPELLA_FORK_EPOCH`, where `current_epoch` is defined by the current wall-clock time
   - Messages received before Capella fork activation should be ignored

2. **[IGNORE]** The `signed_bls_to_execution_change` is the first valid signed BLS to execution change received for the validator with index `signed_bls_to_execution_change.message.validator_index`
   - Duplicate messages for the same validator should be ignored

3. **[REJECT]** All of the conditions within `process_bls_to_execution_change` pass validation:
   - **MUST** assert `address_change.validator_index < len(state.validators)`
   - **MUST** assert `validator.withdrawal_credentials[:1] == BLS_WITHDRAWAL_PREFIX` (0x00)
   - **MUST** assert `validator.withdrawal_credentials[1:] == hash(address_change.from_bls_pubkey)[1:]`
   - **MUST** assert `bls.Verify(address_change.from_bls_pubkey, signing_root, signed_address_change.signature)`
     - Where signing_root is computed using `DOMAIN_BLS_TO_EXECUTION_CHANGE` domain (fork-agnostic)

### Key Points:
- Introduced in Capella and remains unchanged in Deneb, Electra, and Fulu
- Uses fork-agnostic domain for signature verification
- Message type is `SignedBLSToExecutionChange`
- Used to change withdrawal credentials from BLS to execution address format

## 2. Current Implementation in Hermes

### Message Type Support
- **Defined**: `MessageBlsToExecutionChange` in `/eth/pubsub/common/types.go`
- **Domain Type**: `DomainBlsToExecutionChange = 0x0A000000` defined
- **Topic Registration**: Registered in `/eth/node.go` line 891

### Delegated Mode Implementation
Location: `/eth/pubsub/handlers/delegated/`

- **Handler**: `BlsToExecutionChangeValidator` implemented in `validators.go`
- **Functionality**: 
  - Decompresses snappy data
  - Unmarshals `SignedBLSToExecutionChange` message
  - Returns decoded object without validation
  - Accepts all messages that decode successfully

### Independent Mode Implementation
Location: `/eth/pubsub/handlers/independent/simple_validators.go`

- **Handler**: `BLSToExecutionChangeValidator` (lines 361-436)
- **Current Validation**:
  1. Decompresses and decodes the message
  2. Checks validator index is within range
  3. Verifies `from_bls_pubkey` matches validator's public key
  4. Checks withdrawal credentials have BLS prefix (0x00)
  5. Verifies BLS signature using `DomainBlsToExecutionChange`

## 3. Missing Implementations and Issues

### Independent Mode Issues:

1. **Missing Fork Epoch Check**:
   - No check for `current_epoch >= CAPELLA_FORK_EPOCH`
   - Should ignore messages before Capella activation

2. **Missing Deduplication**:
   - No tracking of seen BLS to execution changes per validator
   - Should ignore duplicate messages for same validator index

3. **Incomplete Withdrawal Credentials Validation**:
   - Missing check: `validator.withdrawal_credentials[1:] == hash(address_change.from_bls_pubkey)[1:]`
   - Only checks the BLS prefix but not the hash match

4. **Fork Epoch Information**:
   - No access to Capella fork epoch from beacon state
   - Need to retrieve fork schedule information

### Delegated Mode:
- Currently accepts all messages that decode successfully
- This is appropriate for delegated mode as validation is handled by the connected beacon node

## 4. Required Changes

### For Independent Mode:

1. **Add Fork Epoch Check**:
```go
// In BLSToExecutionChangeValidator.Handle()
currentEpoch := v.validator.stateSync.GetCurrentState().Epoch
capellaForkEpoch := v.validator.stateSync.GetCapellaForkEpoch() // Need to implement
if currentEpoch < capellaForkEpoch {
    return nil, errors.New("BLS to execution changes not yet active")
}
```

2. **Add Deduplication Cache**:
```go
// Add to IndependentValidator struct
seenBLSChanges map[common.ValidatorIndex]bool // or use LRU cache

// In validation
if v.validator.seenBLSChanges[validatorIdx] {
    return nil, errors.New("duplicate BLS to execution change")
}
// Mark as seen after successful validation
v.validator.seenBLSChanges[validatorIdx] = true
```

3. **Fix Withdrawal Credentials Validation**:
```go
// After line 408 in simple_validators.go
// Compute hash of from_bls_pubkey
pubkeyHash := hash.Hash(change.Message.FromBlsPubkey)

// Verify withdrawal credentials match
if !bytes.Equal(validator.WithdrawalCredentials[1:], pubkeyHash[1:]) {
    return nil, errors.New("withdrawal credentials don't match BLS pubkey hash")
}
```

4. **Add Fork Schedule Support**:
```go
// Need to add to state sync or beacon client
type ForkSchedule struct {
    Phase0Epoch    Epoch
    AltairEpoch    Epoch
    BellatrixEpoch Epoch
    CapellaEpoch   Epoch
    DenebEpoch     Epoch
    ElectraEpoch   Epoch
}
```

### For Delegated Mode:
- No changes required - current implementation is appropriate

## 5. Dependencies on Missing Components

1. **Fork Schedule Information**:
   - Need access to fork activation epochs from beacon node
   - Could be retrieved via beacon API `/eth/v1/config/fork_schedule`
   - Should be cached and updated periodically

2. **Deduplication Cache**:
   - Need persistent cache for tracking seen BLS changes per validator
   - Should survive restarts to prevent replay
   - Consider using LRU cache with appropriate size

3. **Hash Function**:
   - Already available: `github.com/OffchainLabs/prysm/v6/crypto/hash`
   - Used for computing withdrawal credentials hash

## 6. Implementation Priority

1. **High Priority**:
   - Fix withdrawal credentials validation (security issue)
   - Add fork epoch check (consensus rule)

2. **Medium Priority**:
   - Implement deduplication (prevents spam)

3. **Low Priority**:
   - Optimize caching strategies
   - Add metrics for BLS change validations

## 7. Testing Recommendations

1. Test with pre-Capella messages (should be ignored)
2. Test duplicate messages for same validator (should be ignored)
3. Test invalid withdrawal credentials hash (should be rejected)
4. Test invalid BLS signature (should be rejected)
5. Test valid BLS to execution change (should be accepted)

## 8. File Locations Summary

- **Specification**: `/validation-specs/pubsub/bls_to_execution_change.md`
- **Message Types**: `/eth/pubsub/common/types.go`
- **Independent Validator**: `/eth/pubsub/handlers/independent/simple_validators.go` (lines 361-436)
- **Delegated Validator**: `/eth/pubsub/handlers/delegated/validators.go` (lines 258-281)
- **Topic Registration**: `/eth/node.go` (line 891)
- **Constants**: `/eth/pubsub/common/utils.go` (BLS_WITHDRAWAL_PREFIX)