# Beacon Attestation Validation Compliance Analysis

## 1. What the Validation Spec Requires

The beacon attestation validation specification defines rules for validating unaggregated attestations on `beacon_attestation_{subnet_id}` topics across different fork versions:

### Phase 0 - Capella Requirements

1. **[REJECT]** Committee index within expected range
2. **[REJECT]** Attestation on correct subnet
3. **[IGNORE]** Slot within `ATTESTATION_PROPAGATION_SLOT_RANGE` (±32 slots)
4. **[REJECT]** Target epoch matches slot's epoch
5. **[REJECT]** Exactly one aggregation bit set (unaggregated)
6. **[REJECT]** Aggregation bits length matches committee size
7. **[IGNORE]** No duplicate attestation from same validator for target epoch
8. **[REJECT]** Valid signature
9. **[IGNORE]** Block being voted for has been seen
10. **[REJECT]** Block passes validation
11. **[REJECT]** Target block is ancestor of LMD vote block
12. **[IGNORE]** Current finalized checkpoint is ancestor of voted block

### Deneb Fork Changes (EIP-7045)
- Removes slot range validation
- Adds: **[IGNORE]** Slot ≤ current slot
- Adds: **[IGNORE]** Epoch is current or previous

### Electra Fork Changes
- Changes message type from `Attestation` to `SingleAttestation`
- Adds: **[REJECT]** `attestation.data.index == 0`
- Adds: **[REJECT]** Attester is committee member
- Removes aggregation-related checks

## 2. What Currently Exists in Hermes

### Independent Mode Implementation

**File: `/eth/pubsub/handlers/independent/attestation_validator.go`**

Current implementation covers:
- ✅ Snappy decompression
- ✅ SSZ unmarshaling
- ✅ Subnet ID extraction and validation (lines 37-64)
- ✅ Basic attestation data validation (lines 83-113)
  - Slot not in future
  - Attestation within epoch
  - Target epoch matches slot epoch
  - Source before target
- ✅ Signature verification (lines 133-173)
- ✅ Attestation tracking for block validation (lines 175-189)
- ⚠️ Partial aggregation bit validation (lines 115-131)

**File: `/eth/pubsub/handlers/independent/single_attestation_validator.go`**

Electra support:
- ✅ SingleAttestation type handling
- ✅ Attester committee membership check (lines 56-67)
- ✅ Signature verification adapted for SingleAttestation

### Delegated Mode Implementation

**File: `/eth/pubsub/handlers/delegated/validators.go`**

Current implementation:
- ✅ Message type detection based on fork
- ✅ Snappy decompression
- ✅ SSZ unmarshaling
- ❌ No validation logic - only deserializes messages

### Supporting Infrastructure

**AttestationTracker** (`/eth/pubsub/handlers/independent/attestation_tracker.go`):
- Tracks attestations by block root
- Counts unique validators
- Provides attestation count queries
- Supports waiting for attestation threshold

## 3. What Needs to Change

### Independent Mode Changes

#### Missing Validations (Phase 0-Capella):
1. **Committee index range check**:
   ```go
   // Need to add:
   committeeCount := getCommitteeCountPerSlot(state, attestation.Data.Target.Epoch)
   if attestation.Data.CommitteeIndex >= committeeCount {
       return errors.New("committee index out of range")
   }
   ```

2. **Proper subnet computation**:
   ```go
   // Current implementation is simplified, needs:
   func computeSubnetForAttestation(slot Slot, committeeIndex uint64, committeesPerSlot uint64) uint64 {
       slotsSinceEpochStart := uint64(slot % SLOTS_PER_EPOCH)
       committeesSinceEpochStart := committeesPerSlot * slotsSinceEpochStart
       return (committeesSinceEpochStart + committeeIndex) % ATTESTATION_SUBNET_COUNT
   }
   ```

3. **Aggregation bits validation**:
   ```go
   // Need to verify exactly one bit is set:
   bitCount := countSetBits(attestation.AggregationBits)
   if bitCount != 1 {
       return errors.New("attestation must have exactly one aggregation bit set")
   }
   
   // Verify length matches committee size:
   if len(attestation.AggregationBits) * 8 < len(committee.ValidatorIndices) {
       return errors.New("aggregation bits length mismatch")
   }
   ```

4. **Duplicate attestation tracking**:
   ```go
   // Need to track by validator + target epoch:
   type attestationKey struct {
       ValidatorIndex ValidatorIndex
       TargetEpoch    Epoch
   }
   ```

5. **Block validation checks**:
   - Need infrastructure to track seen blocks
   - Need to validate block when first seen
   - Need to check target is ancestor of LMD vote
   - Need to verify finalized checkpoint ancestry

#### Deneb Fork Adaptations:
1. Update slot validation logic based on fork
2. Add epoch validation (current/previous only)

#### Electra Fork Adaptations:
1. Add validation for `attestation.data.index == 0`
2. Already have attester committee membership check

### Delegated Mode Changes

The delegated mode currently only deserializes messages without validation. Options:
1. **Add full validation** - Implement all checks similar to independent mode
2. **Keep minimal** - Continue delegating validation to connected node
3. **Hybrid approach** - Add critical checks (signature, basic data validation)

### Infrastructure Needs

1. **Historical Block Storage**:
   ```go
   type BlockStore interface {
       HasBlock(root [32]byte) bool
       GetBlock(root [32]byte) (*SignedBeaconBlock, error)
       IsAncestor(ancestor, descendant [32]byte) (bool, error)
       GetCheckpointBlock(blockRoot [32]byte, epoch Epoch) ([32]byte, error)
   }
   ```

2. **Fork-aware Validation**:
   ```go
   type ForkAwareValidator struct {
       phase0Validator   AttestationValidator
       denebValidator    AttestationValidator
       electraValidator  AttestationValidator
   }
   ```

3. **Enhanced State Access**:
   ```go
   type StateProvider interface {
       GetCommitteeCountPerSlot(epoch Epoch) (uint64, error)
       GetFinalizedCheckpoint() (*Checkpoint, error)
   }
   ```

## 4. Specific Code Examples and File Locations

### Example: Complete Phase 0 Attestation Validation

**Location**: `/eth/pubsub/handlers/independent/attestation_validator.go`

```go
func (v *StandardAttestationValidator) validatePhase0Attestation(
    attestation *ethpb.Attestation,
    subnetID uint64,
) error {
    state := v.validator.stateSync.GetCurrentState()
    if state == nil {
        return errors.New("no beacon state available")
    }

    // 1. Committee index range check
    committeesPerSlot := getCommitteeCountPerSlot(state, attestation.Data.Target.Epoch)
    if attestation.Data.CommitteeIndex >= committeesPerSlot {
        return errors.New("[REJECT] committee index out of range")
    }

    // 2. Subnet validation
    expectedSubnet := computeSubnetForAttestation(
        attestation.Data.Slot,
        uint64(attestation.Data.CommitteeIndex),
        committeesPerSlot,
    )
    if expectedSubnet != subnetID {
        return fmt.Errorf("[REJECT] wrong subnet: expected %d, got %d", 
            expectedSubnet, subnetID)
    }

    // 3. Slot range check (pre-Deneb)
    currentSlot := v.validator.clock.CurrentSlot()
    if !v.isSlotInRange(attestation.Data.Slot, currentSlot) {
        return errors.New("[IGNORE] attestation slot out of range")
    }

    // 4. Target epoch validation
    expectedEpoch := SlotToEpoch(attestation.Data.Slot)
    if attestation.Data.Target.Epoch != expectedEpoch {
        return errors.New("[REJECT] target epoch mismatch")
    }

    // 5. Aggregation bits validation
    bitCount := countSetBits(attestation.AggregationBits)
    if bitCount != 1 {
        return errors.New("[REJECT] not unaggregated (must have exactly 1 bit)")
    }

    // 6. Committee size validation
    committee, err := v.validator.committeeCache.GetCommittee(
        attestation.Data.Slot,
        attestation.Data.CommitteeIndex,
    )
    if err != nil {
        return errors.Wrap(err, "committee not found")
    }
    
    if len(attestation.AggregationBits) * 8 < len(committee.ValidatorIndices) {
        return errors.New("[REJECT] aggregation bits length mismatch")
    }

    // 7. Duplicate check
    attesterIndex := v.getAttesterIndex(committee, attestation.AggregationBits)
    if v.hasDuplicateAttestation(*attesterIndex, attestation.Data.Target.Epoch) {
        return errors.New("[IGNORE] duplicate attestation")
    }

    // 8. Signature verification
    if err := v.verifyAttestationSignature(attestation, *attesterIndex); err != nil {
        return errors.Wrap(err, "[REJECT] invalid signature")
    }

    // 9. Block seen check
    blockRoot := [32]byte{}
    copy(blockRoot[:], attestation.Data.BeaconBlockRoot)
    if !v.validator.blockStore.HasBlock(blockRoot) {
        return errors.New("[IGNORE] block not seen")
    }

    // 10. Block validation
    if err := v.validator.blockStore.ValidateBlock(blockRoot); err != nil {
        return errors.Wrap(err, "[REJECT] invalid block")
    }

    // 11. Target ancestry check
    checkpointBlock := v.validator.blockStore.GetCheckpointBlock(
        blockRoot, 
        attestation.Data.Target.Epoch,
    )
    if !bytes.Equal(checkpointBlock[:], attestation.Data.Target.Root) {
        return errors.New("[REJECT] target not ancestor of block")
    }

    // 12. Finalized checkpoint ancestry
    finalized := v.validator.stateSync.GetFinalizedCheckpoint()
    if !v.validator.blockStore.IsAncestor(finalized.Root, blockRoot) {
        return errors.New("[IGNORE] finalized checkpoint not ancestor")
    }

    return nil
}
```

### Example: Fork-Aware Router

**Location**: `/eth/pubsub/handlers/router.go` (enhancement needed)

```go
func (r *MessageRouter) RouteAttestationMessage(
    ctx context.Context,
    data []byte,
    topic string,
) (interface{}, error) {
    fork := r.forkDetector.CurrentFork()
    
    switch fork {
    case ElectraFork:
        return r.electraAttestationValidator.Handle(ctx, data, topic)
    case DenebFork:
        return r.denebAttestationValidator.Handle(ctx, data, topic)
    default:
        return r.phase0AttestationValidator.Handle(ctx, data, topic)
    }
}
```

## 5. Dependencies on Missing Components

### 1. Historical Block Storage System
- Need persistent storage for blocks
- Need ancestry tracking
- Need checkpoint block computation
- Integration with existing block validation

### 2. Enhanced State Management
- Access to committee counts per slot
- Finalized checkpoint tracking
- Fork version detection

### 3. Duplicate Detection System
- Per-validator, per-epoch tracking
- Efficient lookup structure
- Cleanup of old entries

### 4. Clock/Time Management
- Accurate slot timing
- MAXIMUM_GOSSIP_CLOCK_DISPARITY handling
- Fork-aware slot range validation

### 5. Metrics and Monitoring
- Validation outcome counters (IGNORE vs REJECT)
- Attestation processing latency
- Subnet distribution tracking

## Implementation Priority

1. **Phase 1 - Core Validations**:
   - Fix subnet computation
   - Add committee index range check
   - Improve aggregation bits validation
   - Add duplicate detection

2. **Phase 2 - Block Dependencies**:
   - Implement block storage interface
   - Add block seen/validation checks
   - Add ancestry validation

3. **Phase 3 - Fork Support**:
   - Implement Deneb-specific validations
   - Ensure Electra validations are complete
   - Add fork-aware routing

4. **Phase 4 - Delegated Mode**:
   - Decide on validation strategy
   - Implement chosen approach
   - Add configuration options

## Testing Requirements

1. Unit tests for each validation rule
2. Fork transition tests
3. Performance benchmarks for high attestation volume
4. Integration tests with real beacon node data
5. Negative test cases for each REJECT condition