# Beacon Aggregate and Proof Validation Analysis

## 1. What the Validation Spec Requires

The `beacon_aggregate_and_proof` topic validation spec defines comprehensive rules that evolve across different forks:

### Phase 0 - Capella Validation Rules

1. **Committee index validation** [REJECT]:
   - `index < get_committee_count_per_slot(state, aggregate.data.target.epoch)`

2. **Slot timing validation** [IGNORE]:
   - `aggregate.data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot >= aggregate.data.slot`
   - Must include `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance

3. **Epoch consistency** [REJECT]:
   - `aggregate.data.target.epoch == compute_epoch_at_slot(aggregate.data.slot)`

4. **Aggregation bits length** [REJECT]:
   - `len(aggregation_bits) == len(get_beacon_committee(state, aggregate.data.slot, index))`

5. **Has participants** [REJECT]:
   - `len(get_attesting_indices(state, aggregate)) >= 1`

6. **No superset seen** [IGNORE]:
   - Must not have seen a valid aggregate for same data with superset aggregation_bits

7. **First from aggregator** [IGNORE]:
   - First valid aggregate from aggregator for the epoch

8. **Selection proof validates** [REJECT]:
   - `is_aggregator(state, aggregate.data.slot, index, aggregate_and_proof.selection_proof)` returns True

9. **Aggregator in committee** [REJECT]:
   - `aggregate_and_proof.aggregator_index in get_beacon_committee(state, aggregate.data.slot, index)`

10. **Selection proof signature** [REJECT]:
    - Valid signature of slot by aggregator

11. **Aggregator signature** [REJECT]:
    - `signed_aggregate_and_proof.signature` is valid

12. **Aggregate signature** [REJECT]:
    - The aggregate attestation signature is valid

13. **Block has been seen** [IGNORE]:
    - Must have seen the `aggregate.data.beacon_block_root`

### Deneb Fork Changes (EIP-7045)

- **Removed**: Slot range validation
- **Added**:
  1. Aggregate not from future [IGNORE]: `aggregate.data.slot <= current_slot`
  2. From current/previous epoch [IGNORE]: `compute_epoch_at_slot(aggregate.data.slot) in (get_previous_epoch(state), get_current_epoch(state))`

### Electra Fork Changes

- **Modified**: `index = get_committee_indices(aggregate.committee_bits)[0]`
- **Added**:
  1. Single committee [REJECT]: `len(committee_indices) == 1`
  2. Zero index field [REJECT]: `aggregate.data.index == 0`

## 2. What Currently Exists in Hermes

### Message Type Registration
- File: `/eth/node.go` (lines 659, 887)
- Registers `beacon_aggregate_and_proof` topic with `common.MessageAggregateAndProof` type

### Type Definitions
- File: `/eth/pubsub/common/types.go`
- Defines `MessageAggregateAndProof` enum value
- Defines `DomainAggregateAndProof` and `DomainSelectionProof` domain types

### Validation Infrastructure

#### Router Level
- File: `/eth/pubsub/handlers/router.go`
- Routes `MessageAggregateAndProof` to `ValidateAggregateAndProof` method
- TypedValidator interface includes `ValidateAggregateAndProof` method

#### Delegated Mode
- File: `/eth/pubsub/handlers/delegated/delegated_handler.go`
- Implements `ValidateAggregateAndProof` - simply accepts all messages (delegated validation)

#### Independent Mode
- File: `/eth/pubsub/handlers/independent/aggregate_validator.go`
- Implements `AggregateAndProofValidator` with partial validation
- File: `/eth/pubsub/handlers/independent/independent_validator.go`
- Registers aggregate validator at line 419

### Current Implementation Gaps

The existing implementation in `aggregate_validator.go` only validates:
1. Basic nil checks
2. Slot not from future
3. Aggregator exists and is active
4. Selection proof signature (partial)
5. Aggregator signature
6. Basic aggregate attestation validation

**Missing validations**:
- Committee index range check
- Proper slot timing with ATTESTATION_PROPAGATION_SLOT_RANGE
- Epoch consistency check
- Proper aggregation bits length validation
- Superset aggregate deduplication
- First-from-aggregator tracking
- Full `is_aggregator` selection proof validation
- Aggregator committee membership check
- Block has been seen check
- Fork-specific logic (Deneb/Electra)

## 3. What Needs to Change

### For Both Independent and Delegated Modes

1. **Fork Version Handling**
   - Add fork version detection to handle Phase0/Capella, Deneb, and Electra differently
   - Use `VersionedAggregateAndProof` type for proper SSZ unmarshaling

2. **Message Type Structure**
   - Properly handle both pre-Electra and Electra+ message formats
   - Support committee_bits field for Electra

### For Independent Mode Specifically

1. **Complete Validation Implementation**
   ```go
   // Add to aggregate_validator.go
   
   // Check committee index range
   committeeCount := getCommitteeCountPerSlot(state, targetEpoch)
   if index >= committeeCount {
       return nil, fmt.Errorf("committee index %d >= committee count %d", index, committeeCount)
   }
   
   // Add proper slot timing validation
   currentSlot := v.validator.wallclock.Slot()
   if v.validator.forkVersion < DenebForkVersion {
       // Phase0-Capella: use ATTESTATION_PROPAGATION_SLOT_RANGE
       minSlot := currentSlot - ATTESTATION_PROPAGATION_SLOT_RANGE
       if aggregate.Data.Slot < minSlot || aggregate.Data.Slot > currentSlot {
           return nil, fmt.Errorf("aggregate slot %d outside valid range [%d, %d]", 
               aggregate.Data.Slot, minSlot, currentSlot)
       }
   } else {
       // Deneb+: aggregate must be from current or previous epoch
       aggregateEpoch := computeEpochAtSlot(aggregate.Data.Slot)
       currentEpoch := v.validator.wallclock.Epoch()
       previousEpoch := currentEpoch - 1
       if aggregateEpoch != currentEpoch && aggregateEpoch != previousEpoch {
           return nil, fmt.Errorf("aggregate from epoch %d not in [%d, %d]", 
               aggregateEpoch, previousEpoch, currentEpoch)
       }
   }
   ```

2. **Add Missing Components**
   - Implement superset aggregate tracking cache
   - Add aggregator-per-epoch tracking
   - Implement `is_aggregator` function
   - Add block seen validation (requires historical block storage)

3. **Electra Support**
   ```go
   // Handle Electra committee bits
   if v.validator.forkVersion >= ElectraForkVersion {
       committeeIndices := getCommitteeIndices(aggregate.CommitteeBits)
       if len(committeeIndices) != 1 {
           return nil, fmt.Errorf("expected single committee, got %d", len(committeeIndices))
       }
       if aggregate.Data.Index != 0 {
           return nil, fmt.Errorf("index field must be 0 for Electra, got %d", aggregate.Data.Index)
       }
       index = committeeIndices[0]
   }
   ```

### For Delegated Mode

- No changes needed - continues to accept all messages

## 4. Specific Code Examples and File Locations

### Files to Modify

1. **`/eth/pubsub/handlers/independent/aggregate_validator.go`**
   - Add complete validation logic as shown above
   - Implement fork-specific handling
   - Add proper caching for deduplication

2. **`/eth/pubsub/handlers/independent/independent_validator.go`**
   - Add aggregate tracking structures:
   ```go
   type IndependentValidator struct {
       // ... existing fields
       
       // Add for aggregate tracking
       seenAggregates     *lru.Cache[string, *bitfield.Bitlist] // key: attestation_data_root
       aggregatorTracker  *AggregatorTracker // tracks aggregators per epoch
   }
   ```

3. **Create new file: `/eth/pubsub/handlers/independent/aggregator_tracker.go`**
   ```go
   type AggregatorTracker struct {
       mu                sync.RWMutex
       aggregatorsByEpoch map[common.Epoch]map[common.ValidatorIndex]bool
   }
   
   func (at *AggregatorTracker) HasSeenAggregator(epoch common.Epoch, index common.ValidatorIndex) bool {
       // Implementation
   }
   
   func (at *AggregatorTracker) MarkAggregatorSeen(epoch common.Epoch, index common.ValidatorIndex) {
       // Implementation
   }
   ```

4. **Add utility functions in `/eth/pubsub/common/utils.go`**
   ```go
   func IsAggregator(state *BeaconState, slot Slot, index CommitteeIndex, selectionProof [96]byte) (bool, error) {
       committee, err := GetBeaconCommittee(state, slot, index)
       if err != nil {
           return false, err
       }
       
       modulo := Max(1, len(committee)/TARGET_AGGREGATORS_PER_COMMITTEE)
       hashInput := append(selectionProof[:], littleEndianUint64(uint64(slot))...)
       hash := sha256.Sum256(hashInput)
       
       return binary.LittleEndian.Uint64(hash[:8])%uint64(modulo) == 0, nil
   }
   ```

## 5. Dependencies on Missing Components

### Historical Block Storage
The validation rule "Block being voted for has been seen" requires:
- A way to track blocks that have been seen via gossip or non-gossip sources
- This could be implemented as:
  ```go
  type BlockTracker interface {
      HasSeenBlock(root [32]byte) bool
      MarkBlockSeen(root [32]byte)
  }
  ```

### Constants Needed
```go
const (
    ATTESTATION_PROPAGATION_SLOT_RANGE = 32
    TARGET_AGGREGATORS_PER_COMMITTEE = 16
    MAXIMUM_GOSSIP_CLOCK_DISPARITY = 500 * time.Millisecond
)
```

### Fork Version Detection
Need to properly detect fork boundaries:
```go
func (v *IndependentValidator) getCurrentFork() ForkVersion {
    state := v.stateSync.GetCurrentState()
    if state == nil {
        return v.config.ForkVersion
    }
    
    currentEpoch := v.wallclock.Epoch()
    // Logic to determine active fork based on epoch
    return determineForkVersion(currentEpoch, state.Fork)
}
```

## Summary

The current Hermes implementation has basic aggregate and proof validation but lacks many critical checks required by the specification. The main areas needing work are:

1. **Timing validations** - proper slot range checks based on fork
2. **Deduplication** - tracking seen aggregates and aggregators
3. **Committee validations** - proper committee membership and size checks
4. **Fork handling** - different logic for Phase0/Capella, Deneb, and Electra
5. **Block tracking** - ability to verify the attested block has been seen

The delegated mode requires no changes as it accepts all messages by design.