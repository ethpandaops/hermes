# Sync Committee Validation Analysis for Hermes

## 1. What the Validation Spec Requires

Based on `/validation-specs/pubsub/sync_committee.md`, the sync committee message validation must enforce:

### MUST Requirements:

1. **[IGNORE] Slot Timing Check**:
   - `sync_committee_message.slot == current_slot` (with `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance)
   - Messages from future or past slots should be ignored

2. **[REJECT] Subnet ID Validation**:
   - `subnet_id in compute_subnets_for_sync_committee(state, sync_committee_message.validator_index)`
   - Validates that the validator is part of the current sync committee AND assigned to the correct subnet

3. **[IGNORE] Duplicate Message Prevention**:
   - No other valid sync committee message for the declared `slot` for the validator
   - Requires maintaining a cache of size `SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT` for each subnet
   - Cache can be flushed after each slot
   - This is **per topic** - multiple messages allowed with same `validator_index` on different `subnet_id`s

4. **[REJECT] Signature Validation**:
   - The `signature` is valid for the message `beacon_block_root` for the validator referenced by `validator_index`

## 2. What Currently Exists in Hermes

### Independent Mode Implementation
Located in `/eth/pubsub/handlers/independent/sync_committee_validator.go`:

**Current Implementation:**
- `SyncCommitteeMessageValidator` struct with basic validation
- Decompresses snappy data and unmarshals using `altair.SyncCommitteeMessage`
- Basic slot validation (checks if slot is from future)
- Period calculation and sync committee selection (current vs next)
- Validator membership check (basic index bounds check)
- Signature verification using domain `DomainSyncCommittee`

**Missing Features:**
1. **No subnet ID validation** - doesn't check if validator is assigned to the correct subnet
2. **No duplicate message tracking** - missing per-slot, per-validator cache
3. **No MAXIMUM_GOSSIP_CLOCK_DISPARITY tolerance** - strict future slot check
4. **No compute_subnets_for_sync_committee implementation**
5. **Doesn't extract subnet ID from topic**

### Delegated Mode Implementation
Located in `/eth/pubsub/handlers/delegated/validators.go`:

**Current Implementation:**
- `SyncCommitteeMessageValidator` that only decompresses and unmarshals
- Returns the decoded message without any validation
- Relies entirely on external Prysm node for validation

### Supporting Infrastructure

**Topic Classification** (`/eth/pubsub/common/utils.go`):
- `ClassifyMessage` correctly identifies sync committee messages with pattern `sync_committee_{subnet_id}`
- `ExtractSyncSubnet` function exists to extract subnet ID from topic
- Constants defined: `SYNC_COMMITTEE_SUBNET_COUNT = 4`, `SYNC_COMMITTEE_SIZE = 512`

**Router** (`/eth/pubsub/handlers/router.go`):
- Routes sync committee messages to appropriate validator
- Supports typed validation methods

## 3. What Needs to Change

### For Independent Mode

1. **Add compute_subnets_for_sync_committee Function**:
```go
// In a new file or common/utils.go
func ComputeSubnetsForSyncCommittee(state *StateInfo, validatorIndex ValidatorIndex) ([]uint64, error) {
    // Algorithm:
    // 1. Find validator's position in sync committee
    // 2. Calculate which subnet(s) the validator is assigned to
    // 3. Return list of valid subnet IDs
}
```

2. **Enhance SyncCommitteeMessageValidator**:
```go
// In sync_committee_validator.go
type SyncCommitteeMessageValidator struct {
    validator *IndependentValidator
    // Add per-subnet caches for duplicate detection
    seenMessages map[uint64]*lru.Cache[string, bool] // subnet_id -> cache
}

func (v *SyncCommitteeMessageValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
    // 1. Extract subnet ID from topic
    subnetID, err := common.ExtractSyncSubnet(topic)
    
    // 2. Add MAXIMUM_GOSSIP_CLOCK_DISPARITY tolerance
    if !isWithinClockDisparity(msg.Slot, currentSlot) {
        return nil, errors.New("[IGNORE] slot outside clock disparity")
    }
    
    // 3. Check subnet assignment
    validSubnets, err := ComputeSubnetsForSyncCommittee(state, msg.ValidatorIndex)
    if !contains(validSubnets, subnetID) {
        return nil, errors.New("[REJECT] validator not assigned to subnet")
    }
    
    // 4. Check for duplicates
    cacheKey := fmt.Sprintf("%d-%d", msg.Slot, msg.ValidatorIndex)
    if cache, exists := v.seenMessages[subnetID]; exists {
        if _, seen := cache.Get(cacheKey); seen {
            return nil, errors.New("[IGNORE] duplicate message")
        }
    }
    
    // 5. After successful validation, mark as seen
    v.seenMessages[subnetID].Add(cacheKey, true)
}
```

3. **Add Cache Management**:
```go
// Initialize caches on creation
func NewSyncCommitteeMessageValidator(iv *IndependentValidator) *SyncCommitteeMessageValidator {
    caches := make(map[uint64]*lru.Cache[string, bool])
    for i := uint64(0); i < SYNC_COMMITTEE_SUBNET_COUNT; i++ {
        cache, _ := lru.New[string, bool](SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT)
        caches[i] = cache
    }
    return &SyncCommitteeMessageValidator{
        validator: iv,
        seenMessages: caches,
    }
}

// Add method to flush caches after slot
func (v *SyncCommitteeMessageValidator) FlushSlotCaches(slot Slot) {
    for _, cache := range v.seenMessages {
        cache.Purge()
    }
}
```

### For Delegated Mode

The delegated mode is already compliant as it delegates all validation to the external Prysm node. No changes needed.

## 4. Specific Code Examples and File Locations

### Files to Modify:

1. **`/eth/pubsub/handlers/independent/sync_committee_validator.go`**:
   - Add duplicate message caching
   - Implement subnet validation
   - Add clock disparity tolerance

2. **`/eth/pubsub/common/utils.go`** or new file:
   - Add `ComputeSubnetsForSyncCommittee` function
   - Add helper for clock disparity check

3. **`/eth/pubsub/handlers/independent/state_sync.go`** (if needed):
   - Ensure sync committee info includes validator positions

### Example Implementation:

```go
// compute_subnets_for_sync_committee.go
func ComputeSubnetsForSyncCommittee(syncCommittee *SyncCommitteeInfo, validatorIndex ValidatorIndex) ([]uint64, error) {
    // Find validator's positions in sync committee
    positions := []int{}
    for i, idx := range syncCommittee.ValidatorIndices {
        if idx == validatorIndex {
            positions = append(positions, i)
        }
    }
    
    if len(positions) == 0 {
        return nil, fmt.Errorf("validator %d not in sync committee", validatorIndex)
    }
    
    // Calculate subnet assignments
    subnets := make(map[uint64]bool)
    subcommitteeSize := SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT
    
    for _, pos := range positions {
        subnet := uint64(pos) / subcommitteeSize
        subnets[subnet] = true
    }
    
    // Convert to slice
    result := make([]uint64, 0, len(subnets))
    for subnet := range subnets {
        result = append(result, subnet)
    }
    
    return result, nil
}

// Clock disparity helper
func isWithinClockDisparity(messageSlot, currentSlot Slot) bool {
    // Assuming MAXIMUM_GOSSIP_CLOCK_DISPARITY is 500ms
    // and slot duration is 12 seconds
    // This allows for messages from current slot only
    return messageSlot == currentSlot
}
```

## 5. Dependencies on Missing Components

### Required Infrastructure:

1. **Sync Committee Membership Tracking**:
   - Current implementation has basic sync committee info
   - Need to ensure it includes full validator index mappings

2. **Clock Synchronization**:
   - Need access to `MAXIMUM_GOSSIP_CLOCK_DISPARITY` constant
   - May need integration with ethwallclock for accurate slot timing

3. **Cache Lifecycle Management**:
   - Need to hook into slot transitions to flush caches
   - Could integrate with existing epoch-based state updates

### No Historical Block Storage Dependency:
Unlike some other validations, sync committee message validation doesn't require historical blocks - it only needs:
- Current state (for sync committee membership)
- Current slot timing
- Per-slot message cache

### Integration Points:

1. **With State Sync**:
   - Already integrated for current state access
   - May need to enhance sync committee info structure

2. **With Router**:
   - Already properly routed through typed validation methods

3. **With Metrics**:
   - Can use existing metrics infrastructure for tracking validation outcomes

## Summary

The sync committee validation in Hermes is partially implemented but missing critical spec requirements:
1. Subnet assignment validation (most critical)
2. Duplicate message prevention 
3. Proper clock disparity tolerance

The delegated mode is compliant by design. The independent mode needs enhancements primarily around subnet validation and duplicate tracking. The infrastructure is mostly in place - the main work is implementing the missing validation logic and cache management.