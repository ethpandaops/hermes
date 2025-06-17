# Proposer Slashing Validation Analysis for Hermes

## 1. What the Validation Spec Requires

According to `/validation-specs/pubsub/proposer_slashing.md`, the proposer slashing topic validation requires:

### MUST Requirements:

1. **[IGNORE] Duplicate Prevention**
   - The proposer slashing must be the first valid proposer slashing received for the proposer with index `proposer_slashing.signed_header_1.message.proposer_index`
   - Clients MUST ignore duplicate proposer slashings for the same validator

2. **[REJECT] Validation Requirements**
   - All conditions within `process_proposer_slashing` must pass:
     - Header slots MUST match: `header_1.slot == header_2.slot`
     - Header proposer indices MUST match: `header_1.proposer_index == header_2.proposer_index`
     - Headers MUST be different: `header_1 != header_2`
     - Proposer MUST be slashable: `is_slashable_validator(proposer, get_current_epoch(state))`
     - Both signatures MUST be valid BLS signatures from the proposer

### Message Structure:
- Type: `ProposerSlashing`
- Contains:
  - `signed_header_1`: `SignedBeaconBlockHeader`
  - `signed_header_2`: `SignedBeaconBlockHeader`

## 2. What Currently Exists in Hermes

### Independent Mode (`/eth/pubsub/handlers/independent/simple_validators.go`)

The `ProposerSlashingValidator` (lines 97-198) implements:

✅ **Implemented:**
- Decompression and decoding of `ProposerSlashing` messages
- Verification that headers are for the same slot
- Verification that headers have the same proposer index
- Verification that headers are different (comparing HashTreeRoot)
- Basic slashability check (proposer is active and not already slashed)
- Signature verification for both headers using the beacon proposer domain

❌ **Missing:**
- **No duplicate tracking** - The validator doesn't maintain any cache of seen proposer slashings
- **Incomplete slashability check** - Uses simplified `proposer.Active && !proposer.Slashed` instead of proper `is_slashable_validator` logic

### Delegated Mode (`/eth/pubsub/handlers/delegated/validators.go`)

The `ProposerSlashingValidator` (lines 183-206) implements:

✅ **Implemented:**
- Basic decompression and SSZ decoding
- Returns decoded message for external validation

❌ **Missing:**
- **No validation logic** - Delegated mode only decodes messages and relies on external validation
- **No duplicate tracking** - The general message deduplication in `delegated_handler.go` only prevents duplicate message IDs, not duplicate slashings for the same validator

## 3. What Needs to Change

### For Both Modes:
1. **Add Proposer Slashing Cache**
   - Implement a dedicated cache to track seen proposer slashings by validator index
   - Cache should persist across multiple epochs (slashings are permanent)
   - Consider using LRU cache with sufficient size (e.g., 10,000 entries)

### For Independent Mode:
1. **Fix Duplicate Detection**
   - Add check against proposer slashing cache before processing
   - Return `ValidationIgnore` for duplicate slashings

2. **Implement Proper Slashability Check**
   - Replace simplified check with proper `is_slashable_validator` logic:
   ```go
   func isSlashableValidator(validator *Validator, epoch Epoch) bool {
       return !validator.Slashed && 
              validator.ActivationEpoch <= epoch && 
              epoch < validator.WithdrawableEpoch
   }
   ```

### For Delegated Mode:
1. **Add Minimal Duplicate Checking**
   - Even in delegated mode, duplicate slashing detection prevents DoS
   - Add proposer slashing cache check before forwarding

## 4. Specific Code Examples and File Locations

### Add to `/eth/pubsub/handlers/independent/independent_validator.go`:

```go
type IndependentValidator struct {
    // ... existing fields ...
    
    // Add slashing caches
    proposerSlashingCache  *lru.Cache[common.ValidatorIndex, time.Time]
    attesterSlashingCache  *lru.Cache[string, time.Time] // key: sorted validator indices
}

// In NewIndependentValidator:
proposerSlashingCache, err := lru.New[common.ValidatorIndex, time.Time](10000)
if err != nil {
    return nil, errors.Wrap(err, "failed to create proposer slashing cache")
}
```

### Update `/eth/pubsub/handlers/independent/simple_validators.go`:

```go
func (v *ProposerSlashingValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
    // ... existing decompression and decoding ...
    
    proposerIndex := slashing.Header_1.Header.ProposerIndex
    
    // Check duplicate slashing (IGNORE rule)
    if _, seen := v.validator.proposerSlashingCache.Get(common.ValidatorIndex(proposerIndex)); seen {
        return nil, errors.New("duplicate proposer slashing")
    }
    
    // ... existing validation ...
    
    // Fix slashability check
    currentEpoch := v.validator.stateSync.GetCurrentState().Epoch
    if !isSlashableValidator(proposer, currentEpoch) {
        return nil, errors.New("proposer is not slashable")
    }
    
    // ... existing signature verification ...
    
    // Cache successful validation
    v.validator.proposerSlashingCache.Add(common.ValidatorIndex(proposerIndex), time.Now())
    
    return slashing, nil
}

// Add helper function
func isSlashableValidator(validator *common.Validator, epoch common.Epoch) bool {
    return !validator.Slashed && 
           validator.ActivationEpoch <= epoch && 
           epoch < validator.WithdrawableEpoch
}
```

### Add to `/eth/pubsub/handlers/delegated/delegated_handler.go`:

```go
type DelegatedHandler struct {
    // ... existing fields ...
    
    // Add slashing caches
    proposerSlashingCache  *lru.Cache[uint64, time.Time]
}

// Update initializeValidators to pass cache to validators
```

### Update `/eth/pubsub/handlers/delegated/validators.go`:

```go
type ProposerSlashingValidator struct {
    handler *DelegatedHandler
    slashingCache *lru.Cache[uint64, time.Time]
}

func (v *ProposerSlashingValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
    // ... existing decompression ...
    
    slashing := &ethtypes.ProposerSlashing{}
    if err := slashing.UnmarshalSSZ(decompressed); err != nil {
        return nil, fmt.Errorf("unmarshal proposer slashing: %w", err)
    }
    
    // Add minimal duplicate check
    if slashing.Header_1 != nil && slashing.Header_1.Header != nil {
        proposerIndex := slashing.Header_1.Header.ProposerIndex
        if _, seen := v.slashingCache.Get(proposerIndex); seen {
            return nil, fmt.Errorf("duplicate proposer slashing for validator %d", proposerIndex)
        }
        v.slashingCache.Add(proposerIndex, time.Now())
    }
    
    return slashing, nil
}
```

## 5. Dependencies on Missing Components

### Required Components:
1. **Validator State Access**
   - ✅ Already available via `stateSync.GetValidator()` 
   - Need to ensure validator has `ActivationEpoch` and `WithdrawableEpoch` fields

2. **Historical Block Storage**
   - ❌ **Not required** for proposer slashing validation
   - The validation only needs current validator state, not historical blocks

3. **Epoch Calculation**
   - ✅ Already available via `stateSync.GetCurrentState().Epoch`
   - Helper functions exist in `common` package

### Additional Considerations:
1. **Cache Persistence**
   - Consider persisting slashing cache across restarts
   - Slashings are permanent, so cache entries never expire

2. **Cache Size Management**
   - With ~1M validators, cache needs appropriate sizing
   - Consider periodic cleanup of very old entries

3. **Metrics**
   - Add metrics for duplicate slashings detected
   - Track cache hit/miss rates

## Summary

The current implementation has the core validation logic but critically lacks the duplicate detection required by the spec's IGNORE rule. Both independent and delegated modes need to add proposer slashing caches to track seen slashings by validator index. The independent mode also needs a minor fix to properly implement the `is_slashable_validator` check according to consensus rules.

No historical block storage is required - all validation can be performed with current state information.