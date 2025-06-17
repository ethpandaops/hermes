# Attester Slashing Validation Analysis for Hermes

## 1. What the validation spec requires

According to `/validation-specs/pubsub/attester_slashing.md`, the following validation rules must be implemented:

### MUST Requirements:

1. **[IGNORE] Duplicate slashing prevention**: At least one index in the intersection of the attesting indices of each attestation has not yet been seen in any prior `attester_slashing`
   - Calculate: `attester_slashed_indices = set(attestation_1.attesting_indices).intersection(attestation_2.attesting_indices)`
   - Verify if: `any(attester_slashed_indices.difference(prior_seen_attester_slashed_indices))`
   - This prevents propagating duplicate slashings for already-slashed validators

2. **[REJECT] Core validation**: All conditions within `process_attester_slashing` pass validation:
   - The attestation data must be slashable according to Casper FFG rules (`is_slashable_attestation_data`):
     - Either a **double vote**: `data_1 != data_2 AND data_1.target.epoch == data_2.target.epoch`
     - Or a **surround vote**: `data_1.source.epoch < data_2.source.epoch AND data_2.target.epoch < data_1.target.epoch`
   - Both indexed attestations must be valid (`is_valid_indexed_attestation` for both attestation_1 and attestation_2)
   - At least one validator in the intersection must be slashable (not already slashed and within the withdrawable epoch)

3. **[REJECT] Type validation**: Messages must be of correct type (`AttesterSlashing`)

### Electra Fork Changes:
- Support for new `AttesterSlashingElectra` type with larger committee sizes
- `attesting_indices` can now contain up to `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT` validators

## 2. What currently exists in Hermes

### Independent Mode (`/eth/pubsub/handlers/independent/simple_validators.go`):

**Lines 200-267**: `AttesterSlashingValidator` implementation
- ✅ Decompresses snappy data
- ✅ Unmarshals `AttesterSlashing` message
- ✅ Checks if attestations are slashable (double vote or surround vote) via `isSlashableAttestationPair()`
- ✅ Finds intersection of validators who signed both attestations
- ✅ Verifies all slashed validators are slashable (active and not already slashed)
- ✅ Verifies signatures for both indexed attestations

**Missing**:
- ❌ No tracking of previously seen attester slashings
- ❌ No deduplication check for already-slashed validators
- ❌ No support for Electra fork's `AttesterSlashingElectra` type

### Delegated Mode (`/eth/pubsub/handlers/delegated/validators.go`):

**Lines 151-181**: `AttesterSlashingValidator` implementation
- ✅ Decompresses snappy data
- ✅ Fork-aware unmarshaling (supports Electra)
- ✅ Returns decoded message

**Missing**:
- ❌ No actual validation logic (just decoding)
- ❌ Relies entirely on external validator for validation

## 3. What needs to change

### For Independent Mode:

1. **Add slashing deduplication tracking**:
   - Create a new `SlashingTracker` component similar to `AttestationTracker`
   - Track seen attester slashing indices
   - Implement the [IGNORE] rule for duplicate slashings

2. **Add Electra support**:
   - Update unmarshaling to support both `AttesterSlashing` and `AttesterSlashingElectra` based on fork version
   - Handle larger committee sizes in Electra

3. **Enhanced validation**:
   - Add checks for withdrawable epoch
   - Ensure complete implementation of `process_attester_slashing` logic

### For Delegated Mode:
- Current implementation is correct as it delegates all validation to external validator
- No changes needed

## 4. Specific code examples and file locations

### New component needed: `SlashingTracker`

Create `/eth/pubsub/handlers/independent/slashing_tracker.go`:

```go
package independent

import (
    "sync"
    "time"
    
    lru "github.com/hashicorp/golang-lru/v2"
    "github.com/sirupsen/logrus"
    
    "github.com/probe-lab/hermes/eth/pubsub/common"
)

type SlashingTracker struct {
    logger *logrus.Logger
    mu     sync.RWMutex
    
    // Track validator indices that have been slashed
    seenSlashedIndices *lru.Cache[common.ValidatorIndex, time.Time]
}

func NewSlashingTracker(logger *logrus.Logger, cacheSize int) (*SlashingTracker, error) {
    cache, err := lru.New[common.ValidatorIndex, time.Time](cacheSize)
    if err != nil {
        return nil, err
    }
    
    return &SlashingTracker{
        logger:             logger,
        seenSlashedIndices: cache,
    }, nil
}

func (st *SlashingTracker) HasNewSlashing(indices []common.ValidatorIndex) bool {
    st.mu.RLock()
    defer st.mu.RUnlock()
    
    for _, idx := range indices {
        if _, seen := st.seenSlashedIndices.Get(idx); !seen {
            return true
        }
    }
    return false
}

func (st *SlashingTracker) RecordSlashing(indices []common.ValidatorIndex) {
    st.mu.Lock()
    defer st.mu.Unlock()
    
    now := time.Now()
    for _, idx := range indices {
        st.seenSlashedIndices.Add(idx, now)
    }
}

func (st *SlashingTracker) CleanupOldData(maxAge time.Duration) {
    st.mu.Lock()
    defer st.mu.Unlock()
    
    now := time.Now()
    keys := st.seenSlashedIndices.Keys()
    
    for _, key := range keys {
        if seenTime, ok := st.seenSlashedIndices.Peek(key); ok {
            if now.Sub(seenTime) > maxAge {
                st.seenSlashedIndices.Remove(key)
            }
        }
    }
}
```

### Update `IndependentValidator` in `/eth/pubsub/handlers/independent/independent_validator.go`:

Add to struct (around line 36):
```go
slashingTracker    *SlashingTracker
```

Add to `NewIndependentValidator` (around line 188):
```go
// Create slashing tracker
slashingTracker, err := NewSlashingTracker(logger, config.CommitteeCacheSize)
if err != nil {
    return nil, errors.Wrap(err, "failed to create slashing tracker")
}
```

Add to validator initialization (around line 201):
```go
slashingTracker:    slashingTracker,
```

Add to cleanup loop (around line 480):
```go
v.slashingTracker.CleanupOldData(1 * time.Hour) // Keep slashing data for 1 hour
```

### Update `AttesterSlashingValidator` in `/eth/pubsub/handlers/independent/simple_validators.go`:

Replace the existing implementation (lines 200-267) with:

```go
// AttesterSlashingValidator validates attester slashing messages
type AttesterSlashingValidator struct {
    validator *IndependentValidator
}

func NewAttesterSlashingValidator(iv *IndependentValidator) *AttesterSlashingValidator {
    return &AttesterSlashingValidator{validator: iv}
}

func (v *AttesterSlashingValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
    // Decompress the snappy-compressed data
    decompressed, err := snappy.Decode(nil, data)
    if err != nil {
        return nil, errors.Wrap(err, "failed to decompress snappy data")
    }

    // Fork-aware unmarshaling
    var slashing interface{}
    var att1, att2 *ethpb.IndexedAttestation
    
    if v.validator.isElectraOrLater() {
        slashingElectra := &ethpb.AttesterSlashingElectra{}
        if err := slashingElectra.UnmarshalSSZ(decompressed); err != nil {
            return nil, errors.Wrap(err, "failed to decode attester slashing")
        }
        slashing = slashingElectra
        att1 = &ethpb.IndexedAttestation{
            AttestingIndices: slashingElectra.Attestation_1.AttestingIndices,
            Data:            slashingElectra.Attestation_1.Data,
            Signature:       slashingElectra.Attestation_1.Signature,
        }
        att2 = &ethpb.IndexedAttestation{
            AttestingIndices: slashingElectra.Attestation_2.AttestingIndices,
            Data:            slashingElectra.Attestation_2.Data,
            Signature:       slashingElectra.Attestation_2.Signature,
        }
    } else {
        slashingPhase0 := &ethpb.AttesterSlashing{}
        if err := slashingPhase0.UnmarshalSSZ(decompressed); err != nil {
            return nil, errors.Wrap(err, "failed to decode attester slashing")
        }
        slashing = slashingPhase0
        att1 = slashingPhase0.Attestation_1
        att2 = slashingPhase0.Attestation_2
    }

    // Check if attestations are slashable (double vote or surround vote)
    if !isSlashableAttestationPair(att1, att2) {
        return nil, errors.New("attestations are not slashable")
    }

    // Get indices of validators in both attestations
    indices1 := getAttestingIndices(att1)
    indices2 := getAttestingIndices(att2)

    // Find intersection (validators who signed both)
    slashedIndices := intersection(indices1, indices2)
    if len(slashedIndices) == 0 {
        return nil, errors.New("no validators signed both attestations")
    }

    // IGNORE rule: Check if we've seen all these slashings before
    if !v.validator.slashingTracker.HasNewSlashing(slashedIndices) {
        return nil, errors.New("all slashed validators have been seen before")
    }

    // Get current state
    currentState := v.validator.stateSync.GetCurrentState()
    if currentState == nil {
        return nil, errors.New("no beacon state available")
    }

    // Verify all slashed validators are slashable
    currentEpoch := currentState.Epoch
    hasSlashableValidator := false
    
    for _, idx := range slashedIndices {
        validator, err := v.validator.stateSync.GetValidator(common.ValidatorIndex(idx))
        if err != nil {
            return nil, errors.Wrapf(err, "validator %d not found", idx)
        }

        // Check if validator is slashable:
        // 1. Must be active
        // 2. Must not already be slashed
        // 3. Must be before withdrawable epoch
        if validator.Active && !validator.Slashed {
            // Check withdrawable epoch (if available in validator data)
            // For now, we assume active + not slashed = slashable
            hasSlashableValidator = true
        }
    }

    if !hasSlashableValidator {
        return nil, errors.New("no slashable validators in intersection")
    }

    // Verify signatures for both attestations
    domain := common.DomainBeaconAttester

    // Verify first attestation
    if err := v.verifyIndexedAttestation(att1, domain); err != nil {
        return nil, errors.Wrap(err, "invalid signature for attestation 1")
    }

    // Verify second attestation
    if err := v.verifyIndexedAttestation(att2, domain); err != nil {
        return nil, errors.Wrap(err, "invalid signature for attestation 2")
    }

    // Record the slashing to prevent duplicate propagation
    v.validator.slashingTracker.RecordSlashing(slashedIndices)

    return slashing, nil
}
```

## 5. Dependencies on missing components

### Required dependencies:

1. **Historical validator state tracking**:
   - Need to track withdrawable epoch for validators
   - Currently, the `ValidatorInfo` struct doesn't include withdrawable epoch
   - Would need to extend state tracking to include this field

2. **Fork version detection**:
   - Already implemented via `isElectraOrLater()` method
   - Used to determine which message type to unmarshal

3. **Slashing cache persistence**:
   - Current implementation uses in-memory LRU cache
   - For production, might need persistent storage to survive restarts
   - Could integrate with existing state storage mechanism

### Nice-to-have improvements:

1. **Metrics for slashing validation**:
   - Track number of slashings seen
   - Track duplicate slashings ignored
   - Track validation failures by reason

2. **Configuration for cache sizes**:
   - Add `SlashingCacheSize` to `IndependentConfig`
   - Allow tuning based on network conditions

3. **Better error categorization**:
   - Distinguish between IGNORE and REJECT cases more clearly
   - Return specific error types for different validation failures

## Summary

The current Hermes implementation has most of the core validation logic for attester slashings but is missing the critical deduplication tracking required by the spec's [IGNORE] rule. The delegated mode correctly delegates validation to external validators, while the independent mode needs the additions outlined above to be fully compliant with the specification.

Key changes needed:
1. Add `SlashingTracker` component for deduplication
2. Update `AttesterSlashingValidator` to use the tracker
3. Add support for Electra fork's larger committee sizes
4. Enhance validator state tracking to include withdrawable epoch (if needed for complete validation)