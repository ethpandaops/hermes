# Voluntary Exit Validation Analysis for Hermes

## 1. What the Validation Spec Requires

Based on `/validation-specs/pubsub/voluntary_exit.md`, the voluntary exit validation must enforce:

### Phase 0 - Capella Requirements:
1. **[IGNORE]** First valid voluntary exit for validator index (deduplication)
2. **[REJECT]** Validator must be active: `is_active_validator(validator, get_current_epoch(state))`
3. **[REJECT]** Exit not initiated: `validator.exit_epoch == FAR_FUTURE_EPOCH`
4. **[REJECT]** Exit epoch not in future: `get_current_epoch(state) >= voluntary_exit.epoch`
5. **[REJECT]** Validator active long enough: `get_current_epoch(state) >= validator.activation_epoch + SHARD_COMMITTEE_PERIOD`
6. **[REJECT]** Valid signature

### Deneb Fork Changes (EIP-7044):
- Signature domain uses fixed `CAPELLA_FORK_VERSION` regardless of current fork
- `domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, CAPELLA_FORK_VERSION, state.genesis_validators_root)`

### Electra Fork Changes (EIP-7251):
- **[REJECT]** No pending withdrawals: `get_pending_balance_to_withdraw(state, voluntary_exit.validator_index) == 0`

### General Requirements:
- Message type MUST be `SignedVoluntaryExit`
- MUST reject incorrect type or invalid payload

## 2. What Currently Exists in Hermes

### Independent Mode (`/eth/pubsub/handlers/independent/simple_validators.go`):

**Current Implementation (lines 16-95):**
```go
type VoluntaryExitValidator struct {
    validator *IndependentValidator
}

func (v *VoluntaryExitValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
    // ✓ Decompresses snappy data
    // ✓ Decodes SignedVoluntaryExit
    // ✓ Gets validator from state
    // ✓ Checks validator exists
    // ✓ Checks exit epoch not already set (FAR_FUTURE_EPOCH)
    // ✓ Checks exit epoch not in past
    // ✓ Verifies signature
}
```

**Issues Found:**
1. ❌ No per-validator deduplication (only message-level deduplication in IndependentValidator)
2. ❌ No active validator check
3. ❌ No check for minimum active duration (SHARD_COMMITTEE_PERIOD)
4. ❌ Incorrect epoch validation (checks if exit epoch is in past, should check if it's in future)
5. ❌ Uses current fork version instead of fixed CAPELLA_FORK_VERSION (Deneb requirement)
6. ❌ No Electra pending withdrawals check
7. ❌ Missing constants (FAR_FUTURE_EPOCH hardcoded as 18446744073709551615)

### Delegated Mode (`/eth/pubsub/handlers/delegated/validators.go`):

**Current Implementation (lines 127-149):**
```go
type VoluntaryExitValidator struct {
    handler *DelegatedHandler
}

func (v *VoluntaryExitValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
    // ✓ Decompresses snappy data
    // ✓ Decodes SignedVoluntaryExit
    // Returns decoded object only - NO VALIDATION
}
```

**Issues Found:**
- ❌ No validation at all - just deserializes and returns

### Deduplication Infrastructure:
- Independent mode has general message deduplication via `seenMessages` cache
- Uses message hash (data + peer + topic) for deduplication
- No per-validator-index deduplication for voluntary exits

## 3. What Needs to Change

### For Both Modes:

1. **Add Constants** (create in `/eth/pubsub/common/constants.go`):
```go
const (
    FAR_FUTURE_EPOCH = ^primitives.Epoch(0) // 2^64 - 1
    SHARD_COMMITTEE_PERIOD = 256
)
```

2. **Add Helper Functions** (in `/eth/pubsub/common/utils.go`):
```go
// IsActiveValidator checks if validator is active at given epoch
func IsActiveValidator(validator *Validator, epoch Epoch) bool {
    return validator.ActivationEpoch <= epoch && epoch < validator.ExitEpoch
}

// GetPendingBalanceToWithdraw returns pending withdrawal balance for validator (Electra)
func GetPendingBalanceToWithdraw(state *BeaconState, validatorIndex ValidatorIndex) uint64 {
    // Implementation needed based on Electra spec
    return 0
}
```

### Independent Mode Changes:

**1. Add Per-Validator Exit Tracking:**
```go
// In IndependentValidator struct
type IndependentValidator struct {
    // ... existing fields ...
    seenExits *lru.Cache[common.ValidatorIndex, time.Time] // Track exits by validator index
}

// In NewIndependentValidator
seenExits, err := lru.New[common.ValidatorIndex, time.Time](config.SeenMessageCacheSize)
```

**2. Update VoluntaryExitValidator.Handle():**
```go
func (v *VoluntaryExitValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
    // Decompress and decode
    decompressed, err := snappy.Decode(nil, data)
    if err != nil {
        return nil, errors.Wrap(err, "failed to decompress snappy data")
    }

    exit := &ethpb.SignedVoluntaryExit{}
    if err := exit.UnmarshalSSZ(decompressed); err != nil {
        return nil, errors.Wrap(err, "failed to decode voluntary exit")
    }

    // Check for duplicate exit for this validator [IGNORE]
    validatorIdx := exit.Exit.ValidatorIndex
    if v.validator.hasSeenExit(common.ValidatorIndex(validatorIdx)) {
        return nil, &common.ValidationError{
            Result: common.ValidationIgnore,
            Reason: "duplicate voluntary exit for validator",
        }
    }

    // Get current state and validator
    state := v.validator.stateSync.GetCurrentState()
    if state == nil {
        return nil, errors.New("no beacon state available")
    }

    validator, exists := state.Validators[common.ValidatorIndex(validatorIdx)]
    if !exists {
        return nil, errors.New("validator not found")
    }

    currentEpoch := state.Epoch

    // Check validator is active [REJECT]
    if !common.IsActiveValidator(validator, currentEpoch) {
        return nil, errors.New("validator is not active")
    }

    // Check exit not already initiated [REJECT]
    if validator.ExitEpoch != common.FAR_FUTURE_EPOCH {
        return nil, errors.New("validator already has exit initiated")
    }

    // Check exit epoch is not in the future [REJECT]
    if currentEpoch < exit.Exit.Epoch {
        return nil, errors.New("exit epoch is in the future")
    }

    // Check validator has been active long enough [REJECT]
    if currentEpoch < validator.ActivationEpoch + common.SHARD_COMMITTEE_PERIOD {
        return nil, errors.New("validator has not been active long enough")
    }

    // For Electra+, check no pending withdrawals [REJECT]
    if v.validator.isElectraOrLater() {
        pendingBalance := common.GetPendingBalanceToWithdraw(state, common.ValidatorIndex(validatorIdx))
        if pendingBalance > 0 {
            return nil, errors.New("validator has pending withdrawals")
        }
    }

    // Compute domain with fixed CAPELLA_FORK_VERSION for Deneb+
    var forkVersion [4]byte
    if v.validator.isDenebOrLater() {
        forkVersion = common.CapellaForkVersion
    } else {
        forkVersion = state.Fork.CurrentVersion
    }

    domain, err := common.ComputeDomain(
        common.DomainVoluntaryExit,
        forkVersion,
        state.GenesisValidatorsRoot,
    )
    if err != nil {
        return nil, errors.Wrap(err, "failed to compute domain")
    }

    // Verify signature [REJECT]
    signingRoot, err := common.ComputeSigningRoot(exit.Exit, domain)
    if err != nil {
        return nil, errors.Wrap(err, "failed to compute signing root")
    }

    err = v.validator.signatureVerifier.VerifySignature(
        validator.PublicKey,
        signingRoot[:],
        exit.Signature,
        common.DomainVoluntaryExit,
        exit.Exit.Epoch,
    )
    if err != nil {
        return nil, err
    }

    // Mark exit as seen for this validator
    v.validator.markExitSeen(common.ValidatorIndex(validatorIdx))

    return exit, nil
}
```

**3. Add Helper Methods to IndependentValidator:**
```go
func (v *IndependentValidator) hasSeenExit(validatorIdx common.ValidatorIndex) bool {
    v.mu.RLock()
    defer v.mu.RUnlock()
    _, exists := v.seenExits.Get(validatorIdx)
    return exists
}

func (v *IndependentValidator) markExitSeen(validatorIdx common.ValidatorIndex) {
    v.mu.Lock()
    defer v.mu.Unlock()
    v.seenExits.Add(validatorIdx, time.Now())
}

func (v *IndependentValidator) isDenebOrLater() bool {
    return v.forkVersion[0] >= common.DenebForkVersion[0]
}
```

### Delegated Mode Changes:

For delegated mode, we need to decide if it should perform any validation or continue to delegate all validation to the beacon node. Current implementation suggests it's meant to be a pass-through.

If validation is needed:
1. Would need access to beacon state (currently doesn't have StateProvider)
2. Would need to implement similar validation logic as independent mode
3. Would need deduplication tracking

## 4. Specific Code Examples and File Locations

### Files to Modify:

1. **`/eth/pubsub/common/constants.go`** (create new file):
```go
package common

import "github.com/OffchainLabs/prysm/v6/consensus-types/primitives"

const (
    FAR_FUTURE_EPOCH = ^primitives.Epoch(0)
    SHARD_COMMITTEE_PERIOD = primitives.Epoch(256)
)
```

2. **`/eth/pubsub/common/utils.go`** (add functions):
```go
func IsActiveValidator(validator *Validator, epoch Epoch) bool {
    return validator.ActivationEpoch <= epoch && epoch < validator.ExitEpoch
}
```

3. **`/eth/pubsub/handlers/independent/simple_validators.go`** (replace lines 25-95)
   - Complete rewrite of VoluntaryExitValidator.Handle() as shown above

4. **`/eth/pubsub/handlers/independent/independent_validator.go`**:
   - Add `seenExits` field to struct (line ~44)
   - Initialize in NewIndependentValidator (line ~200)
   - Add helper methods (after line 672)
   - Add cleanup for seenExits in cleanupLoop

## 5. Dependencies on Missing Components

### Required But Missing:

1. **Pending Withdrawals State Access (Electra)**:
   - Need access to withdrawal queue state
   - May require beacon state provider updates
   - Implementation of `GetPendingBalanceToWithdraw`

2. **Fork Version Detection**:
   - Need reliable fork version detection
   - Already partially implemented (`isElectraOrLater`)
   - Need to add `isDenebOrLater` method

### Nice to Have:

1. **Metrics for Exit Validation**:
   - Track duplicate exits ignored
   - Track validation failures by reason
   - Add to existing metrics structure

2. **Configurable Constants**:
   - Make SHARD_COMMITTEE_PERIOD configurable per network
   - Allow override of fork versions for testing

### Testing Requirements:

1. Unit tests for all validation rules
2. Integration tests with different fork versions
3. Test duplicate exit handling
4. Test edge cases (e.g., validator at exactly SHARD_COMMITTEE_PERIOD epochs)

## Summary

The current voluntary exit validation in Hermes is incomplete for both independent and delegated modes. Independent mode has partial validation but misses critical checks and uses incorrect domain computation for Deneb+. Delegated mode performs no validation at all. 

Key missing pieces:
- Per-validator deduplication (IGNORE rule)
- Active validator checks
- Minimum active duration checks  
- Fixed CAPELLA_FORK_VERSION for signatures (Deneb+)
- Pending withdrawals check (Electra+)

The implementation requires updates to handle fork-specific logic and proper state access for all validation rules.