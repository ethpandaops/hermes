# Light Client Optimistic Update - Hermes Compliance Analysis

## 1. What the Validation Spec Requires

The `light_client_optimistic_update` topic validation has different requirements based on node type:

### General Validation Rules (All Nodes)
1. **[IGNORE]** The `attested_header.beacon.slot` must be greater than all previously forwarded optimistic updates
2. **[IGNORE]** The update must be received after sufficient propagation time (1/3 of `SECONDS_PER_SLOT` after slot start, with `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance)

### Additional Rules for Full Nodes
3. **[IGNORE]** The received update must match the locally computed one exactly (as defined in `create_light_client_optimistic_update`)

### Additional Rules for Light Clients
4. **[REJECT]** The update must be valid according to `process_light_client_optimistic_update`
5. **[IGNORE]** The update either matches the most recent finality update or advances the local store's optimistic header

### Key Implementation Requirements
- Fork-specific message types (Altair, Capella, Deneb, Electra)
- Tracking of previously forwarded updates
- Time-based validation using slot timing
- Light client store for header tracking
- Ability to compute local optimistic updates (for full nodes)

## 2. What Currently Exists in Hermes

After searching the codebase:

### Missing Components
- **No light client message types**: The `MessageType` enum in `/eth/pubsub/common/types.go` does not include light client update types
- **No light client validators**: No validators exist for light client messages in the independent validator
- **No light client topic classification**: The `ClassifyMessage` function in `/eth/pubsub/common/utils.go` doesn't handle light client topics
- **No light client state tracking**: No light client store implementation exists

### Existing Infrastructure That Can Be Leveraged
- Fork version support exists (`/eth/pubsub/common/fork_version.go`)
- Wall clock timing with epoch tracking (`ethwallclock` integration)
- Message deduplication cache
- Signature verification infrastructure
- State provider interface for beacon state access

## 3. What Needs to Change

### For Both Independent and Delegated Modes

#### 1. Add Light Client Message Types
In `/eth/pubsub/common/types.go`, add:
```go
const (
    // ... existing types ...
    MessageLightClientOptimisticUpdate MessageType = 10
    MessageLightClientFinalityUpdate   MessageType = 11
)
```

#### 2. Update Message Classification
In `/eth/pubsub/common/utils.go`, update `ClassifyMessage`:
```go
case "light_client_optimistic_update":
    return MessageLightClientOptimisticUpdate
case "light_client_finality_update":
    return MessageLightClientFinalityUpdate
```

#### 3. Update Router to Handle Light Client Types
In `/eth/pubsub/handlers/router.go`:
- Add methods to `TypedValidator` interface:
```go
ValidateLightClientOptimisticUpdate(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult
ValidateLightClientFinalityUpdate(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult
```
- Add cases in `getValidatorForMessageType`:
```go
case common.MessageLightClientOptimisticUpdate:
    return typedValidator.ValidateLightClientOptimisticUpdate
case common.MessageLightClientFinalityUpdate:
    return typedValidator.ValidateLightClientFinalityUpdate
```

### For Independent Mode

#### 1. Create Light Client Store
Create `/eth/pubsub/handlers/independent/light_client_store.go`:
```go
type LightClientStore struct {
    mu                    sync.RWMutex
    optimisticHeader      *LightClientHeader
    finalizedHeader       *LightClientHeader
    bestValidUpdate       *LightClientUpdate
    previousBestUpdates   map[common.Slot]*LightClientOptimisticUpdate
    maxTrackedUpdates     int
}

func (s *LightClientStore) GetLatestOptimisticSlot() common.Slot
func (s *LightClientStore) HasSeenOptimisticUpdate(slot common.Slot) bool
func (s *LightClientStore) AddOptimisticUpdate(update *LightClientOptimisticUpdate)
func (s *LightClientStore) ProcessOptimisticUpdate(update *LightClientOptimisticUpdate) error
```

#### 2. Create Light Client Validators
Create `/eth/pubsub/handlers/independent/light_client_validators.go`:
```go
type LightClientOptimisticUpdateValidator struct {
    validator      *IndependentValidator
    store          *LightClientStore
    wallclock      *ethwallclock.EthereumBeaconChain
}

func (v *LightClientOptimisticUpdateValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
    // 1. Decode based on fork version
    // 2. Check slot is greater than previous
    // 3. Check timing constraints
    // 4. For full nodes: verify against local computation
    // 5. For light clients: process update
    // 6. Track the update
}
```

#### 3. Add Light Client Computation Support
Create `/eth/pubsub/handlers/independent/light_client_computation.go`:
```go
func CreateLightClientOptimisticUpdate(state *BeaconState, block *BeaconBlock) (*LightClientOptimisticUpdate, error) {
    // Implementation based on spec
}
```

#### 4. Update Independent Validator
In `/eth/pubsub/handlers/independent/independent_validator.go`:
- Add light client store initialization
- Add light client validators to `initializeValidators()`
- Add typed handler methods for light client messages

### For Delegated Mode

#### 1. Update Delegated Validators
In `/eth/pubsub/handlers/delegated/validators.go`:
- Add light client message handling cases
- Implement basic deduplication without full validation

#### 2. Add Configuration for Light Client Mode
```go
type DelegatedConfig struct {
    // ... existing fields ...
    LightClientMode bool // Whether to operate as light client vs full node
}
```

## 4. Specific Code Examples and File Locations

### Example: Light Client Message Type Definition
```go
// In /eth/pubsub/common/types.go
type LightClientOptimisticUpdate interface {
    GetAttestedHeader() *LightClientHeader
    GetSyncAggregate() *SyncAggregate
    GetSignatureSlot() common.Slot
}

// Fork-specific implementations
type AltairLightClientOptimisticUpdate struct {
    AttestedHeader  *LightClientHeader
    SyncAggregate   *SyncAggregate
    SignatureSlot   common.Slot
}
```

### Example: Validation Implementation
```go
// In /eth/pubsub/handlers/independent/light_client_validators.go
func (v *LightClientOptimisticUpdateValidator) validateTiming(slot common.Slot) error {
    currentTime := v.wallclock.Now()
    slotTime := v.wallclock.SlotStartTime(slot)
    
    // Must wait 1/3 of slot duration
    minTime := slotTime.Add(v.wallclock.SlotDuration() / 3)
    if currentTime.Before(minTime.Add(-MAXIMUM_GOSSIP_CLOCK_DISPARITY)) {
        return errors.New("update received too early")
    }
    return nil
}
```

## 5. Dependencies on Missing Components

### Required New Components
1. **Light Client Types**: Need SSZ definitions for all light client message types across forks
2. **Light Client Store**: Persistent storage for tracking light client state
3. **Merkle Proof Verification**: For verifying sync committee branches in updates
4. **Historical Block Access**: For full nodes to compute `create_light_client_optimistic_update`

### External Dependencies
1. **Prysm Light Client Types**: May need to import or define light client specific types
2. **SSZ Encoding/Decoding**: For fork-specific light client messages
3. **Sync Committee Utilities**: For handling sync aggregates and participation

### Integration Points
1. **State Provider**: Need methods to access sync committee data
2. **Block Cache**: Full nodes need access to recent blocks for creating updates
3. **Fork Schedule**: For determining correct message types by slot

## Implementation Priority

1. **Phase 1**: Basic message type support and routing
2. **Phase 2**: Delegated mode support (basic validation)
3. **Phase 3**: Light client mode in independent validator
4. **Phase 4**: Full node mode with local computation
5. **Phase 5**: Comprehensive testing and optimization

## Testing Considerations

- Need test vectors for different fork versions
- Mock light client store for unit tests
- Integration tests with actual light client updates
- Performance testing for update processing
- Fork transition testing