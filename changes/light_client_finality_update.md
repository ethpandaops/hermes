# Light Client Finality Update Validation Analysis for Hermes

## 1. Validation Spec Requirements

The `light_client_finality_update` topic validation requirements from `/validation-specs/pubsub/light_client_finality_update.md`:

### General Validations (All Nodes)
1. **[IGNORE]** The `finalized_header.beacon.slot` MUST be greater than all previously forwarded `finality_update`s, OR it matches the highest previously forwarded slot with supermajority sync committee participation
2. **[IGNORE]** Must wait for 1/3 of signature slot to pass (timing constraint)

### Full Node Additional Validations
3. **[IGNORE]** The received `finality_update` MUST match the locally computed one exactly

### Light Client Additional Validations
4. **[REJECT]** The `finality_update` MUST be valid (process without errors)
5. **[IGNORE]** Must advance the `finalized_header` of local `LightClientStore`

### Message Types by Fork
- Altair-Bellatrix: `altair.LightClientFinalityUpdate`
- Capella: `capella.LightClientFinalityUpdate`
- Deneb: `deneb.LightClientFinalityUpdate`
- Electra+: `electra.LightClientFinalityUpdate`

## 2. Current State in Hermes

After searching the codebase, I found:
- **NO existing implementation** for light client finality update validation
- Light client topics are mentioned in validation specs but not implemented
- Current message types in `/eth/pubsub/common/types.go` do not include light client messages
- The router in `/eth/pubsub/handlers/router.go` does not handle light client topics
- No light client message classification in `/eth/pubsub/common/utils.go`

## 3. Required Changes

### 3.1 Add Light Client Message Types

**File**: `/eth/pubsub/common/types.go`
```go
const (
    // ... existing message types ...
    MessageLightClientFinalityUpdate MessageType = iota + 10
    MessageLightClientOptimisticUpdate
)
```

### 3.2 Update Message Classification

**File**: `/eth/pubsub/common/utils.go`
```go
// In ClassifyMessage function, add:
case "light_client_finality_update":
    return MessageLightClientFinalityUpdate
case "light_client_optimistic_update":
    return MessageLightClientOptimisticUpdate

// In GetMessageTypeName function, add:
case MessageLightClientFinalityUpdate:
    return "light_client_finality_update"
case MessageLightClientOptimisticUpdate:
    return "light_client_optimistic_update"
```

### 3.3 Update Router Interface

**File**: `/eth/pubsub/handlers/router.go`
```go
// In TypedValidator interface, add:
ValidateLightClientFinalityUpdate(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult
ValidateLightClientOptimisticUpdate(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult

// In getValidatorForMessageType function, add cases:
case common.MessageLightClientFinalityUpdate:
    return typedValidator.ValidateLightClientFinalityUpdate
case common.MessageLightClientOptimisticUpdate:
    return typedValidator.ValidateLightClientOptimisticUpdate
```

### 3.4 Independent Mode Implementation

**New File**: `/eth/pubsub/handlers/independent/light_client_validator.go`
```go
package independent

import (
    "context"
    "fmt"
    "time"
    
    pubsub "github.com/libp2p/go-libp2p-pubsub"
    "github.com/sirupsen/logrus"
    // Import appropriate light client types based on fork
)

// ValidateLightClientFinalityUpdate validates light client finality updates
func (v *IndependentValidator) ValidateLightClientFinalityUpdate(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
    // 1. Decode the message based on fork
    // 2. Track highest finalized slot
    // 3. Check timing constraint (1/3 of signature slot)
    // 4. For full node mode: compute local finality update and compare
    // 5. For light client mode: validate using process_light_client_finality_update
    
    return pubsub.ValidationAccept
}
```

**Update File**: `/eth/pubsub/handlers/independent/independent_validator.go`
```go
// Add to IndependentValidator struct:
type IndependentValidator struct {
    // ... existing fields ...
    
    // Light client tracking
    highestFinalizedSlot     Slot
    highestFinalizedSlotLock sync.RWMutex
    lightClientStore         *LightClientStore // If operating as light client
}
```

### 3.5 Delegated Mode Implementation

**Update File**: `/eth/pubsub/handlers/delegated/validators.go`
```go
// Add validation methods:
func (h *DelegatedHandler) ValidateLightClientFinalityUpdate(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
    // Forward to upstream validator
    return h.validateWithUpstream(ctx, msg, "light_client_finality_update")
}

func (h *DelegatedHandler) ValidateLightClientOptimisticUpdate(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
    // Forward to upstream validator
    return h.validateWithUpstream(ctx, msg, "light_client_optimistic_update")
}
```

## 4. Implementation Details

### 4.1 Independent Mode Requirements

1. **State Tracking**:
   - Track highest finalized slot seen
   - Track sync committee participation for duplicate slots
   - Maintain light client store if operating as light client

2. **Full Node Mode**:
   - Need access to beacon state to compute local finality update
   - Requires `create_light_client_finality_update` implementation
   - Must have access to finalized block and state

3. **Light Client Mode**:
   - Implement `process_light_client_finality_update` function
   - Maintain `LightClientStore` with finalized header
   - Validate sync aggregate signatures

### 4.2 Delegated Mode Requirements

1. **Message Forwarding**:
   - Decode message to extract necessary fields for upstream
   - Forward to upstream validator
   - Cache validation results

## 5. Dependencies and Missing Components

### 5.1 Missing Dependencies

1. **Light Client Types**:
   - Need to import/define `LightClientFinalityUpdate` structs for each fork
   - Need `LightClientStore` implementation
   - Need sync committee related types

2. **Cryptographic Functions**:
   - BLS signature verification for sync aggregates
   - Merkle proof verification for finality branch

3. **State Access**:
   - For full node validation: need access to finalized states
   - Need ability to compute light client updates from state

### 5.2 Historical Block Storage

For full node validation, the validator needs:
- Access to finalized blocks and states
- Ability to retrieve sync committee for given period
- Access to block at `signature_slot`

This may require:
```go
// In beacon state provider interface
type BeaconStateProvider interface {
    // ... existing methods ...
    
    // For light client support
    GetFinalizedBlock(ctx context.Context) (*SignedBeaconBlock, error)
    GetSyncCommittee(ctx context.Context, period uint64) (*SyncCommittee, error)
    ComputeLightClientFinalityUpdate(ctx context.Context) (*LightClientFinalityUpdate, error)
}
```

## 6. Testing Considerations

1. **Unit Tests**:
   - Test slot progression tracking
   - Test sync committee participation comparison
   - Test timing validation (1/3 slot wait)

2. **Integration Tests**:
   - Test with different fork versions
   - Test with competing finality updates
   - Test light client store advancement

3. **Edge Cases**:
   - Same slot with different sync participation
   - Clock drift scenarios
   - Fork transition handling

## 7. Implementation Priority

1. **Phase 1**: Add message types and classification
2. **Phase 2**: Implement delegated mode (simpler, forwards to upstream)
3. **Phase 3**: Implement independent mode with basic validation
4. **Phase 4**: Add full node validation (requires state access)
5. **Phase 5**: Add light client mode validation (requires store implementation)

## 8. Example Implementation Snippet

```go
// Example of basic validation logic
func (v *IndependentValidator) ValidateLightClientFinalityUpdate(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
    // Decode message
    var update LightClientFinalityUpdate
    if err := v.decodeMessage(msg.Data, &update); err != nil {
        v.logger.WithError(err).Debug("Failed to decode light client finality update")
        return pubsub.ValidationReject
    }
    
    // Check timing constraint
    signatureSlot := update.SignatureSlot
    slotStart := v.genesisTime + (uint64(signatureSlot) * SECONDS_PER_SLOT)
    oneThirdSlot := slotStart + (SECONDS_PER_SLOT / 3)
    
    if time.Now().Unix() < int64(oneThirdSlot) {
        v.logger.Debug("Light client finality update received too early")
        return pubsub.ValidationIgnore
    }
    
    // Check slot progression
    v.highestFinalizedSlotLock.RLock()
    highestSlot := v.highestFinalizedSlot
    v.highestFinalizedSlotLock.RUnlock()
    
    finalizedSlot := update.FinalizedHeader.Beacon.Slot
    if finalizedSlot < highestSlot {
        return pubsub.ValidationIgnore
    }
    
    if finalizedSlot == highestSlot {
        // Check sync committee participation
        participation := countSyncCommitteeParticipation(update.SyncAggregate)
        if participation <= (2 * SYNC_COMMITTEE_SIZE / 3) {
            return pubsub.ValidationIgnore
        }
    }
    
    // Update tracking
    v.highestFinalizedSlotLock.Lock()
    v.highestFinalizedSlot = finalizedSlot
    v.highestFinalizedSlotLock.Unlock()
    
    return pubsub.ValidationAccept
}
```

This analysis provides a comprehensive overview of what needs to be implemented to support light client finality update validation in Hermes, covering both independent and delegated modes.