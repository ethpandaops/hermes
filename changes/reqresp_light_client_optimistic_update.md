# Light Client Optimistic Update Req/Resp - Hermes Compliance Analysis

## 1. What the Validation Spec Requires

The `/eth2/beacon_chain/req/light_client_optimistic_update/1/` protocol allows light clients to get the latest optimistic header update.

### Request Validation
- **No Request Content** - The request has no parameters
- The request MUST be encoded according to the encoding strategy (SSZ-snappy)

### Response Validation

#### For the Responding Peer (Server)
1. **SHOULD** provide results as defined in `create_light_client_optimistic_update`
2. **MUST** respond with error code `3: ResourceUnavailable` when no `LightClientOptimisticUpdate` is available
3. **MUST** use the correct fork digest context based on `compute_fork_version(compute_epoch_at_slot(optimistic_update.attested_header.beacon.slot))` to select the fork namespace:
   - `ALTAIR_FORK_VERSION` and later: `altair.LightClientOptimisticUpdate`
   - `CAPELLA_FORK_VERSION` and later: `capella.LightClientOptimisticUpdate`
   - `DENEB_FORK_VERSION` and later: `deneb.LightClientOptimisticUpdate`
   - `ELECTRA_FORK_VERSION` and later: `electra.LightClientOptimisticUpdate`
4. **MUST** follow general req/resp rules:
   - Validate the incoming request before processing
   - Write the response chunk with appropriate response code
   - Close the write side of the stream after sending response

#### For the Requesting Peer (Client)
1. **MUST** encode the request according to the encoding strategy
2. **MUST** close the write side of the stream after sending request
3. **SHOULD** read from the stream until either:
   - An error result is received
   - The responder closes the stream
   - The response chunk fails validation
4. **MUST** validate the response according to the expected schema

### Response Codes
- `0`: Success - normal response with `LightClientOptimisticUpdate`
- `1`: InvalidRequest - malformed or invalid request
- `2`: ServerError - error during processing
- `3`: ResourceUnavailable - no optimistic update available

## 2. What Currently Exists in Hermes

After analyzing the codebase:

### Existing Req/Resp Infrastructure
- **Manager and Handler Pattern**: `/eth/reqresp/handler.go` defines a `Manager` that registers protocol handlers
- **Two Implementation Modes**:
  - **Delegated**: Forwards requests to another libp2p peer (typically Prysm)
  - **Upstream**: Proxies requests through beacon API endpoints
- **Registered Protocols** (in `RegisterHandlers()`):
  - `/eth2/beacon_chain/req/ping/1/ssz_snappy`
  - `/eth2/beacon_chain/req/goodbye/1/ssz_snappy`
  - `/eth2/beacon_chain/req/status/1/ssz_snappy`
  - `/eth2/beacon_chain/req/metadata/1/ssz_snappy` and `/2/ssz_snappy`
  - `/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy`
  - `/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy`
  - `/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy`
  - `/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy`

### Missing Components
- **No Light Client Req/Resp Protocols**: The handler interface and manager do not include any light client protocols
- **No Light Client Message Types**: No SSZ types defined for light client updates
- **No Light Client State**: No storage or computation for light client updates
- **No Beacon API Light Client Endpoints**: The upstream handler doesn't implement light client endpoints

### Mode Selection Logic
From `/eth/node.go` lines 220-251:
- If `ValidationMode == "independent"`, req/resp automatically uses `upstream` mode
- Otherwise, defaults to `delegated` mode
- Upstream mode requires a beacon URL (either configured or derived from PrysmHost)

## 3. What Needs to Change for Both Independent and Delegated Modes

### 3.1. Add Light Client Protocol Constants

In `/eth/reqresp/handler.go`, add after line 31:
```go
// Light client protocols
ProtocolLightClientBootstrap       = "light_client_bootstrap"
ProtocolLightClientUpdates         = "light_client_updates_by_range"
ProtocolLightClientFinalityUpdate  = "light_client_finality_update"
ProtocolLightClientOptimisticUpdate = "light_client_optimistic_update"
```

### 3.2. Update Handler Interface

In `/eth/reqresp/types.go`, add to the `Handler` interface after line 67:
```go
// Light client handlers
LightClientBootstrap(ctx context.Context, stream network.Stream) error
LightClientUpdatesByRange(ctx context.Context, stream network.Stream) error
LightClientFinalityUpdate(ctx context.Context, stream network.Stream) error
LightClientOptimisticUpdate(ctx context.Context, stream network.Stream) error
```

### 3.3. Register Light Client Protocols

In `/eth/reqresp/handler.go`, update `RegisterHandlers()` to add after line 118:
```go
// Light client protocols
buildProtocolID(forkDigest, ProtocolLightClientBootstrap, 1):       m.wrapHandler("light_client_bootstrap", m.handler.LightClientBootstrap),
buildProtocolID(forkDigest, ProtocolLightClientUpdates, 1):         m.wrapHandler("light_client_updates", m.handler.LightClientUpdatesByRange),
buildProtocolID(forkDigest, ProtocolLightClientFinalityUpdate, 1):  m.wrapHandler("light_client_finality_update", m.handler.LightClientFinalityUpdate),
buildProtocolID(forkDigest, ProtocolLightClientOptimisticUpdate, 1): m.wrapHandler("light_client_optimistic_update", m.handler.LightClientOptimisticUpdate),
```

### 3.4. Define Light Client Types

Create `/eth/reqresp/light_client_types.go`:
```go
package reqresp

import (
    "github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
)

// LightClientHeader represents a light client header
type LightClientHeader struct {
    Beacon          *BeaconBlockHeader
    ExecutionBranch [][]byte // Merkle branch for execution payload
    Execution       *ExecutionPayloadHeader // Optional, added in Capella
}

// LightClientOptimisticUpdate represents the optimistic update
type LightClientOptimisticUpdate struct {
    AttestedHeader *LightClientHeader
    SyncAggregate  *SyncAggregate
    SignatureSlot  primitives.Slot
}

// Fork-specific variants
type AltairLightClientOptimisticUpdate struct {
    AttestedHeader *LightClientHeader
    SyncAggregate  *SyncAggregate
    SignatureSlot  primitives.Slot
}

type CapellaLightClientOptimisticUpdate struct {
    AttestedHeader *LightClientHeader // With execution payload
    SyncAggregate  *SyncAggregate
    SignatureSlot  primitives.Slot
}

// Add Deneb and Electra variants...
```

## 4. Specific Changes for Delegated Mode

### 4.1. Implement Light Client Handlers in Delegated Handler

In `/eth/reqresp/delegated/handler.go`, add methods:
```go
// LightClientOptimisticUpdate handles light client optimistic update requests
func (h *DelegatedHandler) LightClientOptimisticUpdate(ctx context.Context, stream network.Stream) error {
    defer stream.Close()
    
    // Log the request
    h.logger.Debug("Handling light client optimistic update request",
        "peer", stream.Conn().RemotePeer(),
        "protocol", stream.Protocol())
    
    // Check if we have a delegate peer
    if h.delegatePeer == (peer.ID{}) {
        return h.writeErrorResponse(stream, ResponseCodeResourceUnavailable, "no delegate peer configured")
    }
    
    // Forward to delegate peer
    delegateStream, err := h.host.NewStream(ctx, h.delegatePeer, stream.Protocol())
    if err != nil {
        return h.writeErrorResponse(stream, ResponseCodeServerError, "failed to connect to delegate")
    }
    defer delegateStream.Close()
    
    // Since this is a no-parameter request, just close the write side
    if err := delegateStream.CloseWrite(); err != nil {
        return h.writeErrorResponse(stream, ResponseCodeServerError, "failed to forward request")
    }
    
    // Copy response from delegate to original requester
    if err := h.copyResponse(delegateStream, stream); err != nil {
        return err
    }
    
    return nil
}
```

## 5. Specific Changes for Independent/Upstream Mode

### 5.1. Add Light Client Store

Create `/eth/reqresp/upstream/light_client_store.go`:
```go
package upstream

import (
    "sync"
    "github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
)

// LightClientStore maintains the latest light client update
type LightClientStore struct {
    mu                    sync.RWMutex
    latestOptimisticUpdate *LightClientOptimisticUpdate
    updateSlot            primitives.Slot
}

func NewLightClientStore() *LightClientStore {
    return &LightClientStore{}
}

func (s *LightClientStore) SetOptimisticUpdate(update *LightClientOptimisticUpdate, slot primitives.Slot) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.latestOptimisticUpdate = update
    s.updateSlot = slot
}

func (s *LightClientStore) GetOptimisticUpdate() (*LightClientOptimisticUpdate, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    if s.latestOptimisticUpdate == nil {
        return nil, false
    }
    return s.latestOptimisticUpdate, true
}
```

### 5.2. Implement Light Client Handler in Upstream Handler

In `/eth/reqresp/upstream/handler.go`, add:
```go
// Add to UpstreamHandler struct
lightClientStore *LightClientStore

// In NewUpstreamHandler, initialize:
lightClientStore: NewLightClientStore(),

// Add method
func (h *UpstreamHandler) LightClientOptimisticUpdate(ctx context.Context, stream network.Stream) error {
    defer stream.Close()
    
    h.logger.Debug("Handling light client optimistic update request",
        "peer", stream.Conn().RemotePeer())
    
    // No request parameters to read for this protocol
    
    // Try to get from store first
    if update, ok := h.lightClientStore.GetOptimisticUpdate(); ok {
        return h.writeLightClientOptimisticUpdate(stream, update)
    }
    
    // Otherwise, fetch from beacon API
    endpoint := "/eth/v1/beacon/light_client/optimistic_update"
    
    var response struct {
        Data *BeaconAPILightClientOptimisticUpdate `json:"data"`
    }
    
    if err := h.beaconClient.Get(ctx, endpoint, &response); err != nil {
        if isNotFoundError(err) {
            return h.writeErrorResponse(stream, ResponseCodeResourceUnavailable, "no optimistic update available")
        }
        return h.writeErrorResponse(stream, ResponseCodeServerError, err.Error())
    }
    
    // Convert from beacon API format to SSZ format
    update := convertToSSZFormat(response.Data)
    
    // Cache for future requests
    h.lightClientStore.SetOptimisticUpdate(update, update.AttestedHeader.Beacon.Slot)
    
    // Write response
    return h.writeLightClientOptimisticUpdate(stream, update)
}

func (h *UpstreamHandler) writeLightClientOptimisticUpdate(stream network.Stream, update *LightClientOptimisticUpdate) error {
    // Determine fork version based on slot
    forkVersion := h.getForkVersionForSlot(update.AttestedHeader.Beacon.Slot)
    
    // Encode based on fork version
    var encoded []byte
    var err error
    
    switch forkVersion {
    case AltairForkVersion:
        encoded, err = ssz.MarshalSSZ(update.ToAltair())
    case CapellaForkVersion:
        encoded, err = ssz.MarshalSSZ(update.ToCapella())
    case DenebForkVersion:
        encoded, err = ssz.MarshalSSZ(update.ToDeneb())
    case ElectraForkVersion:
        encoded, err = ssz.MarshalSSZ(update.ToElectra())
    default:
        return h.writeErrorResponse(stream, ResponseCodeServerError, "unknown fork version")
    }
    
    if err != nil {
        return h.writeErrorResponse(stream, ResponseCodeServerError, err.Error())
    }
    
    // Write success response with encoded data
    return h.writeResponse(stream, ResponseCodeSuccess, encoded)
}
```

### 5.3. Add Beacon API Types

Create `/eth/reqresp/upstream/beacon_api_light_client_types.go`:
```go
package upstream

// BeaconAPILightClientOptimisticUpdate represents the JSON format from beacon API
type BeaconAPILightClientOptimisticUpdate struct {
    AttestedHeader struct {
        Beacon struct {
            Slot          string `json:"slot"`
            ProposerIndex string `json:"proposer_index"`
            ParentRoot    string `json:"parent_root"`
            StateRoot     string `json:"state_root"`
            BodyRoot      string `json:"body_root"`
        } `json:"beacon"`
        Execution *struct {
            // Execution payload fields...
        } `json:"execution,omitempty"`
        ExecutionBranch []string `json:"execution_branch,omitempty"`
    } `json:"attested_header"`
    SyncAggregate struct {
        SyncCommitteeBits      string `json:"sync_committee_bits"`
        SyncCommitteeSignature string `json:"sync_committee_signature"`
    } `json:"sync_aggregate"`
    SignatureSlot string `json:"signature_slot"`
}
```

## 6. Dependencies on Missing Components

### 6.1. SSZ Encoding/Decoding
- Need to import or implement SSZ marshaling for light client types
- Fork-specific encoding based on slot

### 6.2. Fork Schedule Integration
- Need access to fork schedule to determine correct message format
- Already exists in Hermes via `fork_version.go`

### 6.3. Beacon API Client Enhancement
- The existing beacon client in `/eth/reqresp/upstream/beacon_client.go` needs methods for light client endpoints
- Standard beacon API endpoints: `/eth/v1/beacon/light_client/optimistic_update`

### 6.4. Error Handling
- Need to handle 404 responses as `ResourceUnavailable`
- Server errors should map to `ServerError` response code

## 7. Implementation Steps

### Phase 1: Basic Protocol Support
1. Add protocol constants and handler interface methods
2. Implement stub handlers that return `ResourceUnavailable`
3. Update manager to register new protocols

### Phase 2: Delegated Mode
1. Implement request forwarding in delegated handler
2. Test with Prysm or other beacon nodes that support light client protocols

### Phase 3: Upstream Mode with Beacon API
1. Add beacon API client methods for light client endpoints
2. Implement JSON to SSZ conversion
3. Add basic caching for performance

### Phase 4: Full Independent Mode (Future)
1. Implement `create_light_client_optimistic_update` computation
2. Add state access for generating updates
3. Integrate with validator infrastructure

## 8. Testing Considerations

### Unit Tests
- Mock beacon API responses for upstream mode
- Test fork version selection logic
- Verify SSZ encoding/decoding

### Integration Tests
- Test against real beacon nodes
- Verify protocol compatibility
- Test error scenarios (no update available, etc.)

### Performance Tests
- Measure latency of API calls vs cached responses
- Load test with multiple concurrent requests

## 9. Example File Locations Summary

- `/eth/reqresp/handler.go` - Add protocol constants and registration
- `/eth/reqresp/types.go` - Add handler interface methods
- `/eth/reqresp/light_client_types.go` - New file for SSZ types
- `/eth/reqresp/delegated/handler.go` - Add delegated implementation
- `/eth/reqresp/upstream/handler.go` - Add upstream implementation
- `/eth/reqresp/upstream/light_client_store.go` - New file for caching
- `/eth/reqresp/upstream/beacon_api_light_client_types.go` - New file for API types