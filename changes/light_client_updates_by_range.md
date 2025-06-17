# Light Client Updates by Range Req/Resp Analysis for Hermes

## 1. Validation Spec Requirements

The `light_client_updates_by_range` protocol validation requirements from `/validation-specs/reqresp/light_client_updates_by_range.md`:

### Protocol Details
- **Protocol ID**: `/eth2/beacon_chain/req/light_client_updates_by_range/1/`
- **Encoding**: `ssz_snappy`
- **Request/Response model**: Single request, streaming response

### Request Structure
```go
type LightClientUpdatesByRangeRequest struct {
    StartPeriod uint64 `ssz-size:"8"`
    Count       uint64 `ssz-size:"8"`
}
```

### Request Validation Rules
1. Request MUST be encoded as SSZ container with `start_period` and `count` fields
2. Maximum concurrent requests: 2 (`MAX_CONCURRENT_REQUESTS`)
3. Request MUST include encoding-dependent header (length as protobuf varint)
4. Requester MUST close write side after sending request

### Response Validation Rules
1. Response consists of zero or more `response_chunk`s
2. Each chunk contains a single `LightClientUpdate`
3. Maximum results: `min(MAX_REQUEST_LIGHT_CLIENT_UPDATES, count)` where `MAX_REQUEST_LIGHT_CLIENT_UPDATES = 128`
4. Results MUST be in consecutive order by period
5. Results from range `[start_period, start_period + count)`
6. Fork digest context based on `compute_fork_version(compute_epoch_at_slot(update.attested_header.beacon.slot))`

### Response Codes
- `0`: Success
- `1`: Invalid request
- `2`: Server error  
- `3`: Resource unavailable
- `128-255`: Reserved

### Fork-Specific Types
- **Altair-Bellatrix**: `altair.LightClientUpdate`
- **Capella**: `capella.LightClientUpdate`
- **Deneb**: `deneb.LightClientUpdate`
- **Electra+**: `electra.LightClientUpdate`

## 2. Current State in Hermes

After searching the codebase:

### What Exists
1. **Req/Resp Framework**: 
   - Handler interface in `/eth/reqresp/types.go`
   - Manager in `/eth/reqresp/handler.go`
   - Upstream mode in `/eth/reqresp/upstream/`
   - Delegated mode in `/eth/reqresp/delegated/`

2. **Existing Protocols**:
   ```go
   // From /eth/reqresp/handler.go
   ProtocolPing          = "ping"
   ProtocolGoodbye       = "goodbye"
   ProtocolStatus        = "status"
   ProtocolMetadata      = "metadata"
   ProtocolBeaconBlocks  = "beacon_blocks_by_range"
   ProtocolBlocksByRoot  = "beacon_blocks_by_root"
   ProtocolBlobSidecars  = "blob_sidecars_by_range"
   ProtocolBlobsByRoot   = "blob_sidecars_by_root"
   ```

3. **No Light Client Implementation**:
   - No light client protocols in handler definitions
   - No light client types imported
   - No light client storage or validation logic

## 3. Required Changes

### 3.1 Add Protocol Constants

**File**: `/eth/reqresp/handler.go`
```go
const (
    // ... existing protocols ...
    ProtocolLightClientBootstrap       = "light_client_bootstrap"
    ProtocolLightClientUpdatesByRange  = "light_client_updates_by_range"
    ProtocolLightClientFinalityUpdate  = "light_client_finality_update"
    ProtocolLightClientOptimisticUpdate = "light_client_optimistic_update"
)
```

### 3.2 Update Handler Interface

**File**: `/eth/reqresp/types.go`
```go
type Handler interface {
    // ... existing methods ...
    
    // Light client methods
    LightClientBootstrap(ctx context.Context, stream network.Stream) error
    LightClientUpdatesByRange(ctx context.Context, stream network.Stream) error
    LightClientFinalityUpdate(ctx context.Context, stream network.Stream) error
    LightClientOptimisticUpdate(ctx context.Context, stream network.Stream) error
}
```

### 3.3 Register Light Client Handlers

**File**: `/eth/reqresp/handler.go`
```go
func (m *Manager) RegisterHandlers() error {
    // ... existing code ...
    
    // Add to protocols map:
    buildProtocolID(forkDigest, ProtocolLightClientUpdatesByRange, 1): m.wrapHandler("light_client_updates_by_range", m.handler.LightClientUpdatesByRange),
    buildProtocolID(forkDigest, ProtocolLightClientBootstrap, 1):      m.wrapHandler("light_client_bootstrap", m.handler.LightClientBootstrap),
    // ... other light client protocols
}
```

### 3.4 Implement Request/Response Types

**New File**: `/eth/reqresp/types_light_client.go`
```go
package reqresp

import (
    "github.com/prysmaticlabs/go-bitfield"
    ssz "github.com/ferranbt/fastssz"
)

// LightClientUpdatesByRangeRequest represents a light client updates by range request
type LightClientUpdatesByRangeRequest struct {
    StartPeriod uint64 `ssz-size:"8"`
    Count       uint64 `ssz-size:"8"`
}

// MarshalSSZ implements ssz.Marshaler
func (r *LightClientUpdatesByRangeRequest) MarshalSSZ() ([]byte, error) {
    return ssz.MarshalSSZ(r)
}

// UnmarshalSSZ implements ssz.Unmarshaler
func (r *LightClientUpdatesByRangeRequest) UnmarshalSSZ(buf []byte) error {
    return ssz.UnmarshalSSZ(r, buf)
}

// SizeSSZ returns the size of the serialized object
func (r *LightClientUpdatesByRangeRequest) SizeSSZ() int {
    return 16 // 8 bytes for each uint64
}

// Constants for light client protocols
const (
    MAX_REQUEST_LIGHT_CLIENT_UPDATES = 128
    EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256
)
```

### 3.5 Upstream Mode Implementation

**New File**: `/eth/reqresp/upstream/light_client.go`
```go
package upstream

import (
    "context"
    "errors"
    "fmt"
    "net/http"
    
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/probe-lab/hermes/eth/reqresp"
)

// LightClientUpdatesByRange handles light client updates by range requests
func (h *UpstreamHandler) LightClientUpdatesByRange(ctx context.Context, stream network.Stream) error {
    defer stream.Close()
    
    // Read request
    var req reqresp.LightClientUpdatesByRangeRequest
    if err := h.readRequest(ctx, stream, &req); err != nil {
        // Write error response
        h.writeErrorResponse(ctx, stream, reqresp.InvalidRequestCode)
        return fmt.Errorf("read request: %w", err)
    }
    
    // Validate request
    if req.Count == 0 || req.Count > reqresp.MAX_REQUEST_LIGHT_CLIENT_UPDATES {
        h.writeErrorResponse(ctx, stream, reqresp.InvalidRequestCode)
        return errors.New("invalid count parameter")
    }
    
    // Fetch from beacon API
    updates, err := h.beaconClient.GetLightClientUpdatesByRange(ctx, req.StartPeriod, req.Count)
    if err != nil {
        if errors.Is(err, ErrResourceNotFound) {
            h.writeErrorResponse(ctx, stream, reqresp.ResourceUnavailableCode)
        } else {
            h.writeErrorResponse(ctx, stream, reqresp.ServerErrorCode)
        }
        return fmt.Errorf("fetch updates: %w", err)
    }
    
    // Stream responses
    for _, update := range updates {
        if err := h.writeResponse(ctx, stream, update); err != nil {
            return fmt.Errorf("write response: %w", err)
        }
    }
    
    return nil
}

// Add to BeaconClient
func (c *BeaconClient) GetLightClientUpdatesByRange(ctx context.Context, startPeriod, count uint64) ([]*LightClientUpdate, error) {
    // Call beacon API endpoint
    // GET /eth/v1/beacon/light_client/updates?start_period={start_period}&count={count}
    endpoint := fmt.Sprintf("/eth/v1/beacon/light_client/updates?start_period=%d&count=%d", startPeriod, count)
    
    var response struct {
        Data []*LightClientUpdate `json:"data"`
    }
    
    if err := c.get(ctx, endpoint, &response); err != nil {
        return nil, err
    }
    
    return response.Data, nil
}
```

### 3.6 Delegated Mode Implementation

**Update File**: `/eth/reqresp/delegated/handler.go`
```go
// Add to methods
func (h *DelegatedHandler) LightClientUpdatesByRange(ctx context.Context, stream network.Stream) error {
    return h.forwardStream(ctx, stream, reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolLightClientUpdatesByRange, 1))
}

func (h *DelegatedHandler) LightClientBootstrap(ctx context.Context, stream network.Stream) error {
    return h.forwardStream(ctx, stream, reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolLightClientBootstrap, 1))
}

func (h *DelegatedHandler) LightClientFinalityUpdate(ctx context.Context, stream network.Stream) error {
    return h.forwardStream(ctx, stream, reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolLightClientFinalityUpdate, 1))
}

func (h *DelegatedHandler) LightClientOptimisticUpdate(ctx context.Context, stream network.Stream) error {
    return h.forwardStream(ctx, stream, reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolLightClientOptimisticUpdate, 1))
}
```

### 3.7 Independent Mode Implementation

**New File**: `/eth/reqresp/independent/light_client.go`
```go
package independent

import (
    "context"
    "errors"
    "fmt"
    "sync"
    
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/probe-lab/hermes/eth/reqresp"
)

// LightClientStore manages light client updates
type LightClientStore struct {
    mu      sync.RWMutex
    updates map[uint64]*LightClientUpdate // period -> update
}

// IndependentHandler extends base handler with light client support
type IndependentHandler struct {
    *reqresp.BaseHandler
    lightClientStore *LightClientStore
}

// LightClientUpdatesByRange handles light client updates by range requests
func (h *IndependentHandler) LightClientUpdatesByRange(ctx context.Context, stream network.Stream) error {
    defer stream.Close()
    
    // Read request
    var req reqresp.LightClientUpdatesByRangeRequest
    if err := h.readRequest(ctx, stream, &req); err != nil {
        h.writeErrorResponse(ctx, stream, reqresp.InvalidRequestCode)
        return fmt.Errorf("read request: %w", err)
    }
    
    // Validate request
    if req.Count == 0 || req.Count > reqresp.MAX_REQUEST_LIGHT_CLIENT_UPDATES {
        h.writeErrorResponse(ctx, stream, reqresp.InvalidRequestCode)
        return errors.New("invalid count parameter")
    }
    
    // Get updates from store
    h.lightClientStore.mu.RLock()
    defer h.lightClientStore.mu.RUnlock()
    
    sent := uint64(0)
    for period := req.StartPeriod; period < req.StartPeriod+req.Count && sent < req.Count; period++ {
        update, exists := h.lightClientStore.updates[period]
        if !exists {
            // Skip missing periods but continue
            continue
        }
        
        // Write response chunk
        if err := h.writeResponse(ctx, stream, update); err != nil {
            return fmt.Errorf("write response: %w", err)
        }
        sent++
    }
    
    // If no updates found, return resource unavailable
    if sent == 0 {
        h.writeErrorResponse(ctx, stream, reqresp.ResourceUnavailableCode)
        return errors.New("no updates available in requested range")
    }
    
    return nil
}

// AddLightClientUpdate adds an update to the store
func (h *IndependentHandler) AddLightClientUpdate(period uint64, update *LightClientUpdate) {
    h.lightClientStore.mu.Lock()
    defer h.lightClientStore.mu.Unlock()
    h.lightClientStore.updates[period] = update
}
```

## 4. Dependencies and Missing Components

### 4.1 Light Client Types

Need to import or define:
```go
// Light client update structures for each fork
type LightClientUpdate struct {
    AttestedHeader          *BeaconBlockHeader
    NextSyncCommittee       *SyncCommittee
    NextSyncCommitteeBranch [][]byte
    FinalizedHeader         *BeaconBlockHeader
    FinalityBranch          [][]byte
    SyncAggregate           *SyncAggregate
    SignatureSlot           uint64
}

type SyncCommittee struct {
    Pubkeys         [][]byte
    AggregatePubkey []byte
}

type SyncAggregate struct {
    SyncCommitteeBits      bitfield.Bitvector512
    SyncCommitteeSignature []byte
}
```

### 4.2 Historical Storage Requirements

For independent mode to serve light client updates:

1. **Period Calculation**:
   ```go
   func ComputeSyncCommitteePeriod(epoch uint64) uint64 {
       return epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD
   }
   
   func ComputeSyncCommitteePeriodAtSlot(slot uint64) uint64 {
       return ComputeSyncCommitteePeriod(ComputeEpochAtSlot(slot))
   }
   ```

2. **Update Generation**:
   - Need access to beacon blocks and states
   - Must compute sync committee proofs
   - Requires finality proofs from state

3. **Storage Interface**:
   ```go
   type LightClientUpdateProvider interface {
       // Get update for a specific period
       GetLightClientUpdate(ctx context.Context, period uint64) (*LightClientUpdate, error)
       
       // Get range of updates
       GetLightClientUpdateRange(ctx context.Context, startPeriod, count uint64) ([]*LightClientUpdate, error)
       
       // Store new update
       StoreLightClientUpdate(ctx context.Context, period uint64, update *LightClientUpdate) error
   }
   ```

### 4.3 Beacon API Extensions

For upstream mode, need beacon API client methods:
```go
// Beacon API endpoints needed
GET /eth/v1/beacon/light_client/updates?start_period={period}&count={count}
GET /eth/v1/beacon/light_client/bootstrap/{block_root}
GET /eth/v1/beacon/light_client/finality_update
GET /eth/v1/beacon/light_client/optimistic_update
```

## 5. Implementation Priority

1. **Phase 1**: Add protocol constants and handler interface methods
2. **Phase 2**: Implement delegated mode (simplest - just forwards)
3. **Phase 3**: Implement upstream mode with beacon API integration
4. **Phase 4**: Add light client types and SSZ encoding
5. **Phase 5**: Implement independent mode with storage

## 6. Testing Considerations

### Unit Tests
```go
func TestLightClientUpdatesByRange(t *testing.T) {
    // Test request validation
    // - Count = 0 (invalid)
    // - Count > MAX_REQUEST_LIGHT_CLIENT_UPDATES (invalid)
    // - Valid ranges
    
    // Test response ordering
    // - Updates must be consecutive by period
    // - Missing periods should be skipped
    
    // Test fork version handling
    // - Different update types per fork
}
```

### Integration Tests
1. Test with real beacon node responses
2. Test streaming multiple updates
3. Test error conditions (resource unavailable)
4. Test timeout handling

## 7. Example Usage

```go
// Client making a request
func requestLightClientUpdates(h host.Host, peer peer.ID, startPeriod, count uint64) ([]*LightClientUpdate, error) {
    ctx := context.Background()
    
    // Open stream
    stream, err := h.NewStream(ctx, peer, reqresp.GetProtocolID(forkDigest, reqresp.ProtocolLightClientUpdatesByRange, 1))
    if err != nil {
        return nil, err
    }
    defer stream.Close()
    
    // Send request
    req := &reqresp.LightClientUpdatesByRangeRequest{
        StartPeriod: startPeriod,
        Count:       count,
    }
    if err := reqresp.WriteRequest(ctx, stream, encoder, req, timeout); err != nil {
        return nil, err
    }
    
    // Read responses
    var updates []*LightClientUpdate
    for {
        var update LightClientUpdate
        responseCode, err := reqresp.ReadResponseChunk(ctx, stream, encoder, &update, timeout)
        if err == io.EOF {
            break
        }
        if err != nil {
            return nil, err
        }
        if responseCode != 0 {
            return nil, fmt.Errorf("error response: %d", responseCode)
        }
        updates = append(updates, &update)
    }
    
    return updates, nil
}
```

## 8. Conclusion

Implementing light client updates by range in Hermes requires:

1. **Protocol Registration**: Add new protocol IDs and handler methods
2. **Type Definitions**: Import/define light client structures with SSZ support
3. **Mode Implementation**:
   - **Delegated**: Simple forwarding (easiest)
   - **Upstream**: Beacon API proxy (moderate)
   - **Independent**: Full validation with storage (complex)
4. **Storage Backend**: For independent mode to store/retrieve historical updates
5. **Testing**: Comprehensive tests for all modes and edge cases

The implementation should follow the existing pattern in Hermes where delegated mode is simplest, upstream mode proxies through beacon API, and independent mode requires full protocol implementation.