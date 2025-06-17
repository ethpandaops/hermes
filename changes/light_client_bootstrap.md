# Light Client Bootstrap Request/Response Validation Analysis for Hermes

## 1. Validation Spec Requirements

The `light_client_bootstrap` req/resp protocol validation requirements from `/validation-specs/reqresp/light_client_bootstrap.md`:

### Protocol Details
- **Protocol ID**: `/eth2/beacon_chain/req/light_client_bootstrap/1/`
- **Purpose**: Allows light clients to initialize their sync process from a trusted block root

### Request Validation (Server/Responder Side)
1. **Request Format**: 
   - MUST be encoded as an SSZ-field containing a single `Root` (the beacon block root)
   - MUST be properly SSZ-encoded
   - Length assertions MUST match the expected size for a `Root` type

2. **Bootstrap Creation**:
   - Requested block root MUST correspond to a post-Altair block (`compute_epoch_at_slot(state.slot) >= ALTAIR_FORK_EPOCH`)
   - Block and its post state MUST be known/available
   - Uses `create_light_client_bootstrap` function

3. **Error Response**:
   - When `LightClientBootstrap` cannot be produced, respond with error code `3: ResourceUnavailable`

4. **Fork Selection**:
   - Fork namespace selected based on `compute_fork_version(compute_epoch_at_slot(bootstrap.header.beacon.slot))`:
     - Altair-Bellatrix: `altair.LightClientBootstrap`
     - Capella: `capella.LightClientBootstrap`
     - Deneb: `deneb.LightClientBootstrap`
     - Electra+: `electra.LightClientBootstrap`

### Response Validation (Client/Requester Side)
1. **Response Format**: MUST contain a single `LightClientBootstrap` structure
2. **SSZ Encoding**: MUST be properly SSZ-encoded and Snappy compressed
3. **Length Validation**: Length-prefix MUST be within expected bounds
4. **Bootstrap Validation**:
   - `bootstrap.header` MUST be valid (`is_valid_light_client_header`)
   - Hash of `bootstrap.header.beacon` MUST equal the requested `trusted_block_root`
   - `current_sync_committee` MUST be correctly proven via Merkle branch

### General Rules
- Stream handling: Requester closes write side after request, responder after response
- Invalid responses cause stream reset
- Timeouts trigger stream reset

## 2. Current State in Hermes

After searching the Hermes codebase:

### Existing Infrastructure
1. **Req/Resp Framework**: Exists in `/eth/reqresp/` with:
   - `Manager` for protocol registration
   - `Handler` interface for protocol implementations
   - Support for delegated and upstream modes
   - Existing protocols: ping, goodbye, status, metadata, blocks_by_range, blocks_by_root, blob_sidecars_by_range, blob_sidecars_by_root

2. **No Light Client Implementation**: 
   - NO light client bootstrap protocol handler
   - NO light client types or structures
   - NO light client validation logic

3. **Protocol Registration Pattern** (from `/eth/reqresp/handler.go`):
   ```go
   protocols := map[string]ContextStreamHandler{
       buildProtocolID(forkDigest, ProtocolPing, 1): m.wrapHandler("ping", m.handler.Ping),
       // ... other protocols
   }
   ```

## 3. Required Changes

### 3.1 Add Protocol Constants

**File**: `/eth/reqresp/handler.go`
```go
const (
    // ... existing protocols ...
    ProtocolLightClientBootstrap = "light_client_bootstrap"
)
```

### 3.2 Update Handler Interface

**File**: `/eth/reqresp/types.go`
```go
type Handler interface {
    // ... existing methods ...
    
    // Light client protocols
    LightClientBootstrap(ctx context.Context, stream network.Stream) error
}
```

### 3.3 Register Protocol in Manager

**File**: `/eth/reqresp/handler.go` (in `RegisterHandlers` method)
```go
protocols := map[string]ContextStreamHandler{
    // ... existing protocols ...
    buildProtocolID(forkDigest, ProtocolLightClientBootstrap, 1): 
        m.wrapHandler("light_client_bootstrap", m.handler.LightClientBootstrap),
}
```

### 3.4 Implement Upstream Mode Handler

**New File**: `/eth/reqresp/upstream/light_client.go`
```go
package upstream

import (
    "context"
    "errors"
    "fmt"
    
    "github.com/libp2p/go-libp2p/core/network"
    ssz "github.com/ferranbt/fastssz"
    "github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
    
    "github.com/probe-lab/hermes/eth/reqresp"
)

// LightClientBootstrap handles light client bootstrap requests
func (h *UpstreamHandler) LightClientBootstrap(ctx context.Context, stream network.Stream) error {
    // 1. Read request
    var blockRoot primitives.Root
    if err := h.readRequest(stream, &blockRoot); err != nil {
        return h.writeErrorResponse(stream, reqresp.InvalidRequest, "failed to decode request")
    }
    
    // 2. Fetch bootstrap from beacon API
    bootstrap, err := h.beaconClient.GetLightClientBootstrap(ctx, blockRoot)
    if err != nil {
        if errors.Is(err, ErrNotFound) {
            return h.writeErrorResponse(stream, reqresp.ResourceUnavailable, "bootstrap not available")
        }
        return h.writeErrorResponse(stream, reqresp.ServerError, "internal error")
    }
    
    // 3. Write response
    return h.writeResponse(stream, bootstrap)
}
```

**Update File**: `/eth/reqresp/upstream/beacon_client.go`
```go
// Add to BeaconClient struct methods
func (c *BeaconClient) GetLightClientBootstrap(ctx context.Context, blockRoot primitives.Root) (ssz.Marshaler, error) {
    endpoint := fmt.Sprintf("/eth/v1/beacon/light_client/bootstrap/%#x", blockRoot)
    
    resp, err := c.get(ctx, endpoint)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode == 404 {
        return nil, ErrNotFound
    }
    
    // Parse response based on fork version
    // This requires determining the fork from the response headers
    var bootstrap ssz.Marshaler
    contentType := resp.Header.Get("Eth-Consensus-Version")
    
    switch contentType {
    case "altair", "bellatrix":
        bootstrap = &altair.LightClientBootstrap{}
    case "capella":
        bootstrap = &capella.LightClientBootstrap{}
    case "deneb":
        bootstrap = &deneb.LightClientBootstrap{}
    case "electra":
        bootstrap = &electra.LightClientBootstrap{}
    default:
        return nil, fmt.Errorf("unknown fork version: %s", contentType)
    }
    
    // Decode JSON response
    if err := json.NewDecoder(resp.Body).Decode(bootstrap); err != nil {
        return nil, fmt.Errorf("failed to decode bootstrap: %w", err)
    }
    
    return bootstrap, nil
}
```

### 3.5 Implement Delegated Mode Handler

**Update File**: `/eth/reqresp/delegated/handler.go`
```go
// LightClientBootstrap forwards light client bootstrap requests to the delegate peer
func (h *DelegatedHandler) LightClientBootstrap(ctx context.Context, stream network.Stream) error {
    protocolID := reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolLightClientBootstrap, 1)
    return h.forwardStream(ctx, stream, protocolID)
}
```

## 4. Implementation Details for Both Modes

### 4.1 Independent Mode (Future Implementation)

For a full independent validator implementation, Hermes would need:

1. **State Storage**:
   - Historical block storage with post-states
   - Ability to retrieve blocks by root
   - Access to sync committees from state

2. **Light Client Logic**:
   ```go
   func (v *IndependentValidator) LightClientBootstrap(ctx context.Context, stream network.Stream) error {
       // 1. Read block root request
       var blockRoot primitives.Root
       if err := v.readRequest(stream, &blockRoot); err != nil {
           return v.writeErrorResponse(stream, reqresp.InvalidRequest, "invalid request")
       }
       
       // 2. Retrieve block and state
       block, err := v.blockStore.GetBlockByRoot(ctx, blockRoot)
       if err != nil {
           return v.writeErrorResponse(stream, reqresp.ResourceUnavailable, "block not found")
       }
       
       // 3. Check if post-Altair
       slot := block.Block().Slot()
       epoch := primitives.Epoch(slot / SLOTS_PER_EPOCH)
       if epoch < v.altairForkEpoch {
           return v.writeErrorResponse(stream, reqresp.ResourceUnavailable, "pre-altair block")
       }
       
       // 4. Create bootstrap
       bootstrap, err := v.createLightClientBootstrap(ctx, block)
       if err != nil {
           return v.writeErrorResponse(stream, reqresp.ServerError, "failed to create bootstrap")
       }
       
       // 5. Write response
       return v.writeResponse(stream, bootstrap)
   }
   ```

3. **Bootstrap Creation Function**:
   ```go
   func (v *IndependentValidator) createLightClientBootstrap(ctx context.Context, block *ethpb.SignedBeaconBlock) (*LightClientBootstrap, error) {
       // 1. Get post-state
       state, err := v.stateStore.GetStateByRoot(ctx, block.Block().StateRoot())
       if err != nil {
           return nil, err
       }
       
       // 2. Create light client header
       header := &LightClientHeader{
           Beacon: block.Block(),
           // Add execution payload header if post-merge
       }
       
       // 3. Get current sync committee
       currentSyncCommittee := state.CurrentSyncCommittee()
       
       // 4. Create Merkle proof for sync committee
       proof, err := state.CurrentSyncCommitteeProof()
       if err != nil {
           return nil, err
       }
       
       // 5. Return bootstrap
       return &LightClientBootstrap{
           Header:                     header,
           CurrentSyncCommittee:       currentSyncCommittee,
           CurrentSyncCommitteeBranch: proof,
       }, nil
   }
   ```

### 4.2 Current Implementation Priority

Given the current Hermes architecture:

1. **Upstream Mode**: Already has beacon API access, easiest to implement
2. **Delegated Mode**: Simple forwarding, relies on delegate peer
3. **Independent Mode**: Requires significant infrastructure (block/state storage)

## 5. Dependencies and Missing Components

### 5.1 Required Types

Need to import or define:
```go
// Light client types for each fork
type LightClientBootstrap struct {
    Header                     *LightClientHeader
    CurrentSyncCommittee       *SyncCommittee
    CurrentSyncCommitteeBranch [][]byte
}

type LightClientHeader struct {
    Beacon          *BeaconBlockHeader
    Execution       *ExecutionPayloadHeader // Post-merge only
    ExecutionBranch [][]byte               // Post-merge only
}
```

### 5.2 Missing Infrastructure for Independent Mode

1. **Block/State Storage**:
   - Need persistent storage for historical blocks
   - Need state storage or ability to reconstruct states
   - Need indexing by block root

2. **Merkle Proof Generation**:
   - Need ability to generate proofs for sync committee
   - Need generalized index calculations

3. **Fork Awareness**:
   - Need to track fork epochs (Altair, Bellatrix, Capella, etc.)
   - Need fork-specific type handling

### 5.3 Beacon API Extensions

For upstream mode, need beacon API client methods:
- `/eth/v1/beacon/light_client/bootstrap/{block_root}`
- Proper fork version handling from response headers

## 6. Testing Strategy

### 6.1 Unit Tests

```go
func TestLightClientBootstrapHandler(t *testing.T) {
    tests := []struct {
        name      string
        blockRoot []byte
        wantErr   bool
        errCode   uint64
    }{
        {
            name:      "valid post-altair block",
            blockRoot: validBlockRoot,
            wantErr:   false,
        },
        {
            name:      "pre-altair block",
            blockRoot: preAltairBlockRoot,
            wantErr:   true,
            errCode:   3, // ResourceUnavailable
        },
        {
            name:      "unknown block",
            blockRoot: unknownBlockRoot,
            wantErr:   true,
            errCode:   3, // ResourceUnavailable
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

### 6.2 Integration Tests

1. Test with real beacon node API
2. Test fork transitions
3. Test error scenarios
4. Test timeout handling

## 7. Implementation Roadmap

### Phase 1: Basic Protocol Support (Upstream Mode)
1. Add protocol constants and handler interface
2. Implement upstream handler with beacon API
3. Add basic unit tests

### Phase 2: Delegated Mode
1. Implement stream forwarding for delegated mode
2. Add integration tests with mock delegate

### Phase 3: Type Definitions
1. Import or define light client types for all forks
2. Add SSZ encoding/decoding support
3. Add fork-aware type handling

### Phase 4: Independent Mode (Future)
1. Implement block/state storage interface
2. Add bootstrap creation logic
3. Implement Merkle proof generation
4. Add comprehensive validation

## 8. Example Implementation Snippets

### Request Reading Helper
```go
func readLightClientBootstrapRequest(stream network.Stream, encoder encoder.NetworkEncoding) (primitives.Root, error) {
    var blockRoot primitives.Root
    
    // Set read deadline
    stream.SetReadDeadline(time.Now().Add(reqresp.ReadTimeout))
    
    // Read SSZ-encoded root
    if err := encoder.DecodeWithMaxLength(stream, &blockRoot); err != nil {
        return blockRoot, fmt.Errorf("failed to decode block root: %w", err)
    }
    
    return blockRoot, nil
}
```

### Response Writing Helper
```go
func writeLightClientBootstrapResponse(stream network.Stream, encoder encoder.NetworkEncoding, bootstrap ssz.Marshaler) error {
    // Set write deadline
    stream.SetWriteDeadline(time.Now().Add(reqresp.WriteTimeout))
    
    // Write response code (success = 0)
    if _, err := stream.Write([]byte{0}); err != nil {
        return err
    }
    
    // Encode and write bootstrap
    if _, err := encoder.EncodeWithMaxLength(stream, bootstrap); err != nil {
        return fmt.Errorf("failed to encode bootstrap: %w", err)
    }
    
    return nil
}
```

This implementation would bring Hermes into compliance with the light client bootstrap validation spec, supporting both upstream and delegated modes initially, with a clear path for future independent mode implementation.