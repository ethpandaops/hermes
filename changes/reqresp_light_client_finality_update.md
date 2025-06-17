# ReqResp Light Client Finality Update Implementation Analysis for Hermes

## 1. What the Validation Spec Requires

Based on `/validation-specs/reqresp/light_client_finality_update.md`, the protocol `/eth2/beacon_chain/req/light_client_finality_update/1/` requires:

### Request/Response Structure
- **Request**: Empty (no content)
- **Response**: `LightClientFinalityUpdate` structure
- **Encoding**: SSZ-Snappy with proper length prefixing

### Server (Response Provider) Requirements
1. **Provide Latest Update**: Return the `LightClientFinalityUpdate` with the highest `attested_header.beacon.slot` (if multiple, highest `signature_slot`) as selected by fork choice
2. **Error Handling**: Respond with error code `3: ResourceUnavailable` when no update is available
3. **Fork Version Context**: Use `ForkDigest` based on `compute_fork_version(compute_epoch_at_slot(finality_update.attested_header.beacon.slot))`
4. **Push Mechanism**: Support push delivery when `finalized_header` changes
5. **Supermajority**: Deliver second update if first lacks > 2/3 sync committee participation

### Client (Request Handler) Validation
Must validate through `process_light_client_finality_update`:
1. **Sync Committee Participation**: Verify `sum(sync_aggregate.sync_committee_bits) >= MIN_SYNC_COMMITTEE_PARTICIPANTS`
2. **Slot Ordering**: Verify `current_slot >= update.signature_slot > update.attested_header.beacon.slot >= update.finalized_header.beacon.slot`
3. **Sync Committee Period**: Must not skip periods
4. **Update Relevance**: Must advance finalized header or provide next sync committee
5. **Finality Branch**: Validate merkle proof for finality branch
6. **Signature**: Verify BLS aggregate signature

### Fork Version Mapping
- Altair-Bellatrix: `altair.LightClientFinalityUpdate`
- Capella: `capella.LightClientFinalityUpdate`
- Deneb: `deneb.LightClientFinalityUpdate`
- Electra+: `electra.LightClientFinalityUpdate`

## 2. What Currently Exists in Hermes

After searching the codebase:

### ReqResp Infrastructure (EXISTS)
- **Manager**: `/eth/reqresp/handler.go` - Manages protocol registration
- **Handler Interface**: `/eth/reqresp/types.go` - Defines handler methods
- **Delegated Mode**: `/eth/reqresp/delegated/handler.go` - Forwards to another peer
- **Upstream Mode**: `/eth/reqresp/upstream/handler.go` - Proxies through beacon API

### Current Protocol Support
```go
// In /eth/reqresp/handler.go
const (
    ProtocolPing          = "ping"
    ProtocolGoodbye       = "goodbye"
    ProtocolStatus        = "status"
    ProtocolMetadata      = "metadata"
    ProtocolBeaconBlocks  = "beacon_blocks_by_range"
    ProtocolBlocksByRoot  = "beacon_blocks_by_root"
    ProtocolBlobSidecars  = "blob_sidecars_by_range"
    ProtocolBlobsByRoot   = "blob_sidecars_by_root"
)
```

### Missing Components
- **NO** light client protocol constants defined
- **NO** light client handler methods in the Handler interface
- **NO** light client finality update types imported
- **NO** light client store implementation
- **NO** sync committee tracking

## 3. What Needs to Change

### 3.1 Add Protocol Constants

**File**: `/eth/reqresp/handler.go`
```go
const (
    // ... existing protocols ...
    
    // Light client protocols
    ProtocolLightClientBootstrap      = "light_client_bootstrap"
    ProtocolLightClientUpdatesByRange = "light_client_updates_by_range"
    ProtocolLightClientFinalityUpdate = "light_client_finality_update"
    ProtocolLightClientOptimisticUpdate = "light_client_optimistic_update"
)
```

### 3.2 Update Handler Interface

**File**: `/eth/reqresp/types.go`
```go
type Handler interface {
    // ... existing methods ...
    
    // Light client handlers
    LightClientBootstrap(ctx context.Context, stream network.Stream) error
    LightClientUpdatesByRange(ctx context.Context, stream network.Stream) error
    LightClientFinalityUpdate(ctx context.Context, stream network.Stream) error
    LightClientOptimisticUpdate(ctx context.Context, stream network.Stream) error
}
```

### 3.3 Register Light Client Protocols

**File**: `/eth/reqresp/handler.go`
```go
func (m *Manager) RegisterHandlers() error {
    // ... existing code ...
    
    protocols := map[string]ContextStreamHandler{
        // ... existing protocols ...
        
        // Light client protocols
        buildProtocolID(forkDigest, ProtocolLightClientBootstrap, 1):       m.wrapHandler("light_client_bootstrap", m.handler.LightClientBootstrap),
        buildProtocolID(forkDigest, ProtocolLightClientUpdatesByRange, 1):  m.wrapHandler("light_client_updates_by_range", m.handler.LightClientUpdatesByRange),
        buildProtocolID(forkDigest, ProtocolLightClientFinalityUpdate, 1):  m.wrapHandler("light_client_finality_update", m.handler.LightClientFinalityUpdate),
        buildProtocolID(forkDigest, ProtocolLightClientOptimisticUpdate, 1): m.wrapHandler("light_client_optimistic_update", m.handler.LightClientOptimisticUpdate),
    }
    
    // ... rest of registration ...
}
```

### 3.4 Implement Delegated Mode Handler

**File**: `/eth/reqresp/delegated/handler.go`
```go
// LightClientFinalityUpdate handles light client finality update requests by delegating
func (h *DelegatedHandler) LightClientFinalityUpdate(ctx context.Context, stream network.Stream) error {
    return h.delegateStream(ctx, stream, reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolLightClientFinalityUpdate, 1))
}

// LightClientOptimisticUpdate handles light client optimistic update requests by delegating
func (h *DelegatedHandler) LightClientOptimisticUpdate(ctx context.Context, stream network.Stream) error {
    return h.delegateStream(ctx, stream, reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolLightClientOptimisticUpdate, 1))
}

// LightClientBootstrap handles light client bootstrap requests by delegating
func (h *DelegatedHandler) LightClientBootstrap(ctx context.Context, stream network.Stream) error {
    return h.delegateStream(ctx, stream, reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolLightClientBootstrap, 1))
}

// LightClientUpdatesByRange handles light client updates by range requests by delegating
func (h *DelegatedHandler) LightClientUpdatesByRange(ctx context.Context, stream network.Stream) error {
    return h.delegateStream(ctx, stream, reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolLightClientUpdatesByRange, 1))
}
```

### 3.5 Implement Upstream Mode Handler

**New File**: `/eth/reqresp/upstream/light_client.go`
```go
package upstream

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "net/http"
    
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/probe-lab/hermes/eth/reqresp"
)

// LightClientFinalityUpdate handles light client finality update requests
func (h *UpstreamHandler) LightClientFinalityUpdate(ctx context.Context, stream network.Stream) error {
    defer stream.Close()
    
    // No request body for this protocol
    if err := stream.CloseRead(); err != nil {
        h.logger.Warn("Failed to close read side", "err", err)
    }
    
    // Get latest finality update from beacon API
    update, err := h.beaconClient.GetLightClientFinalityUpdate(ctx)
    if err != nil {
        h.logger.Error("Failed to get light client finality update", "err", err)
        
        // Write error response
        if _, writeErr := stream.Write([]byte{reqresp.ResponseCodeResourceUnavailable}); writeErr != nil {
            h.logger.Warn("Failed to write error response", "err", writeErr)
        }
        return fmt.Errorf("get finality update: %w", err)
    }
    
    // Write success response code
    if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
        return fmt.Errorf("write response code: %w", err)
    }
    
    // Encode and write the update
    if err := h.writeResponse(ctx, stream, update); err != nil {
        return fmt.Errorf("write finality update: %w", err)
    }
    
    return nil
}

// LightClientOptimisticUpdate handles light client optimistic update requests
func (h *UpstreamHandler) LightClientOptimisticUpdate(ctx context.Context, stream network.Stream) error {
    defer stream.Close()
    
    // Similar implementation to finality update
    // No request body
    if err := stream.CloseRead(); err != nil {
        h.logger.Warn("Failed to close read side", "err", err)
    }
    
    // Get latest optimistic update from beacon API
    update, err := h.beaconClient.GetLightClientOptimisticUpdate(ctx)
    if err != nil {
        h.logger.Error("Failed to get light client optimistic update", "err", err)
        
        if _, writeErr := stream.Write([]byte{reqresp.ResponseCodeResourceUnavailable}); writeErr != nil {
            h.logger.Warn("Failed to write error response", "err", writeErr)
        }
        return fmt.Errorf("get optimistic update: %w", err)
    }
    
    // Write response
    if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
        return fmt.Errorf("write response code: %w", err)
    }
    
    if err := h.writeResponse(ctx, stream, update); err != nil {
        return fmt.Errorf("write optimistic update: %w", err)
    }
    
    return nil
}

// LightClientBootstrap handles light client bootstrap requests
func (h *UpstreamHandler) LightClientBootstrap(ctx context.Context, stream network.Stream) error {
    defer stream.Close()
    
    // Read the block root from request
    var blockRoot [32]byte
    if err := h.readRequest(ctx, stream, &blockRoot); err != nil {
        return fmt.Errorf("read block root: %w", err)
    }
    
    // Get bootstrap data from beacon API
    bootstrap, err := h.beaconClient.GetLightClientBootstrap(ctx, blockRoot)
    if err != nil {
        h.logger.Error("Failed to get light client bootstrap", "err", err, "root", fmt.Sprintf("%x", blockRoot))
        
        if _, writeErr := stream.Write([]byte{reqresp.ResponseCodeResourceUnavailable}); writeErr != nil {
            h.logger.Warn("Failed to write error response", "err", writeErr)
        }
        return fmt.Errorf("get bootstrap: %w", err)
    }
    
    // Write response
    if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
        return fmt.Errorf("write response code: %w", err)
    }
    
    if err := h.writeResponse(ctx, stream, bootstrap); err != nil {
        return fmt.Errorf("write bootstrap: %w", err)
    }
    
    return nil
}

// LightClientUpdatesByRange handles light client updates by range requests
func (h *UpstreamHandler) LightClientUpdatesByRange(ctx context.Context, stream network.Stream) error {
    defer stream.Close()
    
    // Read the request
    var req LightClientUpdatesByRangeRequest
    if err := h.readRequest(ctx, stream, &req); err != nil {
        return fmt.Errorf("read request: %w", err)
    }
    
    // Validate request
    if req.Count == 0 || req.Count > MAX_REQUEST_LIGHT_CLIENT_UPDATES {
        if _, err := stream.Write([]byte{reqresp.ResponseCodeInvalidRequest}); err != nil {
            h.logger.Warn("Failed to write error response", "err", err)
        }
        return errors.New("invalid count")
    }
    
    // Get updates from beacon API
    updates, err := h.beaconClient.GetLightClientUpdatesByRange(ctx, req.StartPeriod, req.Count)
    if err != nil {
        h.logger.Error("Failed to get light client updates", "err", err)
        
        if _, writeErr := stream.Write([]byte{reqresp.ResponseCodeServerError}); writeErr != nil {
            h.logger.Warn("Failed to write error response", "err", writeErr)
        }
        return fmt.Errorf("get updates: %w", err)
    }
    
    // Write each update
    for _, update := range updates {
        if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
            return fmt.Errorf("write response code: %w", err)
        }
        
        if err := h.writeResponse(ctx, stream, update); err != nil {
            return fmt.Errorf("write update: %w", err)
        }
    }
    
    return nil
}
```

### 3.6 Update Beacon Client

**File**: `/eth/reqresp/upstream/beacon_client.go` (add methods)
```go
// GetLightClientFinalityUpdate retrieves the latest light client finality update
func (c *BeaconClient) GetLightClientFinalityUpdate(ctx context.Context) (*LightClientFinalityUpdate, error) {
    endpoint := fmt.Sprintf("%s/eth/v1/beacon/light_client/finality_update", c.baseURL)
    
    resp, err := c.httpClient.Get(endpoint)
    if err != nil {
        return nil, fmt.Errorf("http get: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode == http.StatusNotFound {
        return nil, errors.New("no finality update available")
    }
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
    }
    
    var result struct {
        Version string                    `json:"version"`
        Data    *LightClientFinalityUpdate `json:"data"`
    }
    
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("decode response: %w", err)
    }
    
    return result.Data, nil
}

// GetLightClientOptimisticUpdate retrieves the latest light client optimistic update
func (c *BeaconClient) GetLightClientOptimisticUpdate(ctx context.Context) (*LightClientOptimisticUpdate, error) {
    // Similar implementation to finality update
    endpoint := fmt.Sprintf("%s/eth/v1/beacon/light_client/optimistic_update", c.baseURL)
    // ... rest similar to GetLightClientFinalityUpdate
}

// GetLightClientBootstrap retrieves bootstrap data for a given block root
func (c *BeaconClient) GetLightClientBootstrap(ctx context.Context, blockRoot [32]byte) (*LightClientBootstrap, error) {
    endpoint := fmt.Sprintf("%s/eth/v1/beacon/light_client/bootstrap/0x%x", c.baseURL, blockRoot)
    // ... implementation
}

// GetLightClientUpdatesByRange retrieves light client updates for a range of sync committee periods
func (c *BeaconClient) GetLightClientUpdatesByRange(ctx context.Context, startPeriod, count uint64) ([]*LightClientUpdate, error) {
    endpoint := fmt.Sprintf("%s/eth/v1/beacon/light_client/updates?start_period=%d&count=%d", c.baseURL, startPeriod, count)
    // ... implementation
}
```

### 3.7 Add Light Client Types

**New File**: `/eth/reqresp/types_light_client.go`
```go
package reqresp

import (
    "github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
    ethpb "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
)

// Constants for light client protocols
const (
    MAX_REQUEST_LIGHT_CLIENT_UPDATES = 128
)

// LightClientUpdatesByRangeRequest represents a request for light client updates by range
type LightClientUpdatesByRangeRequest struct {
    StartPeriod uint64 `ssz-size:"8"`
    Count       uint64 `ssz-size:"8"`
}

// Light client types would typically come from the Prysm or consensus-specs libraries
// These are placeholders - actual types need to be imported or defined based on fork
type LightClientFinalityUpdate struct {
    AttestedHeader  *ethpb.LightClientHeader
    FinalizedHeader *ethpb.LightClientHeader
    FinalityBranch  [][]byte `ssz-size:"?,32"`
    SyncAggregate   *ethpb.SyncAggregate
    SignatureSlot   primitives.Slot
}

type LightClientOptimisticUpdate struct {
    AttestedHeader *ethpb.LightClientHeader
    SyncAggregate  *ethpb.SyncAggregate
    SignatureSlot  primitives.Slot
}

type LightClientBootstrap struct {
    Header                     *ethpb.LightClientHeader
    CurrentSyncCommittee       *ethpb.SyncCommittee
    CurrentSyncCommitteeBranch [][]byte `ssz-size:"?,32"`
}

type LightClientUpdate struct {
    AttestedHeader          *ethpb.LightClientHeader
    NextSyncCommittee       *ethpb.SyncCommittee
    NextSyncCommitteeBranch [][]byte `ssz-size:"?,32"`
    FinalizedHeader         *ethpb.LightClientHeader
    FinalityBranch          [][]byte `ssz-size:"?,32"`
    SyncAggregate           *ethpb.SyncAggregate
    SignatureSlot           primitives.Slot
}
```

### 3.8 Update Response Codes

**File**: `/eth/reqresp/utils.go` (if not already defined)
```go
const (
    ResponseCodeSuccess            = 0
    ResponseCodeInvalidRequest     = 1
    ResponseCodeServerError        = 2
    ResponseCodeResourceUnavailable = 3
    ResponseCodeRateLimited        = 139
)
```

## 4. Specific Code Examples and File Locations

### 4.1 Example: Complete Light Client Finality Update Handler (Independent Mode)

**New File**: `/eth/reqresp/independent/light_client.go`
```go
package independent

import (
    "context"
    "errors"
    "fmt"
    
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/probe-lab/hermes/eth/reqresp"
)

// IndependentHandler implements the light client handlers for independent validation
type IndependentHandler struct {
    *reqresp.BaseHandler
    
    // Light client store for validation
    lightClientStore *LightClientStore
    
    // Function to compute local finality update
    computeFinalityUpdate func() (*LightClientFinalityUpdate, error)
}

// LightClientFinalityUpdate handles requests for the latest finality update
func (h *IndependentHandler) LightClientFinalityUpdate(ctx context.Context, stream network.Stream) error {
    defer stream.Close()
    
    // No request body
    if err := stream.CloseRead(); err != nil {
        h.logger.Warn("Failed to close read side", "err", err)
    }
    
    // Get our latest finality update
    update, err := h.computeFinalityUpdate()
    if err != nil {
        h.logger.Error("Failed to compute finality update", "err", err)
        
        // Send ResourceUnavailable response
        if _, writeErr := stream.Write([]byte{reqresp.ResponseCodeResourceUnavailable}); writeErr != nil {
            h.logger.Warn("Failed to write error response", "err", writeErr)
        }
        return fmt.Errorf("compute finality update: %w", err)
    }
    
    // Write success response
    if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
        return fmt.Errorf("write response code: %w", err)
    }
    
    // Write the update
    if err := h.writeResponse(ctx, stream, update); err != nil {
        return fmt.Errorf("write update: %w", err)
    }
    
    h.logger.Debug("Served light client finality update", 
        "finalized_slot", update.FinalizedHeader.Beacon.Slot,
        "attested_slot", update.AttestedHeader.Beacon.Slot)
    
    return nil
}

// validateLightClientFinalityUpdate validates an incoming finality update
func (h *IndependentHandler) validateLightClientFinalityUpdate(update *LightClientFinalityUpdate) error {
    // Implement validation according to spec:
    
    // 1. Check sync committee participation
    participation := countBits(update.SyncAggregate.SyncCommitteeBits)
    if participation < MIN_SYNC_COMMITTEE_PARTICIPANTS {
        return errors.New("insufficient sync committee participation")
    }
    
    // 2. Verify slot ordering
    currentSlot := getCurrentSlot()
    if currentSlot < update.SignatureSlot {
        return errors.New("signature slot is in the future")
    }
    
    if update.SignatureSlot <= update.AttestedHeader.Beacon.Slot {
        return errors.New("invalid slot ordering")
    }
    
    if update.AttestedHeader.Beacon.Slot < update.FinalizedHeader.Beacon.Slot {
        return errors.New("finalized slot after attested slot")
    }
    
    // 3. Verify finality branch
    if err := verifyFinalityBranch(
        update.FinalizedHeader,
        update.FinalityBranch,
        update.AttestedHeader,
    ); err != nil {
        return fmt.Errorf("invalid finality branch: %w", err)
    }
    
    // 4. Verify sync aggregate signature
    if err := verifySyncAggregateSignature(
        update.AttestedHeader,
        update.SyncAggregate,
        update.SignatureSlot,
    ); err != nil {
        return fmt.Errorf("invalid sync aggregate signature: %w", err)
    }
    
    return nil
}
```

### 4.2 Example: Testing Light Client Finality Update

**New File**: `/eth/reqresp/light_client_test.go`
```go
package reqresp_test

import (
    "context"
    "testing"
    
    "github.com/stretchr/testify/require"
    "github.com/probe-lab/hermes/eth/reqresp"
)

func TestLightClientFinalityUpdate(t *testing.T) {
    // Setup test environment
    ctx := context.Background()
    
    // Create mock hosts and handlers
    serverHost, clientHost := createTestHosts(t)
    
    // Create server handler with test data
    serverHandler := &MockHandler{
        finalityUpdate: createTestFinalityUpdate(),
    }
    
    // Register server handler
    manager, err := reqresp.NewManager(serverHost, serverHandler, testConfig)
    require.NoError(t, err)
    require.NoError(t, manager.RegisterHandlers())
    
    // Create client
    client := reqresp.NewClient(clientHost, testConfig)
    
    // Request finality update
    stream, err := client.NewStream(ctx, serverHost.ID(), 
        reqresp.GetProtocolID(testForkDigest, reqresp.ProtocolLightClientFinalityUpdate, 1))
    require.NoError(t, err)
    defer stream.Close()
    
    // No request body - close write
    require.NoError(t, stream.CloseWrite())
    
    // Read response
    var respCode byte
    _, err = stream.Read([]byte{respCode})
    require.NoError(t, err)
    require.Equal(t, reqresp.ResponseCodeSuccess, respCode)
    
    // Decode finality update
    var update LightClientFinalityUpdate
    err = testConfig.Encoder.DecodeWithMaxLength(stream, &update)
    require.NoError(t, err)
    
    // Verify update matches expected
    require.Equal(t, serverHandler.finalityUpdate.FinalizedHeader.Beacon.Slot, 
        update.FinalizedHeader.Beacon.Slot)
}
```

## 5. Dependencies on Missing Components

### 5.1 Light Client Types
The implementation requires proper light client types from consensus libraries:
- Import from Prysm: `github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1`
- Or define custom types matching the consensus-specs

### 5.2 Beacon State Access (for Independent Mode)
For full node validation, need access to:
```go
type BeaconStateProvider interface {
    // Get current finalized checkpoint
    GetFinalizedCheckpoint(ctx context.Context) (*ethpb.Checkpoint, error)
    
    // Get block by root
    GetBlock(ctx context.Context, root [32]byte) (*ethpb.SignedBeaconBlock, error)
    
    // Get state by root
    GetState(ctx context.Context, root [32]byte) (*ethpb.BeaconState, error)
    
    // Compute light client finality update from current state
    ComputeLightClientFinalityUpdate(ctx context.Context) (*LightClientFinalityUpdate, error)
}
```

### 5.3 Cryptographic Functions
Need BLS and Merkle proof verification:
```go
// BLS signature verification
func VerifySyncAggregateSignature(
    attestedHeader *LightClientHeader,
    syncAggregate *SyncAggregate,
    signatureSlot Slot,
    syncCommittee *SyncCommittee,
) error

// Merkle proof verification
func VerifyMerkleBranch(
    leaf [32]byte,
    branch [][]byte,
    depth uint64,
    index uint64,
    root [32]byte,
) bool
```

### 5.4 Light Client Store (for Light Client Mode)
```go
type LightClientStore struct {
    // Stores the latest valid finalized header
    FinalizedHeader *LightClientHeader
    
    // Current sync committee
    CurrentSyncCommittee *SyncCommittee
    
    // Next sync committee (if known)
    NextSyncCommittee *SyncCommittee
    
    // Best valid update for next sync committee
    BestValidUpdate *LightClientUpdate
    
    // Optimistic header
    OptimisticHeader *LightClientHeader
    
    // Previous max active participants
    PreviousMaxActiveParticipants uint64
    
    // Current max active participants
    CurrentMaxActiveParticipants uint64
}
```

## 6. Implementation Priority and Phasing

### Phase 1: Basic Protocol Support (Delegated Mode)
1. Add protocol constants and handler interface methods
2. Implement delegated mode (simplest - just forwards)
3. Add basic tests for protocol registration

### Phase 2: Upstream Mode with Beacon API
1. Implement beacon API client methods for light client endpoints
2. Add upstream handler implementations
3. Test with real beacon nodes

### Phase 3: Independent Mode (Advanced)
1. Import/define proper light client types
2. Implement state access interface
3. Add validation logic
4. Implement `ComputeLightClientFinalityUpdate`

### Phase 4: Full Light Client Support
1. Implement light client store
2. Add push mechanism for updates
3. Implement supermajority tracking
4. Add comprehensive validation

## 7. Testing Strategy

### Unit Tests
- Protocol registration and routing
- Request/response encoding/decoding
- Validation logic for each requirement

### Integration Tests
- End-to-end request/response flow
- Fork version handling
- Error cases (no update available, invalid requests)

### Stress Tests
- Multiple concurrent requests
- Large update ranges
- Network failures and timeouts

## 8. Summary

The implementation of light client finality update reqresp support in Hermes requires:

1. **Minimal Changes** for basic support (delegated mode)
2. **Moderate Changes** for upstream mode with beacon API
3. **Significant Changes** for full independent validation

The modular architecture of Hermes makes it straightforward to add new protocols. The main complexity lies in implementing proper validation for independent mode, which requires access to beacon state and cryptographic primitives.

Starting with delegated and upstream modes provides immediate functionality while deferring the complexity of full validation to a later phase.