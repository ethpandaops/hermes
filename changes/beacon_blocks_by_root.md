# BeaconBlocksByRoot Implementation Analysis for Hermes

## 1. What the Validation Spec Requires

Based on `/validation-specs/reqresp/beacon_blocks_by_root.md`, the BeaconBlocksByRoot protocol requires:

### Request Validation
- **Protocol**: `/eth2/beacon_chain/req/beacon_blocks_by_root/2/`
- **Request Format**: SSZ-encoded `List[Root, MAX_REQUEST_BLOCKS]` where each Root is `hash_tree_root(SignedBeaconBlock.message)`
- **Size Limits**:
  - Phase 0: `MAX_REQUEST_BLOCKS = 1024`
  - Deneb+: `MAX_REQUEST_BLOCKS_DENEB = 128`
- **Encoding**: SSZ with length-prefix as unsigned protobuf varint
- **Stream handling**: Requester must close write side after sending request

### Response Validation
- **Format**: Zero or more `response_chunk`s, each containing a single `SignedBeaconBlock`
- **Block Availability**:
  - MUST support blocks since latest finalized epoch
  - MAY limit the number of blocks in response
  - Missing blocks are simply omitted (no error)
- **Fork Context**: Must use appropriate SSZ type based on fork version
- **Error Codes**:
  - 0: Success
  - 1: InvalidRequest
  - 2: ServerError
  - 3: ResourceUnavailable
- **Stream handling**: Responder must close write side after sending all chunks

## 2. What Currently Exists in Hermes

### Upstream Mode Implementation (`/eth/reqresp/upstream/blocks.go`)
- **Function**: `handleBlocksByRoot` (lines 114-205)
- **Current Implementation**:
  ```go
  func (h *UpstreamHandler) handleBlocksByRoot(ctx context.Context, stream network.Stream) error
  ```
- **Features**:
  - Reads request as `types.BeaconBlockByRootsReq`
  - Validates request is not empty
  - Checks against `MAX_REQUEST_BLOCKS` limit (but doesn't check Deneb limit)
  - Fetches blocks from beacon API client
  - Writes success response code
  - Serializes each block with fork digest and SSZ encoding
  - Supports all fork versions (Phase0 through Electra)

### Delegated Mode Implementation (`/eth/reqresp/delegated/handler.go`)
- **Function**: `BlocksByRoot` (lines 254-256)
- **Current Implementation**:
  ```go
  func (h *DelegatedHandler) BlocksByRoot(ctx context.Context, stream network.Stream) error {
      return h.delegateStream(ctx, stream, reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolBlocksByRoot, 2))
  }
  ```
- **Features**: Simply forwards the entire stream to the delegate peer

### Beacon Client (`/eth/reqresp/upstream/beacon_client.go`)
- **Function**: `GetBlocksByRoot` (lines 159-204)
- **Current Implementation**:
  - Fetches blocks one by one from beacon API endpoint `/eth/v2/beacon/blocks/{root}`
  - Handles missing blocks by skipping (404 responses)
  - Decodes blocks based on fork version from response header

## 3. What Needs to Change

### For Upstream Mode
1. **Deneb Fork Handling**:
   ```go
   // Need to check if we're post-Deneb and apply appropriate limit
   maxBlocks := params.BeaconConfig().MaxRequestBlocks
   currentSlot := // need to get current slot
   denebSlot := primitives.Slot(uint64(params.BeaconConfig().DenebForkEpoch) * uint64(params.BeaconConfig().SlotsPerEpoch))
   if currentSlot >= denebSlot {
       maxBlocks = params.BeaconConfig().MaxRequestBlocksDeneb
   }
   ```

2. **Missing Validation**:
   - Need to validate request encoding format
   - Need to handle concurrent request limits
   - Should add timeout handling for beacon API calls

3. **Error Response Handling**:
   - Currently returns `ServerError` for all beacon API failures
   - Should distinguish between `ServerError` and `ResourceUnavailable`

### For Delegated Mode
- Current implementation is adequate - it correctly forwards the stream

### For Independent Mode (Not Yet Implemented)
Need to create a new handler that:
1. Maintains a local block store/cache
2. Implements block retrieval from local storage
3. Handles finalized block pruning
4. Validates blocks are within the finalized window

## 4. Specific Code Examples and File Locations

### Fix Deneb Limit Check in Upstream Mode
**File**: `/eth/reqresp/upstream/blocks.go`
**Line**: ~127

```go
// Current code:
if uint64(len(req)) > params.BeaconConfig().MaxRequestBlocks {
    return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
}

// Should be:
maxBlocks := params.BeaconConfig().MaxRequestBlocks
// Need to determine if we should use Deneb limit based on current network state
// This requires access to current slot/epoch information
if h.shouldUseDenebLimits() {
    maxBlocks = params.BeaconConfig().MaxRequestBlocksDeneb
}
if uint64(len(req)) > maxBlocks {
    return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
}
```

### Add Timeout to Beacon Client Calls
**File**: `/eth/reqresp/upstream/blocks.go`
**Line**: ~138

```go
// Current code:
blocks, err := h.beaconClient.GetBlocksByRoot(ctx, roots)

// Should be:
ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
defer cancel()
blocks, err := h.beaconClient.GetBlocksByRoot(ctx, roots)
```

### Independent Mode Implementation Skeleton
**New File**: `/eth/reqresp/independent/handler.go`

```go
package independent

type IndependentHandler struct {
    host       host.Host
    cfg        *reqresp.Config
    logger     *slog.Logger
    blockStore BlockStore // Interface for local block storage
    
    // Status and metadata
    statusMu   sync.RWMutex
    status     *pb.Status
    metaDataMu sync.RWMutex
    metaData   *pb.MetaDataV1
}

func (h *IndependentHandler) BlocksByRoot(ctx context.Context, stream network.Stream) error {
    defer stream.Close()
    
    // Read request
    var req types.BeaconBlockByRootsReq
    if err := h.readRequest(ctx, stream, &req); err != nil {
        return fmt.Errorf("read blocks by root request: %w", err)
    }
    
    // Validate request
    if len(req) == 0 {
        return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
    }
    
    // Check limits based on fork
    maxBlocks := h.getMaxRequestBlocks()
    if uint64(len(req)) > maxBlocks {
        return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
    }
    
    // Write success response code
    if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
        return fmt.Errorf("write response code: %w", err)
    }
    
    // Fetch and send blocks
    for _, root := range req {
        block, err := h.blockStore.GetBlockByRoot(ctx, root)
        if err != nil {
            // Skip missing blocks per spec
            continue
        }
        
        if err := h.writeBlock(stream, block); err != nil {
            return fmt.Errorf("write block: %w", err)
        }
    }
    
    return nil
}
```

## 5. Dependencies on Missing Components

### For Independent Mode
1. **Block Storage Interface**:
   - Need a component that stores historical blocks
   - Must support retrieval by root hash
   - Should handle pruning of blocks older than finalized epoch
   
2. **State Management**:
   - Need access to current finalized checkpoint
   - Need to track current slot/epoch for Deneb limit determination
   
3. **Fork Schedule Awareness**:
   - Need mechanism to determine which fork rules apply
   - Should integrate with existing fork schedule configuration

### For Upstream Mode Improvements
1. **Current Slot/Epoch Tracking**:
   - Need reliable way to determine current network time
   - Could use beacon API's `/eth/v1/beacon/headers/head` endpoint
   
2. **Enhanced Error Handling**:
   - Need to distinguish between temporary and permanent failures
   - Should implement retry logic for transient errors

### Integration Points
1. **Configuration**:
   - Need to add block store configuration for independent mode
   - Should allow configuration of block retention policy
   
2. **Metrics**:
   - Add metrics for blocks served vs. blocks missing
   - Track response times and error rates
   
3. **Testing**:
   - Need test cases for various fork transitions
   - Should test behavior with missing blocks
   - Must verify compliance with size limits

## Summary

The current Hermes implementation has basic BeaconBlocksByRoot support in both upstream and delegated modes. The main gaps are:

1. **Deneb fork handling** - Not checking reduced block limits post-Deneb
2. **Independent mode** - Completely missing, needs local block storage
3. **Validation completeness** - Missing some edge cases and proper timeout handling
4. **Error distinction** - Not differentiating between error types properly

The upstream and delegated modes are functional but need refinement. The independent mode requires significant new components, particularly around block storage and state management.