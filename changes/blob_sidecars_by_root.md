# BlobSidecarsByRoot Request/Response Validation Analysis for Hermes

## 1. What the Validation Spec Requires

The blob sidecars by root validation spec (`validation-specs/reqresp/blob_sidecars_by_root.md`) requires:

### Request Validation Rules:
1. **Request Size Limit**: MUST NOT request more than `MAX_REQUEST_BLOB_SIDECARS` at a time
   - Deneb: 128 * 6 = 768 blob sidecars
   - Electra: Updated to `MAX_REQUEST_BLOB_SIDECARS_ELECTRA`

### Response Validation Rules:

#### For the Responding Peer:
1. **MUST** support requesting sidecars since `minimum_request_epoch`, where:
   - `minimum_request_epoch = max(finalized_epoch, current_epoch - MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS, DENEB_FORK_EPOCH)`
   - MAY respond with error code `3: ResourceUnavailable` for blocks before this epoch

2. **MUST** respond with at least one sidecar, if they have it

3. **SHOULD** include a sidecar in the response as soon as it passes gossip validation rules

4. **SHOULD NOT** respond with sidecars related to blocks that fail gossip validation

5. **SHOULD NOT** respond with sidecars related to blocks that fail state transition

6. Response **MUST** consist of zero or more `response_chunk`, each containing a single `BlobSidecar`

7. For each chunk, use `ForkDigest`-context based on `compute_fork_version(compute_epoch_at_slot(blob_sidecar.signed_block_header.message.slot))`

#### For the Requesting Peer (Response Reader):
Before consuming the next response chunk, **SHOULD** verify:
1. The blob sidecar is well-formatted
2. Has valid inclusion proof (via `verify_blob_sidecar_inclusion_proof`)
3. Is correct w.r.t. KZG commitments through `verify_blob_kzg_proof`

### Key Constants:
- `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS`: 4096 epochs (~18 days)
- `MAX_REQUEST_BLOB_SIDECARS`: MAX_REQUEST_BLOCKS_DENEB * MAX_BLOBS_PER_BLOCK (768 for mainnet)

## 2. What Currently Exists in Hermes

### Request/Response Infrastructure (`eth/reqresp/`):

1. **Protocol Registration** (`handler.go`):
   - Protocol ID: `/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy`
   - Handler mapping exists: `ProtocolBlobsByRoot` → `handler.BlobSidecarsByRoot`

2. **Delegated Mode** (`delegated/handler.go`):
   - Simple stream forwarding to delegate peer
   - No validation performed

3. **Upstream Mode** (`upstream/blobs.go`):
   ```go
   func (h *UpstreamHandler) handleBlobSidecarsByRoot(ctx context.Context, stream network.Stream) error {
       // Reads request as types.BlobSidecarsByRootReq
       // Validates request count (max 768)
       // Fetches from beacon API
       // Writes response chunks with fork digest
   }
   ```

4. **Beacon Client** (`upstream/beacon_client.go`):
   - `GetBlobSidecarsByRoot()`: Fetches blob sidecars from beacon API
   - Uses `/eth/v1/beacon/blob_sidecars/{block_id}` endpoint
   - Filters by requested indices

### Missing Components:

1. **Historical Data Management**:
   - No tracking of `minimum_request_epoch`
   - No calculation of how far back blob sidecars should be available
   - No integration with blob sidecar pruning logic

2. **Validation of Responses**:
   - No inclusion proof verification before sending
   - No KZG proof verification before sending
   - No check for gossip validation status

3. **Fork Handling**:
   - Basic fork digest handling exists
   - No Electra-specific constants or logic

4. **Independent Mode**:
   - No implementation for serving blob sidecars from local storage
   - Would require blob sidecar storage/indexing

## 3. What Needs to Change for Both Independent and Delegated Modes

### For Delegated Mode:

The current implementation is mostly complete for delegated mode since it forwards requests. Minor improvements:

1. **Add request validation** before forwarding:
```go
func (h *DelegatedHandler) BlobSidecarsByRoot(ctx context.Context, stream network.Stream) error {
    // Read and validate request size before delegating
    var reqBuf bytes.Buffer
    if _, err := io.Copy(&reqBuf, stream); err != nil {
        return fmt.Errorf("failed to read request: %w", err)
    }
    
    // Decode to check size
    var req types.BlobSidecarsByRootReq
    if err := h.cfg.Encoder.DecodeWithMaxLength(bytes.NewReader(reqBuf.Bytes()), &req); err != nil {
        if _, writeErr := stream.Write([]byte{reqresp.ResponseCodeInvalidRequest}); writeErr != nil {
            h.logger.Warn("Failed to write error response", "err", writeErr)
        }
        return fmt.Errorf("failed to decode request: %w", err)
    }
    
    // Validate request count
    maxBlobSidecars := params.BeaconConfig().MaxRequestBlocksDeneb * 6 // MAX_BLOBS_PER_BLOCK
    if len(req) > int(maxBlobSidecars) {
        if _, writeErr := stream.Write([]byte{reqresp.ResponseCodeInvalidRequest}); writeErr != nil {
            h.logger.Warn("Failed to write error response", "err", writeErr)
        }
        return fmt.Errorf("request exceeds max blob sidecars: %d > %d", len(req), maxBlobSidecars)
    }
    
    // Continue with delegation...
    return h.delegateStreamWithBuffer(ctx, stream, &reqBuf, reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolBlobsByRoot, 1))
}
```

### For Independent Mode:

This requires significant new implementation:

1. **Create Independent Handler** (`eth/reqresp/independent/handler.go`):
```go
type IndependentHandler struct {
    host        host.Host
    cfg         *reqresp.Config
    logger      *slog.Logger
    
    // Blob sidecar storage
    blobStore   BlobSidecarStore
    
    // State tracking
    wallclock   *ethwallclock.EthereumBeaconChain
    stateSync   *statesync.Service
    
    // Caches
    statusMu    sync.RWMutex
    status      *pb.Status
    metaDataMu  sync.RWMutex
    metaData    *pb.MetaDataV1
}
```

2. **Implement BlobSidecarsByRoot handler** (`eth/reqresp/independent/blobs.go`):
```go
func (h *IndependentHandler) BlobSidecarsByRoot(ctx context.Context, stream network.Stream) error {
    defer stream.Close()
    
    // Read request
    var req types.BlobSidecarsByRootReq
    if err := h.readRequest(ctx, stream, &req); err != nil {
        return fmt.Errorf("read blob sidecars by root request: %w", err)
    }
    
    // Validate request size
    maxBlobSidecars := h.getMaxBlobSidecars()
    if len(req) == 0 || len(req) > int(maxBlobSidecars) {
        return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
    }
    
    // Calculate minimum request epoch
    currentEpoch := h.wallclock.CurrentEpoch()
    finalizedEpoch := h.getFinalizedEpoch()
    minRequestEpoch := max(
        finalizedEpoch,
        currentEpoch - MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS,
        params.BeaconConfig().DenebForkEpoch,
    )
    
    // Write success code
    if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
        return fmt.Errorf("write response code: %w", err)
    }
    
    // Process each request
    for _, blobId := range req {
        // Check if block is within minimum epoch
        blockSlot, err := h.getBlockSlot(blobId.BlockRoot)
        if err != nil {
            continue // Skip if we don't have the block
        }
        
        blockEpoch := blockSlot / params.BeaconConfig().SlotsPerEpoch
        if blockEpoch < minRequestEpoch {
            continue // Skip old blobs
        }
        
        // Fetch blob sidecar from store
        blob, err := h.blobStore.GetBlobSidecar(blobId.BlockRoot, blobId.Index)
        if err != nil {
            continue // Skip if not found
        }
        
        // Validate before sending
        if err := h.validateBlobSidecar(blob); err != nil {
            h.logger.Warn("Skipping invalid blob sidecar", 
                "root", hex.EncodeToString(blobId.BlockRoot), 
                "index", blobId.Index,
                "err", err)
            continue
        }
        
        // Write chunk with fork digest
        if err := h.writeBlobSidecarChunk(stream, blob); err != nil {
            return fmt.Errorf("write blob sidecar chunk: %w", err)
        }
    }
    
    return nil
}

func (h *IndependentHandler) validateBlobSidecar(blob *deneb.BlobSidecar) error {
    // Verify inclusion proof
    if err := common.VerifyBlobSidecarInclusionProof(blob); err != nil {
        return fmt.Errorf("invalid inclusion proof: %w", err)
    }
    
    // Verify KZG proof
    if err := h.kzgVerifier.VerifyBlobKZGProof(
        blob.Blob,
        blob.KZGCommitment,
        blob.KZGProof,
    ); err != nil {
        return fmt.Errorf("invalid KZG proof: %w", err)
    }
    
    return nil
}
```

3. **Create Blob Sidecar Store Interface** (`eth/storage/blobs.go`):
```go
type BlobSidecarStore interface {
    // Store a validated blob sidecar
    StoreBlobSidecar(blob *deneb.BlobSidecar) error
    
    // Retrieve a specific blob sidecar
    GetBlobSidecar(blockRoot [32]byte, index uint64) (*deneb.BlobSidecar, error)
    
    // Prune blob sidecars older than the given epoch
    PruneBefore(epoch phase0.Epoch) error
    
    // Get slot for a block root
    GetBlockSlot(blockRoot [32]byte) (phase0.Slot, error)
}
```

### For Upstream Mode:

Current implementation is mostly complete but needs:

1. **Add minimum epoch validation**:
```go
func (h *UpstreamHandler) handleBlobSidecarsByRoot(ctx context.Context, stream network.Stream) error {
    // ... existing request reading and validation ...
    
    // Calculate minimum request epoch for logging/metrics
    currentSlot := h.getCurrentSlot()
    currentEpoch := currentSlot / params.BeaconConfig().SlotsPerEpoch
    finalizedCheckpoint := h.getFinalizedCheckpoint()
    minRequestEpoch := max(
        finalizedCheckpoint.Epoch,
        currentEpoch - MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS,
        params.BeaconConfig().DenebForkEpoch,
    )
    
    h.logger.Debug("Processing blob sidecars by root request",
        "count", len(req),
        "min_epoch", minRequestEpoch)
    
    // ... rest of existing implementation ...
}
```

2. **Add Electra support**:
```go
func (h *UpstreamHandler) getMaxBlobSidecars() uint64 {
    currentSlot := h.getCurrentSlot()
    
    // Check if we're in Electra
    if h.isElectraActivated(currentSlot) {
        return params.BeaconConfig().MaxRequestBlobSidecarsElectra
    }
    
    return params.BeaconConfig().MaxRequestBlocksDeneb * 6 // MAX_BLOBS_PER_BLOCK
}
```

## 4. Specific Code Examples and File Locations

### New Files to Create:

1. **`eth/reqresp/independent/handler.go`** - Main independent handler
2. **`eth/reqresp/independent/blobs.go`** - Blob sidecar handlers
3. **`eth/storage/blobs.go`** - Blob storage interface
4. **`eth/storage/memory/blobs.go`** - In-memory blob store implementation
5. **`eth/storage/badger/blobs.go`** - Persistent blob store implementation

### Files to Modify:

1. **`eth/reqresp/handler.go`**:
   - Add support for creating independent handlers
   - Add mode selection logic

2. **`eth/reqresp/upstream/blobs.go`**:
   - Add minimum epoch calculation
   - Add Electra support
   - Improve error handling and logging

3. **`eth/reqresp/delegated/handler.go`**:
   - Add request validation before delegation
   - Add metrics for delegated requests

4. **`eth/reqresp/types.go`**:
   - Add constants for blob sidecar limits
   - Add helper functions for epoch calculations

## 5. Dependencies on Missing Components

### 1. Historical Block Storage
- **Required for**: Mapping block roots to slots/epochs
- **Solution**: Extend existing block storage or maintain a lightweight index

### 2. Blob Sidecar Storage
- **Required for**: Independent mode to serve historical blob sidecars
- **Solution**: Implement storage interface with configurable backends

### 3. State Synchronization
- **Required for**: Getting finalized checkpoint
- **Solution**: Use existing state sync service or beacon client

### 4. KZG Verifier
- **Required for**: Validating blob sidecars before serving
- **Solution**: Reuse existing KZG verifier from pubsub validation

### 5. Fork Detection
- **Required for**: Applying correct limits and fork digest
- **Solution**: Extend existing fork detection logic

## Implementation Priority

1. **Phase 1** - Enhance existing modes:
   - Add request validation to delegated mode
   - Add Electra support to upstream mode
   - Add minimum epoch logging

2. **Phase 2** - Storage infrastructure:
   - Design and implement blob storage interface
   - Create in-memory implementation for testing
   - Add blob pruning logic

3. **Phase 3** - Independent mode:
   - Implement independent handler
   - Add blob sidecar validation
   - Integrate with storage

4. **Phase 4** - Production readiness:
   - Add persistent storage backend
   - Implement proper pruning
   - Add comprehensive metrics

## Testing Considerations

1. **Unit Tests**:
   - Request size validation
   - Minimum epoch calculation
   - Fork detection logic

2. **Integration Tests**:
   - Full request/response flow
   - Error handling scenarios
   - Fork transition handling

3. **Performance Tests**:
   - Large request handling (768 blob sidecars)
   - Storage performance
   - Concurrent request handling