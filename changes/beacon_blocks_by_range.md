# BeaconBlocksByRange Implementation Analysis for Hermes

## 1. Validation Spec Requirements

Based on the validation spec at `/validation-specs/reqresp/beacon_blocks_by_range.md`, the key requirements are:

### Request Structure
- Protocol: `/eth2/beacon_chain/req/beacon_blocks_by_range/2/`
- SSZ-encoded request: `(start_slot: Slot, count: uint64, step: uint64)`
- `step` MUST be 1 (deprecated parameter)
- `count` MUST NOT exceed `MAX_REQUEST_BLOCKS` (1024 in phase0, 128 in Deneb+)

### Response Requirements
1. **Block Selection**: Must respond with blocks from current fork choice view
2. **Chain Consistency**: Blocks must be from single chain defined by current head
3. **Ordering**: Blocks must be sent in consecutive order when `step == 1`
4. **Parent-Child Validation**: Each `parent_root` must match `hash_tree_root` of preceding block
5. **Epoch Range**: Must keep blocks for `[max(GENESIS_EPOCH, current_epoch - MIN_EPOCHS_FOR_BLOCK_REQUESTS), current_epoch]`
   - `MIN_EPOCHS_FOR_BLOCK_REQUESTS` = 33024 epochs (~5 months)
6. **Fork-Specific Types**: Response uses `ForkDigest`-context to select appropriate block type

### Error Handling
- Return error code `3: ResourceUnavailable` if unable to serve blocks in required epoch range
- May stop responding if fork choice changes during response

## 2. Current Implementation in Hermes

### Upstream Mode (`/eth/reqresp/upstream/blocks.go`)
✅ **Implemented Features:**
- Basic request/response handling
- SSZ encoding/decoding
- Fork-specific block type handling (Phase0 through Electra)
- Request validation (count limits, Deneb-specific limits)
- Error response codes

❌ **Missing Features:**
- No validation of consecutive block ordering
- No parent-child relationship validation
- No epoch range enforcement
- No fork choice consistency checks
- Relies entirely on beacon API response ordering

**Code Location**: `/eth/reqresp/upstream/blocks.go:19-111`

### Delegated Mode (`/eth/reqresp/delegated/handler.go`)
✅ **Implemented Features:**
- Stream delegation to another peer
- Basic error handling

❌ **Missing Features:**
- No request validation before delegation
- No response validation after delegation
- Simply forwards the entire stream

**Code Location**: `/eth/reqresp/delegated/handler.go:248-251`

### Independent Mode
❌ **Not Implemented** - No independent handler exists for req/resp protocols

## 3. Required Changes

### 3.1 Upstream Mode Enhancements

**File**: `/eth/reqresp/upstream/blocks.go`

1. **Add Block Validation**:
```go
// After line 108, before returning nil
func (h *UpstreamHandler) validateBlockSequence(blocks []spec.VersionedSignedBeaconBlock) error {
    if len(blocks) < 2 {
        return nil // Nothing to validate
    }
    
    for i := 1; i < len(blocks); i++ {
        prevBlock := blocks[i-1]
        currBlock := blocks[i]
        
        // Extract block roots and parent roots based on version
        prevRoot, err := prevBlock.Root()
        if err != nil {
            return fmt.Errorf("get root for block %d: %w", i-1, err)
        }
        
        currParentRoot, err := getParentRoot(currBlock)
        if err != nil {
            return fmt.Errorf("get parent root for block %d: %w", i, err)
        }
        
        // Validate parent-child relationship
        if !bytes.Equal(prevRoot[:], currParentRoot[:]) {
            return fmt.Errorf("block %d parent root doesn't match block %d root", i, i-1)
        }
    }
    
    return nil
}
```

2. **Add Epoch Range Validation**:
```go
// After line 42, add epoch range check
func (h *UpstreamHandler) validateEpochRange(startSlot primitives.Slot) error {
    currentEpoch := h.getCurrentEpoch() // Need to implement
    minEpoch := currentEpoch - MIN_EPOCHS_FOR_BLOCK_REQUESTS
    if minEpoch < 0 {
        minEpoch = 0
    }
    
    requestEpoch := startSlot / params.BeaconConfig().SlotsPerEpoch
    if requestEpoch < primitives.Epoch(minEpoch) {
        return reqresp.ErrResourceUnavailable
    }
    
    return nil
}
```

### 3.2 Create Independent Mode Handler

**New File**: `/eth/reqresp/independent/handler.go`

```go
package independent

import (
    "context"
    "errors"
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/probe-lab/hermes/eth/reqresp"
    // ... other imports
)

type IndependentHandler struct {
    host        host.Host
    cfg         *reqresp.Config
    logger      *slog.Logger
    blockStore  BlockStore      // Need to implement
    stateCache  *StateCache     // Need to implement
    forkChoice  ForkChoice      // Need to implement
}

func (h *IndependentHandler) BlocksByRange(ctx context.Context, stream network.Stream) error {
    // Implementation needed - see section 3.3
}
```

### 3.3 Independent Mode Requirements

The independent mode needs several new components:

1. **Block Storage System**:
   - Store blocks for at least 5 months (MIN_EPOCHS_FOR_BLOCK_REQUESTS)
   - Index by slot and root
   - Support efficient range queries
   - Handle fork choice updates

2. **Fork Choice Integration**:
   - Access to current head
   - Ensure response consistency with single chain view
   - Handle reorgs during response

3. **State Management**:
   - Track finalized checkpoint
   - Validate blocks lead to finalized block

### 3.4 Delegated Mode Enhancements

**File**: `/eth/reqresp/delegated/handler.go`

Add response validation after delegation:
```go
func (h *DelegatedHandler) BlocksByRange(ctx context.Context, stream network.Stream) error {
    // Read request first to validate
    var req pb.BeaconBlocksByRangeRequest
    if err := h.readRequest(ctx, stream, &req); err != nil {
        return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
    }
    
    // Validate request
    if err := validateBlocksRequest(req); err != nil {
        return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
    }
    
    // Then delegate with validation wrapper
    return h.delegateStreamWithValidation(ctx, stream, 
        reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolBeaconBlocks, 2),
        validateBlocksResponse)
}
```

## 4. Dependencies on Missing Components

### 4.1 Block Storage (Critical for Independent Mode)
- **Required**: Historical block storage system
- **Capacity**: ~5 months of blocks (33024 epochs * 32 slots * ~1MB average = ~1TB)
- **Performance**: Fast range queries, concurrent reads
- **Options**: 
  - LevelDB/RocksDB for persistent storage
  - In-memory cache for recent blocks
  - Integration with existing beacon node database

### 4.2 Fork Choice State (Critical for Independent Mode)
- **Required**: Access to fork choice store
- **Components**:
  - Current head tracking
  - Finalized checkpoint
  - Fork choice rule implementation
- **Options**:
  - Port from Prysm/Lighthouse
  - Integrate with existing validator components

### 4.3 Epoch Time Tracking
- **Required**: Current epoch calculation
- **Implementation**: Already exists in independent validator via ethwallclock

## 5. Implementation Priority

1. **Phase 1 - Upstream Mode Hardening** (Low effort, high impact)
   - Add block sequence validation
   - Add epoch range checks
   - Improve error handling

2. **Phase 2 - Delegated Mode Enhancement** (Medium effort)
   - Add request validation
   - Add response validation wrapper
   - Implement retry logic

3. **Phase 3 - Independent Mode** (High effort)
   - Design and implement block storage
   - Integrate fork choice
   - Full protocol implementation

## 6. Testing Requirements

1. **Unit Tests**:
   - Block sequence validation
   - Epoch range calculations
   - Fork-specific encoding/decoding

2. **Integration Tests**:
   - Multi-fork block responses
   - Large range requests
   - Concurrent request handling

3. **Stress Tests**:
   - Maximum block requests
   - Rapid successive requests
   - Fork choice changes during response