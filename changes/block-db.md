# Block Database Component Specification

## Purpose and Requirements

The Block Database component provides minimal historical block storage to support validation operations in Hermes. Based on the shared requirements analysis, this component needs to:

### Core Requirements
1. **Store only unfinalized blocks** in memory for validation operations
2. **Route finalized block requests** to the upstream beacon node to minimize resource usage
3. **Support epoch-based lookups** for attestation validation and other epoch-relative operations
4. **Automatic pruning** when blocks become finalized
5. **No execution client dependency** - store only consensus layer data needed for validation

### Specific Use Cases
- **Attestation validation**: Access recent unfinalized blocks for target/source checks
- **Aggregate validation**: Verify aggregator selection via parent block lookup
- **Sync committee validation**: Access blocks for sync committee period transitions
- **Blob validation**: Parent block lookups for blob validation
- **Fork choice integration**: Provide block data for fork choice operations

## Minimal Viable Design

### Storage Model
- **In-memory storage only** for unfinalized blocks (no disk persistence needed)
- **Block retention**: Only blocks after the last finalized checkpoint
- **Indexed by**: block root (primary), slot (secondary), parent root
- **Stored data**: Minimal block data needed for validation (no full state)
- **Finalized block access**: Proxy requests to upstream beacon node

### Data Structure
```go
type StoredBlock struct {
    // Core identifiers
    Root       [32]byte
    ParentRoot [32]byte
    Slot       uint64
    
    // Validation data
    ProposerIndex    uint64
    RandaoReveal     [96]byte
    StateRoot        [32]byte
    
    // Fork choice data
    ExecutionPayloadHash [32]byte
    
    // Metadata
    ReceivedTime time.Time
    Finalized    bool
}
```

## Interface Definition

```go
type BlockDB interface {
    // Core operations - checks local cache first, then upstream
    AddBlock(block *spec.VersionedSignedBeaconBlock) error
    GetBlock(root [32]byte) (*StoredBlock, error)
    GetBlockBySlot(slot uint64) (*StoredBlock, error)
    HasBlock(root [32]byte) bool
    
    // Epoch operations
    GetBlocksInEpoch(epoch uint64) ([]*StoredBlock, error)
    GetLatestBlockBeforeSlot(slot uint64) (*StoredBlock, error)
    
    // Finality updates
    UpdateFinalizedCheckpoint(checkpoint *phase0.Checkpoint) error
    
    // Metrics
    GetStorageMetrics() StorageMetrics
}

type StorageMetrics struct {
    BlockCount          int
    MemoryUsageBytes    int64
    OldestSlot          uint64
    NewestSlot          uint64
    FinalizedSlot       uint64
}

// Upstream beacon node client interface
type BeaconNodeClient interface {
    GetBlockByRoot(ctx context.Context, root [32]byte) (*spec.VersionedSignedBeaconBlock, error)
    GetBlockBySlot(ctx context.Context, slot uint64) (*spec.VersionedSignedBeaconBlock, error)
}
```

## Storage Strategy

### In-Memory Storage
- Store only unfinalized blocks in memory
- Dual-index map structure:
  - Map by root for O(1) lookups
  - Ordered map by slot for range queries
- Memory estimation: ~1KB per block × 32 blocks (1 epoch) = ~32KB typical usage

### Upstream Integration
- All requests check local cache first
- If block is finalized (slot < finalized_slot), query upstream beacon node
- Cache upstream responses temporarily (with TTL) to avoid repeated queries
- Handle upstream failures gracefully with retries and circuit breakers

### Pruning Strategy
1. **Finality-based pruning**: Remove all blocks before finalized checkpoint
2. **Triggered by**:
   - Finalized checkpoint updates from state sync
   - No time-based pruning needed since finality handles it
3. **Zero finalized blocks stored** - always use upstream for finalized data

## Integration Points

### 1. Gossipsub Block Handler Integration
```go
// In block_validator.go
func (v *BeaconBlockValidator) Validate(msg *pubsub.Message) pubsub.ValidationResult {
    // Existing validation...
    
    // Store validated block in DB for future use
    if result == pubsub.ValidationAccept {
        if err := v.blockDB.AddBlock(block); err != nil {
            v.log.Warn("Failed to store block", "err", err)
        }
    }
    
    return result
}
```

### 2. Req/Resp Integration
```go
// In upstream/blocks.go - check local storage first
func (h *UpstreamHandler) handleBlocksByRoot(stream network.Stream, roots [][32]byte) {
    for _, root := range roots {
        // Check local storage first
        if block, err := h.blockDB.GetBlock(root); err == nil && block != nil {
            if err := sendBlock(stream, block); err != nil {
                return err
            }
            continue
        }
        
        // Fall back to beacon API if not found locally
        apiBlock, err := h.beaconClient.GetBlockByRoot(ctx, root)
        // ... existing logic
    }
}
```

### 3. Attestation Validator Integration
```go
// In attestation validator
func (v *AttestationValidator) validateTarget(att *phase0.Attestation) error {
    targetBlock, err := v.blockDB.GetBlock(att.Data.Target.Root)
    if err != nil {
        return fmt.Errorf("target block not found: %w", err)
    }
    // Validation logic...
}
```

### 4. Fork Choice Integration
```go
// Provide block data to fork choice
func (fc *ForkChoice) getBlock(root [32]byte) (*StoredBlock, error) {
    return fc.blockDB.GetBlock(root)
}
```

### 5. Finality Updates
```go
// Update finalized checkpoint and prune old blocks
func (h *Handler) onFinalizedCheckpoint(checkpoint *phase0.Checkpoint) {
    if err := h.blockDB.UpdateFinalizedCheckpoint(checkpoint); err != nil {
        log.Warn("Failed to update finalized checkpoint", "err", err)
    }
}
```

### 6. Boot Prewarming
```go
// Prewarm block DB on startup with recent unfinalized blocks
func (db *blockDB) Prewarm(ctx context.Context) error {
    // Get current head from beacon node
    head, err := db.beaconClient.GetHead(ctx)
    if err != nil {
        return fmt.Errorf("failed to get head: %w", err)
    }
    
    // Get finalized checkpoint
    finalized, err := db.beaconClient.GetFinalizedCheckpoint(ctx)
    if err != nil {
        return fmt.Errorf("failed to get finalized checkpoint: %w", err)
    }
    
    db.finalizedSlot = finalized.Epoch * SLOTS_PER_EPOCH
    
    // Fetch all blocks from finalized to head
    currentSlot := head.Slot
    startSlot := db.finalizedSlot + 1
    
    log.Info("Prewarming block DB", "from", startSlot, "to", currentSlot)
    
    for slot := startSlot; slot <= currentSlot; slot++ {
        block, err := db.beaconClient.GetBlockBySlot(ctx, slot)
        if err != nil {
            // Skip missing slots
            continue
        }
        
        if err := db.AddBlock(block); err != nil {
            log.Warn("Failed to add block during prewarm", "slot", slot, "err", err)
        }
    }
    
    log.Info("Block DB prewarm complete", "blocks", db.GetStorageMetrics().BlockCount)
    return nil
}
```

### 7. Implementation Example
```go
type blockDB struct {
    mu              sync.RWMutex
    blocksByRoot    map[[32]byte]*StoredBlock
    blocksBySlot    *btree.BTree // ordered by slot
    finalizedSlot   uint64
    beaconClient    BeaconNodeClient
    cache           *lru.Cache // temporary cache for finalized blocks
}

func (db *blockDB) GetBlock(root [32]byte) (*StoredBlock, error) {
    db.mu.RLock()
    block, exists := db.blocksByRoot[root]
    db.mu.RUnlock()
    
    if exists {
        return block, nil
    }
    
    // Check if we should query upstream (likely finalized)
    if db.cache.Contains(root) {
        return db.cache.Get(root).(*StoredBlock), nil
    }
    
    // Query upstream beacon node
    versionedBlock, err := db.beaconClient.GetBlockByRoot(context.Background(), root)
    if err != nil {
        return nil, fmt.Errorf("block not found locally or upstream: %w", err)
    }
    
    // Convert and cache the response
    storedBlock := convertToStoredBlock(versionedBlock)
    db.cache.Add(root, storedBlock)
    
    return storedBlock, nil
}
```

### 8. Startup Sequence
```go
// During Hermes initialization
func initializeBlockDB(ctx context.Context, cfg Config) (*blockDB, error) {
    db := &blockDB{
        blocksByRoot: make(map[[32]byte]*StoredBlock),
        blocksBySlot: btree.New(32),
        beaconClient: cfg.BeaconClient,
        cache:        lru.New(cfg.CacheSize),
    }
    
    // Prewarm with unfinalized blocks
    if err := db.Prewarm(ctx); err != nil {
        return nil, fmt.Errorf("failed to prewarm block DB: %w", err)
    }
    
    return db, nil
}
```

## Configuration

```yaml
block_db:
  enabled: true
  upstream_cache_size: 1000  # Number of finalized blocks to cache
  upstream_cache_ttl: "5m"   # TTL for cached finalized blocks
  memory_limit_mb: 10        # Much smaller since only unfinalized blocks
```

## Implementation Considerations

### Performance
- O(1) block lookups by root for unfinalized blocks
- O(log n) slot-based queries for local blocks
- Minimal memory footprint (~32KB for unfinalized blocks)
- Network I/O only for finalized blocks (with caching)

### Reliability
- Graceful handling of upstream failures with retries
- Circuit breaker for upstream beacon node
- No persistence needed - can rebuild from chain on restart

### Monitoring
- Metrics for:
  - Local block count (unfinalized only)
  - Upstream cache hit/miss rates
  - Upstream query latency
  - Memory usage
- Alerts for upstream connectivity issues

## Future Extensions

1. **Compressed storage**: Use compression for older blocks
2. **Shared memory**: Allow multiple Hermes instances to share block storage
3. **Extended retention**: Configurable retention for specific use cases
4. **State snapshots**: Store minimal state data for advanced validation