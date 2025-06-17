# Block Database Component Specification

## Purpose and Requirements

The Block Database component provides minimal historical block storage to support validation operations in Hermes. Based on the shared requirements analysis, this component needs to:

### Core Requirements
1. **Store recent blocks** for validation operations that need to look up parent blocks, shuffling seeds, and randao values
2. **Support epoch-based lookups** for attestation validation and other epoch-relative operations
3. **Minimize resource usage** with aggressive pruning and efficient storage
4. **No execution client dependency** - store only consensus layer data needed for validation

### Specific Use Cases
- **Attestation validation**: Access blocks from current and previous epochs for target/source checks
- **Aggregate validation**: Verify aggregator selection via parent block lookup
- **Sync committee validation**: Access blocks for sync committee period transitions
- **Blob validation**: Parent block lookups for blob validation
- **Fork choice integration**: Provide block data for fork choice operations

## Minimal Viable Design

### Storage Model
- **In-memory primary storage** with optional disk persistence
- **Block retention**: 2-3 epochs worth of blocks (64-96 blocks)
- **Indexed by**: block root (primary), slot (secondary), parent root
- **Stored data**: Minimal block data needed for validation (no full state)

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
    // Core operations
    AddBlock(block *spec.VersionedSignedBeaconBlock) error
    GetBlock(root [32]byte) (*StoredBlock, error)
    GetBlockBySlot(slot uint64) (*StoredBlock, error)
    HasBlock(root [32]byte) bool
    
    // Epoch operations
    GetBlocksInEpoch(epoch uint64) ([]*StoredBlock, error)
    GetLatestBlockBeforeSlot(slot uint64) (*StoredBlock, error)
    
    // Maintenance
    PruneBeforeSlot(slot uint64) error
    SetFinalized(root [32]byte) error
    
    // Metrics
    GetStorageMetrics() StorageMetrics
}

type StorageMetrics struct {
    BlockCount      int
    MemoryUsageBytes int64
    OldestSlot      uint64
    NewestSlot      uint64
}
```

## Storage Strategy

### In-Memory Storage
- Primary storage using a dual-index map structure:
  - Map by root for O(1) lookups
  - Ordered map by slot for range queries
- Memory estimation: ~1KB per block × 96 blocks = ~100KB base usage

### Optional Persistence
- Configurable disk backing for crash recovery
- Write-through cache pattern
- SSZ encoding for compact storage
- File-based storage with slot-based partitioning

### Pruning Strategy
1. **Time-based pruning**: Remove blocks older than 2-3 epochs
2. **Finality-based pruning**: Keep finalized blocks longer (up to weak subjectivity period)
3. **Triggered by**:
   - New finalized checkpoint updates
   - Periodic cleanup (every epoch)
   - Memory pressure thresholds

## Integration Points

### 1. Block Handler Integration
```go
// In beacon_block handler
func (h *BeaconBlockHandler) handleBlock(block *spec.VersionedSignedBeaconBlock) {
    // Existing validation...
    
    // Store block for future validation needs
    if err := h.blockDB.AddBlock(block); err != nil {
        log.Warn("Failed to store block", "err", err)
    }
}
```

### 2. Attestation Validator Integration
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

### 3. Fork Choice Integration
```go
// Provide block data to fork choice
func (fc *ForkChoice) getBlock(root [32]byte) (*StoredBlock, error) {
    return fc.blockDB.GetBlock(root)
}
```

### 4. Finality Updates
```go
// Update finalized blocks
func (h *Handler) onFinalizedCheckpoint(checkpoint *phase0.Checkpoint) {
    h.blockDB.SetFinalized(checkpoint.Root)
    h.blockDB.PruneBeforeSlot(checkpoint.Epoch * SLOTS_PER_EPOCH)
}
```

## Configuration

```yaml
block_db:
  enabled: true
  retention_epochs: 3
  persistence:
    enabled: false
    path: "./block_db"
  memory_limit_mb: 50
  pruning:
    interval: "1m"
    keep_finalized: true
```

## Implementation Considerations

### Performance
- O(1) block lookups by root
- O(log n) slot-based queries
- Minimal memory footprint (~100KB for 3 epochs)
- No network I/O required

### Reliability
- Graceful handling of missing blocks
- No critical path dependencies
- Optional persistence for recovery

### Monitoring
- Metrics for block count, memory usage, hit/miss rates
- Alerts for storage pressure
- Pruning effectiveness tracking

## Future Extensions

1. **Compressed storage**: Use compression for older blocks
2. **Shared memory**: Allow multiple Hermes instances to share block storage
3. **Extended retention**: Configurable retention for specific use cases
4. **State snapshots**: Store minimal state data for advanced validation