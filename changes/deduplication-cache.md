# Unified Deduplication Cache System Specification

## 1. Purpose and Requirements

### 1.1 Overview
The deduplication cache system is critical infrastructure for preventing DoS attacks and ensuring specification compliance across all Ethereum consensus layer message types. Based on analysis of validation specifications, every gossipsub topic requires deduplication to prevent processing duplicate messages from the same validator/proposer.

### 1.2 Requirements from Validation Specs

#### Message Types Requiring Deduplication:
1. **Attestations** (beacon_attestation_{subnet_id})
   - Key: `validator_index + target_epoch`
   - Spec: "The aggregate attestation defined by hash_tree_root(attestation) has not already been seen"
   - Purpose: Prevent validators from broadcasting multiple attestations for same epoch

2. **Aggregate Attestations** (beacon_aggregate_and_proof)
   - Key: `aggregator_index + slot`
   - Spec: "First aggregate with valid signature from the aggregator for this epoch"
   - Purpose: Prevent aggregators from broadcasting multiple aggregates per slot

3. **Blocks** (beacon_block)
   - Key: `proposer_index + slot`
   - Spec: "First block with valid signature for proposer at slot"
   - Purpose: Prevent equivocation (multiple blocks from same proposer)

4. **Blob Sidecars** (blob_sidecar_{subnet_id})
   - Key: `block_root + proposer_index + blob_index`
   - Spec: "Not seen before for this `blob_id` tuple"
   - Purpose: Prevent duplicate blob propagation

5. **Voluntary Exits** (voluntary_exit)
   - Key: `validator_index`
   - Spec: "No other voluntary exit for the validator has been seen"
   - Purpose: Prevent spamming exit messages

6. **Proposer Slashings** (proposer_slashing)
   - Key: `proposer_index`
   - Spec: "No other proposer slashing for the proposer has been seen"
   - Purpose: Prevent duplicate slashing propagation

7. **Attester Slashings** (attester_slashing)
   - Key: Set of all `validator_indices` in both attestations
   - Spec: "No other attester slashing for any indices has been seen"
   - Purpose: Complex - must track all slashed validators

8. **BLS to Execution Changes** (bls_to_execution_change)
   - Key: `validator_index`
   - Spec: "No other change for the validator has been seen"
   - Purpose: Prevent duplicate credential changes

9. **Sync Committee Messages** (sync_committee_{subnet_id})
   - Key: `validator_index + slot`
   - Spec: "No duplicate message from same validator for slot"
   - Purpose: Prevent duplicate sync committee contributions

10. **Sync Committee Contributions** (sync_committee_contribution_and_proof)
    - Key: `aggregator_index + slot + subcommittee_index`
    - Spec: "First contribution from aggregator for slot and subcommittee"
    - Purpose: Prevent duplicate aggregations

### 1.3 DoS Prevention Requirements

The deduplication cache must prevent:
1. **Memory exhaustion**: Attackers sending unique but invalid messages
2. **CPU exhaustion**: Repeated signature verification on duplicate messages
3. **Network amplification**: Re-broadcasting duplicate messages
4. **State corruption**: Processing duplicate state transitions

## 2. Unified Design

### 2.1 Core Architecture

```go
// Package dedupe provides a unified deduplication cache system
package dedupe

import (
    "context"
    "sync"
    "time"
    
    lru "github.com/hashicorp/golang-lru/v2"
    "github.com/probe-lab/hermes/eth/pubsub/common"
)

// Cache represents a unified deduplication cache
type Cache struct {
    // Topic-specific caches with different key strategies
    attestations        *lru.Cache[string, time.Time]
    aggregates          *lru.Cache[string, time.Time]
    blocks              *lru.Cache[string, time.Time]
    blobs               *lru.Cache[string, time.Time]
    exits               *lru.Cache[string, time.Time]
    proposerSlashings   *lru.Cache[string, time.Time]
    attesterSlashings   *lru.Cache[string, time.Time]
    blsChanges          *lru.Cache[string, time.Time]
    syncMessages        *lru.Cache[string, time.Time]
    syncContributions   *lru.Cache[string, time.Time]
    
    // Epoch-based cleanup tracking
    epochCleanup        map[common.Epoch][]string
    cleanupMu           sync.RWMutex
    
    // Configuration
    config              *Config
    metrics             *Metrics
}

// Config defines cache configuration
type Config struct {
    // Base cache sizes (adjusted per topic)
    AttestationCacheSize      int
    BlockCacheSize            int
    DefaultCacheSize          int
    
    // Retention periods
    AttestationRetention      time.Duration  // ~2 epochs
    BlockRetention            time.Duration  // ~1 epoch
    SlashingRetention         time.Duration  // ~5 epochs
    PermanentRetention        time.Duration  // Until validator exit
    
    // Cleanup intervals
    CleanupInterval           time.Duration
    EpochTransitionBuffer     time.Duration
}
```

### 2.2 Message Type Handlers

Each message type has a specific deduplication strategy:

```go
// MessageType represents different gossipsub message types
type MessageType int

const (
    TypeAttestation MessageType = iota
    TypeAggregateAttestation
    TypeBlock
    TypeBlobSidecar
    TypeVoluntaryExit
    TypeProposerSlashing
    TypeAttesterSlashing
    TypeBLSToExecutionChange
    TypeSyncCommitteeMessage
    TypeSyncCommitteeContribution
)

// DuplicateChecker interface for type-specific duplicate detection
type DuplicateChecker interface {
    // IsDuplicate checks if message is duplicate and marks as seen if not
    IsDuplicate(ctx context.Context, msgType MessageType, data interface{}) (bool, error)
    
    // MarkSeen explicitly marks a message as seen
    MarkSeen(ctx context.Context, msgType MessageType, data interface{}) error
    
    // Cleanup removes old entries based on current slot/epoch
    Cleanup(ctx context.Context, currentEpoch common.Epoch)
}
```

### 2.3 Key Generation Strategies

Different message types require different key generation:

```go
// KeyGenerator generates cache keys for different message types
type KeyGenerator struct {
    forkVersion common.ForkVersion
}

// Attestation key: validator_index + target_epoch
func (kg *KeyGenerator) AttestationKey(validatorIndex common.ValidatorIndex, targetEpoch common.Epoch) string {
    return fmt.Sprintf("att:%d:%d", validatorIndex, targetEpoch)
}

// Aggregate key: aggregator_index + slot
func (kg *KeyGenerator) AggregateKey(aggregatorIndex common.ValidatorIndex, slot common.Slot) string {
    return fmt.Sprintf("agg:%d:%d", aggregatorIndex, slot)
}

// Block key: proposer_index + slot
func (kg *KeyGenerator) BlockKey(proposerIndex common.ValidatorIndex, slot common.Slot) string {
    return fmt.Sprintf("blk:%d:%d", proposerIndex, slot)
}

// Blob key: block_root + proposer_index + blob_index
func (kg *KeyGenerator) BlobKey(blockRoot [32]byte, proposerIndex common.ValidatorIndex, blobIndex uint64) string {
    return fmt.Sprintf("blob:%x:%d:%d", blockRoot[:8], proposerIndex, blobIndex)
}

// Exit key: validator_index (permanent until processed)
func (kg *KeyGenerator) ExitKey(validatorIndex common.ValidatorIndex) string {
    return fmt.Sprintf("exit:%d", validatorIndex)
}

// Proposer slashing key: proposer_index
func (kg *KeyGenerator) ProposerSlashingKey(proposerIndex common.ValidatorIndex) string {
    return fmt.Sprintf("pslash:%d", proposerIndex)
}

// Attester slashing key: sorted validator indices
func (kg *KeyGenerator) AttesterSlashingKey(indices []common.ValidatorIndex) string {
    // Sort indices for consistent key generation
    sorted := make([]common.ValidatorIndex, len(indices))
    copy(sorted, indices)
    sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
    
    h := sha256.New()
    for _, idx := range sorted {
        binary.Write(h, binary.BigEndian, uint64(idx))
    }
    return fmt.Sprintf("aslash:%x", h.Sum(nil)[:8])
}

// Sync committee message key: validator_index + slot
func (kg *KeyGenerator) SyncMessageKey(validatorIndex common.ValidatorIndex, slot common.Slot) string {
    return fmt.Sprintf("sync:%d:%d", validatorIndex, slot)
}

// Sync contribution key: aggregator_index + slot + subcommittee_index
func (kg *KeyGenerator) SyncContributionKey(aggregatorIndex common.ValidatorIndex, slot common.Slot, subcommitteeIndex uint64) string {
    return fmt.Sprintf("syncagg:%d:%d:%d", aggregatorIndex, slot, subcommitteeIndex)
}
```

## 3. Interface Definition

### 3.1 Public API

```go
// NewCache creates a new deduplication cache
func NewCache(config *Config) (*Cache, error) {
    // Initialize LRU caches with appropriate sizes
    // Start cleanup goroutine
    // Return cache instance
}

// IsDuplicate checks if a message is duplicate and marks it as seen
func (c *Cache) IsDuplicate(ctx context.Context, msgType MessageType, data interface{}) (bool, error) {
    switch msgType {
    case TypeAttestation:
        return c.isDuplicateAttestation(ctx, data.(*ethpb.Attestation))
    case TypeAggregateAttestation:
        return c.isDuplicateAggregate(ctx, data.(*ethpb.SignedAggregateAndProof))
    case TypeBlock:
        return c.isDuplicateBlock(ctx, data.(*ethpb.SignedBeaconBlock))
    // ... other types
    default:
        return false, fmt.Errorf("unknown message type: %v", msgType)
    }
}

// CleanupOldEntries removes entries older than retention period
func (c *Cache) CleanupOldEntries(currentEpoch common.Epoch) {
    c.cleanupMu.Lock()
    defer c.cleanupMu.Unlock()
    
    // Clean up epoch-based entries
    for epoch, keys := range c.epochCleanup {
        if epoch < currentEpoch-c.config.RetentionEpochs {
            for _, key := range keys {
                c.removeKey(key)
            }
            delete(c.epochCleanup, epoch)
        }
    }
}

// GetMetrics returns cache performance metrics
func (c *Cache) GetMetrics() *Metrics {
    return &Metrics{
        Hits:       c.metrics.hits.Load(),
        Misses:     c.metrics.misses.Load(),
        Evictions:  c.metrics.evictions.Load(),
        Size:       c.getTotalSize(),
    }
}
```

### 3.2 Integration Points

```go
// Integration with validators
type ValidatorWithDedupe struct {
    validator Validator
    cache     *dedupe.Cache
}

func (v *ValidatorWithDedupe) ValidateAttestation(ctx context.Context, att *ethpb.Attestation) error {
    // Check for duplicate first
    if duplicate, err := v.cache.IsDuplicate(ctx, dedupe.TypeAttestation, att); err != nil {
        return err
    } else if duplicate {
        return ErrIgnore("duplicate attestation")
    }
    
    // Proceed with validation
    return v.validator.ValidateAttestation(ctx, att)
}
```

## 4. Memory-Efficient Implementation

### 4.1 LRU Cache Configuration

```go
// Optimal cache sizes based on network parameters
const (
    // Attestations: ~1M validators / 32 slots = ~31k per slot
    AttestationCacheSize = 100_000  // ~3 slots worth
    
    // Blocks: 1 per slot maximum
    BlockCacheSize = 64  // 2 epochs worth
    
    // Aggregates: ~512 per slot (16 aggregators * 32 subnets)
    AggregateCacheSize = 16_384  // ~32 slots worth
    
    // Blobs: up to 6 per block (Deneb), 3 per block (Fulu)
    BlobCacheSize = 1024  // ~170 blocks worth
    
    // Slashings/Exits: rare events
    SlashingCacheSize = 1000
    ExitCacheSize = 1000
    
    // Sync committee: 512 validators * 32 slots per epoch
    SyncMessageCacheSize = 32_768  // 2 epochs worth
)
```

### 4.2 Memory Usage Optimization

```go
// CompactEntry stores minimal data with timestamp
type CompactEntry struct {
    SeenAt uint32  // Unix timestamp (4 bytes vs 8)
    Epoch  uint16  // Epoch number (2 bytes)
}

// Memory calculation example:
// Attestation cache: 100,000 entries
// Key (avg): ~16 bytes ("att:123456:1234")
// Value: 6 bytes (CompactEntry)
// Overhead: ~8 bytes (LRU pointers)
// Total: 100,000 * 30 bytes = ~3MB
```

### 4.3 Eviction Strategies

```go
// EvictionCallback handles cache evictions
func (c *Cache) onEviction(key string, value interface{}) {
    c.metrics.evictions.Add(1)
    
    // Log if premature eviction (still within retention)
    if entry, ok := value.(CompactEntry); ok {
        age := time.Since(time.Unix(int64(entry.SeenAt), 0))
        if age < c.config.AttestationRetention {
            c.metrics.prematureEvictions.Add(1)
        }
    }
}

// Adaptive sizing based on memory pressure
func (c *Cache) adaptCacheSize() {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    
    // If memory usage > 80%, reduce cache sizes
    if m.Alloc > uint64(0.8 * m.Sys) {
        c.reduceCacheSizes()
    }
}
```

## 5. Cache Sizing and Eviction Strategies

### 5.1 Dynamic Cache Sizing

```go
// DynamicSizer adjusts cache sizes based on network conditions
type DynamicSizer struct {
    baseConfig      *Config
    validatorCount  uint64
    committeeSize   uint64
    
    mu sync.RWMutex
}

func (ds *DynamicSizer) GetAttestationCacheSize() int {
    ds.mu.RLock()
    defer ds.mu.RUnlock()
    
    // Size = validators_per_slot * retention_slots * safety_factor
    slotsPerEpoch := uint64(32)
    retentionSlots := uint64(64)  // 2 epochs
    committeesPerSlot := ds.validatorCount / (ds.committeeSize * slotsPerEpoch)
    attestationsPerSlot := committeesPerSlot * ds.committeeSize
    
    return int(attestationsPerSlot * retentionSlots * 1.5)  // 1.5x safety factor
}
```

### 5.2 Prioritized Eviction

```go
// PriorityEntry adds priority to cache entries
type PriorityEntry struct {
    CompactEntry
    Priority uint8  // 0-255, higher = keep longer
}

// Priority levels
const (
    PriorityNormal    uint8 = 128
    PrioritySlashing  uint8 = 255  // Never evict until processed
    PriorityOldEpoch  uint8 = 64   // Can evict sooner
)

// Custom eviction policy
func (c *Cache) shouldEvict(key string, entry PriorityEntry, currentEpoch common.Epoch) bool {
    // Never evict high priority entries
    if entry.Priority >= PrioritySlashing {
        return false
    }
    
    // Check age against retention policy
    entryEpoch := common.Epoch(entry.Epoch)
    epochAge := currentEpoch - entryEpoch
    
    // Adjust retention based on priority
    adjustedRetention := c.config.RetentionEpochs * uint64(entry.Priority) / 128
    return epochAge > common.Epoch(adjustedRetention)
}
```

## 6. Integration with Slot/Epoch Transitions

### 6.1 Epoch Transition Handler

```go
// EpochTransitionHandler manages cache cleanup at epoch boundaries
type EpochTransitionHandler struct {
    cache       *Cache
    wallclock   common.Wallclock
    cleanupChan chan common.Epoch
}

func (h *EpochTransitionHandler) Start(ctx context.Context) {
    go func() {
        epochSub := h.wallclock.SubscribeEpochTransitions()
        defer epochSub.Unsubscribe()
        
        for {
            select {
            case epoch := <-epochSub.C:
                h.onEpochTransition(epoch)
            case <-ctx.Done():
                return
            }
        }
    }()
}

func (h *EpochTransitionHandler) onEpochTransition(newEpoch common.Epoch) {
    // Schedule cleanup with buffer to handle clock skew
    time.AfterFunc(h.cache.config.EpochTransitionBuffer, func() {
        h.cache.CleanupOldEntries(newEpoch)
        h.updateCacheSizes(newEpoch)
        h.logMetrics(newEpoch)
    })
}
```

### 6.2 Slot-Based Cleanup

```go
// SlotCleanup handles more granular cleanup for time-sensitive caches
type SlotCleanup struct {
    cache     *Cache
    wallclock common.Wallclock
}

func (sc *SlotCleanup) cleanupSlotData(slot common.Slot) {
    // Clean attestations from old slots
    oldSlot := slot - common.Slot(sc.cache.config.AttestationRetentionSlots)
    sc.cache.cleanupAttestationsBeforeSlot(oldSlot)
    
    // Clean sync committee messages (1 slot retention)
    sc.cache.cleanupSyncMessagesBeforeSlot(slot - 1)
    
    // Update metrics
    sc.cache.metrics.lastCleanupSlot.Store(uint64(slot))
}
```

### 6.3 Integration Example

```go
// Complete integration with validators
type IntegratedValidator struct {
    dedupe          *dedupe.Cache
    wallclock       common.Wallclock
    epochHandler    *EpochTransitionHandler
    slotHandler     *SlotCleanup
}

func NewIntegratedValidator(config *Config) (*IntegratedValidator, error) {
    // Create deduplication cache
    dedupeCache, err := dedupe.NewCache(config.DedupeConfig)
    if err != nil {
        return nil, err
    }
    
    // Create wallclock for time tracking
    wallclock := common.NewWallclock(config.GenesisTime, config.SlotDuration)
    
    // Setup epoch transition handler
    epochHandler := &EpochTransitionHandler{
        cache:     dedupeCache,
        wallclock: wallclock,
    }
    
    // Setup slot cleanup
    slotHandler := &SlotCleanup{
        cache:     dedupeCache,
        wallclock: wallclock,
    }
    
    return &IntegratedValidator{
        dedupe:       dedupeCache,
        wallclock:    wallclock,
        epochHandler: epochHandler,
        slotHandler:  slotHandler,
    }, nil
}

func (iv *IntegratedValidator) Start(ctx context.Context) error {
    // Start epoch transition monitoring
    iv.epochHandler.Start(ctx)
    
    // Start slot-based cleanup
    go iv.runSlotCleanup(ctx)
    
    return nil
}
```

## 7. Performance Considerations

### 7.1 Benchmarks

```go
// Expected performance characteristics
// Cache operations: O(1) for LRU get/put
// Key generation: O(n) for attester slashing, O(1) for others
// Memory usage: ~10-20MB total for all caches
// Cleanup: O(n) where n is expired entries

// Benchmark results (example):
// BenchmarkAttestationDedupe-8     5000000    234 ns/op    32 B/op    1 allocs/op
// BenchmarkBlockDedupe-8          10000000    187 ns/op    24 B/op    1 allocs/op
// BenchmarkCleanup1000Entries-8      10000  98234 ns/op   128 B/op    4 allocs/op
```

### 7.2 Optimization Strategies

1. **Batch Operations**: Process multiple deduplication checks together
2. **Sharded Caches**: Split large caches by validator index ranges
3. **Bloom Filters**: Pre-filter before LRU lookup for very large caches
4. **Memory Pooling**: Reuse key strings and entry objects

## 8. Monitoring and Metrics

```go
// Metrics tracks cache performance
type Metrics struct {
    // Hit/Miss rates
    hits              atomic.Uint64
    misses            atomic.Uint64
    
    // Cache sizes
    attestationSize   atomic.Uint64
    blockSize         atomic.Uint64
    totalSize         atomic.Uint64
    
    // Evictions
    evictions         atomic.Uint64
    prematureEvictions atomic.Uint64
    
    // Cleanup stats
    lastCleanupTime   atomic.Int64
    lastCleanupSlot   atomic.Uint64
    cleanupDuration   atomic.Int64
    
    // Memory usage
    memoryUsageBytes  atomic.Uint64
}

// Export Prometheus metrics
func (m *Metrics) Export() {
    prometheus.NewGaugeFunc(prometheus.GaugeOpts{
        Name: "dedupe_cache_hit_rate",
        Help: "Cache hit rate",
    }, func() float64 {
        hits := m.hits.Load()
        misses := m.misses.Load()
        total := hits + misses
        if total == 0 {
            return 0
        }
        return float64(hits) / float64(total)
    })
}
```

## 9. Testing Strategy

```go
// Comprehensive test suite
func TestDeduplicationCache(t *testing.T) {
    t.Run("AttestationDeduplication", testAttestationDedupe)
    t.Run("EpochTransitionCleanup", testEpochCleanup)
    t.Run("MemoryPressure", testMemoryEviction)
    t.Run("ConcurrentAccess", testConcurrency)
    t.Run("ForkTransition", testForkHandling)
}

// Fuzz testing for edge cases
func FuzzDeduplicationKeys(f *testing.F) {
    f.Add(uint64(12345), uint64(100))  // validator_index, epoch
    f.Fuzz(func(t *testing.T, validatorIndex, epoch uint64) {
        kg := &KeyGenerator{}
        key := kg.AttestationKey(common.ValidatorIndex(validatorIndex), common.Epoch(epoch))
        // Verify key properties
        assert.NotEmpty(t, key)
        assert.True(t, strings.HasPrefix(key, "att:"))
    })
}
```

## 10. Migration and Deployment

### 10.1 Gradual Rollout

1. **Phase 1**: Deploy with monitoring only (no rejections)
2. **Phase 2**: Enable for non-critical messages (sync committee)
3. **Phase 3**: Enable for attestations with conservative settings
4. **Phase 4**: Full deployment with tuned parameters

### 10.2 Configuration Example

```yaml
deduplication:
  enabled: true
  
  cache_sizes:
    attestations: 100000
    blocks: 64
    aggregates: 16384
    blobs: 1024
    slashings: 1000
    exits: 1000
    
  retention:
    attestation_epochs: 2
    block_epochs: 1
    slashing_epochs: 5
    permanent_retention: true  # for exits/bls changes
    
  cleanup:
    interval: 6s  # every slot
    epoch_buffer: 500ms  # delay after epoch transition
    
  memory:
    max_memory_mb: 50
    enable_adaptive_sizing: true
    eviction_batch_size: 100
```

## 11. Future Enhancements

1. **Persistent Cache**: Optional disk-backed cache for restart resilience
2. **Distributed Cache**: Redis/Memcached backend for multi-node setups
3. **ML-Based Sizing**: Predict cache sizes based on network patterns
4. **Compression**: Compress old entries to extend retention
5. **Telemetry**: Detailed performance tracking and alerting