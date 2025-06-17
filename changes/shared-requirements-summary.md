# Shared Requirements Summary for Hermes Validation Specs

This document summarizes common requirements and patterns identified across all validation specifications in the ./changes/ directory, prioritized by implementation value.

## 1. Common Missing Components

### 1.1 Historical Block Storage (Critical - Needed by 8+ specs)
**Required by**: beacon_block, beacon_attestation, blob_sidecar, beacon_blocks_by_range, beacon_blocks_by_root, blob_sidecars_by_range, blob_sidecars_by_root, light client protocols

**Requirements**:
- Store blocks for at least 5 months (MIN_EPOCHS_FOR_BLOCK_REQUESTS = 33024 epochs)
- Store blob sidecars for at least 18 days (MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS = 4096 epochs)
- Index by slot and root for efficient retrieval
- Track validation status of blocks
- Support parent-child relationship queries
- Implement pruning mechanism for old data

**Priority**: HIGHEST - Enables multiple validation methods and req/resp protocols

### 1.2 Deduplication Caches (Critical - Needed by 11+ specs)
**Required by**: All pubsub topics (attestations, blocks, slashings, exits, sync committee messages, etc.)

**Common Pattern**:
```go
type DeduplicationCache interface {
    HasSeen(key string) bool
    MarkSeen(key string)
    CleanupOld(maxAge time.Duration)
}
```

**Specific Caches Needed**:
- Per-validator attestation tracking (by target epoch)
- Per-proposer block tracking (by slot)
- Per-validator slashing tracking (attester & proposer)
- Per-validator exit tracking
- Per-validator BLS change tracking
- Per-subnet sync committee message tracking
- Blob sidecar tracking (by slot-proposer-index tuple)

**Priority**: HIGHEST - Required for spec compliance and DoS prevention

### 1.3 Fork Schedule and Version Management (High - Needed by 10+ specs)
**Required by**: All protocols that have fork-specific behavior

**Requirements**:
- Track fork activation epochs (Altair, Bellatrix, Capella, Deneb, Electra, Fulu)
- Determine active fork based on slot/epoch
- Fork-specific message type selection
- Fork-specific validation rules
- Fork-specific constants (e.g., MAX_BLOBS_PER_BLOCK vs MAX_BLOBS_PER_BLOCK_ELECTRA)

**Priority**: HIGH - Essential for multi-fork support

### 1.4 Clock Synchronization and Timing (High - Needed by 8+ specs)
**Required by**: All time-sensitive validations

**Common Constants**:
- `MAXIMUM_GOSSIP_CLOCK_DISPARITY = 500ms`
- Slot timing validation
- Epoch boundary calculations
- Future message tolerance

**Priority**: HIGH - Critical for message timing validation

### 1.5 Light Client Infrastructure (Medium - Needed by 6 specs)
**Required by**: All light client protocols (bootstrap, updates, finality, optimistic)

**Components**:
- Light client store implementation
- Sync committee tracking
- Merkle proof generation/verification
- Light client update computation
- Fork-specific light client types

**Priority**: MEDIUM - Enables light client support but not critical for basic operations

## 2. Common Validation Patterns

### 2.1 Signature Verification Pattern
**Used by**: All signed message types

```go
// Common pattern across specs
1. Get validator public key from state
2. Compute domain (often fork-specific)
3. Compute signing root
4. Verify BLS signature
```

**Abstraction Opportunity**: Create unified signature verification service

### 2.2 Committee Validation Pattern
**Used by**: Attestations, aggregates, sync committee messages

```go
// Common pattern
1. Get committee for slot/index
2. Verify validator is in committee
3. Check subnet assignment (if applicable)
4. Validate aggregation bits match committee size
```

**Abstraction Opportunity**: Create committee service with caching

### 2.3 State Access Pattern
**Used by**: Almost all validators

```go
// Common pattern
1. Get current state from state sync
2. Extract validator info
3. Check validator status (active, slashed, etc.)
4. Get epoch-specific data
```

**Abstraction Opportunity**: Enhanced state provider interface

### 2.4 Message Timing Pattern
**Used by**: All pubsub topics

```go
// Common pattern
1. Get current slot/epoch
2. Check message slot within acceptable range
3. Apply MAXIMUM_GOSSIP_CLOCK_DISPARITY tolerance
4. Handle fork-specific timing rules
```

## 3. Infrastructure Requirements by Mode

### 3.1 Independent Mode Requirements
1. **State Management**:
   - Full beacon state access
   - Historical state for finalized blocks
   - Validator registry with all fields
   - Committee caches

2. **Storage**:
   - Block storage (5+ months)
   - Blob storage (18+ days)  
   - State snapshots
   - Persistent caches for deduplication

3. **Computation**:
   - Proposer shuffling
   - Committee assignments
   - Sync committee calculations
   - Light client update creation

### 3.2 Delegated Mode Requirements
1. **Basic Validation**:
   - Message deserialization
   - Subnet validation (can be done without state)
   - Basic deduplication
   - Rate limiting

2. **Beacon Node Integration**:
   - Forward validation to beacon node
   - Cache validation results
   - Handle validation responses

### 3.3 Upstream Mode Requirements
1. **Beacon API Integration**:
   - Extended endpoints for light client
   - State queries for validation
   - Block/blob retrieval
   - Status synchronization

## 4. Priority Implementation Order

### Phase 1: Core Infrastructure (Enables 80% of validations)
1. **Historical Block Storage**
   - In-memory cache for recent blocks
   - Persistent storage interface
   - Pruning mechanism

2. **Deduplication Framework**
   - Generic cache interface
   - Per-topic cache implementations
   - Cleanup scheduling

3. **Fork Schedule Management**
   - Configuration loading
   - Fork detection utilities
   - Fork-specific routing

### Phase 2: Smart Validation Features
1. **Attestation-Aware Block Propagation**
   - Track attestations by block root
   - Wait for threshold before propagating
   - Implement "smart" validation modes

2. **Enhanced State Management**
   - Proposer cache
   - Committee cache with subnet assignments
   - Sync committee tracking

3. **Signature Verification Service**
   - Batch verification support
   - Domain computation caching
   - Fork-aware signature validation

### Phase 3: Advanced Features
1. **Light Client Support**
   - Store implementation
   - Update computation
   - Proof generation

2. **Req/Resp Independent Mode**
   - Serve historical data
   - Validate requests
   - Rate limiting

3. **Metrics and Monitoring**
   - Validation success/failure rates
   - Cache hit rates
   - Performance metrics

## 5. Minimal Viable Implementation

For a minimal viable implementation that avoids running an execution client:

### Required Components:
1. **Block/Blob Storage** - Can start with in-memory only
2. **Basic Deduplication** - Simple LRU caches
3. **Fork Detection** - Hardcoded fork epochs
4. **State Sync** - Existing implementation is sufficient
5. **Signature Verification** - Already implemented

### Can Defer:
1. Light client protocols
2. Persistent storage (use in-memory initially)
3. Complex caching strategies
4. Full proposer shuffling (can use beacon API)

### Smart Validation MVP:
1. Track attestations by block root (existing AttestationTracker)
2. Configure threshold (e.g., 15 attestations)
3. Delay block propagation until threshold met
4. Simple timeout fallback (e.g., 4 seconds)

This approach provides immediate value by reducing invalid block propagation while avoiding the complexity of running a full execution client.

## 6. Common Missing Constants

These constants appear across multiple specs and should be defined centrally:

```go
const (
    // Timing
    MAXIMUM_GOSSIP_CLOCK_DISPARITY = 500 * time.Millisecond
    ATTESTATION_PROPAGATION_SLOT_RANGE = 32
    
    // Epochs
    MIN_EPOCHS_FOR_BLOCK_REQUESTS = 33024
    MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS = 4096
    FAR_FUTURE_EPOCH = ^uint64(0)
    
    // Validators
    SHARD_COMMITTEE_PERIOD = 256
    
    // Sync Committee
    SYNC_COMMITTEE_SIZE = 512
    SYNC_COMMITTEE_SUBNET_COUNT = 4
    TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE = 16
    
    // Blobs
    MAX_BLOBS_PER_BLOCK = 6
    MAX_BLOBS_PER_BLOCK_ELECTRA = 6 // Update when known
    
    // Requests
    MAX_REQUEST_BLOCKS = 1024
    MAX_REQUEST_BLOCKS_DENEB = 128
    MAX_REQUEST_LIGHT_CLIENT_UPDATES = 128
    MAX_CONCURRENT_REQUESTS = 2
)
```

## 7. Recommendations

1. **Start with Phase 1** infrastructure as it enables the majority of validation improvements
2. **Implement deduplication caches** early as they prevent DoS attacks
3. **Use existing AttestationTracker** as foundation for smart block validation
4. **Defer light client support** unless specifically required
5. **Focus on pubsub validation** before req/resp protocols for maximum impact
6. **Leverage delegated mode** where possible to reduce implementation complexity