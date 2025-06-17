# Beacon Block Validation Analysis for Hermes

## 1. What the Validation Spec Requires

The beacon block validation spec (`validation-specs/pubsub/beacon_block.md`) defines comprehensive validation rules that have evolved across different Ethereum forks:

### Phase 0 (Base Rules)

1. **Timing Validations**:
   - **[IGNORE]** Block not from future: `slot <= current_slot` (with `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance)
   - **[IGNORE]** Block after finalized slot: `slot > compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)`

2. **Signature Validation**:
   - **[REJECT]** Valid proposer signature with respect to `proposer_index` pubkey

3. **Uniqueness Validation**:
   - **[IGNORE]** First block with valid signature for the proposer at this slot

4. **Chain Validations**:
   - **[IGNORE]** Block's parent has been seen (via gossip or non-gossip)
   - **[REJECT]** Block's parent passes validation
   - **[REJECT]** Block is from higher slot than parent
   - **[REJECT]** Finalized checkpoint is ancestor of block

5. **Proposer Validation**:
   - **[REJECT]** Block from expected `proposer_index` for slot (may queue if cannot verify immediately)

### Bellatrix Fork (Merge)

When execution is enabled:
- **[REJECT]** Correct execution payload timestamp: `execution_payload.timestamp == compute_timestamp_at_slot(state, block.slot)`
- Different parent validation based on execution payload verification status

### Deneb Fork

- **[REJECT]** KZG commitments count: `len(blob_kzg_commitments) <= MAX_BLOBS_PER_BLOCK`

### Electra Fork

- **[REJECT]** Updated KZG commitments count: `len(blob_kzg_commitments) <= MAX_BLOBS_PER_BLOCK_ELECTRA`

## 2. What Currently Exists in Hermes

### Independent Mode (`eth/pubsub/handlers/independent/block_validator.go`)

Current implementation includes:

1. **Decompression**: Snappy decompression of gossip data
2. **Fork-aware Deserialization**: Attempts to unmarshal for each fork version (Electra → Phase0)
3. **Basic Validations**:
   - Slot not from future (simple check without `MAXIMUM_GOSSIP_CLOCK_DISPARITY`)
   - Slot recency check (hardcoded 64 slots)
   - Proposer signature verification

**Missing validations**:
- No finalized checkpoint ancestry check
- No parent block validation
- No proposer index verification against shuffling
- No execution payload timestamp validation
- No KZG commitments validation
- No duplicate block tracking
- No `MAXIMUM_GOSSIP_CLOCK_DISPARITY` tolerance

### Delegated Mode (`eth/pubsub/handlers/delegated/validators.go`)

Current implementation:
- Only deserializes blocks based on fork version
- No validation logic (pure deserialization)

## 3. What Needs to Change

### For Independent Mode

1. **Add Missing Core Validations**:
   ```go
   // Add to BeaconBlockValidator struct
   type BeaconBlockValidator struct {
       validator           *IndependentValidator
       seenBlocks         *lru.Cache // Track seen blocks per proposer/slot
       blockStore         BlockStore  // For parent block checks
       maxClockDisparity  time.Duration
   }
   ```

2. **Implement Timing Validation with Clock Disparity**:
   ```go
   // Check future slot with MAXIMUM_GOSSIP_CLOCK_DISPARITY
   currentTime := time.Now()
   slotTime := v.validator.stateSync.GenesisTime + (uint64(slot) * 12)
   if slotTime > currentTime.Unix() + int64(v.maxClockDisparity.Seconds()) {
       return nil, ErrIgnore("block from future slot")
   }
   ```

3. **Add Finalized Checkpoint Validation**:
   ```go
   // Check block after finalized slot
   finalizedSlot := v.validator.stateSync.GetFinalizedCheckpoint().Epoch * 32
   if slot <= finalizedSlot {
       return nil, ErrIgnore("block before finalized slot")
   }
   ```

4. **Implement Parent Block Validation**:
   ```go
   // Check parent exists and is valid
   parentRoot := getParentRoot(block)
   if !v.blockStore.HasBlock(parentRoot) {
       return nil, ErrIgnore("parent block not seen")
   }
   
   // Verify parent passed validation
   if !v.blockStore.IsValidated(parentRoot) {
       return nil, ErrReject("parent block failed validation")
   }
   
   // Check slot ordering
   parentSlot := v.blockStore.GetSlot(parentRoot)
   if slot <= parentSlot {
       return nil, ErrReject("block slot not higher than parent")
   }
   ```

5. **Add Proposer Index Validation**:
   ```go
   // Get expected proposer for slot
   expectedProposer, err := v.validator.GetProposerForSlot(slot)
   if err != nil {
       // Cannot verify immediately, queue for later
       return nil, ErrIgnore("cannot verify proposer yet")
   }
   
   if proposerIndex != expectedProposer {
       return nil, ErrReject("incorrect proposer for slot")
   }
   ```

6. **Implement Fork-Specific Validations**:
   ```go
   // Bellatrix+ execution payload validation
   if v.validator.IsExecutionEnabled(slot) {
       if !v.validateExecutionPayloadTimestamp(block, slot) {
           return nil, ErrReject("invalid execution payload timestamp")
       }
   }
   
   // Deneb+ blob validation
   if v.validator.IsDenebOrLater(slot) {
       maxBlobs := v.validator.GetMaxBlobsPerBlock(slot)
       if len(getBlobCommitments(block)) > maxBlobs {
           return nil, ErrReject("too many blob commitments")
       }
   }
   ```

7. **Track Seen Blocks**:
   ```go
   // Check if we've seen a block from this proposer for this slot
   key := fmt.Sprintf("%d-%d", proposerIndex, slot)
   if v.seenBlocks.Contains(key) {
       return nil, ErrIgnore("already seen block from proposer for slot")
   }
   v.seenBlocks.Add(key, true)
   ```

### For Delegated Mode

Since delegated mode relies on the beacon node for validation, minimal changes needed:

1. **Add Validation Result Tracking**:
   ```go
   // Track validation results from beacon node
   type ValidationResult struct {
       Valid  bool
       Reason string
   }
   ```

2. **Query Beacon Node for Validation Status** (if API available)

## 4. Specific Code Examples and File Locations

### Files to Modify:

1. **`eth/pubsub/handlers/independent/block_validator.go`**:
   - Add complete validation logic as shown above
   - Import necessary packages for LRU cache, time handling

2. **`eth/pubsub/handlers/independent/independent_validator.go`**:
   - Add methods for proposer calculation
   - Add fork version detection methods

3. **Create `eth/pubsub/handlers/independent/block_store.go`**:
   ```go
   package independent
   
   import (
       "sync"
       lru "github.com/hashicorp/golang-lru"
   )
   
   type BlockStore interface {
       HasBlock(root [32]byte) bool
       IsValidated(root [32]byte) bool
       GetSlot(root [32]byte) phase0.Slot
       StoreBlock(root [32]byte, slot phase0.Slot, validated bool)
   }
   
   type InMemoryBlockStore struct {
       mu         sync.RWMutex
       blocks     *lru.Cache
       validated  map[[32]byte]bool
   }
   ```

4. **Update `eth/pubsub/common/errors.go`** (create if doesn't exist):
   ```go
   package common
   
   type ValidationError struct {
       Type   string // "ignore" or "reject"
       Reason string
   }
   
   func ErrIgnore(reason string) error {
       return &ValidationError{Type: "ignore", Reason: reason}
   }
   
   func ErrReject(reason string) error {
       return &ValidationError{Type: "reject", Reason: reason}
   }
   ```

## 5. Dependencies on Missing Components

### Required New Components:

1. **Historical Block Storage**:
   - Need to store recent blocks (at least 2 epochs worth)
   - Track validation status of blocks
   - Required for parent block validation

2. **Proposer Calculation**:
   - Need access to validator shuffling
   - Requires beacon state or committee assignments
   - May need to queue blocks if shuffling not available

3. **Fork Schedule Tracking**:
   - Need to know when Bellatrix, Deneb, Electra activated
   - Required for fork-specific validations

4. **Clock Synchronization**:
   - Need accurate time for `MAXIMUM_GOSSIP_CLOCK_DISPARITY`
   - Consider using beacon node time if available

### Integration Points:

1. **State Sync Enhancement**:
   - `eth/pubsub/handlers/independent/state_sync.go` needs to expose:
     - Finalized checkpoint
     - Genesis time
     - Fork schedule

2. **Configuration**:
   - Add to node config:
     - `MAX_CLOCK_DISPARITY` (default 500ms)
     - `BLOCK_CACHE_SIZE` (default 1000)
     - Fork activation epochs

3. **Metrics**:
   - Track validation outcomes (ignore vs reject)
   - Monitor parent block availability
   - Track proposer verification delays

## Implementation Priority

1. **Phase 1**: Basic validations (timing, signature, slot ordering)
2. **Phase 2**: Parent block and finalization checks (requires block store)
3. **Phase 3**: Proposer verification (requires shuffling access)
4. **Phase 4**: Fork-specific validations (execution, blobs)

## Testing Considerations

- Mock block store for unit tests
- Test edge cases around fork boundaries
- Verify clock disparity handling
- Test queue behavior when parent missing