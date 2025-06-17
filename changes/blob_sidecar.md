# Blob Sidecar Validation Analysis for Hermes

## 1. What the Validation Spec Requires

The blob sidecar validation spec (`validation-specs/pubsub/blob_sidecar.md`) requires the following validations:

### MUST Requirements (REJECT on failure):

1. **Index validation**: `blob_sidecar.index < MAX_BLOBS_PER_BLOCK`
2. **Subnet validation**: `compute_subnet_for_blob_sidecar(blob_sidecar.index) == subnet_id`
3. **Proposer signature**: Valid signature on `blob_sidecar.signed_block_header`
4. **Parent validation**: The parent block must pass validation
5. **Parent slot ordering**: Sidecar's slot > parent's slot
6. **Finalized checkpoint ancestry**: Current finalized checkpoint is ancestor of sidecar's block
7. **Inclusion proof**: Valid via `verify_blob_sidecar_inclusion_proof(blob_sidecar)`
8. **KZG proof**: Valid via `verify_blob_kzg_proof(blob_sidecar.blob, blob_sidecar.kzg_commitment, blob_sidecar.kzg_proof)`
9. **Proposer index**: Expected proposer for the slot in current shuffling

### MUST Requirements (IGNORE on failure):

1. **Not future slot**: `block_header.slot <= current_slot` (with `MAXIMUM_GOSSIP_CLOCK_DISPARITY`)
2. **After finalized**: `block_header.slot > compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)`
3. **Parent seen**: Parent block has been seen via gossip or non-gossip
4. **First sidecar**: First valid sidecar for `(slot, proposer_index, blob_index)` tuple

### Electra Fork Changes:
- Replace `MAX_BLOBS_PER_BLOCK` with `MAX_BLOBS_PER_BLOCK_ELECTRA` in validations

## 2. What Currently Exists in Hermes

### Independent Mode (`eth/pubsub/handlers/independent/blob_validator.go`):

The current implementation includes:

1. **Decompression**: Snappy decompression of message data ✓
2. **SSZ Decoding**: Using `deneb.BlobSidecar` type ✓
3. **Index validation**: Checks `sidecar.Index < MAX_BLOBS_PER_BLOCK` ✓
4. **KZG proof verification**: Implemented via `KZGVerifier` ✓
5. **Inclusion proof verification**: Verifies commitment is in block ✓
6. **Proposer signature verification**: Validates block header signature ✓

### Delegated Mode (`eth/pubsub/handlers/delegated/validators.go`):

The current implementation only includes:
1. **Decompression**: Snappy decompression ✓
2. **SSZ Decoding**: Using `ethtypes.BlobSidecar` ✓
3. **No validation**: Just decodes and returns the blob sidecar

### Missing Components:

1. **Subnet validation**: No `compute_subnet_for_blob_sidecar` implementation
2. **Parent block validation**: No checks for parent validity
3. **Parent slot ordering**: Not verified
4. **Finalized checkpoint ancestry**: Not checked
5. **Temporal checks**: No future slot or after-finalized checks
6. **First-seen tracking**: No deduplication for blob sidecars
7. **Proposer shuffling check**: Not verifying expected proposer
8. **Electra support**: No `MAX_BLOBS_PER_BLOCK_ELECTRA` constant or fork handling
9. **MAXIMUM_GOSSIP_CLOCK_DISPARITY**: Not defined or used

## 3. What Needs to Change

### For Both Modes:

1. **Add missing constants**:
```go
// In eth/pubsub/common/utils.go
const MAX_BLOBS_PER_BLOCK_ELECTRA = 6  // Update when Electra spec is finalized
const MAXIMUM_GOSSIP_CLOCK_DISPARITY = 500 * time.Millisecond
```

2. **Add subnet computation function**:
```go
// In eth/pubsub/common/utils.go
func ComputeSubnetForBlobSidecar(blobIndex uint64) uint64 {
    return blobIndex % MAX_BLOBS_PER_BLOCK
}
```

### For Independent Mode:

1. **Update blob_validator.go to add missing validations**:
```go
func (v *BlobSidecarValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
    // ... existing decompression and decoding ...

    // Extract subnet from topic
    subnet, err := common.ExtractBlobSubnet(topic)
    if err != nil {
        return nil, errors.Wrap(err, "failed to extract subnet from topic")
    }

    // Verify subnet matches blob index
    expectedSubnet := common.ComputeSubnetForBlobSidecar(uint64(sidecar.Index))
    if subnet != expectedSubnet {
        return nil, fmt.Errorf("blob on wrong subnet: expected %d, got %d", expectedSubnet, subnet)
    }

    // Get max blobs based on fork
    maxBlobs := common.MAX_BLOBS_PER_BLOCK
    if v.validator.isElectraOrLater() {
        maxBlobs = common.MAX_BLOBS_PER_BLOCK_ELECTRA
    }

    // Verify blob index is within bounds
    if sidecar.Index >= maxBlobs {
        return nil, fmt.Errorf("blob index %d exceeds max %d", sidecar.Index, maxBlobs)
    }

    // Temporal checks
    currentSlot := v.validator.wallclock.CurrentSlot()
    blockSlot := sidecar.SignedBlockHeader.Message.Slot
    
    // Check not from future
    if blockSlot > currentSlot {
        futureTime := v.validator.wallclock.SlotToTime(blockSlot)
        if time.Until(futureTime) > common.MAXIMUM_GOSSIP_CLOCK_DISPARITY {
            return nil, errors.New("blob sidecar from future slot")
        }
    }

    // Check after finalized
    state := v.validator.stateSync.GetCurrentState()
    if state != nil && state.FinalizedCheckpoint != nil {
        finalizedSlot := common.EpochToSlot(state.FinalizedCheckpoint.Epoch)
        if blockSlot <= finalizedSlot {
            return nil, errors.New("blob sidecar from before finalized slot")
        }
    }

    // Parent validation would require historical block storage
    // For now, we'll need to track seen blocks or integrate with a block store
    
    // Check if parent has been seen
    parentRoot := sidecar.SignedBlockHeader.Message.ParentRoot
    if !v.validator.hasSeenBlock(parentRoot) {
        return nil, errors.New("parent block not seen")
    }

    // Verify parent slot ordering
    parentSlot := v.validator.getBlockSlot(parentRoot)
    if parentSlot >= blockSlot {
        return nil, errors.New("blob sidecar slot not greater than parent")
    }

    // Check finalized checkpoint ancestry
    if err := v.verifyFinalizedCheckpointAncestry(sidecar); err != nil {
        return nil, errors.Wrap(err, "finalized checkpoint ancestry check failed")
    }

    // Check expected proposer
    if err := v.verifyExpectedProposer(sidecar); err != nil {
        return nil, errors.Wrap(err, "proposer index check failed")
    }

    // ... existing KZG, inclusion, and signature checks ...

    // First-seen check (after all other validations pass)
    blobKey := fmt.Sprintf("%d-%d-%d", blockSlot, sidecar.SignedBlockHeader.Message.ProposerIndex, sidecar.Index)
    if v.validator.hasSeenBlobSidecar(blobKey) {
        return nil, errors.New("duplicate blob sidecar")
    }
    v.validator.markBlobSidecarSeen(blobKey)

    return sidecar, nil
}
```

2. **Add helper methods to IndependentValidator**:
```go
// Track seen blocks (needed for parent validation)
func (v *IndependentValidator) hasSeenBlock(root [32]byte) bool {
    // This would need integration with block tracking
    // For now, could use a simple LRU cache
    return false
}

func (v *IndependentValidator) getBlockSlot(root [32]byte) common.Slot {
    // Would need block storage integration
    return 0
}

// Track seen blob sidecars for deduplication
func (v *IndependentValidator) hasSeenBlobSidecar(key string) bool {
    v.mu.RLock()
    defer v.mu.RUnlock()
    _, exists := v.seenBlobSidecars.Get(key)
    return exists
}

func (v *IndependentValidator) markBlobSidecarSeen(key string) {
    v.mu.Lock()
    defer v.mu.Unlock()
    v.seenBlobSidecars.Add(key, time.Now())
}
```

3. **Add new validation methods to blob_validator.go**:
```go
func (v *BlobSidecarValidator) verifyFinalizedCheckpointAncestry(sidecar *deneb.BlobSidecar) error {
    state := v.validator.stateSync.GetCurrentState()
    if state == nil || state.FinalizedCheckpoint == nil {
        return errors.New("no finalized checkpoint available")
    }

    // This requires implementing get_checkpoint_block functionality
    // which needs historical block data
    // For now, this is a placeholder
    return nil
}

func (v *BlobSidecarValidator) verifyExpectedProposer(sidecar *deneb.BlobSidecar) error {
    state := v.validator.stateSync.GetCurrentState()
    if state == nil {
        return errors.New("state not available")
    }

    // Get expected proposer for the slot
    expectedProposer, err := v.validator.getProposerIndex(state, sidecar.SignedBlockHeader.Message.Slot)
    if err != nil {
        return errors.Wrap(err, "failed to get expected proposer")
    }

    if sidecar.SignedBlockHeader.Message.ProposerIndex != expectedProposer {
        return fmt.Errorf("unexpected proposer: expected %d, got %d", 
            expectedProposer, sidecar.SignedBlockHeader.Message.ProposerIndex)
    }

    return nil
}
```

### For Delegated Mode:

Since delegated mode relies on an upstream beacon node for validation, it should:

1. **Add minimal checks** that don't require state:
```go
func (v *BlobSidecarValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
    // ... existing decompression and decoding ...

    // Extract subnet from topic
    subnet, err := common.ExtractBlobSubnet(topic)
    if err != nil {
        return nil, fmt.Errorf("failed to extract subnet from topic: %w", err)
    }

    // Verify subnet matches blob index
    expectedSubnet := common.ComputeSubnetForBlobSidecar(uint64(blob.Index))
    if subnet != expectedSubnet {
        return nil, fmt.Errorf("blob on wrong subnet: expected %d, got %d", expectedSubnet, subnet)
    }

    // Basic index validation
    maxBlobs := common.MAX_BLOBS_PER_BLOCK
    if v.handler.forkVersion == common.ElectraForkVersion {
        maxBlobs = common.MAX_BLOBS_PER_BLOCK_ELECTRA
    }
    
    if blob.Index >= maxBlobs {
        return nil, fmt.Errorf("blob index %d exceeds max %d", blob.Index, maxBlobs)
    }

    return blob, nil
}
```

## 4. Dependencies on Missing Components

### Historical Block Storage
Several validations require access to historical blocks:
- Parent block validation
- Parent slot ordering  
- Finalized checkpoint ancestry check

**Options:**
1. Integrate with a beacon node's block storage
2. Implement a local block cache/database
3. Use the `eth/reqresp` package to fetch blocks on demand

### Proposer Shuffling
The expected proposer check requires:
- Access to the validator shuffling for each epoch
- Implementation of `get_beacon_proposer_index` logic

This could leverage the existing `committeeCache` in independent mode.

### State Fork Tracking
Proper Electra support requires:
- Tracking the current fork version
- Using appropriate constants based on fork

This partially exists but needs enhancement for blob-specific constants.

## 5. Implementation Priority

1. **High Priority** (core functionality):
   - Subnet validation
   - Index bounds checking with fork support
   - Basic temporal checks (future slot, after finalized)

2. **Medium Priority** (security):
   - First-seen deduplication
   - KZG and inclusion proof (already implemented)
   - Proposer signature (already implemented)

3. **Low Priority** (requires infrastructure):
   - Parent block validation
   - Finalized checkpoint ancestry
   - Expected proposer verification

## 6. Testing Considerations

New test cases needed:
- Blob sidecars on wrong subnet
- Blob index exceeding max for fork
- Future slot blobs
- Pre-finalized blobs
- Duplicate blob sidecars
- Invalid KZG proofs
- Invalid inclusion proofs
- Fork transition scenarios (Deneb to Electra)