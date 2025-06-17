# BlobSidecarsByRange Validation Analysis for Hermes

## 1. What the Validation Spec Requires

The BlobSidecarsByRange validation spec (located at `/validation-specs/reqresp/blob_sidecars_by_range.md`) defines the following requirements:

### Request Validation
- Request must be SSZ-encoded containing:
  - `start_slot: Slot`
  - `count: uint64`
- Must not request more than `MAX_REQUEST_BLOCKS_DENEB * MAX_BLOBS_PER_BLOCK` blob sidecars (768 for mainnet)

### Server-side Response Requirements

#### Epoch Range Requirements
- **MUST keep blob sidecars for `blob_serve_range`**:
  ```
  blob_serve_range = [max(current_epoch - MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS, DENEB_FORK_EPOCH), current_epoch]
  where MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS = 4096 epochs (~18 days)
  ```
- Current epoch is determined by wall-clock time

#### Response Content Requirements
- Response consists of zero or more `response_chunk`
- Each successful chunk contains a single `BlobSidecar` payload
- MUST respond with at least the first blob-carrying block in range (if available)
- MUST NOT respond with more than `MAX_REQUEST_BLOB_SIDECARS` sidecars
- Response MUST contain no more than `count * MAX_BLOBS_PER_BLOCK` blob sidecars

#### Completeness Requirements
- **MUST include ALL blob sidecars from each block** (no partial blocks)

#### Fork Choice Consistency
- MUST respond with blob sidecars from current fork choice view
- Sidecars must be from single chain defined by current head
- Pre-finalization blocks MUST lead to finalized block from Status handshake
- Response must be consistent within single chain context

#### Ordering Requirements
- Blob sidecars MUST be sent in consecutive `(slot, index)` order

#### Error Handling
- If unable to serve within `blob_serve_range`, SHOULD respond with error code `3: ResourceUnavailable`

### Client-side Validation Requirements
Before consuming response chunks, client SHOULD verify:
- Blob sidecar is well-formatted
- Has valid inclusion proof (via `verify_blob_sidecar_inclusion_proof`)
- Correct KZG commitments (via `verify_blob_kzg_proof`)

### Fork-specific Updates
- **Electra**: Updates `MAX_REQUEST_BLOB_SIDECARS` to `MAX_REQUEST_BLOB_SIDECARS_ELECTRA`
- **Fulu**: v1 becomes deprecated at `FULU_FORK_EPOCH + MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS`

## 2. What Currently Exists in Hermes

### Upstream Mode Implementation (`/eth/reqresp/upstream/`)

#### blobs.go
- **handleBlobSidecarsByRange** function implemented
- Basic request validation (count > 0, max blob sidecars limit)
- Fetches blobs from beacon API via `beaconClient.GetBlobSidecarsByRange`
- Writes success response code followed by SSZ-encoded blob sidecars
- Uses fork digest prefix for each chunk

#### beacon_client.go
- **GetBlobSidecarsByRange** function uses beacon API endpoint:
  ```
  /eth/v1/beacon/blob_sidecars?start_slot={start}&count={count}
  ```
- Simply fetches and returns blob sidecars from beacon node

#### Issues with Current Upstream Implementation:
1. **No epoch range validation** - doesn't check `blob_serve_range`
2. **No fork choice consistency checks**
3. **No completeness validation** (ensuring all blobs from a block)
4. **No ordering validation** (consecutive slot,index order)
5. **No proper error handling for ResourceUnavailable**
6. **No client-side validation of received blobs**

### Delegated Mode Implementation (`/eth/reqresp/delegated/`)

#### handler.go
- **BlobSidecarsByRange** simply delegates entire stream to another peer
- No validation performed at all
- Just forwards request and response between peers

#### Issues with Current Delegated Implementation:
1. **No validation whatsoever** - completely trusts delegate peer
2. **No error handling specific to blob sidecars**
3. **No metrics or monitoring of delegated responses**

### Protocol Registration (`/eth/reqresp/handler.go`)
- Protocol properly registered as `/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy`
- Handler functions properly wired up for both modes

## 3. What Needs to Change

### For Independent Mode (Not Yet Implemented)

An independent validator mode would need to:

1. **Implement Historical Blob Storage**
   - Store blob sidecars for at least `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` epochs
   - Index by (slot, index) for efficient retrieval
   - Track blob availability per slot

2. **Implement Epoch Range Validation**
   ```go
   func isWithinBlobServeRange(slot Slot, currentEpoch Epoch) bool {
       slotEpoch := computeEpochAtSlot(slot)
       minEpoch := max(currentEpoch - MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS, DENEB_FORK_EPOCH)
       return slotEpoch >= minEpoch && slotEpoch <= currentEpoch
   }
   ```

3. **Implement Fork Choice Integration**
   - Access to current head state
   - Validate requested slots are on canonical chain
   - Check consistency with finalized checkpoint

4. **Implement Response Building**
   - Query blob storage for requested range
   - Ensure completeness (all blobs from included blocks)
   - Sort by (slot, index)
   - Enforce max response limits

### For Upstream Mode

1. **Add Epoch Range Validation**
   ```go
   // In handleBlobSidecarsByRange
   currentSlot := getCurrentSlot()
   currentEpoch := computeEpochAtSlot(currentSlot)
   
   // Check if request is within serveable range
   startEpoch := computeEpochAtSlot(req.StartSlot)
   endEpoch := computeEpochAtSlot(req.StartSlot + req.Count - 1)
   
   minServeEpoch := max(currentEpoch - MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS, DENEB_FORK_EPOCH)
   if startEpoch < minServeEpoch {
       return h.writeErrorResponse(stream, ResponseCodeResourceUnavailable)
   }
   ```

2. **Add Response Validation**
   ```go
   // After fetching blobs from beacon API
   if err := validateBlobResponse(blobs, req.StartSlot, req.Count); err != nil {
       h.logger.Error("Invalid blob response from beacon node", "err", err)
       return h.writeErrorResponse(stream, ResponseCodeServerError)
   }
   ```

3. **Implement validateBlobResponse**
   - Check ordering (consecutive slot, index)
   - Verify completeness (all blobs from each block)
   - Validate against max limits

### For Delegated Mode

1. **Add Basic Response Validation**
   - Parse response chunks to ensure well-formed
   - Verify response codes
   - Add metrics for monitoring

2. **Add Optional Validation**
   - Configuration option to enable validation
   - If enabled, parse and validate blob sidecars similar to upstream mode

## 4. Specific Code Examples and File Locations

### New Files Needed

1. **`/eth/reqresp/upstream/blob_validator.go`**
```go
package upstream

import (
    "fmt"
    "github.com/attestantio/go-eth2-client/spec/deneb"
)

// validateBlobResponse validates a blob sidecar response
func validateBlobResponse(blobs []*deneb.BlobSidecar, startSlot uint64, count uint64) error {
    if len(blobs) == 0 {
        return nil // Empty response is valid
    }
    
    // Check ordering
    var lastSlot uint64
    var lastIndex uint64
    blockBlobCounts := make(map[uint64]map[uint64]bool)
    
    for i, blob := range blobs {
        slot := uint64(blob.Slot)
        index := uint64(blob.Index)
        
        // First blob
        if i == 0 {
            lastSlot = slot
            lastIndex = index
        } else {
            // Check consecutive ordering
            if slot < lastSlot || (slot == lastSlot && index <= lastIndex) {
                return fmt.Errorf("blobs not in consecutive (slot, index) order at position %d", i)
            }
        }
        
        // Track blobs per block
        if blockBlobCounts[slot] == nil {
            blockBlobCounts[slot] = make(map[uint64]bool)
        }
        blockBlobCounts[slot][index] = true
        
        lastSlot = slot
        lastIndex = index
    }
    
    // Check completeness - all blobs from 0 to max index
    for slot, indices := range blockBlobCounts {
        maxIndex := uint64(0)
        for idx := range indices {
            if idx > maxIndex {
                maxIndex = idx
            }
        }
        
        // Check all indices from 0 to maxIndex are present
        for i := uint64(0); i <= maxIndex; i++ {
            if !indices[i] {
                return fmt.Errorf("missing blob index %d for slot %d", i, slot)
            }
        }
    }
    
    return nil
}

// Additional validation functions...
```

2. **`/eth/reqresp/independent/`** (New Package)
   - Would need complete implementation of independent validator
   - Blob storage interface and implementation
   - Fork choice integration
   - State management

### Files to Modify

1. **`/eth/reqresp/upstream/blobs.go`**
   - Add epoch range validation
   - Add response validation
   - Improve error handling

2. **`/eth/reqresp/delegated/handler.go`**
   - Add optional response validation
   - Add metrics collection
   - Improve error handling

3. **`/eth/reqresp/upstream/beacon_client.go`**
   - Add method to get current slot/epoch
   - Add method to get fork choice information

## 5. Dependencies on Missing Components

### For Independent Mode Implementation

1. **Historical Block/Blob Storage System**
   - Need persistent storage for ~18 days of blob data
   - Efficient indexing by (slot, index)
   - Pruning mechanism for old data
   - Example interface:
   ```go
   type BlobStorage interface {
       StoreBlobSidecar(blob *deneb.BlobSidecar) error
       GetBlobSidecarsByRange(startSlot, count uint64) ([]*deneb.BlobSidecar, error)
       GetBlobSidecarsByRoot(blockRoots []Root, indices []uint64) ([]*deneb.BlobSidecar, error)
       PruneOldBlobs(currentEpoch Epoch) error
   }
   ```

2. **Fork Choice Integration**
   - Access to canonical chain information
   - Head state tracking
   - Finalized checkpoint tracking

3. **Consensus Layer State Management**
   - Current slot/epoch tracking
   - Fork version management
   - Network configuration (DENEB_FORK_EPOCH, etc.)

4. **KZG Verification**
   - Already exists in `/eth/pubsub/handlers/independent/kzg_setup.go`
   - Would need integration for response validation

### For Both Modes

1. **Time/Slot Management**
   - Reliable wall-clock to slot conversion
   - Epoch calculation utilities
   - Already partially exists in independent validator components

2. **Configuration Management**
   - Network-specific constants (MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS, etc.)
   - Fork schedule information
   - Blob-specific parameters

3. **Metrics and Monitoring**
   - Request/response counters
   - Validation failure tracking
   - Performance metrics

## Summary

The current Hermes implementation of BlobSidecarsByRange is minimal and doesn't enforce most of the validation rules specified in the spec. The upstream mode simply proxies to a beacon node without validation, while the delegated mode blindly forwards streams. 

To achieve full compliance, Hermes needs:
1. Epoch range validation based on wall-clock time
2. Response validation for ordering and completeness
3. For independent mode: a complete blob storage system and fork choice integration
4. Better error handling and metrics

The most critical missing piece is the historical blob storage system, which would be required for a fully independent implementation.