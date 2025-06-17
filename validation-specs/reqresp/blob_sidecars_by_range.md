# BlobSidecarsByRange Request/Response Validation Rules

## Protocol: `/eth2/beacon_chain/req/blob_sidecars_by_range/1/`

## Overview
The BlobSidecarsByRange protocol allows peers to request a range of blob sidecars by slot.

## Request Validation

### Request Structure
- The request MUST be encoded as an SSZ-container with:
  - `start_slot: Slot`
  - `count: uint64`

### Request Limits
- No more than `MAX_REQUEST_BLOCKS_DENEB * MAX_BLOBS_PER_BLOCK` blob sidecars may be requested (via the `count` parameter)

## Response Validation (Server-side requirements)

### Epoch Range Requirements
1. Clients MUST keep a record of blob sidecars seen on the epoch range `blob_serve_range` where:
   - `blob_serve_range = [max(current_epoch - MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS, DENEB_FORK_EPOCH), current_epoch]`
   - `current_epoch` is defined by the current wall-clock time
2. Clients MUST support serving requests of blobs on this range

### Response Content Requirements
1. The response MUST consist of zero or more `response_chunk`
2. Each successful `response_chunk` MUST contain a single `BlobSidecar` payload
3. Clients MUST respond with at least the blob sidecars of the first blob-carrying block that exists in the range, if they have it
4. Clients MUST NOT respond with more than `MAX_REQUEST_BLOB_SIDECARS` sidecars
5. The response MUST contain no more than `count * MAX_BLOBS_PER_BLOCK` blob sidecars

### Completeness Requirements
1. Clients MUST include all blob sidecars of each block from which they include blob sidecars (i.e., if including any sidecars from a block, include all of them)

### Fork Choice Consistency
1. Clients MUST respond with blob sidecars from their view of the current fork choice
2. Blob sidecars must be from blocks on the single chain defined by the current head
3. Blocks from slots before finalization MUST lead to the finalized block reported in the `Status` handshake
4. Clients MUST respond with blob sidecars that are consistent from a single chain within the context of the request

### Ordering Requirements
1. The blob sidecars MUST be sent in consecutive `(slot, index)` order

### Error Handling
1. Peers unable to reply to blob sidecar requests within the `blob_serve_range` SHOULD respond with error code `3: ResourceUnavailable`

## Response Validation (Client-side requirements)

Before consuming the next response chunk, the response reader SHOULD verify:
- The blob sidecar is well-formatted
- Has valid inclusion proof (via `verify_blob_sidecar_inclusion_proof`)
- Is correct w.r.t. the expected KZG commitments through `verify_blob_kzg_proof`

## Fork-specific Updates

### Electra (EIP7691)
- Updates `MAX_REQUEST_BLOB_SIDECARS` to `MAX_REQUEST_BLOB_SIDECARS_ELECTRA`
- Response content list size updated to `List[BlobSidecar, MAX_REQUEST_BLOB_SIDECARS_ELECTRA]`

### Fulu
- BlobSidecarsByRange v1 becomes deprecated as of `FULU_FORK_EPOCH + MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS`
- During deprecation transition, specific rules apply for handling requests spanning the fork boundary

## Key Constants
- `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS = 2**12` (4096 epochs, ~18 days)
- `MAX_REQUEST_BLOCKS_DENEB = 2**7` (128)
- `MAX_REQUEST_BLOB_SIDECARS = MAX_REQUEST_BLOCKS_DENEB * MAX_BLOBS_PER_BLOCK`