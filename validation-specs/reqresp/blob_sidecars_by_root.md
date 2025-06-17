# BlobSidecarsByRoot Request/Response Validation Rules

## Protocol: `/eth2/beacon_chain/req/blob_sidecars_by_root/1/`

## Overview
The BlobSidecarsByRoot protocol allows peers to request specific blob sidecars by their block root and index.

## Request Validation Rules

### Request Size Limit
1. MUST NOT request more than `MAX_REQUEST_BLOB_SIDECARS` at a time (128 * MAX_BLOBS_PER_BLOCK in Deneb, updated to `MAX_REQUEST_BLOB_SIDECARS_ELECTRA` in Electra)

## Response Validation Rules

### For the Responding Peer

1. **MUST** support requesting sidecars since `minimum_request_epoch`, where:
   - `minimum_request_epoch = max(finalized_epoch, current_epoch - MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS, DENEB_FORK_EPOCH)`
   - If any root in the request references a block earlier than `minimum_request_epoch`, peers **MAY** respond with error code `3: ResourceUnavailable` or not include the blob sidecar in the response

2. **MUST** respond with at least one sidecar, if they have it

3. **SHOULD** include a sidecar in the response as soon as it passes the gossip validation rules

4. **SHOULD NOT** respond with sidecars related to blocks that fail gossip validation rules

5. **SHOULD NOT** respond with sidecars related to blocks that fail the beacon chain state transition

6. The response **MUST** consist of zero or more `response_chunk`. Each successful `response_chunk` **MUST** contain a single `BlobSidecar` payload

7. For each `response_chunk`, a `ForkDigest`-context based on `compute_fork_version(compute_epoch_at_slot(blob_sidecar.signed_block_header.message.slot))` is used to select the fork namespace

### For the Requesting Peer (Response Reader)

Before consuming the next response chunk, the response reader **SHOULD** verify:
1. The blob sidecar is well-formatted
2. Has valid inclusion proof (via `verify_blob_sidecar_inclusion_proof`)
3. Is correct w.r.t. the expected KZG commitments through `verify_blob_kzg_proof`

## Additional Context from Fork Choice

- The block **MUST NOT** be considered valid until all valid `Blob`s have been downloaded
- Blocks that have been previously validated as available **SHOULD** be considered available even if the associated `Blob`s have subsequently been pruned
- Extraneous or invalid Blobs (in addition to KZG expected/referenced valid blobs) received on the p2p network **MUST NOT** invalidate a block that is otherwise valid and available

## Key Constants

- `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS`: 4096 epochs (~18 days)
- `MAX_REQUEST_BLOB_SIDECARS`: MAX_REQUEST_BLOCKS_DENEB * MAX_BLOBS_PER_BLOCK (updated in Electra)

## Notes
These validation rules ensure that blob sidecars are properly validated before being accepted, that peers maintain the required historical data, and that the request/response protocol operates within defined limits.