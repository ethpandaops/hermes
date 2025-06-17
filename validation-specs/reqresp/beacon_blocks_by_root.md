# BeaconBlocksByRoot Request/Response Validation Rules

## Protocol: `/eth2/beacon_chain/req/beacon_blocks_by_root/2/`

## Overview
The BeaconBlocksByRoot protocol allows peers to request specific beacon blocks by their root hash.

## Request Validation Rules

### Request Size Limit
1. MUST NOT request more than `MAX_REQUEST_BLOCKS` blocks at a time
   - Phase 0: `MAX_REQUEST_BLOCKS = 1024`
   - Deneb+: `MAX_REQUEST_BLOCKS_DENEB = 128`

### Request Encoding
1. Request MUST be encoded as an SSZ-field
2. Request content is `List[Root, MAX_REQUEST_BLOCKS]` where each Root is the block root (`hash_tree_root(SignedBeaconBlock.message)`)

### General Request Validation
1. Request MUST adhere to the encoding specified in the protocol name
2. Requester MUST close the write side of the stream after sending the request
3. Requester MUST NOT make more than `MAX_CONCURRENT_REQUESTS` concurrent requests with the same protocol ID
4. The length-prefix MUST be encoded as an unsigned protobuf varint
5. The length-prefix MUST be within expected size bounds

## Response Validation Rules

### Response Format
1. Response MUST consist of zero or more `response_chunk`s
2. Each successful `response_chunk` MUST contain a single `SignedBeaconBlock` payload
3. Response is a `List[SignedBeaconBlock, MAX_REQUEST_BLOCKS]`

### Block Availability
1. Clients MUST support requesting blocks since the latest finalized epoch
2. Clients MUST respond with at least one block, if they have it
3. Clients MAY limit the number of blocks in the response
4. The response length may be less than requested if the responding peer is missing blocks

### Block Validation (Deneb modification)
1. Clients SHOULD include a block in the response as soon as it passes the gossip validation rules
2. Clients SHOULD NOT respond with blocks that fail the beacon chain state transition

### Fork Context (v2)
A `ForkDigest`-context is used to select the fork namespace of the Response type. Response blocks must use the appropriate SSZ type based on fork version:
- `GENESIS_FORK_VERSION`: `phase0.SignedBeaconBlock`
- `ALTAIR_FORK_VERSION`: `altair.SignedBeaconBlock`
- `BELLATRIX_FORK_VERSION`: `bellatrix.SignedBeaconBlock`
- `CAPELLA_FORK_VERSION`: `capella.SignedBeaconBlock`
- `DENEB_FORK_VERSION`: `deneb.SignedBeaconBlock`
- `ELECTRA_FORK_VERSION`: `electra.SignedBeaconBlock`

### Error Handling
1. If a peer doesn't have a requested block, they simply omit it from the response (no error)
2. Responder MAY use `ResourceUnavailable` error code if unable to serve the request
3. Response code MUST be one of:
   - 0: Success
   - 1: InvalidRequest
   - 2: ServerError
   - 3: ResourceUnavailable

### General Response Validation
1. Response MUST adhere to the encoding strategy
2. Each chunk MUST start with a single-byte response code
3. For multiple chunks, only the last chunk is allowed to have a non-zero error code
4. The size of uncompressed payload MUST NOT exceed `MAX_PAYLOAD_SIZE` or type-specific bounds
5. Responder MUST close their write side of the stream after sending all chunks

## Additional Notes

- `BeaconBlocksByRoot` is primarily used to recover recent blocks (e.g., when receiving a block or attestation whose parent is unknown)
- v1 of the protocol (`/eth2/beacon_chain/req/beacon_blocks_by_root/1/`) is deprecated
- Clients MAY respond with an empty list during the deprecation transition period for v1
- There is no special encoding for missing blocks - they are simply omitted from the response