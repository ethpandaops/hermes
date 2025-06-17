# Light Client Updates by Range Request/Response Validation Rules

## Protocol: `/eth2/beacon_chain/req/light_client_updates_by_range/1/`

## Overview
The Light Client Updates by Range protocol allows light clients to sync historical light client updates.

## Request Validation Rules

### Request Encoding
1. The request MUST be encoded as an SSZ-container with fields:
   - `start_period: uint64`
   - `count: uint64`

### General Req/Resp Rules
1. Clients MUST NOT make more than `MAX_CONCURRENT_REQUESTS` (2) concurrent requests with the same protocol ID
2. The request MUST be encoded according to the `ssz_snappy` encoding strategy
3. The requester MUST close the write side of the stream once it finishes writing the request message
4. Requests MUST include the encoding-dependent header (length of raw SSZ bytes as protobuf varint)

## Response Validation Rules

### Response Structure
1. The response MUST consist of zero or more `response_chunk`s
2. Each successful `response_chunk` MUST contain a single `LightClientUpdate` payload
3. The response MUST NOT contain more than `min(MAX_REQUEST_LIGHT_CLIENT_UPDATES, count)` results
4. `MAX_REQUEST_LIGHT_CLIENT_UPDATES` = 128

### Ordering and Range
1. Peers MUST respond with at least the earliest known result within the requested range
2. Peers MUST send results in consecutive order (by period)
3. Results should be from the range `[start_period, start_period + count)`

### Fork Version Context
1. For each `response_chunk`, a `ForkDigest`-context based on `compute_fork_version(compute_epoch_at_slot(update.attested_header.beacon.slot))` is used to select the fork namespace

### General Response Rules
1. Responders MUST validate the request before processing it
2. Each response chunk MUST start with a single-byte response code
3. Response codes: 0 (success), 1 (invalid request), 2 (server error), 3 (resource unavailable), 128-255 (reserved)
4. The global maximum uncompressed byte size of `MAX_PAYLOAD_SIZE` MUST be applied to all method response chunks
5. Responses MUST use the `ssz_snappy` encoding strategy with proper length prefixing

### Error Handling
1. If an invalid request is received, responders MUST respond with error code 1
2. For server errors, use error code 2
3. When resources are unavailable, use error code 3
4. Only the last chunk is allowed to have a non-zero error code

### Size Limits
1. The size of the compressed payload must not exceed `max_compressed_len(MAX_PAYLOAD_SIZE)`
2. The size of the uncompressed payload must not exceed `MAX_PAYLOAD_SIZE` or the type-specific SSZ bound

## Fork-Specific Response Types

The response type varies by fork:
- **Altair through Bellatrix**: `altair.LightClientUpdate`
- **Capella**: `capella.LightClientUpdate`
- **Deneb**: `deneb.LightClientUpdate`
- **Electra and later**: `electra.LightClientUpdate`

## Notes
These validation rules ensure proper handling of light client update requests and responses across all consensus layer clients implementing the light client protocol.