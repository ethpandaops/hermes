# Status Request/Response Validation Rules

## Protocol: `/eth2/beacon_chain/req/status/1/` (Phase 0)
## Protocol: `/eth2/beacon_chain/req/status/2/` (Fulu)

## Overview
The Status protocol is used for initial handshake between peers to exchange chain state information.

## Request Validation Rules

### MUST Requirements

1. The dialing client MUST send a `Status` request upon connection
2. The request/response MUST be encoded as an SSZ-container
3. The requester MUST close the write side of the stream once it finishes writing the request message
4. Request processing and validation MUST be done according to the encoding strategy

### MUST NOT Requirements

1. The requester MUST NOT make more than `MAX_CONCURRENT_REQUESTS` concurrent requests with the same protocol ID
2. Messages containing only a single field MUST NOT be encoded as an SSZ container (they MUST be encoded directly as the type of that field)

## Response Validation Rules

### MUST Requirements

1. The response MUST consist of a single `response_chunk`
2. The responder MUST validate the request before processing it
3. The responder MUST:
   - Use the encoding strategy to read the optional header
   - Read exactly N bytes from the stream if there are length assertions
   - Deserialize the expected type and process the request
   - Write the response (zero or more `response_chunk`s)
   - Close their write side of the stream
4. If validation fails due to invalid, malformed, or inconsistent data, the responder MUST respond in error
5. When rate limiting, the responder MUST send each `response_chunk` in full promptly (but may introduce delays between chunks)
6. Error messages MUST be treated as valid for any byte sequences (clients MAY interpret as UTF-8 for debugging)

### MUST NOT Requirements

1. The responder MUST NOT respond with an error or close the stream when rate limiting

## General Request/Response Validation

### MUST Requirements

1. Request/response messages MUST adhere to the encoding specified in the protocol name
2. For both requests and responses, the `encoding-dependent-header` MUST be valid
3. The `encoded-payload` MUST be valid within the constraints of the `encoding-dependent-header`
4. A global maximum uncompressed byte size of `MAX_PAYLOAD_SIZE` MUST be applied to all method response chunks
5. Clients MUST ensure that lengths are within bounds
6. Clients MUST consider the following cases as invalid input:
   - Any remaining bytes after reading the expected SSZ bytes
   - An early EOF before fully reading the declared length-prefix
7. In case of invalid input, a reader MUST:
   - From requests: send back an error message with response code `InvalidRequest`
   - From responses: ignore the response and consider it bad server behavior

## Status Message Fields

### Phase 0
```
(
  fork_digest: ForkDigest
  finalized_root: Root
  finalized_epoch: Epoch
  head_root: Root
  head_slot: Slot
)
```

### Fulu
```
(
  fork_digest: ForkDigest
  finalized_root: Root
  finalized_epoch: Epoch
  head_root: Root
  head_slot: Slot
  earliest_available_slot: Slot  # New field
)
```

## Post-Handshake Disconnection Conditions

Clients SHOULD immediately disconnect following the handshake if:
1. `fork_digest` does not match the node's local `fork_digest`
2. The (`finalized_root`, `finalized_epoch`) shared by the peer is not in the client's chain at the expected epoch

## Response Codes

Valid response codes:
- 0: Success
- 1: InvalidRequest
- 2: ServerError
- 3: ResourceUnavailable
- 128-255: Client-specific alternative error responses
- 4-127: RESERVED (should be treated as error if not recognized)

For multiple chunks, only the last chunk is allowed to have a non-zero error code.