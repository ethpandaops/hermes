# Metadata Request/Response Validation Rules from Consensus Specs

Based on searching the consensus-specs p2p-interface.md files across all forks, here are the MUST and MUST NOT requirements for handling metadata requests and responses:

## Metadata Storage and Updates

### Phase 0
- Clients MUST locally store the `MetaData` structure containing:
  - `seq_number`: uint64
  - `attnets`: Bitvector[ATTESTATION_SUBNET_COUNT]

- If any field in the local `MetaData` changes, the node MUST increment `seq_number` by 1
- `seq_number` starts at 0

### Altair and Later
- The `MetaData` structure is extended to include:
  - `seq_number`: uint64
  - `attnets`: Bitvector[ATTESTATION_SUBNET_COUNT]
  - `syncnets`: Bitvector[SYNC_COMMITTEE_SUBNET_COUNT]

## GetMetaData Request Handling

### Request Requirements
- The request MUST be encoded as an SSZ-field (for Ping requests)
- GetMetaData requests have no request content - the request opens and negotiates the stream without sending any request content

### Response Requirements
- The response MUST be encoded as an SSZ-container
- The response MUST consist of a single `response_chunk`
- The responding peer responds with its local most up-to-date MetaData

## General Response Validation Rules (Apply to All Responses Including Metadata)

### Response Structure
- Responses MUST adhere to the encoding specified in the protocol name
- For `ssz_snappy` encoding:
  - Contents are first SSZ-encoded and then compressed with Snappy frames compression
  - The length of raw SSZ bytes MUST be encoded as an unsigned protobuf varint in the header

### Size Limits
- The size of the uncompressed payload MUST NOT exceed `MAX_PAYLOAD_SIZE` or the type-specific SSZ bound, whichever is lower
- A global maximum uncompressed byte size of `MAX_PAYLOAD_SIZE` MUST be applied to all method response chunks
- Clients MUST ensure that lengths are within these bounds

### Response Codes
- Chunks start with a single-byte response code:
  - 0: Success - normal response follows
  - 1: InvalidRequest - semantically invalid or malformed request
  - 2: ServerError - responder encountered an error
  - 3: ResourceUnavailable - responder doesn't have requested resource

### Error Handling
- If any part of the `response_chunk` fails validation, the requester SHOULD stop reading
- The responder MUST respond in error if the request is invalid, malformed, or inconsistent
- The responder MUST NOT respond with an error or close the stream when rate limiting

### Stream Management
- The responder MUST validate the request before responding
- The responder MUST close their write side of the stream after sending the response
- Clients MUST NOT make more than `MAX_CONCURRENT_REQUESTS` concurrent requests

## ENR Consistency
- If a node's `MetaData.attnets` has any non-zero bit, the ENR MUST include the `attnets` entry with the same value as `MetaData.attnets`
- If a node's `MetaData.attnets` is composed of all zeros, the ENR MAY optionally include the `attnets` entry or leave it out entirely

## Protocol Versions
- Phase 0: `/eth2/beacon_chain/req/metadata/1/`
- Altair and later: `/eth2/beacon_chain/req/metadata/2/`

## Rate Limiting
- The responder MAY rate-limit chunks by withholding each chunk until capacity is available
- When rate limiting, the responder MUST send each `response_chunk` in full promptly but may introduce delays between chunks
