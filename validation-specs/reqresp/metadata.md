# Metadata Request/Response Validation Rules

## Protocol: `/eth2/beacon_chain/req/metadata/1/` (Phase 0)
## Protocol: `/eth2/beacon_chain/req/metadata/2/` (Altair)
## Protocol: `/eth2/beacon_chain/req/metadata/3/` (Fulu)

## Overview
The Metadata protocol allows peers to exchange their current metadata about attestation and sync committee subnet memberships.

## Request Details
- **Content**: No request content - the stream is simply opened and negotiated
- **Encoding**: N/A (empty request)

## Response Validation Rules

### MUST Requirements

1. The response MUST be encoded as an SSZ-container
2. The response MUST consist of a single `response_chunk`
3. The responder MUST send their local most up-to-date MetaData
4. The response MUST NOT exceed `MAX_PAYLOAD_SIZE` (general rule for all responses)

### Metadata Updates
1. Clients MUST increment `seq_number` by 1 whenever any other field in MetaData changes
2. `seq_number` starts at 0

### General Response Validation
1. Response chunks MUST start with a single-byte response code (0 for success, 1-3 for various errors)
2. For ssz_snappy encoding, the length MUST be encoded as a protobuf varint in the header
3. Clients MUST ensure lengths are within bounds
4. Responders MUST validate requests before responding
5. Responders MUST NOT respond with an error when rate limiting (they should delay instead)
6. Clients MUST NOT make more than `MAX_CONCURRENT_REQUESTS` concurrent requests

## ENR Consistency

If `MetaData.attnets` has any non-zero bit, the ENR MUST include the `attnets` entry with the same value

## Metadata Structure by Version

### Version 1 (Phase 0)
```
(
  seq_number: uint64
  attnets: Bitvector[ATTESTATION_SUBNET_COUNT]
)
```

### Version 2 (Altair)
```
(
  seq_number: uint64
  attnets: Bitvector[ATTESTATION_SUBNET_COUNT]
  syncnets: Bitvector[SYNC_COMMITTEE_SUBNET_COUNT]
)
```

### Version 3 (Fulu)
```
(
  seq_number: uint64
  attnets: Bitvector[ATTESTATION_SUBNET_COUNT]
  syncnets: Bitvector[SYNC_COMMITTEE_SUBNET_COUNT]
  custody_subnet_count: uint64
)
```

## Purpose

The Metadata protocol is used to:
1. Exchange information about subnet memberships
2. Track peer capabilities for attestation and sync committee participation
3. Monitor metadata changes via sequence numbers

## Notes
- The request has no content - it simply opens the stream
- The response contains the peer's current metadata state
- Sequence numbers allow tracking of metadata updates