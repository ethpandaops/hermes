# Ping Request/Response Validation Rules

## Protocol: `/eth2/beacon_chain/req/ping/1/`

## Overview
The Ping protocol is used to check liveness of connected peers and exchange metadata sequence numbers.

## Message Details
- **Request Content**: A single `uint64` value representing the requester's `MetaData.seq_number`
- **Response Content**: A single `uint64` value representing the responder's `MetaData.seq_number`
- **Encoding**: SSZ-field

## MUST Requirements

### Request Encoding
1. The request MUST be encoded as an SSZ-field

### Response Format
1. The response MUST consist of a single `response_chunk`

### General Request/Response Requirements

#### For Requesters
1. The requester MUST close the write side of the stream once it finishes writing the request message
2. The requester MUST NOT make more than `MAX_CONCURRENT_REQUESTS` (2) concurrent requests with the same protocol ID
3. The request MUST be encoded according to the encoding strategy (SSZ-snappy for ping)

#### For Responders
1. The responder MUST validate the incoming request before processing it
2. The responder MUST respond in error if the request is invalid, malformed, or contains inconsistent data
3. The responder MUST NOT respond with an error or close the stream when rate limiting
4. When rate limiting, the responder MUST send each `response_chunk` in full promptly but may introduce delays between chunks

#### For Both
1. Clients MUST ensure that message lengths are within bounds (`MAX_PAYLOAD_SIZE` = 10 MiB)
2. Before reading the payload, the header MUST be validated:
   - The length-prefix MUST be encoded as an unsigned protobuf varint
   - A reader MUST NOT read more than `max_compressed_len(n)` bytes after reading the SSZ length-prefix `n`
3. Messages that contain only a single field MUST be encoded directly as the type of that field and MUST NOT be encoded as an SSZ container

## MAY Requirements

1. If the peer does not respond to the `Ping` request, the client MAY disconnect from the peer
2. Clients MAY record failures for peer reputation tracking

## Purpose

The Ping protocol is used to:
1. Check liveness of connected peers
2. Exchange metadata sequence numbers
3. Determine if a peer's MetaData record is up to date (and potentially request an update via the MetaData RPC if needed)

## Notes
The ping protocol remains unchanged across all consensus layer forks (Altair, Bellatrix, Capella, Deneb, Electra, Fulu) - only Phase 0 defines it.