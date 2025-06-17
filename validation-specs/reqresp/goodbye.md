# Goodbye Request/Response Validation Rules

## Protocol: `/eth2/beacon_chain/req/goodbye/1/`

## Overview
The Goodbye protocol allows peers to inform each other of disconnection reasons as a courtesy notification.

## Message Details
- **Content**: Single `uint64` field representing the reason code
- **Encoding**: SSZ-field

## MUST Requirements

### Encoding Requirements
1. The request/response MUST be encoded as a single SSZ-field
2. The response MUST consist of a single `response_chunk`

### General Request/Response Requirements
1. The responder MUST validate the request before processing it
2. The responder MUST process and validate according to the encoding strategy until EOF
3. If validation fails due to invalid, malformed, or inconsistent data, the responder MUST respond in error
4. The responder MUST NOT respond with an error or close the stream when rate limiting

### Response Code Requirements
1. Chunks start with a single-byte response code
2. For single chunk responses (like goodbye), the response code determines the contents
3. Valid response codes: 0 (Success), 1 (InvalidRequest), 2 (ServerError), 3 (ResourceUnavailable)
4. The range [4, 127] is RESERVED and should be treated as error if not recognized

### Single Field Encoding
1. All messages that contain only a single field MUST be encoded directly as the type of that field and MUST NOT be encoded as an SSZ container

## MAY Requirements

### Sending Goodbye
1. Client MAY send goodbye messages upon disconnection
2. Clients MAY use reason codes above 128 to indicate alternative, erroneous request-specific responses

### Reason Codes
Valid reason codes:
- 1: Client shut down
- 2: Irrelevant network
- 3: Fault/error
- The range [4, 127] is RESERVED for future usage

### Error Handling
1. Clients tracking peer reputation MAY record validation failures
2. The responder MAY rate-limit chunks
3. The responder MAY penalize peers that concurrently open more than MAX_CONCURRENT_REQUESTS streams

## Key Validation Points

### Request Validation
1. Must be a valid uint64 value
2. Must follow SSZ encoding rules
3. Must have proper stream handling (half-close after request)

### Response Validation
1. Must be a single response chunk
2. Must start with a valid response code byte
3. Must contain a valid uint64 if response code is 0 (Success)
4. Must contain ErrorMessage schema if response code indicates error (1-3)

### Stream Handling
1. Requester must close write side after sending request
2. Responder must close write side after sending response
3. Stream should be fully closed after response is sent

## Notes
The goodbye message is a simple courtesy notification mechanism that allows peers to inform each other of disconnection reasons, but it's not mandatory to send or process.