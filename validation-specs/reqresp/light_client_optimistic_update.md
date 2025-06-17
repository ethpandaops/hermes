# Light Client Optimistic Update Request/Response Validation Rules

## Protocol: `/eth2/beacon_chain/req/light_client_optimistic_update/1/`

## Overview
The GetLightClientOptimisticUpdate protocol allows light clients to get the latest optimistic header update.

## Request Validation
- **No Request Content** - The request has no parameters
- The request MUST be encoded according to the encoding strategy (SSZ-snappy)

## Response Validation

### For the Responding Peer (Server)

1. **SHOULD** provide results as defined in `create_light_client_optimistic_update`

2. **MUST** respond with error code `3: ResourceUnavailable` when no `LightClientOptimisticUpdate` is available

3. **MUST** use the correct fork digest context based on `compute_fork_version(compute_epoch_at_slot(optimistic_update.attested_header.beacon.slot))` to select the fork namespace:
   - `ALTAIR_FORK_VERSION` and later: `altair.LightClientOptimisticUpdate`
   - `CAPELLA_FORK_VERSION` and later: `capella.LightClientOptimisticUpdate`
   - `DENEB_FORK_VERSION` and later: `deneb.LightClientOptimisticUpdate`
   - `ELECTRA_FORK_VERSION` and later: `electra.LightClientOptimisticUpdate`

4. **MUST** follow general req/resp rules:
   - Validate the incoming request before processing
   - Write the response chunk with appropriate response code
   - Close the write side of the stream after sending response

### For the Requesting Peer (Client)

1. **MUST** encode the request according to the encoding strategy
2. **MUST** close the write side of the stream after sending request
3. **SHOULD** read from the stream until either:
   - An error result is received
   - The responder closes the stream
   - The response chunk fails validation
4. **MUST** validate the response according to the expected schema

## General Req/Resp Protocol Rules Applied

### Response Codes
- `0`: Success - normal response with `LightClientOptimisticUpdate`
- `1`: InvalidRequest - malformed or invalid request
- `2`: ServerError - error during processing
- `3`: ResourceUnavailable - no optimistic update available

### Size Constraints
- Response MUST NOT exceed `MAX_PAYLOAD_SIZE` for uncompressed payload
- Length prefix MUST be valid protobuf varint (max 10 bytes)

### Encoding Requirements
- MUST use SSZ-snappy encoding
- MUST include length prefix as protobuf varint
- Single response chunk containing the `LightClientOptimisticUpdate`

## Important Notes

- This is different from the gossipsub `light_client_optimistic_update` topic which has additional validation rules for forwarding
- The fork version for the response type may differ from the one used to verify the `optimistic_update.sync_aggregate` (which is based on `optimistic_update.signature_slot`)
- Light clients receiving these updates should process them with `process_light_client_optimistic_update` to validate the cryptographic proofs