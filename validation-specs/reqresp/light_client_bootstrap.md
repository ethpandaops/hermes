# Light Client Bootstrap Request/Response Validation Rules

## Protocol: `/eth2/beacon_chain/req/light_client_bootstrap/1/`

## Overview
The Light Client Bootstrap protocol allows light clients to initialize their sync process from a trusted block root.

## Request Validation (Server/Responder Side)

### Request Format
1. The request MUST be encoded as an SSZ-field containing a single `Root` (the beacon block root)

### Request Processing
1. The responder MUST validate the request before processing:
   - The request MUST be properly SSZ-encoded
   - The length assertions MUST match the expected size for a `Root` type

### Bootstrap Creation
1. Peers SHOULD provide results as defined in `create_light_client_bootstrap`, which requires:
   - The requested block root MUST correspond to a post-Altair block (`compute_epoch_at_slot(state.slot) >= ALTAIR_FORK_EPOCH`)
   - The block and its post state MUST be known/available

### Error Response
1. When a `LightClientBootstrap` instance cannot be produced for a given block root, peers SHOULD respond with error code `3: ResourceUnavailable`

### Fork Selection
A `ForkDigest`-context based on `compute_fork_version(compute_epoch_at_slot(bootstrap.header.beacon.slot))` is used to select the fork namespace of the Response type:
- `ALTAIR_FORK_VERSION` through `BELLATRIX_FORK_VERSION`: `altair.LightClientBootstrap`
- `CAPELLA_FORK_VERSION`: `capella.LightClientBootstrap`
- `DENEB_FORK_VERSION`: `deneb.LightClientBootstrap`
- `ELECTRA_FORK_VERSION` and later: `electra.LightClientBootstrap`

## Response Validation (Client/Requester Side)

### Response Format
1. The response MUST contain a single `LightClientBootstrap` structure

### SSZ Encoding
1. The response MUST be properly SSZ-encoded and compressed with Snappy according to the `ssz_snappy` encoding strategy

### Length Validation
1. The length-prefix MUST be encoded as an unsigned protobuf varint
2. The length-prefix MUST be within the expected size bounds for the `LightClientBootstrap` type or `MAX_PAYLOAD_SIZE`, whichever is smaller

### Bootstrap Validation (when initializing from the bootstrap)
1. The `bootstrap.header` MUST be valid (`is_valid_light_client_header(bootstrap.header)`)
2. The hash of `bootstrap.header.beacon` MUST equal the `trusted_block_root` provided by the client
3. The `current_sync_committee` MUST be correctly proven via the Merkle branch:
   ```
   is_valid_normalized_merkle_branch(
       leaf=hash_tree_root(bootstrap.current_sync_committee),
       branch=bootstrap.current_sync_committee_branch,
       gindex=current_sync_committee_gindex_at_slot(bootstrap.header.beacon.slot),
       root=bootstrap.header.beacon.state_root,
   )
   ```

## General Request/Response Rules

### Stream Handling
1. The requester MUST close the write side of the stream after sending the request
2. The responder MUST close their write side after sending the response
3. Invalid responses MUST cause the requester to reset the stream

### Error Handling
1. If validation fails, the responder MUST respond with an appropriate error code
2. Clients MAY track peer reputation for invalid requests/responses

### Timeouts
1. If a timeout occurs or the response is no longer relevant, the requester SHOULD reset the stream

## Notes
These validation rules ensure that light clients can safely bootstrap their sync process from a trusted block root while preventing invalid or malicious data from being accepted.