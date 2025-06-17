# Light Client Finality Update Request/Response Validation Rules

## Protocol: `/eth2/beacon_chain/req/light_client_finality_update/1/`

## Overview
The Light Client Finality Update protocol allows light clients to get the latest finality update.

## Request Details
- **Content**: No request content (empty request)
- **Response Content**: `LightClientFinalityUpdate` structure

## Response Provider (Server) MUST Requirements

### Provide Latest Update
1. Peers SHOULD provide results as defined in `create_light_client_finality_update`, which returns the `LightClientFinalityUpdate` with the highest `attested_header.beacon.slot` (if multiple, highest `signature_slot`) as selected by fork choice

### Error Handling
1. When no `LightClientFinalityUpdate` is available, peers SHOULD respond with error code `3: ResourceUnavailable`

### Fork Version Context
1. A `ForkDigest`-context based on `compute_fork_version(compute_epoch_at_slot(finality_update.attested_header.beacon.slot))` is used to select the fork namespace of the Response type

### Support Push Mechanism
1. Full nodes SHOULD support a push mechanism to deliver new `LightClientFinalityUpdate` whenever `finalized_header` changes

### Supermajority Participation
1. If the `LightClientFinalityUpdate` does not have supermajority (> 2/3) sync committee participation, a second `LightClientFinalityUpdate` SHOULD be delivered for the same `finalized_header` once supermajority participation is obtained

## Request Handler (Client) Validation

When processing a received `LightClientFinalityUpdate`, the client MUST validate it through `process_light_client_finality_update`, which internally converts it to a `LightClientUpdate` and validates:

### Sync Committee Participation
1. MUST verify sync committee has sufficient participants: `sum(sync_aggregate.sync_committee_bits) >= MIN_SYNC_COMMITTEE_PARTICIPANTS`

### Slot Ordering
1. MUST verify: `current_slot >= update.signature_slot > update.attested_header.beacon.slot >= update.finalized_header.beacon.slot`

### Sync Committee Period Validity
1. MUST NOT skip a sync committee period
2. If next sync committee is known: `update_signature_period in (store_period, store_period + 1)`
3. If next sync committee is not known: `update_signature_period == store_period`

### Update Relevance
1. MUST verify the update is relevant (advances the finalized header or provides next sync committee)

### Finality Branch Validation
1. MUST verify the `finality_branch` confirms `finalized_header` matches the finalized checkpoint root in `attested_header`
2. MUST validate merkle branch proof

### Signature Validation
1. MUST verify the sync committee aggregate signature using BLS verification

## General Req/Resp Requirements

### Response Codes
- `0`: Success - normal response follows
- `1`: InvalidRequest - semantically invalid or malformed request
- `2`: ServerError - responder encountered an error
- `3`: ResourceUnavailable - responder does not have requested resource

### Encoding
1. MUST use `ssz_snappy` encoding with proper length prefixing

### Stream Handling
1. One stream per request/response interaction
2. Requester MUST close write side after sending request
3. Responder MUST close write side after sending response
4. Streams are closed when interaction finishes

### Fork Version Mapping (varies by fork)
- Altair through Bellatrix: `altair.LightClientFinalityUpdate`
- Capella: `capella.LightClientFinalityUpdate`
- Deneb: `deneb.LightClientFinalityUpdate`
- Electra and later: `electra.LightClientFinalityUpdate`

## Notes
These validation rules ensure that light clients can safely sync with the network and validate finality updates from peers while preventing various attack vectors and ensuring data integrity.