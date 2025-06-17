# Light Client Finality Update Topic Validation Rules

## Topic: `light_client_finality_update`

## Overview
The `light_client_finality_update` topic is used to propagate the latest finalized header for light clients. Introduced in Altair and message types updated in subsequent forks.

## Altair and Later Forks Validation Rules

### General Validations (Apply to All Nodes)

1. **[IGNORE]** The `finalized_header.beacon.slot` MUST be greater than that of all previously forwarded `finality_update`s, OR it matches the highest previously forwarded slot and also has a `sync_aggregate` indicating supermajority (> 2/3) sync committee participation while the previously forwarded `finality_update` for that slot did not indicate supermajority

2. **[IGNORE]** The `finality_update` MUST be received after the block at `signature_slot` was given enough time to propagate through the network:
   - Validate that one-third of `finality_update.signature_slot` has transpired (`SECONDS_PER_SLOT / INTERVALS_PER_SLOT` seconds after the start of the slot, with a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance)

### Full Node Additional Validations

3. **[IGNORE]** The received `finality_update` MUST match the locally computed one exactly (as defined in `create_light_client_finality_update`)

### Light Client Additional Validations

4. **[REJECT]** The `finality_update` MUST be valid:
   - Validate that `process_light_client_finality_update` does not indicate errors

5. **[IGNORE]** The `finality_update` MUST advance the `finalized_header` of the local `LightClientStore`:
   - Validate that processing `finality_update` increases `store.finalized_header.beacon.slot`

## Additional Requirements

- Light clients SHOULD call `process_light_client_finality_update` even if the message is ignored
- The gossip `ForkDigestValue` is determined based on `compute_fork_version(compute_epoch_at_slot(finality_update.attested_header.beacon.slot))`

## Message Types by Fork

- **Altair through Bellatrix**: `altair.LightClientFinalityUpdate`
- **Capella**: `capella.LightClientFinalityUpdate`
- **Deneb**: `deneb.LightClientFinalityUpdate`
- **Electra and later**: `electra.LightClientFinalityUpdate`

## Key Points

These validation rules ensure that:
- Only newer or equally recent but better finality updates are propagated
- Updates have proper timing constraints to prevent premature propagation
- Full nodes only forward updates they can verify against their local state
- Light clients only accept valid updates that advance their finalized state

## Validation Outcomes

- **[IGNORE]**: Don't forward the message but may process it locally
- **[REJECT]**: Don't forward the message and don't process it