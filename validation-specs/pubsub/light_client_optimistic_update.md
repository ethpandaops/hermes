# Light Client Optimistic Update Topic Validation Rules

## Topic: `light_client_optimistic_update`

## Overview
The `light_client_optimistic_update` topic is used to propagate the latest optimistic header for light clients. Introduced in Altair with message types updated in subsequent forks.

## Altair and Later Forks Validation Rules

### General Validation Rules (All Nodes)

Before forwarding the `optimistic_update` on the network, the following validations MUST pass:

1. **[IGNORE]** The `attested_header.beacon.slot` is greater than that of all previously forwarded `optimistic_update`s

2. **[IGNORE]** The `optimistic_update` is received after the block at `signature_slot` was given enough time to propagate through the network:
   - Validate that one-third of `optimistic_update.signature_slot` has transpired (`SECONDS_PER_SLOT / INTERVALS_PER_SLOT` seconds after the start of the slot, with a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance)

### Additional Validation Rules for Full Nodes

For full nodes, the following validations MUST additionally pass before forwarding:

3. **[IGNORE]** The received `optimistic_update` matches the locally computed one exactly (as defined in `create_light_client_optimistic_update`)

### Additional Validation Rules for Light Clients

For light clients, the following validations MUST additionally pass before forwarding:

4. **[REJECT]** The `optimistic_update` is valid:
   - Validate that `process_light_client_optimistic_update` does not indicate errors

5. **[IGNORE]** The `optimistic_update` either matches corresponding fields of the most recently forwarded `LightClientFinalityUpdate` (if any), or it advances the `optimistic_header` of the local `LightClientStore`:
   - Validate that processing `optimistic_update` increases `store.optimistic_header.beacon.slot`

## Important Notes

- Light clients SHOULD call `process_light_client_optimistic_update` even if the message is ignored
- The gossip `ForkDigestValue` is determined based on `compute_fork_version(compute_epoch_at_slot(optimistic_update.attested_header.beacon.slot))`

## Message Types by Fork

- **Altair through Bellatrix**: `altair.LightClientOptimisticUpdate`
- **Capella**: `capella.LightClientOptimisticUpdate`
- **Deneb**: `deneb.LightClientOptimisticUpdate`
- **Electra and later**: `electra.LightClientOptimisticUpdate`

## Key Points

The validation rules ensure:
- Only newer optimistic updates are propagated
- Updates have proper timing constraints
- Full nodes only forward updates matching their local computation
- Light clients only accept valid updates that advance their state

## Validation Outcomes

- **[IGNORE]**: The message should not be forwarded but doesn't indicate a protocol violation
- **[REJECT]**: The message is invalid and indicates a protocol violation