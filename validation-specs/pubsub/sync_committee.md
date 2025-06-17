# Sync Committee Topic Validation Rules

## Topic: `sync_committee_{subnet_id}`

## Overview
The `sync_committee_{subnet_id}` topics are used to propagate sync committee messages. Introduced in Altair and unchanged in subsequent forks.

## Altair and Later Forks Validation Rules

### MUST Requirements

1. **[IGNORE]** The message's slot is for the current slot (with a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance):
   - `sync_committee_message.slot == current_slot`

2. **[REJECT]** The `subnet_id` is valid for the given validator:
   - `subnet_id in compute_subnets_for_sync_committee(state, sync_committee_message.validator_index)`
   - This validation implies the validator is part of the broader current sync committee along with the correct subcommittee

3. **[IGNORE]** There has been no other valid sync committee message for the declared `slot` for the validator:
   - Referenced by `sync_committee_message.validator_index`
   - Requires maintaining a cache of size `SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT` for each subnet
   - Cache can be flushed after each slot
   - This validation is **per topic** - multiple messages could be forwarded with the same `validator_index` as long as the `subnet_id`s are distinct

4. **[REJECT]** The `signature` is valid for the message `beacon_block_root` for the validator referenced by `validator_index`

## Key Points

- **IGNORE** rules indicate messages that should be dropped without penalizing the peer
- **REJECT** rules indicate messages that should result in peer penalties
- The validation ensures:
  - Messages are timely (not from future or too far in past)
  - Validators are assigned to the correct subnet
  - No duplicate messages per validator per slot per subnet
  - Signatures are valid

## Cache Requirements

- Maintain a cache of size `SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT` for each subnet
- Cache tracks validators who have already sent a message for the current slot
- Cache can be flushed after each slot

## Fork Consistency

These rules have remained consistent since Altair (where sync committees were introduced) through all subsequent forks including Bellatrix, Capella, Deneb, Electra, and Fulu.

## Validation Outcomes

- **[IGNORE]**: Don't forward the message but may process it locally
- **[REJECT]**: Don't forward the message and don't process it