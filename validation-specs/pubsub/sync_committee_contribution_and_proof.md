# Sync Committee Contribution and Proof Topic Validation Rules

## Topic: `sync_committee_contribution_and_proof`

## Overview
The `sync_committee_contribution_and_proof` topic is used to propagate aggregated sync committee signatures. Introduced in Altair and unchanged in subsequent forks.

## Convenience Variables
- `contribution_and_proof = signed_contribution_and_proof.message`
- `contribution = contribution_and_proof.contribution`

## Altair and Later Forks Validation Rules

### MUST Requirements

1. **[IGNORE]** The contribution's slot is for the current slot (with a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance):
   - `contribution.slot == current_slot`

2. **[REJECT]** The subcommittee index is in the allowed range:
   - `contribution.subcommittee_index < SYNC_COMMITTEE_SUBNET_COUNT`

3. **[REJECT]** The contribution has participants:
   - `any(contribution.aggregation_bits)`

4. **[REJECT]** `contribution_and_proof.selection_proof` selects the validator as an aggregator for the slot:
   - `is_sync_committee_aggregator(contribution_and_proof.selection_proof)` returns `True`

5. **[REJECT]** The aggregator's validator index is in the declared subcommittee of the current sync committee:
   - `state.validators[contribution_and_proof.aggregator_index].pubkey in get_sync_subcommittee_pubkeys(state, contribution.subcommittee_index)`

6. **[IGNORE]** A valid sync committee contribution with equal `slot`, `beacon_block_root` and `subcommittee_index` whose `aggregation_bits` is non-strict superset has NOT already been seen

7. **[IGNORE]** The sync committee contribution is the first valid contribution received for the aggregator with index `contribution_and_proof.aggregator_index` for the slot `contribution.slot` and subcommittee index `contribution.subcommittee_index`
   - This requires maintaining a cache of size `SYNC_COMMITTEE_SIZE`

8. **[REJECT]** The `contribution_and_proof.selection_proof` is a valid signature of the `SyncAggregatorSelectionData` derived from the `contribution` by the validator with index `contribution_and_proof.aggregator_index`

9. **[REJECT]** The aggregator signature, `signed_contribution_and_proof.signature`, is valid

10. **[REJECT]** The aggregate signature is valid for the message `beacon_block_root` and aggregate pubkey derived from the participation info in `aggregation_bits` for the subcommittee specified by the `contribution.subcommittee_index`

## Classification

- **[REJECT]** rules: Client MUST NOT process or forward the message; it should be rejected entirely
- **[IGNORE]** rules: Client MUST NOT forward the message but may process it locally; typically used for duplicate/redundant messages

## Key Points

- These validation rules ensure proper aggregation of sync committee signatures
- The rules prevent spam and ensure only valid aggregations from authorized aggregators are propagated
- The validation includes checks for proper selection, membership, and signature validity

## Fork Consistency

These validation rules have remained unchanged since their introduction in Altair and apply to all subsequent forks.

## Validation Outcomes

- **[IGNORE]**: Don't forward the message but may process it locally
- **[REJECT]**: Don't forward the message and don't process it