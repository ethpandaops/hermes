# Beacon Aggregate and Proof Topic Validation Rules

## Topic: `beacon_aggregate_and_proof`

## Overview
The `beacon_aggregate_and_proof` topic is used to propagate aggregated attestations (as `SignedAggregateAndProof`s) to subscribing nodes. Major changes occur in Deneb (EIP-7045) and Electra (new attestation format).

## Convenience Variables
- `aggregate_and_proof = signed_aggregate_and_proof.message`
- `aggregate = aggregate_and_proof.aggregate`
- `index = aggregate.data.index` (Phase0-Deneb)
- `index = get_committee_indices(aggregate.committee_bits)[0]` (Electra)
- `aggregation_bits = attestation.aggregation_bits`

## Phase 0 - Capella Validation Rules

### MUST Requirements

1. **[REJECT]** The committee index is within the expected range:
   - `index < get_committee_count_per_slot(state, aggregate.data.target.epoch)`

2. **[IGNORE]** Slot timing validation:
   - `aggregate.data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot >= aggregate.data.slot`
   - (with `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance)

3. **[REJECT]** The aggregate attestation's epoch matches its target:
   - `aggregate.data.target.epoch == compute_epoch_at_slot(aggregate.data.slot)`

4. **[REJECT]** The number of aggregation bits matches the committee size:
   - `len(aggregation_bits) == len(get_beacon_committee(state, aggregate.data.slot, index))`

5. **[REJECT]** The aggregate attestation has participants:
   - `len(get_attesting_indices(state, aggregate)) >= 1`

6. **[IGNORE]** No superset aggregate already seen:
   - MUST NOT have already seen a valid aggregate attestation for `hash_tree_root(aggregate.data)` whose `aggregation_bits` is a non-strict superset

7. **[IGNORE]** First valid aggregate from aggregator:
   - MUST be the first valid aggregate received for the aggregator with index `aggregate_and_proof.aggregator_index` for the epoch `aggregate.data.target.epoch`

8. **[REJECT]** Selection proof validates aggregator selection:
   - `is_aggregator(state, aggregate.data.slot, index, aggregate_and_proof.selection_proof)` returns `True`

9. **[REJECT]** Aggregator is within the committee:
   - `aggregate_and_proof.aggregator_index in get_beacon_committee(state, aggregate.data.slot, index)`

10. **[REJECT]** Selection proof signature is valid:
    - `aggregate_and_proof.selection_proof` is a valid signature of the `aggregate.data.slot` by the validator with index `aggregate_and_proof.aggregator_index`

11. **[REJECT]** Aggregator signature is valid:
    - `signed_aggregate_and_proof.signature` is valid

12. **[REJECT]** Aggregate signature is valid:
    - The signature of `aggregate` is valid

13. **[IGNORE]** Block being voted for has been seen:
    - MUST have seen the block being voted for (`aggregate.data.beacon_block_root`) via gossip or non-gossip sources

## Deneb Fork Changes (EIP-7045)

### Removed Validation
- The slot range validation is removed

### Added Validations

1. **[IGNORE]** Aggregate slot is not from the future:
   - `aggregate.data.slot <= current_slot` (with `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance)

2. **[IGNORE]** Aggregate is from current or previous epoch:
   - `compute_epoch_at_slot(aggregate.data.slot) in (get_previous_epoch(state), get_current_epoch(state))`

## Electra Fork Changes

### Modified Convenience Variable
- `index = get_committee_indices(aggregate.committee_bits)[0]`

### Added Validations

1. **[REJECT]** Single committee attestation:
   - `len(committee_indices) == 1`, where `committee_indices = get_committee_indices(aggregate)`

2. **[REJECT]** Index field is zero:
   - `aggregate.data.index == 0`

## Summary of Key Changes by Fork

- **Phase0-Capella**: Aggregates must be within `ATTESTATION_PROPAGATION_SLOT_RANGE` slots
- **Deneb**: Aggregates can be from current or previous epoch (extended propagation window for EIP-7045)
- **Electra**: Support for new attestation format with committee bits, requires single committee and zero index field

## Validation Outcomes

- **[IGNORE]**: Don't forward the message but may process it locally
- **[REJECT]**: Don't forward the message and don't process it