# Beacon Attestation Topic Validation Rules

## Topic: `beacon_attestation_{subnet_id}`

## Overview
The `beacon_attestation_{subnet_id}` topics are used to propagate unaggregated attestations to subscribing nodes. Major changes occur in Deneb (EIP-7045) and Electra (switch to `SingleAttestation`).

## Phase 0 - Capella Validation Rules

### MUST Requirements

1. **[REJECT]** The committee index is within the expected range:
   - `index < get_committee_count_per_slot(state, attestation.data.target.epoch)`

2. **[REJECT]** The attestation is for the correct subnet:
   - `compute_subnet_for_attestation(committees_per_slot, attestation.data.slot, index) == subnet_id`
   - where `committees_per_slot = get_committee_count_per_slot(state, attestation.data.target.epoch)`

3. **[IGNORE]** `attestation.data.slot` is within the last `ATTESTATION_PROPAGATION_SLOT_RANGE` slots:
   - `attestation.data.slot + ATTESTATION_PROPAGATION_SLOT_RANGE >= current_slot >= attestation.data.slot`
   - (within a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance)

4. **[REJECT]** The attestation's epoch matches its target:
   - `attestation.data.target.epoch == compute_epoch_at_slot(attestation.data.slot)`

5. **[REJECT]** The attestation is unaggregated (exactly one participating validator):
   - `len([bit for bit in aggregation_bits if bit]) == 1` (exactly 1 bit is set)

6. **[REJECT]** The number of aggregation bits matches the committee size:
   - `len(aggregation_bits) == len(get_beacon_committee(state, attestation.data.slot, index))`

7. **[IGNORE]** There has been no other valid attestation seen on an attestation subnet that has an identical `attestation.data.target.epoch` and participating validator index

8. **[REJECT]** The signature of `attestation` is valid

9. **[IGNORE]** The block being voted for (`attestation.data.beacon_block_root`) has been seen (via gossip or non-gossip sources)

10. **[REJECT]** The block being voted for (`attestation.data.beacon_block_root`) passes validation

11. **[REJECT]** The attestation's target block is an ancestor of the block named in the LMD vote:
    - `get_checkpoint_block(store, attestation.data.beacon_block_root, attestation.data.target.epoch) == attestation.data.target.root`

12. **[IGNORE]** The current `finalized_checkpoint` is an ancestor of the `block` defined by `attestation.data.beacon_block_root`:
    - `get_checkpoint_block(store, attestation.data.beacon_block_root, store.finalized_checkpoint.epoch) == store.finalized_checkpoint.root`

## Deneb Fork Changes (EIP-7045)

### Removed Validation
- The slot range validation is removed

### Added Validations

1. **[IGNORE]** `attestation.data.slot` is equal to or earlier than the `current_slot`:
   - `attestation.data.slot <= current_slot`
   - (with a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance)

2. **[IGNORE]** The epoch of `attestation.data.slot` is either the current or previous epoch:
   - `compute_epoch_at_slot(attestation.data.slot) in (get_previous_epoch(state), get_current_epoch(state))`
   - (with a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance)

## Electra Fork Changes

### Message Type Change
The topic is updated to propagate `SingleAttestation` objects instead of `Attestation` objects.

### Added Validations

1. **[REJECT]** `attestation.data.index == 0`

2. **[REJECT]** The attester is a member of the committee:
   - `attestation.attester_index in get_beacon_committee(state, attestation.data.slot, index)`

### Removed Validations

1. The attestation is unaggregated check (no longer needed as `SingleAttestation` represents a single validator)
2. The number of aggregation bits matches committee size check (no longer applicable to `SingleAttestation`)

### Modified Variables
- The convenience variable is redefined as `index = attestation.committee_index` in Electra

## Summary of Key Changes by Fork

- **Phase0-Capella**: Uses `Attestation` objects with aggregation bits
- **Deneb**: Relaxes timing constraints for attestations (EIP-7045)
- **Electra**: Switches to `SingleAttestation` objects, removing aggregation-related validations and adding explicit attester membership checks

## Validation Outcomes

- **[IGNORE]**: Don't forward the message but may process it locally
- **[REJECT]**: Don't forward the message and don't process it