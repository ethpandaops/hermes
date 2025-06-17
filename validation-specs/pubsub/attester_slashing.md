# Attester Slashing Topic Validation Rules

## Topic: `attester_slashing`

## Overview
The `attester_slashing` topic is used to propagate attester slashings to proposers on the network. In Electra, the message type is updated to support larger committee sizes.

## Phase 0 - Deneb Validation Rules

### MUST Requirements

1. **[IGNORE]** At least one index in the intersection of the attesting indices of each attestation has not yet been seen in any prior `attester_slashing`:
   - Calculate: `attester_slashed_indices = set(attestation_1.attesting_indices).intersection(attestation_2.attesting_indices)`
   - Verify if: `any(attester_slashed_indices.difference(prior_seen_attester_slashed_indices))`
   - This prevents propagating duplicate slashings for already-slashed validators

2. **[REJECT]** All of the conditions within `process_attester_slashing` pass validation, which includes:
   - The attestation data must be slashable according to Casper FFG rules (`is_slashable_attestation_data`):
     - Either a **double vote**: `data_1 != data_2 AND data_1.target.epoch == data_2.target.epoch`
     - Or a **surround vote**: `data_1.source.epoch < data_2.source.epoch AND data_2.target.epoch < data_1.target.epoch`
   - Both indexed attestations must be valid (`is_valid_indexed_attestation` for both attestation_1 and attestation_2)
   - At least one validator in the intersection must be slashable (not already slashed and within the withdrawable epoch)

3. **[REJECT]** Clients MUST reject messages containing an incorrect type (the message must be of type `AttesterSlashing`)

## Electra Fork Changes

### Message Type Update
- The `attester_slashing` topic is modified to support the gossip of the new `AttesterSlashing` type
- The `AttesterSlashing` structure itself is modified with updated `IndexedAttestation` types that support larger committee sizes:
  - `attesting_indices` can now contain up to `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT` validators (increased from the previous limit)

### Validation Rules
- The validation rules themselves remain the same as Phase0, but operate on the new data structures

## Summary of MUST/MUST NOT Requirements

1. Clients **MUST** validate that at least one validator index in the slashing is new (not previously slashed)
2. Clients **MUST** validate all conditions in `process_attester_slashing` before forwarding
3. Clients **MUST** reject messages with incorrect types
4. Clients **MUST NOT** forward attester slashings that fail any of the validation conditions
5. Clients **MUST NOT** forward duplicate slashings for validators that have already been slashed

## Key Points

- These rules ensure that only valid, non-duplicate attester slashings are propagated through the network
- The rules prevent spam and ensure the integrity of the slashing mechanism
- The core validation logic remains unchanged from Phase 0 through Electra, with only data structure updates

## Validation Outcomes

- **[IGNORE]**: Don't forward the message but may process it locally
- **[REJECT]**: Don't forward the message and don't process it