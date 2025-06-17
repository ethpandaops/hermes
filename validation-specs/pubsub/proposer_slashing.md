# Proposer Slashing Topic Validation Rules

## Topic: `proposer_slashing`

## Overview
The `proposer_slashing` topic is used to propagate proposer slashings to proposers on the network. The validation rules have remained unchanged since Phase 0.

## Message Type
- **Type**: `ProposerSlashing`

## Phase 0 Validation Rules (Unchanged in All Forks)

### MUST Requirements

1. **[IGNORE]** The proposer slashing is the first valid proposer slashing received for the proposer with index `proposer_slashing.signed_header_1.message.proposer_index`
   - Clients MUST ignore duplicate proposer slashings for the same validator

2. **[REJECT]** All of the conditions within `process_proposer_slashing` pass validation:
   - The header slots MUST match: `header_1.slot == header_2.slot`
   - The header proposer indices MUST match: `header_1.proposer_index == header_2.proposer_index`
   - The headers MUST be different: `header_1 != header_2`
   - The proposer MUST be slashable: `is_slashable_validator(proposer, get_current_epoch(state))`
   - Both signatures MUST be valid BLS signatures from the proposer

## Additional Requirements

### Message Validation
- Clients MUST reject (fail validation) messages containing an incorrect type or invalid payload
- The message MUST be a valid `ProposerSlashing` container with:
  - `signed_header_1`: `SignedBeaconBlockHeader`
  - `signed_header_2`: `SignedBeaconBlockHeader`

## Key Points

- No changes to these validation rules were made in later forks (Altair, Bellatrix, Capella, Deneb, Electra)
- The validation focuses on preventing duplicate slashings and ensuring the slashing evidence is valid
- The `IGNORE` rule prevents DoS by repeated messages for already-known slashings
- The `REJECT` rule ensures the slashing is cryptographically valid and follows consensus rules

## Validation Outcomes

- **[IGNORE]**: Don't forward the message but may process it locally
- **[REJECT]**: Don't forward the message and don't process it