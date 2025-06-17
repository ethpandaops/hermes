# Voluntary Exit Topic Validation Rules

## Topic: `voluntary_exit`

## Overview
The `voluntary_exit` topic is used to propagate voluntary validator exits. Validation rules have been updated in Deneb (EIP-7044) and Electra (EIP-7251).

## Phase 0 - Capella Validation Rules

### MUST Requirements

1. **[IGNORE]** The voluntary exit is the first valid voluntary exit received for the validator with index `signed_voluntary_exit.message.validator_index`

2. **[REJECT]** All of the conditions within `process_voluntary_exit` pass validation:
   - The validator is active: `is_active_validator(validator, get_current_epoch(state))`
   - Exit has not been initiated: `validator.exit_epoch == FAR_FUTURE_EPOCH`
   - The exit epoch is not in the future: `get_current_epoch(state) >= voluntary_exit.epoch`
   - The validator has been active long enough: `get_current_epoch(state) >= validator.activation_epoch + SHARD_COMMITTEE_PERIOD`
   - The signature is valid

## Deneb Fork Changes (EIP-7044)

### Modified Signature Validation

- The signature validation uses a fixed fork version:
  - `domain = compute_domain(DOMAIN_VOLUNTARY_EXIT, CAPELLA_FORK_VERSION, state.genesis_validators_root)`
- Note: The `voluntary_exit` topic is implicitly modified despite the lock-in use of `CAPELLA_FORK_VERSION` for message signature validation

## Electra Fork Changes (EIP-7251)

### Additional Validation

- **[REJECT]** The validator has no pending withdrawals in the queue:
  - `get_pending_balance_to_withdraw(state, voluntary_exit.validator_index) == 0`

## General Requirements

### Message Type
- The message type for `voluntary_exit` topic MUST be `SignedVoluntaryExit`

### Invalid Messages
- Clients MUST reject (fail validation) messages containing an incorrect type, or invalid payload

## Summary of MUST/MUST NOT Rules

1. **MUST** ignore duplicate voluntary exits for the same validator index
2. **MUST** reject if validator is not active
3. **MUST** reject if exit has already been initiated
4. **MUST** reject if exit epoch is in the future
5. **MUST** reject if validator hasn't been active for at least `SHARD_COMMITTEE_PERIOD`
6. **MUST** reject if signature is invalid
7. **MUST** reject if validator has pending withdrawals (Electra onwards)
8. **MUST** reject messages with incorrect type (not `SignedVoluntaryExit`)
9. **MUST** use fixed `CAPELLA_FORK_VERSION` for signature domain (Deneb onwards)

## Validation Outcomes

- **[IGNORE]**: Don't forward the message but may process it locally
- **[REJECT]**: Don't forward the message and don't process it