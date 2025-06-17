# BLS to Execution Change Topic Validation Rules

## Topic: `bls_to_execution_change`

## Overview
The `bls_to_execution_change` topic is used to propagate BLS to execution address changes for validators. Introduced in Capella and unchanged in subsequent forks.

## Capella and Later Forks Validation Rules

### MUST Requirements

1. **[IGNORE]** `current_epoch >= CAPELLA_FORK_EPOCH`, where `current_epoch` is defined by the current wall-clock time

2. **[IGNORE]** The `signed_bls_to_execution_change` is the first valid signed bls to execution change received for the validator with index `signed_bls_to_execution_change.message.validator_index`

3. **[REJECT]** All of the conditions within `process_bls_to_execution_change` pass validation

### Process BLS to Execution Change Validation

The `process_bls_to_execution_change` function validates:

1. **MUST** assert `address_change.validator_index < len(state.validators)`

2. **MUST** assert `validator.withdrawal_credentials[:1] == BLS_WITHDRAWAL_PREFIX`

3. **MUST** assert `validator.withdrawal_credentials[1:] == hash(address_change.from_bls_pubkey)[1:]`

4. **MUST** assert `bls.Verify(address_change.from_bls_pubkey, signing_root, signed_address_change.signature)`
   - Where the signing_root is computed using `DOMAIN_BLS_TO_EXECUTION_CHANGE` domain (fork-agnostic)

## Important Notes

- The `bls_to_execution_change` topic was introduced in Capella and remains unchanged in Deneb, Electra, and Fulu forks
- The validation rules use a fork-agnostic domain for signature verification, meaning address changes are valid across forks
- The topic type is `SignedBLSToExecutionChange`
- These messages are used to change withdrawal credentials from BLS to execution address format

## Key Points

The validation ensures:
- Messages are only processed after Capella fork activation
- No duplicate address changes for the same validator
- Validator exists and has BLS withdrawal credentials
- The BLS public key matches the withdrawal credentials
- The signature is valid from the correct BLS key

## Validation Outcomes

- **[IGNORE]**: Don't forward the message but may process it locally
- **[REJECT]**: Don't forward the message and don't process it