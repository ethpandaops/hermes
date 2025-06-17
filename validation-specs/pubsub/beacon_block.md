# Beacon Block Topic Validation Rules

## Topic: `beacon_block`

## Overview
The `beacon_block` topic is used to propagate signed beacon blocks across the network. The validation rules have evolved across forks, with significant changes in Bellatrix (execution payload), Deneb (blob commitments), and Electra (updated blob limits).

## Phase 0 (Base Rules)

### MUST Requirements

1. **[IGNORE]** The block is not from a future slot (with a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance):
   - `signed_beacon_block.message.slot <= current_slot`
   - Clients MAY queue future blocks for processing at the appropriate slot

2. **[IGNORE]** The block is from a slot greater than the latest finalized slot:
   - `signed_beacon_block.message.slot > compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)`
   - Clients MAY choose to validate and store such blocks for additional purposes

3. **[IGNORE]** The block is the first block with valid signature received for the proposer for the slot `signed_beacon_block.message.slot`

4. **[REJECT]** The proposer signature, `signed_beacon_block.signature`, is valid with respect to the `proposer_index` pubkey

5. **[IGNORE]** The block's parent (defined by `block.parent_root`) has been seen via gossip or non-gossip sources
   - Clients MAY queue blocks for processing once the parent block is retrieved

6. **[REJECT]** The block's parent (defined by `block.parent_root`) passes validation

7. **[REJECT]** The block is from a higher slot than its parent

8. **[REJECT]** The current `finalized_checkpoint` is an ancestor of `block`:
   - `get_checkpoint_block(store, block.parent_root, store.finalized_checkpoint.epoch) == store.finalized_checkpoint.root`

9. **[REJECT]** The block is proposed by the expected `proposer_index` for the block's slot in the context of the current shuffling (defined by `parent_root`/`slot`)
   - If the `proposer_index` cannot immediately be verified against the expected shuffling, the block MAY be queued for later processing
   - In such cases, do NOT `REJECT`, instead `IGNORE` this message

## Bellatrix Fork (Merge)

### Additional Validation When Execution is Enabled

When `is_execution_enabled(state, block.body)`:

1. **[REJECT]** The block's execution payload timestamp is correct with respect to the slot:
   - `execution_payload.timestamp == compute_timestamp_at_slot(state, block.slot)`

2. If `execution_payload` verification of block's parent by an execution node is not complete:
   - **[REJECT]** The block's parent passes all validation (excluding execution node verification of the `block.body.execution_payload`)

3. Otherwise (if parent's execution payload verification is complete):
   - **[IGNORE]** The block's parent passes all validation (including execution node verification of the `block.body.execution_payload`)

### MUST NOT Requirements

- When execution is enabled, the general Phase 0 "[REJECT] The block's parent passes validation" rule MUST NOT be applied

## Deneb Fork

### Additional Validation

1. **[REJECT]** The length of KZG commitments is less than or equal to the limitation defined in Consensus Layer:
   - `len(signed_beacon_block.message.body.blob_kzg_commitments) <= MAX_BLOBS_PER_BLOCK`

## Electra Fork

### Modified Validation

1. **[REJECT]** The length of KZG commitments is less than or equal to the limitation defined in Consensus Layer:
   - `len(signed_beacon_block.message.body.blob_kzg_commitments) <= MAX_BLOBS_PER_BLOCK_ELECTRA`
   - Note: This replaces the Deneb validation with the updated constant

## Summary of Key Validation Categories

1. **Timing validations**: Ensure blocks are not too far in the future and are after finalization
2. **Signature validations**: Verify proposer signature validity
3. **Chain validations**: Ensure proper parent-child relationships and finalization ancestry
4. **Proposer validations**: Verify the block comes from the expected proposer
5. **Execution validations** (post-Merge): Ensure execution payload timestamp correctness
6. **Blob validations** (post-Deneb): Ensure KZG commitment limits are respected

## Validation Outcomes

- **[IGNORE]**: Don't forward the message but may process/queue it
- **[REJECT]**: Don't forward the message and don't process it