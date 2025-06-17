# Blob Sidecar Topic Validation Rules

## Topic: `blob_sidecar_{subnet_id}`

## Overview
The `blob_sidecar_{subnet_id}` topics are used to propagate blob sidecars for EIP-4844. Introduced in Deneb with updates in Electra.

## Convenience Variables
- `block_header = blob_sidecar.signed_block_header.message`

## Deneb Validation Rules

### MUST Requirements (REJECT)

1. **Index validation**: The sidecar's index is consistent with `MAX_BLOBS_PER_BLOCK`:
   - `blob_sidecar.index < MAX_BLOBS_PER_BLOCK`

2. **Subnet validation**: The sidecar is for the correct subnet:
   - `compute_subnet_for_blob_sidecar(blob_sidecar.index) == subnet_id`

3. **Proposer signature**: The proposer signature of `blob_sidecar.signed_block_header` is valid with respect to the `block_header.proposer_index` pubkey

4. **Parent validation**: The sidecar's block's parent (defined by `block_header.parent_root`) passes validation

5. **Parent slot ordering**: The sidecar is from a higher slot than the sidecar's block's parent

6. **Finalized checkpoint ancestry**: The current finalized_checkpoint is an ancestor of the sidecar's block:
   - `get_checkpoint_block(store, block_header.parent_root, store.finalized_checkpoint.epoch) == store.finalized_checkpoint.root`

7. **Inclusion proof**: The sidecar's inclusion proof is valid as verified by `verify_blob_sidecar_inclusion_proof(blob_sidecar)`

8. **KZG proof**: The sidecar's blob is valid as verified by `verify_blob_kzg_proof(blob_sidecar.blob, blob_sidecar.kzg_commitment, blob_sidecar.kzg_proof)`

9. **Proposer index**: The sidecar is proposed by the expected `proposer_index` for the block's slot in the context of the current shuffling

### MUST Requirements (IGNORE)

1. **Not future slot**: The sidecar is not from a future slot (with a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance):
   - `block_header.slot <= current_slot`

2. **After finalized**: The sidecar is from a slot greater than the latest finalized slot:
   - `block_header.slot > compute_start_slot_at_epoch(store.finalized_checkpoint.epoch)`

3. **Parent seen**: The sidecar's block's parent has been seen (via gossip or non-gossip sources)

4. **First sidecar**: The sidecar is the first sidecar for the tuple `(block_header.slot, block_header.proposer_index, blob_sidecar.index)` with valid header signature, sidecar inclusion proof, and kzg proof

## Electra Fork Changes

The electra fork modifies the blob_sidecar validation with one key change:
- Uses of `MAX_BLOBS_PER_BLOCK` in existing validations are replaced with `MAX_BLOBS_PER_BLOCK_ELECTRA`

## Additional Requirements from Fork Choice

- **Block validity**: The block MUST NOT be considered valid until all valid `Blob`s have been downloaded
- **Extraneous blobs**: Extraneous or invalid Blobs (in addition to KZG expected/referenced valid blobs) received on the p2p network MUST NOT invalidate a block that is otherwise valid and available

## Key Points

These validation rules ensure:
- Blob sidecars are properly indexed and assigned to correct subnets
- Cryptographic proofs (signatures, inclusion proofs, KZG proofs) are valid
- Temporal ordering is maintained relative to the chain state
- Spam prevention through first-seen rules

## Validation Outcomes

- **[IGNORE]**: Don't forward the message but may process it locally
- **[REJECT]**: Don't forward the message and don't process it