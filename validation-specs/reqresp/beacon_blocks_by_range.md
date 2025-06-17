# BeaconBlocksByRange Request/Response Validation Rules

## Protocol: `/eth2/beacon_chain/req/beacon_blocks_by_range/2/`

## Overview
The BeaconBlocksByRange protocol allows peers to request a range of beacon blocks by slot number.

## Request Validation Rules

### Request Structure
- **Encoding**: SSZ-container
- **Content**: `(start_slot: Slot, count: uint64, step: uint64)`
- `step` MUST be set to 1 (deprecated parameter)

### Request Limits
- `count` MUST NOT exceed `MAX_REQUEST_BLOCKS` (1024 in phase0, 128 in Deneb+)
- No more than `MAX_REQUEST_BLOCKS` may be requested at a time

## Response Validation Rules

### Response Structure
1. The response MUST consist of zero or more `response_chunk`
2. Each successful `response_chunk` MUST contain a single `SignedBeaconBlock` payload
3. Response type: `List[SignedBeaconBlock, MAX_REQUEST_BLOCKS]`

### Block Selection and Ordering
1. Clients MUST respond with blocks from their view of the current fork choice
2. Blocks MUST be from the single chain defined by the current head
3. Blocks from slots before finalization MUST lead to the finalized block reported in the `Status` handshake
4. The following blocks, where they exist, MUST be sent in consecutive order
5. Clients MUST respond with blocks that are consistent from a single chain within the context of the request
6. When `step == 1`, each `parent_root` MUST match the `hash_tree_root` of the preceding block

### Response Limits
1. Clients MUST respond with at least the first block that exists in the range, if they have it
2. The response MUST contain no more than `count` blocks
3. The response MUST contain no more than `MAX_REQUEST_BLOCKS` blocks
4. Clients MAY limit the number of blocks in the response

### Epoch Range Requirements
1. Clients MUST keep a record of signed blocks seen on the epoch range `[max(GENESIS_EPOCH, current_epoch - MIN_EPOCHS_FOR_BLOCK_REQUESTS), current_epoch]`
2. Clients MUST support serving requests of blocks on this range
3. `MIN_EPOCHS_FOR_BLOCK_REQUESTS` = 33024 epochs (~5 months)

### Error Handling
1. Peers unable to reply to block requests within the `MIN_EPOCHS_FOR_BLOCK_REQUESTS` epoch range SHOULD respond with error code `3: ResourceUnavailable`
2. Clients MAY stop responding if their fork choice changes the view of the chain during the response

### Weak Subjectivity Considerations
1. Nodes that start from a recent weak subjectivity checkpoint MUST backfill the local block database to at least epoch `current_epoch - MIN_EPOCHS_FOR_BLOCK_REQUESTS`
2. When backfilling, the node MUST validate both:
   - The proposer signatures
   - That the blocks form a valid chain up to the most recent block referenced in the weak subjectivity state

### Fork-Specific Block Types
The response uses a `ForkDigest`-context to select the appropriate block type:
- `GENESIS_FORK_VERSION`: `phase0.SignedBeaconBlock`
- `ALTAIR_FORK_VERSION`: `altair.SignedBeaconBlock`
- `BELLATRIX_FORK_VERSION`: `bellatrix.SignedBeaconBlock`
- `CAPELLA_FORK_VERSION`: `capella.SignedBeaconBlock`
- `DENEB_FORK_VERSION`: `deneb.SignedBeaconBlock`
- `ELECTRA_FORK_VERSION`: `electra.SignedBeaconBlock`

### Additional Deneb+ Requirements
1. Clients SHOULD include a block in the response as soon as it passes the gossip validation rules
2. Clients SHOULD NOT respond with blocks that fail the beacon chain state transition

## General Req/Resp Validation Rules

### SSZ-Snappy Encoding
1. Length-prefix MUST be encoded as an unsigned protobuf varint
2. Length-prefix MUST NOT exceed 10 bytes
3. Length-prefix MUST be within expected size bounds or `MAX_PAYLOAD_SIZE`
4. Reader MUST NOT read more than `max_compressed_len(n)` bytes after reading the SSZ length-prefix `n`

### Error Conditions
Invalid input (header or payload) MUST result in:
- From requests: send back error message with response code `InvalidRequest`
- From responses: ignore the response as bad server behavior

### Response Codes
- `0`: Success
- `1`: InvalidRequest
- `2`: ServerError
- `3`: ResourceUnavailable (valid for BeaconBlocksByRange when outside epoch range)