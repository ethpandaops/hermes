# Ethereum Consensus Layer P2P Validation Specifications

This directory contains the extracted validation requirements for all Ethereum consensus layer P2P topics, organized by protocol type (pubsub and reqresp).

## Overview

These specifications detail the MUST and MUST NOT validation requirements for handling messages in the Ethereum consensus layer P2P network. They have been extracted from the official Ethereum consensus specifications and compiled by fork progression from Phase 0 through Electra.

## Structure

### Pubsub Topics (`/pubsub`)

Gossipsub topics for broadcasting messages across the network:

- **beacon_block.md** - Block propagation validation rules
- **beacon_aggregate_and_proof.md** - Aggregated attestation validation
- **beacon_attestation.md** - Unaggregated attestation validation  
- **voluntary_exit.md** - Voluntary exit validation
- **proposer_slashing.md** - Proposer slashing validation
- **attester_slashing.md** - Attester slashing validation
- **sync_committee.md** - Sync committee message validation (Altair+)
- **sync_committee_contribution_and_proof.md** - Sync committee contribution validation (Altair+)
- **light_client_finality_update.md** - Light client finality update validation (Altair+)
- **light_client_optimistic_update.md** - Light client optimistic update validation (Altair+)
- **bls_to_execution_change.md** - BLS to execution address change validation (Capella+)
- **blob_sidecar.md** - Blob sidecar validation (Deneb+)

### Request/Response Topics (`/reqresp`)

Point-to-point request/response protocols:

- **status.md** - Peer status exchange
- **goodbye.md** - Disconnection notification
- **ping.md** - Liveness check
- **metadata.md** - Peer metadata exchange
- **beacon_blocks_by_range.md** - Block range requests
- **beacon_blocks_by_root.md** - Specific block requests
- **light_client_bootstrap.md** - Light client initialization (Altair+)
- **light_client_updates_by_range.md** - Light client update range requests (Altair+)
- **light_client_finality_update.md** - Light client finality update requests (Altair+)
- **light_client_optimistic_update.md** - Light client optimistic update requests (Altair+)
- **blob_sidecars_by_range.md** - Blob sidecar range requests (Deneb+)
- **blob_sidecars_by_root.md** - Specific blob sidecar requests (Deneb+)

## Fork Progression

The validation rules evolve across consensus layer forks:

1. **Phase 0** - Base validation rules for core topics
2. **Altair** - Adds sync committees and light client support
3. **Bellatrix** - Adds execution payload validation (The Merge)
4. **Capella** - Adds BLS to execution change support
5. **Deneb** - Adds blob sidecar support (EIP-4844) and relaxes attestation timing (EIP-7045)
6. **Electra** - Updates attestation format and increases blob limits

## Validation Outcomes

- **[IGNORE]** - Don't forward the message but may process/queue it locally
- **[REJECT]** - Don't forward the message and don't process it (indicates protocol violation)

## Usage

These specifications serve as the authoritative reference for implementing consensus layer P2P validation in Ethereum clients. Each file contains:

1. Protocol/topic identifier
2. Overview of the topic's purpose
3. Detailed MUST/MUST NOT requirements
4. Fork-specific changes
5. Validation outcome classifications

When implementing validation, ensure all MUST requirements are enforced and MUST NOT conditions are prevented to maintain network security and consistency.