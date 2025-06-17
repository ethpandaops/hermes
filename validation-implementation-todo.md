# Hermes Validation Implementation Todo List

This todo list organizes the implementation of validation spec compliance for Hermes. Tasks are ordered by dependencies and can be parallelized where indicated.

## Phase 1: Core Infrastructure Components

These foundational components must be implemented first as they are dependencies for many validation tasks.

### 1.1 Fork Management System
- [ ] Implement fork management system - [Details](./changes/fork-management.md)
  - Required by: Almost all validation tasks
  - Can be done in parallel with: Block DB, Deduplication Cache

### 1.2 Block Storage System  
- [ ] Implement minimal block DB - [Details](./changes/block-db.md)
  - Required by: beacon_block, beacon_attestation, blob_sidecar validations
  - Can be done in parallel with: Fork Management, Deduplication Cache

### 1.3 Deduplication Cache System
- [ ] Implement unified deduplication cache - [Details](./changes/deduplication-cache.md)
  - Required by: All pubsub topics to prevent DoS
  - Can be done in parallel with: Fork Management, Block DB

### 1.4 Enhanced Clock Synchronization
- [ ] Enhance wallclock integration for MAXIMUM_GOSSIP_CLOCK_DISPARITY
  - Required by: All time-sensitive validations
  - Can be done in parallel with: Other infrastructure components

## Phase 2: Critical Validation Fixes

These are high-priority fixes that can be implemented once Phase 1 infrastructure is ready.

### 2.1 Block Validation (Parallel Group A)
- [ ] Fix beacon_block validation - [Details](./changes/beacon_block.md)
  - Dependencies: Fork Management, Block DB, Clock Sync
  - Priority: HIGH - Core functionality

### 2.2 Attestation Validation (Parallel Group A)
- [ ] Fix beacon_attestation validation - [Details](./changes/beacon_attestation.md)
  - Dependencies: Fork Management, Block DB, Deduplication Cache
  - Priority: HIGH - Core functionality

### 2.3 Aggregate Validation (Parallel Group A)
- [ ] Fix beacon_aggregate_and_proof validation - [Details](./changes/beacon_aggregate_and_proof.md)
  - Dependencies: Fork Management, Deduplication Cache
  - Priority: HIGH - Core functionality

### 2.4 Slashing Validations (Parallel Group B)
- [ ] Fix attester_slashing validation - [Details](./changes/attester_slashing.md)
  - Dependencies: Fork Management, Deduplication Cache
  - Priority: HIGH - Security critical
  
- [ ] Fix proposer_slashing validation - [Details](./changes/proposer_slashing.md)
  - Dependencies: Fork Management, Deduplication Cache
  - Priority: HIGH - Security critical

### 2.5 Exit and Change Validations (Parallel Group B)
- [ ] Fix voluntary_exit validation - [Details](./changes/voluntary_exit.md)
  - Dependencies: Fork Management, Deduplication Cache
  - Priority: MEDIUM
  
- [ ] Fix bls_to_execution_change validation - [Details](./changes/bls_to_execution_change.md)
  - Dependencies: Fork Management, Deduplication Cache
  - Priority: MEDIUM

## Phase 3: Smart Propagation

Implement smart block propagation after core validations are working.

- [ ] Implement smart block propagation - [Details](./changes/smart-propagation.md)
  - Dependencies: Block validation fixes, AttestationTracker integration
  - Priority: HIGH - Enables avoiding invalid block propagation

## Phase 4: Blob and Sync Committee Support

### 4.1 Blob Support (Parallel Group C)
- [ ] Fix blob_sidecar validation - [Details](./changes/blob_sidecar.md)
  - Dependencies: Fork Management, Block DB, Deduplication Cache
  - Priority: MEDIUM - Deneb+ support

### 4.2 Sync Committee Support (Parallel Group C)
- [ ] Fix sync_committee validation - [Details](./changes/sync_committee.md)
  - Dependencies: Fork Management, Deduplication Cache
  - Priority: MEDIUM
  
- [ ] Fix sync_committee_contribution_and_proof validation - [Details](./changes/sync_committee_contribution_and_proof.md)
  - Dependencies: Fork Management, Deduplication Cache
  - Priority: MEDIUM

## Phase 5: Req/Resp Protocol Fixes

These can be done in parallel once infrastructure is ready.

### 5.1 Critical Fixes (Parallel Group D)
- [ ] Fix goodbye protocol compliance - [Details](./changes/goodbye.md)
  - Dependencies: None
  - Priority: HIGH - Protocol compliance
  
- [ ] Fix ping protocol delegated mode - [Details](./changes/ping.md)
  - Dependencies: None
  - Priority: HIGH - Simple fix

- [ ] Fix metadata V2/V3 support - [Details](./changes/metadata.md)
  - Dependencies: Fork Management
  - Priority: HIGH - Protocol compliance

- [ ] Fix status V2 support - [Details](./changes/status.md)
  - Dependencies: Fork Management
  - Priority: MEDIUM

### 5.2 Block/Blob Req/Resp (Parallel Group E)
- [ ] Enhance beacon_blocks_by_range validation - [Details](./changes/beacon_blocks_by_range.md)
  - Dependencies: Block DB
  - Priority: MEDIUM
  
- [ ] Enhance beacon_blocks_by_root validation - [Details](./changes/beacon_blocks_by_root.md)
  - Dependencies: Block DB
  - Priority: MEDIUM

- [ ] Enhance blob_sidecars_by_range validation - [Details](./changes/blob_sidecars_by_range.md)
  - Dependencies: Blob storage (future)
  - Priority: LOW
  
- [ ] Enhance blob_sidecars_by_root validation - [Details](./changes/blob_sidecars_by_root.md)
  - Dependencies: Blob storage (future)
  - Priority: LOW

## Implementation Notes

### Parallelization Strategy
- Tasks within the same "Parallel Group" can be worked on simultaneously
- Different parallel groups can also run concurrently if their phase dependencies are met
- Infrastructure components (Phase 1) should be prioritized and can all be done in parallel

### Testing Strategy
1. Unit tests for each component
2. Integration tests after each phase
3. Full validation suite testing after Phase 4
4. Performance testing for smart propagation

### Rollout Strategy
1. Deploy infrastructure components with feature flags
2. Enable validation fixes in staged rollout
3. Monitor metrics and adjust thresholds
4. Full deployment after stability confirmed

### Resource Monitoring
- Monitor memory usage of deduplication caches
- Track block DB size and pruning effectiveness  
- Measure smart propagation effectiveness
- Watch for any performance regressions

## Summary

**Total Tasks**: 35
- **Phase 1 (Infrastructure)**: 4 tasks
- **Phase 2 (Critical Validation)**: 7 tasks  
- **Phase 3 (Smart Propagation)**: 1 task
- **Phase 4 (Blob/Sync Committee)**: 3 tasks
- **Phase 5 (Req/Resp)**: 8 tasks
- **Phase 6 (Light Client)**: 6 tasks

**Highest Priority Path**:
1. Fork Management + Block DB + Dedup Cache (parallel)
2. Block + Attestation + Aggregate validations (parallel)
3. Smart Propagation
4. Slashing validations

This provides a minimal path to a compliant validator that can intelligently propagate blocks without requiring an execution client.