# Hermes In-Process Gossipsub Validation Implementation Checklist

## Overview
> This checklist tracks the implementation of in-process gossipsub validation for Hermes, transitioning from complete Prysm dependency to independent validation capabilities.

### Goal Summary
- [ ] **Eliminate Prysm dependency** for gossipsub message validation
- [ ] **Implement in-process validation** for all gossipsub topics
- [ ] **Reduce upstream queries** by 99% (only epoch state sync)
- [ ] **Achieve <10ms validation** for most messages
- [ ] **Maintain 100% correctness** with consensus spec

## Pre-Implementation Checklist

### Current State Analysis ✅
- [x] **No validation present** - Confirmed Hermes accepts all messages without validation
- [x] **100% Prysm dependency** - All validation delegated to external Prysm node
- [x] **Performance bottlenecks identified** - Rate limits, synchronous ops, no caching
- [x] **Architecture understood** - Passive observer + RPC proxy pattern
- [x] **Technical debt mapped** - No crypto libs, no state management

### Existing Assets to Leverage ✅
- [x] **P2P networking** - Robust gossipsub participation working
- [x] **Topic handling** - All message types across forks supported
- [x] **Monitoring** - Telemetry integration in place
- [x] **Subnet config** - Flexible configuration system exists
- [x] **Message routing** - Pubsub infrastructure operational

## Architecture Components Checklist

### Core Components to Build
- [ ] **Validation Router** - Route messages based on operating mode
- [ ] **In-Process Validator** - Handle all validation using in-process solutions
- [ ] **Beacon State Sync Service** - Maintain minimal state for validation
- [ ] **Committee Cache Manager** - Efficient committee assignment lookups
- [ ] **Signature Verification Service** - Optimized BLS operations
- [ ] **Creative Validation Solutions** - Novel approaches for complex cases
- [ ] **Prysm Delegation Service** - Maintain current behavior for delegated mode

## Phase 1: Foundation and Simple Validations

### 1.1 Cryptographic Infrastructure
- [ ] **Add BLS signature library** - Integration of `github.com/herumi/bls-eth-go-binary`
- [ ] **Implement domain computation** - Support for all signature domains
- [ ] **Create public key cache** - Validator index to pubkey mapping
- [ ] **Add signature batching** - Performance optimization for bulk verification
- [ ] **Unit tests** - Verify signature operations with test vectors

### 1.2 Message Parsing and SSZ
- [ ] **Integrate SSZ library** - Fork-aware message deserialization
- [ ] **Add message parsers** - Type-safe handlers for each message type
- [ ] **Implement bounds checking** - Validate message structure and limits
- [ ] **Fork version handling** - Support Phase0 through Electra
- [ ] **Unit tests** - SSZ parsing across all forks

### 1.3 Simple Message Validators
- [ ] **`voluntary_exit` validator** - Signature + validator status checks
- [ ] **`proposer_slashing` validator** - Double proposal detection + signatures
- [ ] **`attester_slashing` validator** - Conflicting vote detection + signatures
- [ ] **`bls_to_execution_change` validator** - Credential change + signature
- [ ] **Integration tests** - End-to-end validation flows

## Phase 2: Creative Solutions Implementation

### 2.1 Attestation Threshold Block Validation
- [ ] **Create AttestationTracker** - Monitor attestations per block
- [ ] **Implement threshold config** - Static count or percentage based
- [ ] **Add timeout handling** - Max wait time for attestations
- [ ] **Create attestation pools** - Track valid attestations by block root
- [ ] **Implement social consensus** - Accept blocks with sufficient attestations
- [ ] **Unit tests** - Threshold logic and edge cases

### 2.2 KZG Blob Sidecar Validation  
- [ ] **Integrate KZG library** - go-kzg-4844 or similar
- [ ] **Implement KZG verification** - Blob proof validation
- [ ] **Add inclusion proofs** - Verify commitment in block
- [ ] **Proposer signature check** - Validate block header signature
- [ ] **Blob cache management** - Efficient blob storage
- [ ] **Performance tests** - KZG operation benchmarks

### 2.3 Aggregate Attestation Validation
- [ ] **Committee member resolution** - Map indices to validators
- [ ] **Aggregate signature verification** - BLS aggregate operations
- [ ] **Bitfield processing** - Efficient attestation bit handling
- [ ] **Aggregator eligibility** - Selection proof verification
- [ ] **Performance optimization** - Batch verification where possible
- [ ] **Integration tests** - Full aggregate validation flow

## Phase 3: Beacon State Synchronization

### 3.1 State Sync Service
- [ ] **Create BeaconStateSyncer** - Main state synchronization component
- [ ] **Implement epoch sync** - Fetch state at epoch boundaries
- [ ] **Add state fetching** - Minimal state required for validation
- [ ] **Committee computation** - Pre-compute all committee assignments
- [ ] **Validator registry sync** - Update validator info and pubkeys
- [ ] **Fork handling** - Track fork versions and transitions
- [ ] **Error recovery** - Handle upstream failures gracefully

### 3.2 Committee Cache Implementation
- [ ] **Create CommitteeCache** - Fast committee lookups
- [ ] **Subnet mapping** - Map subnets to committees
- [ ] **Sync committee tracking** - 27-hour period management
- [ ] **Cache warming** - Pre-populate before epoch transition
- [ ] **Cache invalidation** - Clear stale data on epoch change
- [ ] **Memory bounds** - Implement LRU eviction
- [ ] **Performance tests** - Lookup speed benchmarks

## Phase 4: Standard Attestation and Sync Committee Validation

### 4.1 Attestation Validation
- [ ] **`beacon_attestation_{subnet_id}` validator** - Individual votes
- [ ] **Committee membership checks** - Verify validator in committee
- [ ] **Subnet assignment validation** - Correct subnet routing
- [ ] **Aggregation bit handling** - Process attestation bitfields
- [ ] **Signature verification** - Individual attestation signatures
- [ ] **Fork-aware validation** - Handle Phase0 through Electra
- [ ] **Performance optimization** - Batch where possible

### 4.2 Sync Committee Validation
- [ ] **`sync_committee_{subnet_id}` validator** - Sync signatures
- [ ] **Sync committee cache** - 27-hour period management
- [ ] **Membership verification** - Check validator in current sync committee
- [ ] **Subnet assignment** - Verify correct sync subnet
- [ ] **`sync_committee_contribution_and_proof`** - Aggregated sync sigs
- [ ] **Contribution verification** - Validate aggregator selection
- [ ] **Integration tests** - Full sync committee flows

### 4.3 Performance Optimization
- [ ] **Implement LRU caching** - Frequently accessed data
- [ ] **Optimize lookups** - Pre-computed indices and maps
- [ ] **Batch signature verification** - Group similar operations
- [ ] **Memory profiling** - Identify and fix leaks
- [ ] **Benchmark suite** - Track validation latencies
- [ ] **Load testing** - Verify performance under stress

### Component Breakdown

#### **1. Validation Router**
- [ ] **Route messages** based on operating mode (Independent vs Delegated)
- [ ] **Classify message types** for appropriate validation
- [ ] **Select validation implementation** per message type
- [ ] **Aggregate and report results** to callers
- [ ] **Handle mode switching** if runtime changes allowed

#### **2. In-Process Validator** (Independent Mode Only)
- [ ] **BLS signature verification** - Single and aggregate signatures
- [ ] **KZG proof verification** - Blob sidecar validation
- [ ] **Committee-based validation** - Using cached epoch state
- [ ] **Attestation threshold validation** - Creative block validation
- [ ] **Structural validation** - Message format and bounds
- [ ] **Duplicate detection** - Prevent replay attacks

#### **3. Beacon State Sync Service** (Independent Mode Only)
- [ ] **Epoch-boundary synchronization** - Fetch state from upstream
- [ ] **Committee pre-computation** - Calculate all assignments
- [ ] **Validator registry management** - Track all validators
- [ ] **Public key indexing** - Fast validator lookups
- [ ] **Fork transition handling** - Update validation rules
- [ ] **Digest computation** - Fork-specific domains

#### **4. Committee Cache Manager** (Independent Mode Only)
- [ ] **Pre-compute assignments** - All committees per epoch
- [ ] **Subnet-to-committee mapping** - Fast attestation routing
- [ ] **Sync committee tracking** - 27-hour period management
- [ ] **Cache warming** - Pre-populate before epoch transition
- [ ] **Cache invalidation** - Clear stale data
- [ ] **Memory management** - Bounded cache sizes

#### **5. Signature Verification Service** (Independent Mode Only)
- [ ] **Single signature verification** - Exits, slashings, attestations
- [ ] **Aggregate signature verification** - Aggregates, sync committee
- [ ] **Public key caching** - Validator index to pubkey mapping
- [ ] **Domain computation** - All signature domains
- [ ] **Batch verification** - Performance optimization
- [ ] **Error handling** - Invalid signature recovery

#### **6. Creative Validation Solutions** (Independent Mode Only)
- [ ] **Attestation threshold tracking** - Monitor block support
- [ ] **KZG proof verification** - Blob sidecar validation
- [ ] **Attestation pool management** - Track valid attestations
- [ ] **Block confidence scoring** - Social consensus metrics
- [ ] **Advanced cryptography** - KZG, merkle proofs
- [ ] **Timeout handling** - Fallback mechanisms

#### **7. Prysm Delegation Service** (Delegated Mode Only)
- [ ] **Maintain current behavior** - No breaking changes
- [ ] **RPC request handling** - Forward to Prysm
- [ ] **Response processing** - Parse Prysm results
- [ ] **Trusted peer management** - Existing logic
- [ ] **Error recovery** - Handle Prysm failures
- [ ] **Performance monitoring** - Track RPC latency

## Phase 5: Integration and Mode Support

### 5.1 Validation Router Implementation
- [ ] **Create ValidationRouter component** - Central routing logic
- [ ] **Implement mode detection** - Read configuration
- [ ] **Add message routing** - Direct to appropriate validator
- [ ] **Create mode interfaces** - Clean API boundaries
- [ ] **Add fallback logic** - Handle validator failures
- [ ] **Unit tests** - Mode switching and routing

### 5.2 Configuration and Mode Management
- [ ] **Add CLI flags** - `--validation-mode=independent|delegated`
- [ ] **Environment variables** - Alternative configuration method
- [ ] **Configuration validation** - Ensure required dependencies
- [ ] **Mode-specific checks** - Validate setup per mode
- [ ] **Runtime switching** - If hot-swapping needed
- [ ] **Documentation** - Usage instructions

### 5.3 Error Handling and Monitoring
- [ ] **Validation metrics** - Success/failure rates per topic
- [ ] **Latency tracking** - Validation time per message type
- [ ] **Mode-specific metrics** - Independent vs Delegated stats
- [ ] **Error categorization** - Group failures by type
- [ ] **Alerting rules** - Prometheus/Grafana setup
- [ ] **Debug tooling** - Validation analysis utilities
```go
type SignatureVerifier struct {
    pubKeyCache map[ValidatorIndex]blst.PublicKey
    domains     map[DomainType][32]byte
}

func (sv *SignatureVerifier) VerifySignature(
    pubkey blst.PublicKey, 
    message []byte, 
    signature []byte, 
    domain [32]byte,
) bool {
    // Fast signature verification with caching
    sigObj := blst.SignatureFromBytes(signature)
    return sigObj.Verify(pubkey, message, domain)
}
```

## Testing Strategy Checklist

### Unit Testing
- [ ] **BLS signature verification** - Known good/bad signatures
- [ ] **SSZ parsing** - All message types across forks
- [ ] **Committee computations** - Consensus-spec test vectors
- [ ] **Cache operations** - Hits, misses, evictions
- [ ] **Domain calculations** - Fork-specific domains
- [ ] **Bitfield operations** - Attestation aggregation bits

### Integration Testing
- [ ] **End-to-end validation** - Full message flows
- [ ] **Mode switching** - Transition between modes
- [ ] **Upstream failures** - Graceful degradation
- [ ] **Epoch boundaries** - State sync edge cases
- [ ] **Fork transitions** - Validation rule updates
- [ ] **Concurrent validation** - Thread safety

### Performance Testing
- [ ] **Latency benchmarks** - Per message type
- [ ] **Throughput testing** - Messages per second
- [ ] **Memory profiling** - Cache and state usage
- [ ] **CPU profiling** - Signature verification load
- [ ] **Network simulation** - High message volumes
- [ ] **Resource limits** - Bounded memory/CPU usage

#### Sample Implementation
```go
type BlockValidator struct {
    attestationTracker *AttestationTracker
    config            BlockValidationConfig
}

type BlockValidationConfig struct {
    AttestationThreshold int           // Minimum attestations required
    AttestationPercent   float64       // Or percentage of committee
    ValidationTimeout    time.Duration // Max wait time for attestations
}

func (bv *BlockValidator) ValidateBlock(ctx context.Context, block *SignedBeaconBlock) error {
    // Fast structural validation first
    if err := bv.validateBlockStructure(block); err != nil {
        return err
    }
    
    // Wait for attestations as validation signal
    blockRoot := block.Block.HashTreeRoot()
    ctx, cancel := context.WithTimeout(ctx, bv.config.ValidationTimeout)
    defer cancel()
    
    attestationCount := bv.attestationTracker.WaitForAttestations(ctx, blockRoot, bv.config.AttestationThreshold)
    
    if attestationCount >= bv.config.AttestationThreshold {
        return nil // Social consensus validates the block
    }
    
    return errors.New("insufficient attestation support for block")
}
```

## Implementation Dependencies Checklist

### External Dependencies
- [ ] **BLS library** - `github.com/herumi/bls-eth-go-binary`
- [ ] **SSZ library** - Fast SSZ serialization
- [ ] **KZG library** - `go-kzg-4844` or similar
- [ ] **Ethereum types** - Consensus layer types
- [ ] **Crypto primitives** - SHA256, merkle trees

### Phase Dependencies
- [ ] **Phase 1 → Phase 2** - Crypto infrastructure required
- [ ] **Phase 1 → Phase 3** - Message parsing required
- [ ] **Phase 3 → Phase 4** - State sync required
- [ ] **Phase 2-4 → Phase 5** - All validators required
- [ ] **Testing → All Phases** - Continuous validation
```go
type BlobValidator struct {
    kzgCtx     *kzg4844.Context
    validators map[ValidatorIndex]*ValidatorInfo
}

func (bv *BlobValidator) ValidateBlobSidecar(blob *BlobSidecar) error {
    // Verify KZG proof (most expensive operation)
    if !bv.kzgCtx.VerifyBlobKzgProof(
        blob.Blob, 
        blob.KzgCommitment, 
        blob.KzgProof,
    ) {
        return errors.New("invalid KZG proof")
    }
    
    // Verify inclusion proof (merkle proof that commitment is in block)
    if !bv.verifyKzgCommitmentInclusionProof(blob) {
        return errors.New("invalid KZG commitment inclusion proof")
    }
    
    // Verify proposer signature on block header
    proposer := bv.validators[blob.SignedBlockHeader.Message.ProposerIndex]
    return bv.verifyProposerSignature(blob.SignedBlockHeader, proposer.PublicKey)
}
```

## Risk Mitigation Checklist

### Implementation Risks
- [ ] **Consensus rule tests** - Full spec compliance
- [ ] **Fork compatibility** - Test all fork versions
- [ ] **Edge case handling** - Invalid message formats
- [ ] **State consistency** - Epoch boundary races
- [ ] **Gradual rollout** - Phased deployment plan

### Performance Risks
- [ ] **Memory bounds** - Implement limits
- [ ] **CPU limits** - Rate limiting
- [ ] **Cache size limits** - LRU eviction
- [ ] **Goroutine leaks** - Proper cleanup
- [ ] **Resource monitoring** - Runtime metrics

### Security Risks
- [ ] **DoS protection** - Rate limiting
- [ ] **Invalid message rejection** - Early validation
- [ ] **Resource exhaustion** - Bounded queues
- [ ] **Signature malleability** - Strict verification
- [ ] **Replay protection** - Duplicate detection
```go
type AggregateValidator struct {
    committees map[CommitteeKey]*Committee
    pubkeys    map[ValidatorIndex]bls.PublicKey
}

func (av *AggregateValidator) ValidateAggregate(agg *SignedAggregateAndProof) error {
    attestation := agg.Message.Aggregate
    
    // Get committee for this attestation
    committee := av.getCommittee(attestation.Data.Slot, attestation.Data.Index)
    
    // Verify aggregator is in committee and eligible
    aggregatorIndex := agg.Message.AggregatorIndex
    if !av.isValidAggregator(committee, aggregatorIndex, agg.Message.SelectionProof) {
        return errors.New("invalid aggregator")
    }
    
    // Get public keys for all attesters
    attesterIndices := av.getAttesterIndices(committee, attestation.AggregationBits)
    pubkeys := make([]bls.PublicKey, len(attesterIndices))
    for i, idx := range attesterIndices {
        pubkeys[i] = av.pubkeys[idx]
    }
    
    // Verify aggregate signature (expensive!)
    return av.verifyAggregateSignature(attestation, pubkeys)
}
```

### Phase 3: Beacon State Synchronization

#### **3.1 State Sync Service**
- **Create BeaconStateSyncer** component
- **Implement epoch-boundary synchronization**
- **Add committee assignment computation**
- **Create validator registry management**

#### Sample Implementation
```go
type BeaconStateSyncer struct {
    upstreamClient BeaconNodeClient
    currentEpoch   primitives.Epoch
    committees     map[primitives.Epoch]CommitteeAssignments
    validators     map[ValidatorIndex]*ValidatorInfo
}

func (bss *BeaconStateSyncer) SyncEpochState(epoch primitives.Epoch) error {
    // Fetch minimal state needed for validation
    state, err := bss.upstreamClient.GetBeaconState(epoch)
    if err != nil {
        return err
    }
    
    // Pre-compute all committee assignments for epoch
    bss.committees[epoch] = computeCommitteeAssignments(state, epoch)
    
    // Update validator registry
    bss.updateValidatorRegistry(state.Validators)
    
    return nil
}
```

## Success Metrics Checklist

### Performance Targets
- [ ] **Sub-1ms validation** - Simple messages (exits, slashings)
- [ ] **<10ms validation** - Complex messages (blocks, aggregates)
- [ ] **99% query reduction** - Minimal upstream usage
- [ ] **<2GB memory usage** - Full validator set + caches
- [ ] **99.99% uptime** - Independent validation availability

### Correctness Targets
- [ ] **100% spec compliance** - Match consensus rules
- [ ] **Zero false positives** - No invalid accepts
- [ ] **Zero false negatives** - No valid rejects
- [ ] **Fork compatibility** - All Ethereum forks
- [ ] **Test coverage >90%** - Comprehensive testing

### Operational Targets
- [ ] **Graceful degradation** - Handle failures well
- [ ] **Mode flexibility** - Easy switching
- [ ] **Clear monitoring** - Observable behavior
- [ ] **Simple configuration** - User-friendly
- [ ] **Complete documentation** - Usage guides

### Phase 5: Integration and Mode Support

#### **5.1 Validation Router Implementation**
- **Create ValidationRouter** component
- **Implement mode-based routing logic** (Independent vs Delegated)
- **Add operating mode configuration** 
- **Create clean separation** between validation approaches

#### Sample Implementation
```go
type ValidationMode int

const (
    ModeIndependent ValidationMode = iota // Full in-process validation
    ModeDelegated                         // Current Prysm delegation
)

type ValidationRouter struct {
    mode                ValidationMode
    independentValidator *InProcessValidator
    delegatedValidator   *PrysmDelegationService
}

func (vr *ValidationRouter) ValidateMessage(msg *pubsub.Message) error {
    switch vr.mode {
    case ModeIndependent:
        return vr.independentValidator.Validate(msg)
    case ModeDelegated:
        return vr.delegatedValidator.Validate(msg)
    default:
        return errors.New("unknown validation mode")
    }
}
```

## Deliverables Checklist

### Code Deliverables
- [ ] **Validation Router** - Mode-based message routing
- [ ] **In-Process Validator** - All validation implementations
- [ ] **State Sync Service** - Beacon state management
- [ ] **Committee Cache** - Efficient lookups
- [ ] **Signature Verifier** - BLS operations
- [ ] **Creative Solutions** - Novel validation approaches
- [ ] **Prysm Delegation** - Backward compatibility

### Documentation Deliverables
- [ ] **Architecture docs** - System design
- [ ] **API documentation** - Component interfaces
- [ ] **Configuration guide** - Setup instructions
- [ ] **Migration guide** - Upgrade path
- [ ] **Performance guide** - Tuning recommendations
- [ ] **Troubleshooting guide** - Common issues

### Testing Deliverables
- [ ] **Unit test suite** - Component tests
- [ ] **Integration tests** - End-to-end flows
- [ ] **Performance benchmarks** - Latency/throughput
- [ ] **Test vectors** - Validation scenarios
- [ ] **Load test suite** - Stress testing
- [ ] **CI/CD pipeline** - Automated testing

## Timeline and Milestones

### Phase 1: Foundation (2-3 weeks)
- [ ] **Week 1**: BLS library integration + domain computation
- [ ] **Week 1**: SSZ parsing + message handlers
- [ ] **Week 2**: Simple validators (exits, slashings)
- [ ] **Week 2-3**: Unit tests + integration tests
- [ ] **Milestone**: All simple messages validating

### Phase 2: Creative Solutions (3-4 weeks)
- [ ] **Week 1**: Attestation tracker + threshold logic
- [ ] **Week 2**: KZG library + blob validation
- [ ] **Week 3**: Aggregate signature verification
- [ ] **Week 4**: Testing + optimization
- [ ] **Milestone**: Creative validators operational

### Phase 3: State Synchronization (2-3 weeks)
- [ ] **Week 1**: Beacon state syncer implementation
- [ ] **Week 1-2**: Committee cache + pre-computation
- [ ] **Week 2**: Validator registry + pubkey lookup
- [ ] **Week 3**: Testing + edge cases
- [ ] **Milestone**: State sync fully functional

### Phase 4: Standard Validations (2-3 weeks)
- [ ] **Week 1**: Attestation validation
- [ ] **Week 1-2**: Sync committee validation
- [ ] **Week 2**: Performance optimization
- [ ] **Week 3**: Load testing + benchmarks
- [ ] **Milestone**: All topics validated

### Phase 5: Integration (1-2 weeks)
- [ ] **Week 1**: Validation router + mode support
- [ ] **Week 1**: CLI integration + configuration
- [ ] **Week 2**: Monitoring + documentation
- [ ] **Milestone**: Production ready

## Definition of Done

### Phase 1 Complete When:
- [ ] BLS signatures verify correctly
- [ ] SSZ parsing handles all forks
- [ ] Simple validators pass all tests
- [ ] Memory usage within bounds
- [ ] Documentation complete

### Phase 2 Complete When:
- [ ] Attestation threshold works
- [ ] KZG proofs verify correctly
- [ ] Aggregates validate properly
- [ ] Performance meets targets
- [ ] Edge cases handled

### Phase 3 Complete When:
- [ ] State syncs at epoch boundaries
- [ ] Committees compute correctly
- [ ] Caches perform efficiently
- [ ] Fallback mechanisms work
- [ ] Tests pass consistently

### Phase 4 Complete When:
- [ ] All attestations validate
- [ ] Sync committee works
- [ ] Latency <10ms achieved
- [ ] Load tests pass
- [ ] Monitoring in place

### Phase 5 Complete When:
- [ ] Both modes operational
- [ ] Configuration documented
- [ ] Metrics exported
- [ ] CLI integrated
- [ ] Ready for production

## Final Acceptance Criteria

### Technical Requirements Met:
- [ ] **100% topic coverage** - All gossipsub messages validated
- [ ] **Sub-10ms latency** - Performance targets achieved
- [ ] **99% query reduction** - Minimal upstream usage
- [ ] **Zero false positives** - No invalid messages accepted
- [ ] **Zero false negatives** - No valid messages rejected

### Operational Requirements Met:
- [ ] **Mode switching works** - Clean transitions
- [ ] **Graceful degradation** - Handles failures well
- [ ] **Monitoring complete** - Full observability
- [ ] **Documentation ready** - User and developer docs
- [ ] **Tests comprehensive** - >90% coverage

### Production Readiness:
- [ ] **Load tested** - Handles mainnet volumes
- [ ] **Memory bounded** - No leaks or growth
- [ ] **CPU efficient** - Sustainable usage
- [ ] **Configurable** - Tunable parameters
- [ ] **Maintainable** - Clean architecture

## Summary

This checklist provides a complete implementation path for transitioning Hermes from Prysm dependency to in-process gossipsub validation. The approach includes:

### Key Deliverables:
- [ ] **Independent validation mode** - Full in-process validation
- [ ] **Delegated mode** - Backward compatibility maintained
- [ ] **Creative solutions** - Attestation threshold, KZG verification
- [ ] **Performance targets** - <10ms validation latency
- [ ] **Production ready** - Monitored, tested, documented

### Expected Impact:
- [ ] **99% reduction** in upstream beacon node queries
- [ ] **100% coverage** of all gossipsub topics
- [ ] **Zero dependency** on Prysm for validation
- [ ] **<2GB memory** for full operation
- [ ] **99.99% uptime** independent of upstream

The phased approach allows incremental progress while maintaining system stability. Each phase delivers immediate value and builds toward complete validation independence.