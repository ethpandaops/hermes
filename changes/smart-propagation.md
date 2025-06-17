# Smart Block Propagation Specification for Hermes

## 1. Overview

This specification details how Hermes can implement smart block propagation using attestation data to avoid propagating invalid blocks without requiring an execution client. The system leverages the existing `AttestationTracker` to monitor validator attestations and make intelligent decisions about block propagation.

## 2. Core Concept

The fundamental insight is that validators who attest to a block have likely validated it against the execution layer. By tracking attestations and waiting for a threshold before propagating blocks, Hermes can significantly reduce the propagation of invalid blocks.

### 2.1 Key Principles

1. **Attestation as Validation Signal**: When validators attest to a block, they've performed full validation including execution payload verification
2. **Threshold-Based Propagation**: Wait for a configurable number of attestations before propagating
3. **Time-Bounded Waiting**: Apply maximum wait times to prevent excessive delays
4. **Graceful Degradation**: Fall back to normal propagation if thresholds aren't met within timeouts

## 3. Architecture

### 3.1 Components Integration

```
┌─────────────────────────────────────────────────────────────┐
│                     Message Flow                              │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  Incoming Block ──► Block Validator ──► Smart Propagator     │
│                           │                    │              │
│                           ▼                    ▼              │
│                    Signature Check      Attestation Wait     │
│                           │                    │              │
│                           ▼                    ▼              │
│                    Basic Validation    Threshold Check       │
│                           │                    │              │
│                           └────────────────────┘              │
│                                      │                        │
│                                      ▼                        │
│                              Propagation Decision             │
│                                                               │
│  Incoming Attestation ──► Attestation Validator              │
│                                   │                           │
│                                   ▼                           │
│                           AttestationTracker.Track()          │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Leveraging Existing AttestationTracker

The existing `AttestationTracker` already provides:
- Tracking attestations by block root
- Counting unique validators per block
- Real-time notifications when attestation counts change
- LRU caching for memory efficiency

We'll extend this with:
- Integration into block validation flow
- Configurable wait strategies
- Metrics for smart propagation effectiveness

## 4. Algorithm for Attestation-Aware Block Propagation

### 4.1 Block Reception and Validation Flow

```go
func (v *SmartBlockValidator) ValidateBeaconBlock(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
    // 1. Perform basic validation (existing logic)
    block, err := v.basicValidation(ctx, msg)
    if err != nil {
        return handleValidationError(err)
    }
    
    // 2. Extract block root
    blockRoot := getBlockRoot(block)
    slot := getBlockSlot(block)
    
    // 3. Check if smart propagation is enabled and applicable
    if !v.shouldUseSmartPropagation(slot) {
        return pubsub.ValidationAccept // Normal propagation
    }
    
    // 4. Create context with timeout
    waitCtx, cancel := context.WithTimeout(ctx, v.config.MaxWaitTime)
    defer cancel()
    
    // 5. Wait for attestations
    attestationCount := v.attestationTracker.WaitForAttestations(
        waitCtx,
        blockRoot,
        v.config.AttestationThreshold,
    )
    
    // 6. Make propagation decision
    if attestationCount >= v.config.AttestationThreshold {
        v.metrics.RecordSmartPropagation("success", slot)
        return pubsub.ValidationAccept
    }
    
    // 7. Check fallback conditions
    if v.shouldFallbackPropagate(attestationCount, slot) {
        v.metrics.RecordSmartPropagation("fallback", slot)
        return pubsub.ValidationAccept
    }
    
    // 8. Don't propagate - insufficient attestations
    v.metrics.RecordSmartPropagation("blocked", slot)
    return pubsub.ValidationIgnore
}
```

### 4.2 Smart Propagation Decision Logic

```go
func (v *SmartBlockValidator) shouldUseSmartPropagation(slot phase0.Slot) bool {
    // Skip smart propagation for:
    // 1. Blocks older than 2 slots (likely already propagated)
    currentSlot := v.getCurrentSlot()
    if currentSlot > slot && currentSlot - slot > 2 {
        return false
    }
    
    // 2. First slot of epoch (important for chain progress)
    if slot % 32 == 0 {
        return false
    }
    
    // 3. During sync or if we're far behind
    if v.isSyncing() {
        return false
    }
    
    return v.config.SmartPropagationEnabled
}

func (v *SmartBlockValidator) shouldFallbackPropagate(attestationCount int, slot phase0.Slot) bool {
    // Fallback propagation if:
    // 1. We have some attestations (partial confidence)
    if attestationCount >= v.config.MinAttestationsForFallback {
        return true
    }
    
    // 2. Block is from a known good proposer
    proposerIndex := getProposerIndex(block)
    if v.isKnownGoodProposer(proposerIndex) {
        return true
    }
    
    // 3. Network conditions suggest we should propagate
    if v.networkHealthy() && attestationCount > 0 {
        return true
    }
    
    return false
}
```

## 5. Configurable Thresholds and Timeouts

### 5.1 Configuration Structure

```go
type SmartPropagationConfig struct {
    // Feature toggle
    SmartPropagationEnabled bool `yaml:"smart_propagation_enabled" default:"true"`
    
    // Attestation thresholds
    AttestationThreshold       int `yaml:"attestation_threshold" default:"15"`
    MinAttestationsForFallback int `yaml:"min_attestations_fallback" default:"5"`
    
    // Timing configuration
    MaxWaitTime           time.Duration `yaml:"max_wait_time" default:"4s"`
    EarlyPropagationTime  time.Duration `yaml:"early_propagation_time" default:"2s"`
    
    // Advanced tuning
    UseAdaptiveThresholds bool    `yaml:"use_adaptive_thresholds" default:"false"`
    MinThresholdPercent   float64 `yaml:"min_threshold_percent" default:"0.1"`  // 10% of committee
    MaxThresholdPercent   float64 `yaml:"max_threshold_percent" default:"0.3"`  // 30% of committee
    
    // Network conditions
    DisableDuringSyncThreshold int `yaml:"disable_during_sync_threshold" default:"10"` // slots behind
}
```

### 5.2 Adaptive Threshold Calculation

```go
func (v *SmartBlockValidator) calculateAdaptiveThreshold(slot phase0.Slot) int {
    if !v.config.UseAdaptiveThresholds {
        return v.config.AttestationThreshold
    }
    
    // Get committee size for the slot
    committeeSize := v.getCommitteeSize(slot)
    if committeeSize == 0 {
        return v.config.AttestationThreshold // fallback
    }
    
    // Calculate threshold based on committee size
    minThreshold := int(float64(committeeSize) * v.config.MinThresholdPercent)
    maxThreshold := int(float64(committeeSize) * v.config.MaxThresholdPercent)
    
    // Consider network conditions
    networkFactor := v.getNetworkHealthFactor() // 0.5 (unhealthy) to 1.0 (healthy)
    adaptiveThreshold := int(float64(maxThreshold) * networkFactor)
    
    // Ensure within bounds
    if adaptiveThreshold < minThreshold {
        adaptiveThreshold = minThreshold
    }
    if adaptiveThreshold > maxThreshold {
        adaptiveThreshold = maxThreshold
    }
    
    return adaptiveThreshold
}
```

## 6. Integration with Block Validation

### 6.1 Modified Block Validator Structure

```go
type SmartBlockValidator struct {
    *BeaconBlockValidator // Embed existing validator
    
    attestationTracker *AttestationTracker
    config            *SmartPropagationConfig
    metrics           *SmartPropagationMetrics
    
    // Performance tracking
    recentPropagations *lru.Cache // Track recent propagation decisions
    proposerStats      *ProposerStatistics
}
```

### 6.2 Integration Points

1. **Router Integration**:
```go
// In router.go
func (r *Router) CreateTopicValidator(topic string, messageType common.MessageType) pubsub.ValidatorEx {
    validatorFunc := r.getValidatorForMessageType(messageType)
    
    // Wrap block validator with smart propagation
    if messageType == common.MessageBeaconBlock && r.smartPropagationEnabled {
        validatorFunc = r.wrapWithSmartPropagation(validatorFunc)
    }
    
    return func(ctx context.Context, _ peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
        // ... existing validation logic ...
    }
}
```

2. **Attestation Integration**:
```go
// In attestation_validator.go
func (v *AttestationValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
    // ... existing validation ...
    
    // Track attestation for smart propagation
    if attestation != nil && v.attestationTracker != nil {
        v.attestationTracker.TrackAttestation(
            attestation.Data.BeaconBlockRoot,
            attestation.Data.Slot,
            attestation.Data.Index,
            validatorIndex,
        )
    }
    
    return attestation, nil
}
```

## 7. Fallback Mechanisms

### 7.1 Timeout-Based Fallback

```go
func (v *SmartBlockValidator) implementTimeoutFallback(ctx context.Context, blockRoot [32]byte) pubsub.ValidationResult {
    // Create multiple timeout stages
    earlyTimeout := time.NewTimer(v.config.EarlyPropagationTime)
    maxTimeout := time.NewTimer(v.config.MaxWaitTime)
    defer earlyTimeout.Stop()
    defer maxTimeout.Stop()
    
    attestationChan := make(chan int, 10)
    v.attestationTracker.SubscribeToBlock(blockRoot, attestationChan)
    defer v.attestationTracker.UnsubscribeFromBlock(blockRoot, attestationChan)
    
    threshold := v.calculateAdaptiveThreshold(slot)
    earlyThreshold := threshold / 2 // 50% for early propagation
    
    for {
        select {
        case count := <-attestationChan:
            if count >= threshold {
                return pubsub.ValidationAccept
            }
            if count >= earlyThreshold && earlyTimeout.C != nil {
                // Continue waiting but note we hit early threshold
                earlyTimeout.Stop()
                earlyTimeout.C = nil
            }
            
        case <-earlyTimeout.C:
            // Check if we have enough for early propagation
            currentCount := v.attestationTracker.GetBlockAttestationCount(blockRoot)
            if currentCount >= earlyThreshold {
                v.metrics.RecordEarlyPropagation(slot)
                return pubsub.ValidationAccept
            }
            
        case <-maxTimeout.C:
            // Final timeout - make decision based on current count
            currentCount := v.attestationTracker.GetBlockAttestationCount(blockRoot)
            if currentCount >= v.config.MinAttestationsForFallback {
                v.metrics.RecordTimeoutPropagation(slot)
                return pubsub.ValidationAccept
            }
            return pubsub.ValidationIgnore
            
        case <-ctx.Done():
            return pubsub.ValidationIgnore
        }
    }
}
```

### 7.2 Network Health Based Fallback

```go
type NetworkHealthMonitor struct {
    recentBlockTimes    *ring.Ring // Circular buffer of block arrival times
    attestationRates    *ring.Ring // Attestation rates per slot
    propagationSuccess  *ring.Ring // Recent propagation decisions
    peerCount          atomic.Int32
    syncStatus         atomic.Bool
}

func (v *SmartBlockValidator) getNetworkHealthFactor() float64 {
    // Factors to consider:
    // 1. Peer count (more peers = healthier)
    peerFactor := math.Min(float64(v.networkMonitor.peerCount.Load()) / 50.0, 1.0)
    
    // 2. Recent attestation rates
    avgAttestationRate := v.networkMonitor.getAverageAttestationRate()
    attestationFactor := math.Min(avgAttestationRate / 100.0, 1.0) // 100 attestations/slot is healthy
    
    // 3. Block arrival timing consistency
    blockTimingFactor := v.networkMonitor.getBlockTimingConsistency()
    
    // 4. Recent propagation success rate
    propagationFactor := v.networkMonitor.getPropagationSuccessRate()
    
    // Weighted average
    healthFactor := (peerFactor * 0.2) + 
                   (attestationFactor * 0.3) + 
                   (blockTimingFactor * 0.2) + 
                   (propagationFactor * 0.3)
    
    return healthFactor
}
```

## 8. Performance Considerations

### 8.1 Memory Management

```go
// Efficient caching with automatic cleanup
type CacheManager struct {
    blockCache       *lru.Cache     // Recent blocks
    attestationCache *lru.Cache     // Attestation tracker cache
    proposerCache    *lru.Cache     // Proposer performance stats
    
    cleanupInterval  time.Duration
    retentionPeriod  time.Duration
}

func (cm *CacheManager) StartCleanup(ctx context.Context) {
    ticker := time.NewTicker(cm.cleanupInterval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            cm.performCleanup()
        case <-ctx.Done():
            return
        }
    }
}

func (cm *CacheManager) performCleanup() {
    // Clean up old entries based on slot age
    currentSlot := getCurrentSlot()
    maxAge := uint64(cm.retentionPeriod.Seconds() / 12) // Convert to slots
    
    // Cleanup is handled by LRU eviction, but we can add time-based cleanup if needed
}
```

### 8.2 Concurrent Processing

```go
// Parallel attestation processing for efficiency
type ParallelAttestationProcessor struct {
    workers   int
    workQueue chan AttestationWork
    tracker   *AttestationTracker
}

func (p *ParallelAttestationProcessor) ProcessAttestation(work AttestationWork) {
    p.workQueue <- work
}

func (p *ParallelAttestationProcessor) worker(ctx context.Context) {
    for {
        select {
        case work := <-p.workQueue:
            p.tracker.TrackAttestation(
                work.BlockRoot,
                work.Slot,
                work.CommitteeIndex,
                work.ValidatorIndex,
            )
        case <-ctx.Done():
            return
        }
    }
}
```

### 8.3 Metrics and Monitoring

```go
type SmartPropagationMetrics struct {
    // Counters
    blocksReceived        prometheus.Counter
    blocksPropagated      prometheus.Counter
    blocksDelayed         prometheus.Counter
    blocksDropped         prometheus.Counter
    
    // Histograms
    attestationWaitTime   prometheus.Histogram
    attestationCount      prometheus.Histogram
    propagationDecision   prometheus.Histogram
    
    // Gauges
    currentThreshold      prometheus.Gauge
    networkHealthScore    prometheus.Gauge
    averageWaitTime       prometheus.Gauge
}

func (m *SmartPropagationMetrics) RecordPropagationDecision(
    decision string,
    slot phase0.Slot,
    attestationCount int,
    waitTime time.Duration,
) {
    labels := prometheus.Labels{
        "decision": decision,
        "slot":     fmt.Sprintf("%d", slot),
    }
    
    m.propagationDecision.With(labels).Observe(float64(attestationCount))
    m.attestationWaitTime.Observe(waitTime.Seconds())
    
    switch decision {
    case "propagated":
        m.blocksPropagated.Inc()
    case "delayed":
        m.blocksDelayed.Inc()
    case "dropped":
        m.blocksDropped.Inc()
    }
}
```

## 9. Implementation Plan

### 9.1 Phase 1: Core Smart Propagation (Week 1)
1. Extend `BeaconBlockValidator` with smart propagation logic
2. Integrate `AttestationTracker` into block validation flow
3. Implement basic threshold-based waiting
4. Add configuration options

### 9.2 Phase 2: Advanced Features (Week 2)
1. Implement adaptive thresholds
2. Add network health monitoring
3. Implement multi-stage timeout fallbacks
4. Add proposer reputation tracking

### 9.3 Phase 3: Optimization and Monitoring (Week 3)
1. Add comprehensive metrics
2. Implement performance optimizations
3. Add admin API endpoints for monitoring
4. Conduct performance testing

## 10. Configuration Examples

### 10.1 Conservative Configuration (High Security)
```yaml
smart_propagation:
  enabled: true
  attestation_threshold: 20
  min_attestations_fallback: 10
  max_wait_time: 5s
  early_propagation_time: 3s
  use_adaptive_thresholds: false
```

### 10.2 Balanced Configuration (Default)
```yaml
smart_propagation:
  enabled: true
  attestation_threshold: 15
  min_attestations_fallback: 5
  max_wait_time: 4s
  early_propagation_time: 2s
  use_adaptive_thresholds: true
  min_threshold_percent: 0.1
  max_threshold_percent: 0.3
```

### 10.3 Aggressive Configuration (Low Latency)
```yaml
smart_propagation:
  enabled: true
  attestation_threshold: 10
  min_attestations_fallback: 3
  max_wait_time: 2s
  early_propagation_time: 1s
  use_adaptive_thresholds: true
  min_threshold_percent: 0.05
  max_threshold_percent: 0.15
```

## 11. Testing Strategy

### 11.1 Unit Tests
```go
func TestSmartPropagation(t *testing.T) {
    tests := []struct {
        name                string
        attestationCount    int
        waitTime           time.Duration
        expectedDecision   pubsub.ValidationResult
    }{
        {
            name:             "sufficient_attestations",
            attestationCount: 20,
            waitTime:        1 * time.Second,
            expectedDecision: pubsub.ValidationAccept,
        },
        {
            name:             "timeout_with_some_attestations",
            attestationCount: 5,
            waitTime:        5 * time.Second,
            expectedDecision: pubsub.ValidationAccept,
        },
        {
            name:             "timeout_no_attestations",
            attestationCount: 0,
            waitTime:        5 * time.Second,
            expectedDecision: pubsub.ValidationIgnore,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

### 11.2 Integration Tests
- Test with simulated attestation patterns
- Test network partition scenarios
- Test performance under load
- Test fallback mechanisms

### 11.3 Metrics to Monitor
1. **Effectiveness Metrics**:
   - Invalid blocks propagated vs blocked
   - False positive rate (valid blocks delayed/dropped)
   - Average attestation count at propagation

2. **Performance Metrics**:
   - Average wait time
   - Propagation latency impact
   - Memory usage of tracking structures

3. **Network Health Metrics**:
   - Attestation arrival patterns
   - Peer behavior correlation
   - Sync committee participation rates

## 12. Security Considerations

### 12.1 Attack Vectors
1. **Attestation Withholding**: Adversary withholds attestations to prevent propagation
   - Mitigation: Timeout-based fallbacks, network health monitoring

2. **False Attestations**: Adversary sends many attestations for invalid blocks
   - Mitigation: Only track attestations from verified validators

3. **Resource Exhaustion**: Tracking too many blocks/attestations
   - Mitigation: LRU caches, aggressive cleanup policies

### 12.2 Safety Guarantees
- Never block valid blocks indefinitely (timeout fallback)
- Graceful degradation under attack or poor network conditions
- No modification of consensus-critical paths

## 13. Future Enhancements

### 13.1 Machine Learning Integration
- Learn optimal thresholds based on network patterns
- Predict block validity based on proposer history
- Adaptive timeout adjustments

### 13.2 Cross-Client Coordination
- Share attestation observations with other Hermes nodes
- Coordinate propagation decisions across the network
- Build reputation system for proposers

### 13.3 Advanced Heuristics
- Consider sync committee messages as additional signals
- Weight attestations by validator effectiveness
- Incorporate slashing protection database signals

## 14. Conclusion

This smart propagation system provides Hermes with the ability to significantly reduce invalid block propagation without requiring an execution client. By leveraging the existing `AttestationTracker` and implementing configurable thresholds with robust fallback mechanisms, the system can adapt to various network conditions while maintaining security and performance.

The modular design allows for incremental implementation and testing, with clear extension points for future enhancements. The configuration flexibility ensures operators can tune the system for their specific requirements, from high-security environments to low-latency scenarios.