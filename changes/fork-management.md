# Enhanced Fork Management Specification for Hermes

## 1. Overview

This specification defines enhanced fork management capabilities for Hermes to support comprehensive validation across all Ethereum consensus layer forks. The design focuses on providing fork information needed by validators without complex state management, enabling fork-aware message validation, version detection, and future fork support.

## 2. Requirements from Validation Specs

Based on analysis of validation specifications, fork management must support:

### 2.1 Fork-Specific Validation Rules
- **Beacon Blocks**: Different validation rules for Bellatrix (execution payload), Deneb (KZG commitments), Electra (increased blob limits)
- **Blob Sidecars**: MAX_BLOBS_PER_BLOCK changes between Deneb and Electra
- **Light Client Updates**: Fork-specific header formats and sync committee sizes
- **Attestations**: Fork-specific aggregation and signature domain calculations

### 2.2 Fork Schedule Tracking
- Determine active fork at any given slot/epoch
- Support fork version queries for signature domains
- Handle fork transitions gracefully
- Provide fork-specific constants (e.g., MAX_BLOBS_PER_BLOCK)

### 2.3 Version Detection
- Identify message versions based on fork digest in gossip topics
- Map fork versions to specific forks (Phase0, Altair, Bellatrix, Capella, Deneb, Electra, Fulu)
- Support version-specific deserialization

## 3. Design

### 3.1 Core Fork Manager Interface

```go
package fork

import (
    "github.com/probe-lab/hermes/eth/pubsub/common"
    "github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
)

// ForkManager provides fork information without requiring full state
type ForkManager interface {
    // GetCurrentFork returns the fork active at the given slot
    GetCurrentFork(slot common.Slot) Fork
    
    // GetForkAtEpoch returns the fork active at the given epoch
    GetForkAtEpoch(epoch common.Epoch) Fork
    
    // GetForkVersion returns the 4-byte fork version for a given fork
    GetForkVersion(fork Fork) common.ForkVersion
    
    // GetForkEpoch returns the activation epoch for a fork
    GetForkEpoch(fork Fork) (common.Epoch, bool)
    
    // GetForkDigest computes the fork digest for gossip topics
    GetForkDigest(fork Fork, genesisValidatorsRoot [32]byte) ([4]byte, error)
    
    // GetForkFromDigest returns the fork for a given fork digest
    GetForkFromDigest(digest [4]byte) (Fork, error)
    
    // GetAllForks returns all configured forks in activation order
    GetAllForks() []Fork
    
    // GetForkConstants returns fork-specific constants
    GetForkConstants(fork Fork) ForkConstants
}

// Fork represents a consensus fork
type Fork string

const (
    ForkPhase0    Fork = "phase0"
    ForkAltair    Fork = "altair"
    ForkBellatrix Fork = "bellatrix"
    ForkCapella   Fork = "capella"
    ForkDeneb     Fork = "deneb"
    ForkElectra   Fork = "electra"
    ForkFulu      Fork = "fulu"
)

// ForkConstants contains fork-specific constants
type ForkConstants struct {
    // Blob-related constants
    MaxBlobsPerBlock uint64
    
    // Light client constants
    LightClientHeaderType string
    
    // Execution-related flags
    ExecutionEnabled bool
    
    // Other fork-specific values
    AdditionalConstants map[string]interface{}
}
```

### 3.2 Fork Configuration

```go
// ForkConfig defines fork activation schedule
type ForkConfig struct {
    // Fork versions (4 bytes each)
    Phase0Version    common.ForkVersion
    AltairVersion    common.ForkVersion
    BellatrixVersion common.ForkVersion
    CapellaVersion   common.ForkVersion
    DenebVersion     common.ForkVersion
    ElectraVersion   common.ForkVersion
    FuluVersion      common.ForkVersion
    
    // Fork activation epochs
    AltairEpoch    common.Epoch
    BellatrixEpoch common.Epoch
    CapellaEpoch   common.Epoch
    DenebEpoch     common.Epoch
    ElectraEpoch   common.Epoch
    FuluEpoch      common.Epoch
    
    // Genesis configuration
    GenesisTime           uint64
    GenesisValidatorsRoot [32]byte
}

// NewForkManager creates a fork manager from configuration
func NewForkManager(config ForkConfig) ForkManager {
    return &simpleForkManager{
        config: config,
        // Pre-compute fork digests for efficiency
        forkDigests: computeForkDigests(config),
    }
}
```

### 3.3 Implementation Details

```go
type simpleForkManager struct {
    config      ForkConfig
    forkDigests map[Fork][4]byte
    digestToFork map[[4]byte]Fork
}

func (fm *simpleForkManager) GetCurrentFork(slot common.Slot) Fork {
    epoch := common.SlotToEpoch(slot)
    return fm.GetForkAtEpoch(epoch)
}

func (fm *simpleForkManager) GetForkAtEpoch(epoch common.Epoch) Fork {
    // Check forks in reverse order (newest first)
    if fm.config.FuluEpoch != FAR_FUTURE_EPOCH && epoch >= fm.config.FuluEpoch {
        return ForkFulu
    }
    if fm.config.ElectraEpoch != FAR_FUTURE_EPOCH && epoch >= fm.config.ElectraEpoch {
        return ForkElectra
    }
    if fm.config.DenebEpoch != FAR_FUTURE_EPOCH && epoch >= fm.config.DenebEpoch {
        return ForkDeneb
    }
    if fm.config.CapellaEpoch != FAR_FUTURE_EPOCH && epoch >= fm.config.CapellaEpoch {
        return ForkCapella
    }
    if fm.config.BellatrixEpoch != FAR_FUTURE_EPOCH && epoch >= fm.config.BellatrixEpoch {
        return ForkBellatrix
    }
    if fm.config.AltairEpoch != FAR_FUTURE_EPOCH && epoch >= fm.config.AltairEpoch {
        return ForkAltair
    }
    return ForkPhase0
}

func (fm *simpleForkManager) GetForkConstants(fork Fork) ForkConstants {
    constants := ForkConstants{
        AdditionalConstants: make(map[string]interface{}),
    }
    
    switch fork {
    case ForkDeneb:
        constants.MaxBlobsPerBlock = 6
        constants.ExecutionEnabled = true
        constants.LightClientHeaderType = "deneb"
    case ForkElectra:
        constants.MaxBlobsPerBlock = 6 // Update when Electra spec is finalized
        constants.ExecutionEnabled = true
        constants.LightClientHeaderType = "deneb" // May change
    case ForkCapella:
        constants.MaxBlobsPerBlock = 0
        constants.ExecutionEnabled = true
        constants.LightClientHeaderType = "capella"
    case ForkBellatrix:
        constants.MaxBlobsPerBlock = 0
        constants.ExecutionEnabled = true
        constants.LightClientHeaderType = "altair"
    case ForkAltair:
        constants.MaxBlobsPerBlock = 0
        constants.ExecutionEnabled = false
        constants.LightClientHeaderType = "altair"
    default:
        constants.MaxBlobsPerBlock = 0
        constants.ExecutionEnabled = false
        constants.LightClientHeaderType = "phase0"
    }
    
    return constants
}
```

### 3.4 Integration with Existing Fork Version Detection

The existing fork version detection in validators can be enhanced:

```go
// Enhanced message unmarshaling with fork manager
func UnmarshalVersionedMessage(data []byte, topic string, fm ForkManager) (interface{}, Fork, error) {
    // Extract fork digest from topic
    digest, err := extractForkDigest(topic)
    if err != nil {
        return nil, "", err
    }
    
    // Get fork from digest
    fork, err := fm.GetForkFromDigest(digest)
    if err != nil {
        return nil, "", err
    }
    
    // Unmarshal based on fork
    switch fork {
    case ForkElectra:
        // Try Electra-specific types first
    case ForkDeneb:
        // Try Deneb-specific types
    // ... other forks
    }
    
    return message, fork, nil
}
```

## 4. Usage Examples

### 4.1 Blob Sidecar Validation

```go
func (v *BlobSidecarValidator) validateBlobCount(sidecar *deneb.BlobSidecar, slot common.Slot) error {
    // Get current fork
    fork := v.forkManager.GetCurrentFork(slot)
    constants := v.forkManager.GetForkConstants(fork)
    
    // Validate blob index against fork-specific limit
    if uint64(sidecar.Index) >= constants.MaxBlobsPerBlock {
        return fmt.Errorf("blob index %d exceeds max %d for fork %s", 
            sidecar.Index, constants.MaxBlobsPerBlock, fork)
    }
    
    return nil
}
```

### 4.2 Signature Domain Computation

```go
func (v *Validator) computeDomain(domainType common.DomainType, epoch common.Epoch) ([32]byte, error) {
    // Get fork for epoch
    fork := v.forkManager.GetForkAtEpoch(epoch)
    version := v.forkManager.GetForkVersion(fork)
    
    // Compute fork data root
    forkInfo := &common.ForkInfo{
        CurrentVersion: version.ToBytes(),
    }
    
    return common.ComputeDomain(domainType, forkInfo, v.genesisValidatorsRoot)
}
```

### 4.3 Topic Subscription

```go
func (n *Node) subscribeToTopics() error {
    // Get all active forks
    currentSlot := n.clock.GetCurrentSlot()
    currentFork := n.forkManager.GetCurrentFork(currentSlot)
    
    // Subscribe to current fork topics
    digest, _ := n.forkManager.GetForkDigest(currentFork, n.genesisValidatorsRoot)
    topic := fmt.Sprintf("/eth2/%x/beacon_block/ssz_snappy", digest)
    n.pubsub.Subscribe(topic)
    
    // Also subscribe to next fork if transition is near
    nextFork := n.getNextFork(currentFork)
    if nextFork != "" {
        nextEpoch, _ := n.forkManager.GetForkEpoch(nextFork)
        if n.isNearForkTransition(currentSlot, nextEpoch) {
            nextDigest, _ := n.forkManager.GetForkDigest(nextFork, n.genesisValidatorsRoot)
            nextTopic := fmt.Sprintf("/eth2/%x/beacon_block/ssz_snappy", nextDigest)
            n.pubsub.Subscribe(nextTopic)
        }
    }
    
    return nil
}
```

## 5. Minimal Implementation Approach

### Phase 1: Core Fork Manager (Required for validation)
1. Implement `ForkManager` interface with hardcoded fork schedules for known networks
2. Add fork configuration to `NetworkConfig`
3. Create singleton fork manager per network
4. Update validators to use fork manager for constants

### Phase 2: Integration (Enhance existing validators)
1. Update blob validator to use fork-specific MAX_BLOBS_PER_BLOCK
2. Update block validator for fork-specific rules
3. Update signature verification to use fork-aware domains
4. Add fork digest extraction from topics

### Phase 3: Advanced Features (Future enhancements)
1. Dynamic fork configuration from beacon node
2. Fork transition handling and dual-subscription
3. Metrics for fork activation monitoring
4. Support for custom/unknown forks

## 6. Benefits

1. **Centralized Fork Logic**: All fork-related decisions in one place
2. **Future-Proof**: Easy to add new forks by updating configuration
3. **Validation Accuracy**: Fork-specific validation rules properly applied
4. **Minimal State**: No beacon state required for fork information
5. **Performance**: Pre-computed fork digests and efficient lookups

## 7. Testing Strategy

1. **Unit Tests**: Test fork detection at various epochs/slots
2. **Fork Transition Tests**: Verify correct behavior at fork boundaries
3. **Network Tests**: Test with mainnet, testnet, and custom fork schedules
4. **Validation Tests**: Ensure fork-specific validation rules are applied correctly

## 8. Migration Path

1. Create fork manager alongside existing code
2. Gradually migrate validators to use fork manager
3. Remove hardcoded fork logic from validators
4. Centralize all fork constants in fork manager

This design provides a clean, minimal approach to fork management that supports all validation requirements without requiring complex state management or execution client integration.