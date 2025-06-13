# Dynamic Attnets Metadata Implementation Plan

## Overview
> This plan addresses the issue of hardcoded attestation subnet (Attnets) metadata in the ReqResp handler. Currently, the metadata always advertises that the node subscribes to all 64 attestation subnets, regardless of the actual subnet configuration. This implementation will make the metadata reflect the actual attestation subnets that the node is subscribed to and update it dynamically when subnet subscriptions change.

## Current State Assessment

- The ReqResp handler in `/Users/samcm/go/src/github.com/ethpandaops/hermes/eth/reqresp.go` hardcodes all attestation subnet bits to true (lines 87-90)
- Subnet configuration is handled in `/Users/samcm/go/src/github.com/ethpandaops/hermes/eth/subnets.go` with the `GetSubscribedSubnets()` method
- The metadata is served via the metadataV1Handler and metadataV2Handler but never updates after initialization
- There's no mechanism to update metadata when subnet subscriptions change
- The SetMetaData method only updates the sequence number, not the Attnets field

## Goals

1. Primary goal: Make metadata Attnets field accurately reflect configured attestation subnets
2. Enable dynamic updates when attestation subnet subscriptions change
3. Maintain compatibility with the Ethereum P2P specification for metadata exchange
4. Non-functional requirements:
   - Thread-safe metadata updates
   - Minimal performance impact on RPC handlers
   - Clear separation of concerns between subnet configuration and metadata management

## Design Approach

### Architecture Overview
The solution will establish a connection between the subnet configuration system and the ReqResp metadata handler. When subnet subscriptions change, the metadata will be updated to reflect the new state. This involves:
- Passing subnet configuration to the ReqResp handler
- Creating an update mechanism for dynamic subnet changes
- Properly setting attestation subnet bits based on actual subscriptions

### Component Breakdown

1. **ReqResp Handler Enhancement**
   - Purpose: Accept subnet configuration and maintain accurate metadata
   - Responsibilities: 
     - Initialize metadata with correct attestation subnet bits
     - Provide methods to update attestation subnets
     - Ensure thread-safe access to metadata
   - Interfaces: New methods for subnet updates, enhanced constructor

2. **Subnet Configuration Integration**
   - Purpose: Provide current subnet subscriptions to ReqResp handler
   - Responsibilities:
     - Calculate which attestation subnets are active
     - Notify ReqResp handler of changes
   - Interfaces: Existing GetSubscribedSubnets() method

3. **Node Initialization Updates**
   - Purpose: Wire subnet configuration to ReqResp during startup
   - Responsibilities:
     - Pass subnet configuration to ReqResp constructor
     - Set up any necessary update channels
   - Interfaces: Modified node.go initialization

## Implementation Approach

### 1. Update ReqResp Configuration Structure

#### Specific Changes
- Add SubnetConfig field to ReqRespConfig struct
- Add method to calculate attestation subnet bitvector from configuration
- Update NewReqResp to accept and use subnet configuration

#### Sample Implementation
```go
// In reqresp.go
type ReqRespConfig struct {
    ForkDigest [4]byte
    Encoder    encoder.NetworkEncoding
    DataStream hermeshost.DataStream
    
    ReadTimeout  time.Duration
    WriteTimeout time.Duration
    
    // Subnet configuration for attestation subnets
    SubnetConfigs map[string]*SubnetConfig
    
    // Telemetry accessors
    Tracer trace.Tracer
    Meter  metric.Meter
}

// Helper function to create attestation bitvector from subnet config
func createAttnetsBitvector(subnetConfigs map[string]*SubnetConfig) bitfield.Bitvector64 {
    attnets := bitfield.NewBitvector64()
    
    if attestationConfig, exists := subnetConfigs["attestation"]; exists {
        subnets := attestationConfig.GetSubscribedSubnets("attestation", 64)
        for _, subnet := range subnets {
            attnets.SetBitAt(uint64(subnet), true)
        }
    } else {
        // Default to all subnets if no config
        for i := uint64(0); i < 64; i++ {
            attnets.SetBitAt(i, true)
        }
    }
    
    return attnets
}
```

### 2. Modify ReqResp Constructor

#### Specific Changes
- Use subnet configuration to initialize metadata Attnets field
- Remove hardcoded attestation subnet bits
- Maintain backward compatibility if no subnet config provided

#### Sample Implementation
```go
func NewReqResp(h host.Host, cfg *ReqRespConfig) (*ReqResp, error) {
    if cfg == nil {
        return nil, fmt.Errorf("req resp server config must not be nil")
    }
    
    // Create attestation bitvector from subnet configuration
    attnets := createAttnetsBitvector(cfg.SubnetConfigs)
    
    md := &pb.MetaDataV1{
        SeqNumber: 0,
        Attnets:   attnets,
        Syncnets:  bitfield.Bitvector4{byte(0x00)},
    }
    
    p := &ReqResp{
        host:      h,
        cfg:       cfg,
        metaData:  md,
        statusLim: rate.NewLimiter(1, 5),
    }
    
    // ... rest of initialization
}
```

### 3. Add Dynamic Attestation Subnet Update Method

#### Specific Changes
- Create UpdateAttnets method to update attestation subnet bits
- Increment sequence number on updates (per spec)
- Ensure thread-safe updates with existing mutex

#### Sample Implementation
```go
// UpdateAttnets updates the attestation subnet bitvector in metadata
func (r *ReqResp) UpdateAttnets(attnets bitfield.Bitvector64) {
    r.metaDataMu.Lock()
    defer r.metaDataMu.Unlock()
    
    // Only update if actually changed
    if !bytes.Equal(r.metaData.Attnets.Bytes(), attnets.Bytes()) {
        r.metaData = &pb.MetaDataV1{
            SeqNumber: r.metaData.SeqNumber + 1,
            Attnets:   attnets,
            Syncnets:  r.metaData.Syncnets,
        }
        
        slog.Info("Updated attestation subnets in metadata",
            "seq_number", r.metaData.SeqNumber,
            "attnets", hex.EncodeToString(attnets.Bytes()))
    }
}

// GetCurrentAttnets returns the current attestation subnet configuration
func (r *ReqResp) GetCurrentAttnets() bitfield.Bitvector64 {
    r.metaDataMu.RLock()
    defer r.metaDataMu.RUnlock()
    
    return r.metaData.Attnets
}
```

### 4. Update Node Initialization

#### Specific Changes
- Pass subnet configuration to ReqResp during node creation
- Ensure subnet config is available before ReqResp initialization
- Update node.go to wire the configuration

#### Sample Implementation
```go
// In node.go, within the node initialization
reqRespCfg := &ReqRespConfig{
    ForkDigest:    forkDigest,
    Encoder:       encoder,
    DataStream:    dataStream,
    ReadTimeout:   cfg.ReqRespServerCfg.ReadTimeout,
    WriteTimeout:  cfg.ReqRespServerCfg.WriteTimeout,
    SubnetConfigs: cfg.SubnetConfigs, // Pass subnet configuration
    Tracer:        tracer,
    Meter:         meter,
}

reqResp, err := NewReqResp(host, reqRespCfg)
if err != nil {
    return nil, fmt.Errorf("new req resp: %w", err)
}
```

### 5. Handle Dynamic Subnet Changes (Future Enhancement)

#### Specific Changes
- Monitor for subnet subscription changes
- Update metadata when subscriptions change
- Consider implementing a subnet change notification system

#### Sample Implementation
```go
// Method to be called when subnet subscriptions change
func (n *node) updateAttestationSubnets(newSubnets []int) {
    attnets := bitfield.NewBitvector64()
    for _, subnet := range newSubnets {
        attnets.SetBitAt(uint64(subnet), true)
    }
    
    n.reqResp.UpdateAttnets(attnets)
}
```

## Testing Strategy

### Unit Testing
- Test createAttnetsBitvector with various subnet configurations
- Test UpdateAttnets method for proper sequence number increments
- Test thread safety of metadata updates
- Mock subnet configurations for different strategies

### Integration Testing
- Verify metadata responses contain correct attestation subnet bits
- Test that remote peers receive updated metadata after subnet changes
- Validate against Ethereum P2P specification compliance

### Validation Criteria
- Metadata Attnets field matches configured subnets
- Sequence number increments on attestation subnet updates
- No race conditions during concurrent metadata access
- Backward compatibility with nodes expecting all subnets

## Implementation Dependencies

1. **Phase 1: Core Implementation**
   - Update ReqRespConfig structure
   - Modify NewReqResp constructor
   - Implement createAttnetsBitvector helper
   - Dependencies: None

2. **Phase 2: Dynamic Updates**
   - Implement UpdateAttnets method
   - Wire subnet config in node initialization
   - Dependencies: Phase 1 completion

3. **Phase 3: Runtime Updates (Optional)**
   - Implement subnet change monitoring
   - Add notification system for dynamic updates
   - Dependencies: Phase 2 completion

## Risks and Considerations

### Implementation Risks
- Breaking change to ReqRespConfig: Ensure all callers are updated
- Thread safety issues: Use existing mutex patterns consistently

### Performance Considerations
- Bitvector calculation overhead: Cache results when possible
- Metadata update frequency: Rate limit updates if needed

### Security Considerations
- Metadata accuracy: Ensure advertised subnets match actual subscriptions
- ENR consistency: Consider updating ENR attestation bits to match

## Expected Outcomes

- Metadata accurately reflects configured attestation subnets
- Reduced network overhead by advertising only subscribed subnets
- Better network participant identification based on subnet interests

### Success Metrics
- Zero discrepancies between configured and advertised subnets
- Successful metadata exchanges with remote peers
- No performance degradation in RPC handlers