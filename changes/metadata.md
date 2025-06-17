# Metadata Request/Response Compliance Analysis for Hermes

## 1. What the Validation Spec Requires

Based on the validation spec at `validation-specs/reqresp/metadata.md`, the metadata protocol requirements are:

### Protocol Versions
- **Phase 0**: `/eth2/beacon_chain/req/metadata/1/` - MetaDataV1
- **Altair**: `/eth2/beacon_chain/req/metadata/2/` - MetaDataV2  
- **Fulu**: `/eth2/beacon_chain/req/metadata/3/` - MetaDataV3

### Request Requirements
- **No request content** - the stream is simply opened and negotiated
- Request encoding: N/A (empty request)

### Response Requirements (MUST)
1. Response MUST be encoded as an SSZ-container
2. Response MUST consist of a single `response_chunk`
3. Responder MUST send their local most up-to-date MetaData
4. Response MUST NOT exceed `MAX_PAYLOAD_SIZE`
5. Response chunks MUST start with a single-byte response code (0 for success)
6. For ssz_snappy encoding, length MUST be encoded as a protobuf varint in the header

### Metadata Update Requirements
1. Clients MUST increment `seq_number` by 1 whenever any other field in MetaData changes
2. `seq_number` starts at 0

### MetaData Structure by Version

**Version 1 (Phase 0)**:
```
(
  seq_number: uint64
  attnets: Bitvector[ATTESTATION_SUBNET_COUNT]
)
```

**Version 2 (Altair)**:
```
(
  seq_number: uint64
  attnets: Bitvector[ATTESTATION_SUBNET_COUNT]
  syncnets: Bitvector[SYNC_COMMITTEE_SUBNET_COUNT]
)
```

**Version 3 (Fulu)**:
```
(
  seq_number: uint64
  attnets: Bitvector[ATTESTATION_SUBNET_COUNT]
  syncnets: Bitvector[SYNC_COMMITTEE_SUBNET_COUNT]
  custody_subnet_count: uint64
)
```

### ENR Consistency
- If `MetaData.attnets` has any non-zero bit, the ENR MUST include the `attnets` entry with the same value

## 2. What Currently Exists in Hermes

### MetaData Structures
Hermes currently only uses `MetaDataV1` from Prysm:
- Location: `github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1`
- Prysm provides: `MetaDataV0`, `MetaDataV1`, `MetaDataV2` (but NOT MetaDataV3)

### Protocol Registration
- Location: `eth/reqresp/handler.go`
- Currently registers:
  - `/eth2/beacon_chain/req/metadata/1/` → MetaData(version=1)
  - `/eth2/beacon_chain/req/metadata/2/` → MetaData(version=2)
  - NO support for version 3 (Fulu)

### Handler Interface
- Location: `eth/reqresp/types.go`
```go
type Handler interface {
    MetaData(ctx context.Context, stream network.Stream, version uint64) error
    SetMetaData(metadata *pb.MetaDataV1)
    GetMetaData() *pb.MetaDataV1
}
```

### Implementation in Delegated Mode
- Location: `eth/reqresp/delegated/handler.go`
- Current behavior:
  - Stores only `MetaDataV1` internally
  - In `MetaData()` method, it responds with V1 metadata regardless of version requested
  - No request body handling (correctly implements empty request)
  - Properly writes response code before metadata

### Implementation in Upstream Mode  
- Location: `eth/reqresp/upstream/handler.go`
- Current behavior:
  - Stores only `MetaDataV1` internally
  - In `MetaData()` method, it responds with V1 metadata for both v1 and v2
  - No proper conversion to V2 format when v2 is requested
  - Properly handles empty request body

### Node Initialization
- Location: `eth/node.go`
- Initializes metadata as:
```go
metadata := &eth.MetaDataV1{
    SeqNumber: 0,
    Attnets:   attnets,
    Syncnets:  bitfield.Bitvector4{byte(0x00)},
}
```

## 3. What Needs to Change

### Critical Issues

1. **Version 2 Support**: Currently both handlers respond with V1 metadata even when V2 is requested
2. **Version 3 Support**: No support for Fulu fork (MetaDataV3)
3. **Metadata Storage**: Handler interface only supports MetaDataV1, needs to support all versions
4. **Sequence Number Updates**: No mechanism to increment seq_number when metadata fields change
5. **ENR Consistency**: No validation/synchronization with ENR attnets entry

### Changes Required for Both Modes

#### 1. Update Handler Interface (`eth/reqresp/types.go`)
```go
type Handler interface {
    // Update method signatures to support all versions
    MetaData(ctx context.Context, stream network.Stream, version uint64) error
    
    // Add methods for each version
    SetMetaDataV1(metadata *pb.MetaDataV1)
    GetMetaDataV1() *pb.MetaDataV1
    SetMetaDataV2(metadata *pb.MetaDataV2)
    GetMetaDataV2() *pb.MetaDataV2
    // Note: MetaDataV3 not available in Prysm yet
    
    // Add method to update sequence number
    IncrementMetaDataSeqNumber()
}
```

#### 2. Update Handler Registration (`eth/reqresp/handler.go`)
```go
// Add version 3 support when MetaDataV3 becomes available
buildProtocolID(forkDigest, ProtocolMetadata, 3): m.wrapHandler("metadata_v3", func(ctx context.Context, s network.Stream) error { return m.handler.MetaData(ctx, s, 3) }),
```

#### 3. Update Delegated Handler (`eth/reqresp/delegated/handler.go`)
```go
type DelegatedHandler struct {
    // Add storage for all versions
    metaDataV1Mu sync.RWMutex
    metaDataV1   *pb.MetaDataV1
    
    metaDataV2Mu sync.RWMutex  
    metaDataV2   *pb.MetaDataV2
    
    // Add sequence number tracking
    seqNumber    uint64
    seqNumberMu  sync.RWMutex
}

// Update MetaData method to handle versions correctly
func (h *DelegatedHandler) MetaData(ctx context.Context, stream network.Stream, version uint64) error {
    defer stream.Close()
    
    // No request body for metadata
    if err := stream.CloseRead(); err != nil {
        h.logger.Warn("Failed to close read side", "err", err)
    }
    
    // Write response based on version
    switch version {
    case 1:
        metadata := h.GetMetaDataV1()
        if metadata == nil {
            return errors.New("metadata v1 not set")
        }
        // Write response
        if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
            return fmt.Errorf("failed to write response code: %w", err)
        }
        if _, err := h.cfg.Encoder.EncodeWithMaxLength(stream, metadata); err != nil {
            return fmt.Errorf("failed to encode metadata v1: %w", err)
        }
        
    case 2:
        metadata := h.GetMetaDataV2()
        if metadata == nil {
            return errors.New("metadata v2 not set")
        }
        // Write response
        if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
            return fmt.Errorf("failed to write response code: %w", err)
        }
        if _, err := h.cfg.Encoder.EncodeWithMaxLength(stream, metadata); err != nil {
            return fmt.Errorf("failed to encode metadata v2: %w", err)
        }
        
    case 3:
        // TODO: Implement when MetaDataV3 is available
        return errors.New("metadata v3 not yet supported")
        
    default:
        return fmt.Errorf("unsupported metadata version: %d", version)
    }
    
    return nil
}
```

#### 4. Update Upstream Handler (`eth/reqresp/upstream/handler.go`)
Similar changes as delegated handler, but also needs to:
- Fetch correct metadata version from beacon node
- Convert between versions if needed
- Maintain proper sequence numbers

#### 5. Update Node Initialization (`eth/node.go`)
```go
// Initialize all metadata versions
metadataV1 := &eth.MetaDataV1{
    SeqNumber: 0,
    Attnets:   attnets,
}

metadataV2 := &eth.MetaDataV2{
    SeqNumber: 0,
    Attnets:   attnets,
    Syncnets:  bitfield.Bitvector4{byte(0x00)},
}

reqRespHandler.SetMetaDataV1(metadataV1)
reqRespHandler.SetMetaDataV2(metadataV2)
```

#### 6. Add Sequence Number Management
Need to implement logic to increment sequence number when:
- Attestation subnet memberships change
- Sync committee subnet memberships change  
- Custody subnet count changes (for V3)

This could be done through:
- A watcher that monitors subnet changes
- Hook into subnet subscription/unsubscription logic
- Periodic sync with beacon node state

## 4. Specific Code Examples

### Example: Proper Version Handling in MetaData Method
```go
func (h *DelegatedHandler) MetaData(ctx context.Context, stream network.Stream, version uint64) error {
    defer stream.Close()
    
    // Set deadline
    if err := stream.SetDeadline(time.Now().Add(h.cfg.ReadTimeout)); err != nil {
        return fmt.Errorf("failed to set deadline: %w", err)
    }
    
    // No request body - close read side immediately
    if err := stream.CloseRead(); err != nil {
        h.logger.Warn("Failed to close read side", "err", err)
    }
    
    // Get appropriate metadata version
    var metadata ssz.Marshaler
    switch version {
    case 1:
        metadata = h.GetMetaDataV1()
    case 2:
        metadata = h.GetMetaDataV2()
    case 3:
        return h.writeErrorResponse(stream, reqresp.ResponseCodeServerError)
    default:
        return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
    }
    
    if metadata == nil {
        return h.writeErrorResponse(stream, reqresp.ResponseCodeServerError)
    }
    
    // Write success response
    if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
        return fmt.Errorf("failed to write response code: %w", err)
    }
    
    // Encode metadata
    if _, err := h.cfg.Encoder.EncodeWithMaxLength(stream, metadata); err != nil {
        return fmt.Errorf("failed to encode metadata: %w", err)
    }
    
    return nil
}
```

### Example: Sequence Number Update
```go
func (h *DelegatedHandler) UpdateAttnets(newAttnets bitfield.Bitvector64) {
    h.metaDataV1Mu.Lock()
    h.metaDataV2Mu.Lock()
    defer h.metaDataV1Mu.Unlock()
    defer h.metaDataV2Mu.Unlock()
    
    // Check if attnets changed
    if h.metaDataV1 != nil && !bytes.Equal(h.metaDataV1.Attnets, newAttnets) {
        h.incrementSeqNumber()
        h.metaDataV1.Attnets = newAttnets
        h.metaDataV1.SeqNumber = h.getSeqNumber()
    }
    
    if h.metaDataV2 != nil && !bytes.Equal(h.metaDataV2.Attnets, newAttnets) {
        h.metaDataV2.Attnets = newAttnets
        h.metaDataV2.SeqNumber = h.getSeqNumber()
    }
}

func (h *DelegatedHandler) incrementSeqNumber() {
    h.seqNumberMu.Lock()
    defer h.seqNumberMu.Unlock()
    h.seqNumber++
}
```

## 5. Dependencies on Missing Components

### 1. MetaDataV3 Structure
- **Dependency**: Prysm proto definitions
- **Status**: Not available in current Prysm version
- **Action**: Need to wait for Prysm update or define custom structure

### 2. Fork Detection
- **Dependency**: Fork schedule/detection mechanism
- **Status**: Not clear how Hermes determines current fork
- **Action**: Need to integrate with fork detection to serve correct metadata version

### 3. Subnet Management
- **Dependency**: Subnet subscription/unsubscription events
- **Status**: Not clear where subnet memberships are managed
- **Action**: Need hooks into subnet management to update sequence numbers

### 4. ENR Management
- **Dependency**: ENR update mechanism
- **Status**: Need to find where ENR is managed
- **Action**: Ensure ENR attnets field stays synchronized with metadata

### 5. Beacon Node Integration (Upstream Mode)
- **Dependency**: Beacon API client
- **Status**: Exists but may need extension
- **Action**: Add methods to fetch metadata from beacon node API

### 6. Configuration
- **Dependency**: Fork configuration
- **Status**: Need to know which forks are active
- **Action**: Add configuration for supported metadata versions

## Implementation Priority

1. **High Priority**: Fix V2 metadata responses (currently broken)
2. **High Priority**: Implement sequence number updates
3. **Medium Priority**: Add proper version detection based on fork
4. **Low Priority**: Add V3 support (waiting for Prysm)
5. **Low Priority**: ENR synchronization

## Testing Requirements

1. Test metadata responses for all versions
2. Test sequence number increments on subnet changes
3. Test error responses for unsupported versions
4. Test rate limiting behavior
5. Test ENR consistency with metadata
6. Test fork transitions and version changes