# Ping Protocol Implementation Analysis for Hermes

## 1. What the Validation Spec Requires

The `/eth2/beacon_chain/req/ping/1/` protocol has the following requirements:

### MUST Requirements:
- **Request**: Single `uint64` value representing requester's `MetaData.seq_number`
- **Response**: Single `uint64` value representing responder's `MetaData.seq_number`
- **Encoding**: SSZ-field (SSZ-snappy)
- **Stream Management**:
  - Requester MUST close write side after sending request
  - Response MUST consist of a single `response_chunk`
  - MUST validate incoming request before processing
  - MUST respond with error if request is invalid/malformed
  - MUST NOT respond with error when rate limiting (send chunks with delays instead)
  - MUST ensure message lengths are within bounds (MAX_PAYLOAD_SIZE = 10 MiB)
  - Messages with single field MUST be encoded directly as that field type (not SSZ container)

### MAY Requirements:
- MAY disconnect from peer if no response to ping
- MAY record failures for peer reputation tracking

### Purpose:
1. Check liveness of connected peers
2. Exchange metadata sequence numbers
3. Determine if peer's MetaData needs updating

## 2. What Currently Exists in Hermes

### Client Implementation ✅
- **Location**: `/Users/samcm/go/src/github.com/ethpandaops/hermes/eth/reqresp_client.go`
- **Function**: `Node.Ping(ctx context.Context, pid peer.ID) error` (lines 82-109)
- **Implementation**:
  - Correctly sends metadata sequence number as request
  - Reads pong response
  - Uses proper protocol ID
  - Handles stream lifecycle correctly

### Server Implementation Status:

#### Delegated Mode ✅
- **Location**: `/Users/samcm/go/src/github.com/ethpandaops/hermes/eth/reqresp/delegated/handler.go`
- **Function**: `DelegatedHandler.Ping()` (lines 104-133)
- **Implementation**:
  - Reads incoming ping sequence number
  - Responds with the same sequence number (echoes back)
  - Properly handles stream lifecycle
  - Sets appropriate deadlines

#### Upstream Mode ✅
- **Location**: `/Users/samcm/go/src/github.com/ethpandaops/hermes/eth/reqresp/upstream/handler.go`
- **Function**: `UpstreamHandler.Ping()` (lines 142-165)
- **Implementation**:
  - Reads incoming ping sequence number
  - Responds with local metadata sequence number
  - Uses helper methods for request/response handling

#### Independent Mode ❌
- **Status**: NOT IMPLEMENTED
- No independent handler exists in the codebase

### Supporting Infrastructure ✅
- **Protocol Registration**: `/Users/samcm/go/src/github.com/ethpandaops/hermes/eth/reqresp/handler.go`
  - Ping protocol properly registered (line 110)
  - Protocol ID construction correct
- **Constants**: Defined in `handler.go` (line 24)
- **Utils**: Helper functions in `/Users/samcm/go/src/github.com/ethpandaops/hermes/eth/reqresp/utils.go`
  - `ReadRequest()`, `WriteResponse()`, etc.

## 3. What Needs to Change

### Critical Issues:

1. **Delegated Mode Bug**: The delegated handler echoes back the requester's sequence number instead of responding with its own metadata sequence number. This violates the spec.

2. **Missing Independent Mode**: No independent handler implementation exists.

### Required Changes:

#### For Delegated Mode:
```go
// In /eth/reqresp/delegated/handler.go, Ping function should be:
func (h *DelegatedHandler) Ping(ctx context.Context, stream network.Stream) error {
    defer stream.Close()

    // Set deadlines
    if err := stream.SetDeadline(time.Now().Add(h.cfg.ReadTimeout)); err != nil {
        return fmt.Errorf("failed to set deadline: %w", err)
    }

    // Read ping sequence number
    seqNum := primitives.SSZUint64(0)
    if err := h.cfg.Encoder.DecodeWithMaxLength(stream, &seqNum); err != nil {
        return fmt.Errorf("failed to decode ping: %w", err)
    }

    // Close read side
    if err := stream.CloseRead(); err != nil {
        h.logger.Warn("Failed to close read side", "err", err)
    }

    // Get our metadata sequence number
    h.metaDataMu.RLock()
    var ourSeqNum primitives.SSZUint64
    if h.metaData != nil {
        ourSeqNum = primitives.SSZUint64(h.metaData.SeqNumber)
    }
    h.metaDataMu.RUnlock()

    // Write pong response with OUR sequence number
    if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
        return fmt.Errorf("failed to write response code: %w", err)
    }

    if _, err := h.cfg.Encoder.EncodeWithMaxLength(stream, &ourSeqNum); err != nil {
        return fmt.Errorf("failed to encode pong: %w", err)
    }

    return nil
}
```

#### For Independent Mode:
Need to create a new file `/eth/reqresp/independent/handler.go` with full implementation including:
```go
package independent

import (
    "context"
    "errors"
    "fmt"
    "sync"
    "time"

    "github.com/libp2p/go-libp2p/core/host"
    "github.com/libp2p/go-libp2p/core/network"
    "github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
    pb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
    
    "github.com/probe-lab/hermes/eth/reqresp"
)

type IndependentHandler struct {
    host     host.Host
    cfg      *reqresp.Config
    logger   *slog.Logger
    
    // Status and metadata management
    statusMu sync.RWMutex
    status   *pb.Status
    
    metaDataMu sync.RWMutex
    metaData   *pb.MetaDataV1
    
    // Add beacon state access for validation
    // TODO: Add beacon state interface
}

func (h *IndependentHandler) Ping(ctx context.Context, stream network.Stream) error {
    defer stream.Close()

    // Read ping sequence number
    req := primitives.SSZUint64(0)
    if err := reqresp.ReadRequest(ctx, stream, h.cfg.Encoder, &req, h.cfg.ReadTimeout); err != nil {
        return fmt.Errorf("read ping request: %w", err)
    }

    // Get our metadata sequence number
    h.metaDataMu.RLock()
    var seqNum primitives.SSZUint64
    if h.metaData != nil {
        seqNum = primitives.SSZUint64(h.metaData.SeqNumber)
    }
    h.metaDataMu.RUnlock()

    // Write pong response
    if err := reqresp.WriteResponse(ctx, stream, h.cfg.Encoder, &seqNum, h.cfg.WriteTimeout); err != nil {
        return fmt.Errorf("write pong response: %w", err)
    }

    return nil
}

// ... implement other required methods ...
```

## 4. Specific Code Examples and File Locations

### Files to Modify:
1. `/eth/reqresp/delegated/handler.go` - Fix Ping() method (lines 104-133)

### Files to Create:
1. `/eth/reqresp/independent/handler.go` - Complete independent handler implementation

### Integration Points:
1. `/eth/node_config.go` - Add configuration for independent mode
2. `/eth/node.go` - Add initialization logic for independent handler

## 5. Dependencies on Missing Components

### For Independent Mode:
1. **Beacon State Access**: Need interface to access current beacon state for validation
2. **Epoch/Slot Tracking**: Need to track current epoch/slot for proper validation
3. **Fork Choice**: May need fork choice state for certain validations
4. **Peer Scoring**: Need peer scoring mechanism for tracking failures

### Common Dependencies:
1. **Rate Limiting**: Current implementations use basic rate limiting, but spec requires special handling (delays between chunks, not errors)
2. **Metrics**: Need to add ping-specific metrics for monitoring
3. **Tracing**: Should add trace events for ping requests/responses

## Summary

The Ping protocol is mostly implemented correctly in Hermes, with two main issues:
1. **Bug in Delegated Mode**: Easy fix - respond with own metadata sequence number instead of echoing
2. **Missing Independent Mode**: Requires new handler implementation with beacon state integration

The upstream mode implementation is correct and follows the spec properly. The client implementation is also correct.