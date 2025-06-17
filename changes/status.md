# Status Request/Response Compliance Analysis

## 1. What the Validation Spec Requires

### Protocol Versions
- **Phase 0**: `/eth2/beacon_chain/req/status/1/ssz_snappy`
- **Fulu**: `/eth2/beacon_chain/req/status/2/ssz_snappy`

### Request Validation Rules

#### MUST Requirements
1. The dialing client MUST send a `Status` request upon connection
2. The request/response MUST be encoded as an SSZ-container
3. The requester MUST close the write side of the stream once it finishes writing the request message
4. Request processing and validation MUST be done according to the encoding strategy

#### MUST NOT Requirements
1. The requester MUST NOT make more than `MAX_CONCURRENT_REQUESTS` concurrent requests with the same protocol ID
2. Messages containing only a single field MUST NOT be encoded as an SSZ container

### Response Validation Rules

#### MUST Requirements
1. The response MUST consist of a single `response_chunk`
2. The responder MUST validate the request before processing it
3. The responder MUST follow the proper sequence:
   - Use the encoding strategy to read the optional header
   - Read exactly N bytes from the stream if there are length assertions
   - Deserialize the expected type and process the request
   - Write the response (zero or more `response_chunk`s)
   - Close their write side of the stream
4. If validation fails due to invalid, malformed, or inconsistent data, the responder MUST respond in error
5. When rate limiting, the responder MUST send each `response_chunk` in full promptly (but may introduce delays between chunks)
6. Error messages MUST be treated as valid for any byte sequences

#### MUST NOT Requirements
1. The responder MUST NOT respond with an error or close the stream when rate limiting

### Message Formats

#### Phase 0 Status
```
(
  fork_digest: ForkDigest
  finalized_root: Root
  finalized_epoch: Epoch
  head_root: Root
  head_slot: Slot
)
```

#### Fulu Status (Version 2)
```
(
  fork_digest: ForkDigest
  finalized_root: Root
  finalized_epoch: Epoch
  head_root: Root
  head_slot: Slot
  earliest_available_slot: Slot  # New field
)
```

### Post-Handshake Disconnection Conditions
Clients SHOULD immediately disconnect if:
1. `fork_digest` does not match the node's local `fork_digest`
2. The (`finalized_root`, `finalized_epoch`) shared by the peer is not in the client's chain at the expected epoch

### Response Codes
- 0: Success
- 1: InvalidRequest
- 2: ServerError
- 3: ResourceUnavailable
- 128-255: Client-specific alternative error responses
- 4-127: RESERVED

## 2. What Currently Exists in Hermes

### Core Infrastructure

#### Handler Interface (`eth/reqresp/types.go`)
- Defines `Handler` interface with `Status(ctx context.Context, stream network.Stream) error`
- Provides `SetStatus()` and `GetStatus()` methods for status management
- Has `StatusLimiter` for rate limiting (5 req/s, burst 10)

#### Protocol Registration (`eth/reqresp/handler.go`)
- Registers `/eth2/beacon_chain/req/status/1/ssz_snappy` protocol
- No support for Status version 2 (Fulu)
- Uses wrapper for telemetry and error handling
- Protocol ID construction: `buildProtocolID(forkDigest, ProtocolStatus, 1)`

#### Upstream Handler (`eth/reqresp/upstream/handler.go`)
- Implements status handling by proxying to beacon API
- Has `StatusSyncer` that periodically updates status (every 12 seconds)
- Reads peer status, validates, and responds with local status
- Sets fork_digest before responding
- Uses helper methods `readRequest()` and `writeResponse()`

#### Delegated Handler (`eth/reqresp/delegated/handler.go`)
- Implements status handling by delegating to another peer
- Has rate limiting (5 req/s, burst 10)
- Special handling for delegate peer (responds locally)
- Otherwise forwards the stream to delegate peer
- Properly implements stream closing and deadline handling

#### Utils (`eth/reqresp/utils.go`)
- Provides standard request/response helpers
- Proper response code handling
- Deadline management
- Stream read/write closing

### Current Status Implementation

#### Upstream Mode
1. Uses `StatusSyncer` to periodically fetch status from beacon API
2. Stores status locally and notifies subscribers
3. When handling request:
   - Reads peer status
   - Gets local status from syncer
   - Sets fork_digest
   - Writes response

#### Delegated Mode
1. Rate limits incoming requests
2. If request is from delegate peer, responds with local status
3. Otherwise delegates the stream to the configured peer
4. Properly handles bidirectional stream copying

### Missing Components

1. **Status Version 2 Support**: No implementation for Fulu fork
2. **earliest_available_slot Field**: Not present in current status structure
3. **Fork Version Detection**: No mechanism to determine which status version to use
4. **Concurrent Request Limiting**: No tracking of concurrent requests per protocol
5. **Connection Handshake**: No automatic status exchange on new connections
6. **Disconnection Logic**: No implementation for fork_digest mismatch or finalized checkpoint validation

## 3. What Needs to Change

### Both Modes (Common Changes)

1. **Add Status V2 Support**
   - Create new Status V2 structure with `earliest_available_slot` field
   - Register `/eth2/beacon_chain/req/status/2/ssz_snappy` protocol
   - Implement fork version detection to choose correct protocol

2. **Implement Connection Handshake**
   - Add connection notifier to send status on new peer connections
   - Track which peers have completed handshake

3. **Add Concurrent Request Limiting**
   - Track active requests per protocol ID
   - Reject requests exceeding `MAX_CONCURRENT_REQUESTS`

4. **Implement Disconnection Logic**
   - Validate fork_digest matches
   - Check finalized checkpoint is in local chain
   - Disconnect peer if validation fails

### Independent Mode Specific

1. **Status V2 Message Handling**
   - Update status syncer to fetch `earliest_available_slot` from beacon API
   - Store and serve V2 status when appropriate

2. **Proper Error Responses**
   - Return InvalidRequest for malformed requests
   - Return ResourceUnavailable when status not yet available

### Delegated Mode Specific

1. **Status V2 Delegation**
   - Support delegating V2 status requests
   - Handle V2 responses from delegate peer

2. **Enhanced Rate Limiting**
   - Ensure full response chunks are sent even when rate limiting
   - Only delay between chunks, not within chunks

## 4. Specific Code Examples and File Locations

### Add Status V2 Structure

**File: `eth/reqresp/types.go`**
```go
// Add after existing imports
type StatusV2 struct {
    ForkDigest            [4]byte              `ssz-size:"4"`
    FinalizedRoot         [32]byte             `ssz-size:"32"`
    FinalizedEpoch        primitives.Epoch
    HeadRoot              [32]byte             `ssz-size:"32"`
    HeadSlot              primitives.Slot
    EarliestAvailableSlot primitives.Slot      // New field for Fulu
}
```

### Register Status V2 Protocol

**File: `eth/reqresp/handler.go`**
```go
// In RegisterHandlers() method, add:
buildProtocolID(forkDigest, ProtocolStatus, 2): m.wrapHandler("status_v2", m.handler.StatusV2),

// Add new method to Handler interface
StatusV2(ctx context.Context, stream network.Stream) error
```

### Implement Status V2 in Upstream Handler

**File: `eth/reqresp/upstream/handler.go`**
```go
// Add StatusV2 method
func (h *UpstreamHandler) StatusV2(ctx context.Context, stream network.Stream) error {
    defer stream.Close()

    // Read their status V2
    var theirStatus StatusV2
    if err := h.readRequest(ctx, stream, &theirStatus); err != nil {
        return fmt.Errorf("read status v2 request: %w", err)
    }

    // Get our status from syncer
    ourStatus := h.GetStatusV2()
    if ourStatus == nil {
        return errors.New("status v2 not available")
    }

    // Set fork digest
    ourStatus.ForkDigest = h.cfg.ForkDigest

    // Write our status
    if err := h.writeResponse(ctx, stream, ourStatus); err != nil {
        return fmt.Errorf("write status v2 response: %w", err)
    }

    // Validate peer's chain compatibility
    if err := h.validatePeerStatus(&theirStatus); err != nil {
        h.logger.Warn("Peer status validation failed", "err", err)
        // Disconnect peer
        return stream.Conn().Close()
    }

    return nil
}

// Add validation method
func (h *UpstreamHandler) validatePeerStatus(status *StatusV2) error {
    // Check fork digest
    if !bytes.Equal(status.ForkDigest[:], h.cfg.ForkDigest[:]) {
        return fmt.Errorf("fork digest mismatch")
    }
    
    // TODO: Check finalized checkpoint is in our chain
    // This requires access to chain state
    
    return nil
}
```

### Add Connection Handshake

**File: `eth/reqresp/handler.go`**
```go
// Add connection notifier
func (m *Manager) OnPeerConnected(peerID peer.ID) {
    go func() {
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()
        
        // Determine status version based on fork
        version := m.getStatusVersion()
        protocolID := GetProtocolID(m.cfg.ForkDigest, ProtocolStatus, version)
        
        // Send status request
        stream, err := m.host.NewStream(ctx, peerID, protocolID)
        if err != nil {
            m.logger.Warn("Failed to open status stream", "peer", peerID, "err", err)
            return
        }
        defer stream.Close()
        
        // Write our status
        status := m.handler.GetStatus()
        if err := WriteRequest(ctx, stream, m.cfg.Encoder, status, m.cfg.WriteTimeout); err != nil {
            m.logger.Warn("Failed to send status", "peer", peerID, "err", err)
            return
        }
        
        // Read their status
        var theirStatus pb.Status
        if err := ReadResponse(ctx, stream, m.cfg.Encoder, &theirStatus, m.cfg.ReadTimeout); err != nil {
            m.logger.Warn("Failed to read status", "peer", peerID, "err", err)
            return
        }
        
        m.logger.Info("Status exchange completed", "peer", peerID)
    }()
}
```

### Implement Concurrent Request Limiting

**File: `eth/reqresp/handler.go`**
```go
// Add to Manager struct
type Manager struct {
    // ... existing fields ...
    activeRequests map[protocol.ID]map[peer.ID]int
    requestMu      sync.Mutex
}

// Add request tracking
func (m *Manager) trackRequest(protocolID protocol.ID, peerID peer.ID) bool {
    m.requestMu.Lock()
    defer m.requestMu.Unlock()
    
    if m.activeRequests[protocolID] == nil {
        m.activeRequests[protocolID] = make(map[peer.ID]int)
    }
    
    count := m.activeRequests[protocolID][peerID]
    if count >= MAX_CONCURRENT_REQUESTS {
        return false
    }
    
    m.activeRequests[protocolID][peerID] = count + 1
    return true
}

func (m *Manager) releaseRequest(protocolID protocol.ID, peerID peer.ID) {
    m.requestMu.Lock()
    defer m.requestMu.Unlock()
    
    if m.activeRequests[protocolID] != nil {
        m.activeRequests[protocolID][peerID]--
        if m.activeRequests[protocolID][peerID] <= 0 {
            delete(m.activeRequests[protocolID], peerID)
        }
    }
}
```

## 5. Dependencies on Missing Components

1. **Fork Schedule/Configuration**
   - Need mechanism to determine current fork
   - Required to choose between Status V1 and V2

2. **Chain State Access**
   - Required for validating finalized checkpoint
   - Need to check if peer's finalized root exists at claimed epoch

3. **Earliest Available Slot Tracking**
   - Beacon API needs to provide this information
   - May require new endpoint or field in existing endpoints

4. **Connection Event Notifications**
   - Need libp2p connection notifier integration
   - Required for automatic status exchange on connect

5. **MAX_CONCURRENT_REQUESTS Configuration**
   - Need to define this constant (typically 2)
   - Should be configurable per deployment

## Implementation Priority

1. **High Priority**
   - Basic Status V2 support (structure and protocol registration)
   - Concurrent request limiting
   - Proper error response codes

2. **Medium Priority**
   - Connection handshake automation
   - Fork version detection
   - Disconnection validation

3. **Low Priority**
   - Enhanced rate limiting behavior
   - Detailed metrics and logging