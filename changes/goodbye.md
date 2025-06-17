# Goodbye Protocol Compliance Analysis for Hermes

## 1. What the Validation Spec Requires

The Goodbye protocol (`/eth2/beacon_chain/req/goodbye/1/`) is a simple courtesy notification mechanism that allows peers to inform each other of disconnection reasons.

### Key Requirements:

#### Message Structure:
- **Content**: Single `uint64` field representing the reason code
- **Encoding**: SSZ-field (not SSZ container since it's a single field)

#### MUST Requirements:
1. **Encoding**:
   - Request/response MUST be encoded as a single SSZ-field
   - Response MUST consist of a single `response_chunk`
   - Single field messages MUST be encoded directly as the type, NOT as SSZ container

2. **Request/Response Handling**:
   - Responder MUST validate the request before processing
   - Responder MUST process according to encoding strategy until EOF
   - If validation fails, responder MUST respond with error
   - Responder MUST NOT respond with error when rate limiting

3. **Response Codes**:
   - Chunks start with single-byte response code
   - Valid codes: 0 (Success), 1 (InvalidRequest), 2 (ServerError), 3 (ResourceUnavailable)
   - Range [4, 127] is RESERVED and should be treated as error

4. **Stream Handling**:
   - Requester must close write side after sending request
   - Responder must close write side after sending response
   - Stream should be fully closed after response

#### MAY Requirements:
1. **Sending**:
   - Client MAY send goodbye messages upon disconnection
   - Clients MAY use reason codes above 128 for alternative responses

2. **Reason Codes**:
   - 1: Client shut down
   - 2: Irrelevant network
   - 3: Fault/error
   - Range [4, 127] is RESERVED for future usage

3. **Error Handling**:
   - Clients MAY record validation failures for reputation tracking
   - Responder MAY rate-limit chunks
   - Responder MAY penalize concurrent streams exceeding MAX_CONCURRENT_REQUESTS

## 2. What Currently Exists in Hermes

### Current Implementation Status:

#### Handler Interface (`eth/reqresp/types.go`):
```go
type Handler interface {
    Goodbye(ctx context.Context, stream network.Stream) error
    // ... other methods
}
```

#### Upstream Handler (`eth/reqresp/upstream/handler.go`, lines 167-181):
```go
func (h *UpstreamHandler) Goodbye(ctx context.Context, stream network.Stream) error {
    defer stream.Close()

    // Read goodbye reason
    reason := primitives.SSZUint64(0)
    if err := h.readRequest(ctx, stream, &reason); err != nil {
        return fmt.Errorf("read goodbye request: %w", err)
    }

    h.logger.Info("Received goodbye", "reason", reason, "peer", stream.Conn().RemotePeer())

    // Close the stream
    return stream.Reset()
}
```

#### Delegated Handler (`eth/reqresp/delegated/handler.go`, lines 135-154):
```go
func (h *DelegatedHandler) Goodbye(ctx context.Context, stream network.Stream) error {
    defer stream.Close()

    // Set deadlines
    if err := stream.SetDeadline(time.Now().Add(h.cfg.ReadTimeout)); err != nil {
        return fmt.Errorf("failed to set deadline: %w", err)
    }

    // Read goodbye reason
    reason := primitives.SSZUint64(0)
    if err := h.cfg.Encoder.DecodeWithMaxLength(stream, &reason); err != nil {
        return fmt.Errorf("failed to decode goodbye: %w", err)
    }

    h.logger.Info("Received goodbye", "reason", reason, "peer", stream.Conn().RemotePeer())

    // Close the stream
    return stream.Reset()
}
```

### Issues with Current Implementation:

1. **No Response Sent**: Both handlers only read the request but don't send any response
2. **Stream Reset Instead of Proper Close**: Using `stream.Reset()` instead of proper stream closing
3. **No Response Code**: Not writing a response code byte before response
4. **Missing Validation**: No validation of reason code ranges
5. **No Read Side Closure**: Not calling `stream.CloseRead()` after reading request
6. **Missing Write Side Closure**: Not properly closing write side after response

## 3. What Needs to Change

### Both Independent and Delegated Modes:

1. **Add Response Handling**:
   - Write response code byte (Success = 0)
   - Write goodbye reason response (echo back or send own reason)
   - Properly close write side after response

2. **Fix Stream Handling**:
   - Close read side after reading request
   - Close write side after writing response
   - Remove `stream.Reset()` - use proper closing

3. **Add Validation**:
   - Validate reason codes are valid uint64
   - Handle reserved range [4, 127] appropriately

4. **Error Response Handling**:
   - Write error response codes when validation fails
   - Use proper error codes (InvalidRequest, ServerError, etc.)

### Mode-Specific Changes:

#### Upstream Mode (Independent Validator):
- Should respond with its own goodbye reason if needed
- Could forward goodbye to beacon node for awareness

#### Delegated Mode:
- Should check if request is from delegate peer
- If from delegate, respond directly
- If from other peer, could optionally delegate to the delegate peer

## 4. Specific Code Examples and File Locations

### Fix for Upstream Handler (`eth/reqresp/upstream/handler.go`):

```go
func (h *UpstreamHandler) Goodbye(ctx context.Context, stream network.Stream) error {
    defer stream.Close()

    // Read goodbye reason
    reason := primitives.SSZUint64(0)
    if err := h.readRequest(ctx, stream, &reason); err != nil {
        // Write error response if read fails
        _ = reqresp.WriteErrorResponse(stream, reqresp.ResponseCodeInvalidRequest, h.cfg.WriteTimeout)
        return fmt.Errorf("read goodbye request: %w", err)
    }

    h.logger.Info("Received goodbye", "reason", reason, "peer", stream.Conn().RemotePeer())

    // Validate reason code (optional - spec says MAY)
    if reason >= 4 && reason <= 127 {
        h.logger.Warn("Reserved goodbye reason code", "reason", reason)
    }

    // Write success response with our own goodbye reason
    // We can echo back the same reason or send our own
    responseReason := reason // Echo back for now
    if err := h.writeResponse(ctx, stream, &responseReason); err != nil {
        return fmt.Errorf("write goodbye response: %w", err)
    }

    return nil
}
```

### Fix for Delegated Handler (`eth/reqresp/delegated/handler.go`):

```go
func (h *DelegatedHandler) Goodbye(ctx context.Context, stream network.Stream) error {
    defer stream.Close()

    // Set deadlines
    if err := stream.SetDeadline(time.Now().Add(h.cfg.ReadTimeout)); err != nil {
        return fmt.Errorf("failed to set deadline: %w", err)
    }

    // Read goodbye reason
    reason := primitives.SSZUint64(0)
    if err := h.cfg.Encoder.DecodeWithMaxLength(stream, &reason); err != nil {
        // Write error response
        _ = reqresp.WriteErrorResponse(stream, reqresp.ResponseCodeInvalidRequest, h.cfg.WriteTimeout)
        return fmt.Errorf("failed to decode goodbye: %w", err)
    }

    h.logger.Info("Received goodbye", "reason", reason, "peer", stream.Conn().RemotePeer())

    // Close read side
    if err := stream.CloseRead(); err != nil {
        h.logger.Warn("Failed to close read side", "err", err)
    }

    // Write response
    if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
        return fmt.Errorf("failed to write response code: %w", err)
    }

    // Echo back the reason or send our own
    responseReason := reason
    if _, err := h.cfg.Encoder.EncodeWithMaxLength(stream, &responseReason); err != nil {
        return fmt.Errorf("failed to encode goodbye response: %w", err)
    }

    return nil
}
```

### Add Helper for Goodbye Reason Validation (optional):

```go
// In eth/reqresp/utils.go

// GoodbyeReason codes
const (
    GoodbyeReasonClientShutdown = 1
    GoodbyeReasonIrrelevantNetwork = 2
    GoodbyeReasonFaultError = 3
    // Range [4, 127] is RESERVED
)

// ValidateGoodbyeReason checks if a goodbye reason is valid
func ValidateGoodbyeReason(reason uint64) error {
    if reason >= 4 && reason <= 127 {
        return fmt.Errorf("reserved goodbye reason code: %d", reason)
    }
    return nil
}
```

## 5. Dependencies on Missing Components

### Current Dependencies Met:
- SSZ encoding/decoding via `prysm` encoder
- Stream handling via `libp2p`
- Response code constants in `utils.go`
- Helper functions `readRequest`/`writeResponse` for upstream handler

### Potential Missing Components:
1. **No Goodbye Client Functionality**: Hermes only handles incoming goodbye requests but doesn't send goodbye messages when disconnecting
2. **No Rate Limiting for Goodbye**: While spec allows rate limiting, it's not implemented
3. **No Reputation Tracking**: Spec mentions MAY track validation failures for reputation

### Recommendations:
1. Implement proper goodbye response handling as shown above
2. Consider adding goodbye client functionality to send goodbye when Hermes disconnects
3. Consider adding rate limiting if needed (though goodbye is low-frequency)
4. Document the chosen goodbye reason codes when Hermes responds

## Summary

The Goodbye protocol in Hermes is partially implemented but non-compliant with the validation spec. The main issue is that it doesn't send any response, which violates the MUST requirement for responding. Both handler modes need to be updated to:

1. Send a proper response with response code
2. Handle stream closing correctly
3. Optionally validate reason codes

The fixes are straightforward and mainly involve adding the response writing logic that's already used in other protocol handlers like Ping and Status.