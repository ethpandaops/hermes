package reqresp

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/OffchainLabs/prysm/v6/beacon-chain/p2p/encoder"
	ssz "github.com/ferranbt/fastssz"
)

// Response codes
const (
	ResponseCodeSuccess             = 0
	ResponseCodeInvalidRequest      = 1
	ResponseCodeServerError         = 2
	ResponseCodeResourceUnavailable = 3
	ResponseCodeRateLimited         = 139
)

// logDeferErr logs an error from a deferred function call
func logDeferErr(logger *slog.Logger, err error, msg string) {
	if err != nil {
		logger.Warn(msg, "err", err)
	}
}

// ReadRequest reads a request from a stream
func ReadRequest(ctx context.Context, stream network.Stream, encoder encoder.NetworkEncoding, dest ssz.Unmarshaler, timeout time.Duration) error {
	// Set read deadline
	if err := stream.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Decode the request
	if err := encoder.DecodeWithMaxLength(stream, dest); err != nil {
		return fmt.Errorf("failed to decode request: %w", err)
	}

	// Close read side
	if err := stream.CloseRead(); err != nil {
		return fmt.Errorf("failed to close read: %w", err)
	}

	return nil
}

// ReadResponse reads a response from a stream with status code
func ReadResponse(ctx context.Context, stream network.Stream, encoder encoder.NetworkEncoding, dest ssz.Unmarshaler, timeout time.Duration) error {
	// Set read deadline
	if err := stream.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Read response code
	code := make([]byte, 1)
	if _, err := io.ReadFull(stream, code); err != nil {
		return fmt.Errorf("failed to read response code: %w", err)
	}

	// Check response code
	if code[0] != ResponseCodeSuccess {
		// For error responses, we don't decode the message
		return fmt.Errorf("error response code: %d", code[0])
	}

	// Decode successful response
	if err := encoder.DecodeWithMaxLength(stream, dest); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	return nil
}

// WriteRequest writes a request to a stream
func WriteRequest(ctx context.Context, stream network.Stream, encoder encoder.NetworkEncoding, msg ssz.Marshaler, timeout time.Duration) error {
	// Set write deadline
	if err := stream.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	// Encode the request
	if _, err := encoder.EncodeWithMaxLength(stream, msg); err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	// Close write side
	if err := stream.CloseWrite(); err != nil {
		return fmt.Errorf("failed to close write: %w", err)
	}

	return nil
}

// WriteResponse writes a response to a stream with status code
func WriteResponse(ctx context.Context, stream network.Stream, encoder encoder.NetworkEncoding, msg ssz.Marshaler, timeout time.Duration) error {
	// Set write deadline
	if err := stream.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	// Write success response code
	if _, err := stream.Write([]byte{ResponseCodeSuccess}); err != nil {
		return fmt.Errorf("failed to write response code: %w", err)
	}

	// Encode the response
	if _, err := encoder.EncodeWithMaxLength(stream, msg); err != nil {
		return fmt.Errorf("failed to encode response: %w", err)
	}

	return nil
}

// WriteErrorResponse writes an error response to a stream
func WriteErrorResponse(stream network.Stream, code uint8, timeout time.Duration) error {
	// Set write deadline
	if err := stream.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	// Write error response code
	if _, err := stream.Write([]byte{code}); err != nil {
		return fmt.Errorf("failed to write response code: %w", err)
	}

	// Note: We don't write error messages in the response body
	return nil
}