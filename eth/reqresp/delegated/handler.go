package delegated

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	pb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"golang.org/x/time/rate"

	"github.com/probe-lab/hermes/eth/reqresp"
)

// DelegatedHandler implements the reqresp.Handler interface by delegating
// requests to another libp2p peer
type DelegatedHandler struct {
	host     host.Host
	cfg      *reqresp.Config
	delegate peer.ID
	logger   *slog.Logger

	// Status and metadata management
	statusMu sync.RWMutex
	status   *pb.Status

	metaDataMu sync.RWMutex
	metaData   *pb.MetaDataV1

	// Rate limiting
	statusLimiter *rate.Limiter
}

// NewDelegatedHandler creates a new delegated handler
func NewDelegatedHandler(h host.Host, cfg *reqresp.Config, delegate peer.ID, logger *slog.Logger) (*DelegatedHandler, error) {
	if h == nil {
		return nil, errors.New("host is required")
	}
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	if delegate == "" {
		return nil, errors.New("delegate peer ID is required")
	}

	return &DelegatedHandler{
		host:          h,
		cfg:           cfg,
		delegate:      delegate,
		logger:        logger.With("component", "delegated_handler"),
		statusLimiter: rate.NewLimiter(5, 10), // 5 per second, burst 10
	}, nil
}

// Start starts the handler
func (h *DelegatedHandler) Start(ctx context.Context) error {
	h.logger.Info("Starting delegated handler", "delegate", h.delegate.String())
	return nil
}

// Stop stops the handler
func (h *DelegatedHandler) Stop() error {
	h.logger.Info("Stopping delegated handler")
	return nil
}

// SetStatus sets the local status
func (h *DelegatedHandler) SetStatus(status *pb.Status) {
	h.statusMu.Lock()
	defer h.statusMu.Unlock()
	h.status = status
}

// GetStatus gets the local status
func (h *DelegatedHandler) GetStatus() *pb.Status {
	h.statusMu.RLock()
	defer h.statusMu.RUnlock()
	return h.status
}

// SetMetaData sets the local metadata
func (h *DelegatedHandler) SetMetaData(metadata *pb.MetaDataV1) {
	h.metaDataMu.Lock()
	defer h.metaDataMu.Unlock()
	h.metaData = metadata
}

// GetMetaData gets the local metadata
func (h *DelegatedHandler) GetMetaData() *pb.MetaDataV1 {
	h.metaDataMu.RLock()
	defer h.metaDataMu.RUnlock()
	return h.metaData
}

// Ping handles ping requests
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

	// Write pong response
	if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
		return fmt.Errorf("failed to write response code: %w", err)
	}

	if _, err := h.cfg.Encoder.EncodeWithMaxLength(stream, &seqNum); err != nil {
		return fmt.Errorf("failed to encode pong: %w", err)
	}

	return nil
}

// Goodbye handles goodbye requests
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

// Status handles status requests
func (h *DelegatedHandler) Status(ctx context.Context, stream network.Stream) error {
	defer stream.Close()

	// Rate limit status requests
	if !h.statusLimiter.Allow() {
		h.logger.Warn("Rate limiting status request", "peer", stream.Conn().RemotePeer())
		if _, err := stream.Write([]byte{reqresp.ResponseCodeRateLimited}); err != nil {
			return fmt.Errorf("failed to write rate limit response: %w", err)
		}
		return nil
	}

	// Check if request is from delegate - if so, respond with our status
	if stream.Conn().RemotePeer() == h.delegate {
		return h.handleLocalStatus(ctx, stream)
	}

	// Otherwise, delegate the request
	return h.delegateStream(ctx, stream, reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolStatus, 1))
}

// handleLocalStatus responds with local status
func (h *DelegatedHandler) handleLocalStatus(ctx context.Context, stream network.Stream) error {
	// Set deadlines
	if err := stream.SetDeadline(time.Now().Add(h.cfg.ReadTimeout)); err != nil {
		return fmt.Errorf("failed to set deadline: %w", err)
	}

	// Read their status
	var theirStatus pb.Status
	if err := h.cfg.Encoder.DecodeWithMaxLength(stream, &theirStatus); err != nil {
		return fmt.Errorf("failed to decode status: %w", err)
	}

	// Close read side
	if err := stream.CloseRead(); err != nil {
		h.logger.Warn("Failed to close read side", "err", err)
	}

	// Get our status
	ourStatus := h.GetStatus()
	if ourStatus == nil {
		return errors.New("status not set")
	}

	// Write response
	if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
		return fmt.Errorf("failed to write response code: %w", err)
	}

	if _, err := h.cfg.Encoder.EncodeWithMaxLength(stream, ourStatus); err != nil {
		return fmt.Errorf("failed to encode status: %w", err)
	}

	return nil
}

// MetaData handles metadata requests
func (h *DelegatedHandler) MetaData(ctx context.Context, stream network.Stream, version uint64) error {
	defer stream.Close()

	// Set deadlines
	if err := stream.SetDeadline(time.Now().Add(h.cfg.ReadTimeout)); err != nil {
		return fmt.Errorf("failed to set deadline: %w", err)
	}

	// No request body for metadata
	if err := stream.CloseRead(); err != nil {
		h.logger.Warn("Failed to close read side", "err", err)
	}

	// Get our metadata
	metadata := h.GetMetaData()
	if metadata == nil {
		return errors.New("metadata not set")
	}

	// Write response
	if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
		return fmt.Errorf("failed to write response code: %w", err)
	}

	// For V2, we might need to convert metadata format
	// For now, just send V1 metadata
	if _, err := h.cfg.Encoder.EncodeWithMaxLength(stream, metadata); err != nil {
		return fmt.Errorf("failed to encode metadata: %w", err)
	}

	return nil
}

// BlocksByRange handles blocks by range requests by delegating
func (h *DelegatedHandler) BlocksByRange(ctx context.Context, stream network.Stream) error {
	return h.delegateStream(ctx, stream, reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolBeaconBlocks, 2))
}

// BlocksByRoot handles blocks by root requests by delegating
func (h *DelegatedHandler) BlocksByRoot(ctx context.Context, stream network.Stream) error {
	return h.delegateStream(ctx, stream, reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolBlocksByRoot, 2))
}

// BlobSidecarsByRange handles blob sidecars by range requests by delegating
func (h *DelegatedHandler) BlobSidecarsByRange(ctx context.Context, stream network.Stream) error {
	return h.delegateStream(ctx, stream, reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolBlobSidecars, 1))
}

// BlobSidecarsByRoot handles blob sidecars by root requests by delegating
func (h *DelegatedHandler) BlobSidecarsByRoot(ctx context.Context, stream network.Stream) error {
	return h.delegateStream(ctx, stream, reqresp.GetProtocolID(h.cfg.ForkDigest, reqresp.ProtocolBlobsByRoot, 1))
}

// delegateStream forwards a stream to the delegate peer
func (h *DelegatedHandler) delegateStream(ctx context.Context, upstream network.Stream, protocolID protocol.ID) error {
	defer upstream.Close()

	// Create new stream to delegate
	downstream, err := h.host.NewStream(ctx, h.delegate, protocolID)
	if err != nil {
		h.logger.Error("Failed to create downstream stream", "err", err, "protocol", protocolID)
		// Send error response to upstream
		if _, writeErr := upstream.Write([]byte{reqresp.ResponseCodeServerError}); writeErr != nil {
			h.logger.Warn("Failed to write error response", "err", writeErr)
		}
		return fmt.Errorf("failed to create downstream stream: %w", err)
	}
	defer downstream.Close()

	// Copy request from upstream to downstream
	if _, err := io.Copy(downstream, upstream); err != nil {
		h.logger.Error("Failed to copy request", "err", err)
		return fmt.Errorf("failed to copy request: %w", err)
	}

	// Close write side of downstream
	if err := downstream.CloseWrite(); err != nil {
		h.logger.Warn("Failed to close downstream write", "err", err)
	}

	// Close read side of upstream
	if err := upstream.CloseRead(); err != nil {
		h.logger.Warn("Failed to close upstream read", "err", err)
	}

	// Set deadlines for response
	deadline := time.Now().Add(h.cfg.WriteTimeout)
	if err := upstream.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set upstream write deadline: %w", err)
	}
	if err := downstream.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("failed to set downstream read deadline: %w", err)
	}

	// Copy response from downstream to upstream
	if _, err := io.Copy(upstream, downstream); err != nil {
		h.logger.Error("Failed to copy response", "err", err)
		return fmt.Errorf("failed to copy response: %w", err)
	}

	return nil
}