package upstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	pb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	ssz "github.com/ferranbt/fastssz"

	"github.com/probe-lab/hermes/eth/reqresp"
)

// UpstreamHandler implements the reqresp.Handler interface by proxying
// requests through beacon API endpoints
type UpstreamHandler struct {
	host     host.Host
	cfg      *reqresp.Config
	beaconURL string
	logger   *slog.Logger

	// Status and metadata management
	statusMu sync.RWMutex
	status   *pb.Status

	metaDataMu sync.RWMutex
	metaData   *pb.MetaDataV1

	// Status syncer
	statusSyncer *StatusSyncer

	// Beacon API client
	beaconClient *BeaconClient
}

// NewUpstreamHandler creates a new upstream handler
func NewUpstreamHandler(h host.Host, cfg *reqresp.Config, beaconURL string, logger *slog.Logger) (*UpstreamHandler, error) {
	if h == nil {
		return nil, errors.New("host is required")
	}
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	if beaconURL == "" {
		return nil, errors.New("beacon API URL is required")
	}

	handler := &UpstreamHandler{
		host:      h,
		cfg:       cfg,
		beaconURL: beaconURL,
		logger:    logger.With("component", "upstream_handler"),
	}

	// Create beacon API client
	beaconClient, err := NewBeaconClient(beaconURL, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create beacon client: %w", err)
	}
	handler.beaconClient = beaconClient

	// Create status syncer
	handler.statusSyncer = NewStatusSyncer(beaconClient, logger)

	return handler, nil
}

// Start starts the handler
func (h *UpstreamHandler) Start(ctx context.Context) error {
	h.logger.Info("Starting upstream handler", "beacon_url", h.beaconURL)
	
	// Start status syncer
	if err := h.statusSyncer.Start(ctx); err != nil {
		return fmt.Errorf("failed to start status syncer: %w", err)
	}

	// Subscribe to status updates
	go h.subscribeToStatusUpdates(ctx)

	return nil
}

// Stop stops the handler
func (h *UpstreamHandler) Stop() error {
	h.logger.Info("Stopping upstream handler")
	
	// Stop status syncer
	if err := h.statusSyncer.Stop(); err != nil {
		h.logger.Error("Failed to stop status syncer", "err", err)
	}

	return nil
}

// subscribeToStatusUpdates listens for status updates from the syncer
func (h *UpstreamHandler) subscribeToStatusUpdates(ctx context.Context) {
	updates := h.statusSyncer.Subscribe()
	for {
		select {
		case <-ctx.Done():
			return
		case status := <-updates:
			h.SetStatus(status)
		}
	}
}

// SetStatus sets the local status
func (h *UpstreamHandler) SetStatus(status *pb.Status) {
	h.statusMu.Lock()
	defer h.statusMu.Unlock()
	h.status = status
}

// GetStatus gets the local status
func (h *UpstreamHandler) GetStatus() *pb.Status {
	h.statusMu.RLock()
	defer h.statusMu.RUnlock()
	return h.status
}

// SetMetaData sets the local metadata
func (h *UpstreamHandler) SetMetaData(metadata *pb.MetaDataV1) {
	h.metaDataMu.Lock()
	defer h.metaDataMu.Unlock()
	h.metaData = metadata
}

// GetMetaData gets the local metadata
func (h *UpstreamHandler) GetMetaData() *pb.MetaDataV1 {
	h.metaDataMu.RLock()
	defer h.metaDataMu.RUnlock()
	return h.metaData
}

// Ping handles ping requests - responds with metadata sequence number
func (h *UpstreamHandler) Ping(ctx context.Context, stream network.Stream) error {
	defer stream.Close()

	// Read ping sequence number
	req := primitives.SSZUint64(0)
	if err := h.readRequest(ctx, stream, &req); err != nil {
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
	if err := h.writeResponse(ctx, stream, &seqNum); err != nil {
		return fmt.Errorf("write pong response: %w", err)
	}

	return nil
}

// Goodbye handles goodbye requests - just logs and closes
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

// Status handles status requests
func (h *UpstreamHandler) Status(ctx context.Context, stream network.Stream) error {
	defer stream.Close()

	// Read their status
	var theirStatus pb.Status
	if err := h.readRequest(ctx, stream, &theirStatus); err != nil {
		return fmt.Errorf("read status request: %w", err)
	}

	// Get our status from syncer
	ourStatus := h.GetStatus()
	if ourStatus == nil {
		return errors.New("status not available")
	}

	// Set fork digest
	ourStatus.ForkDigest = h.cfg.ForkDigest[:]

	// Write our status
	if err := h.writeResponse(ctx, stream, ourStatus); err != nil {
		return fmt.Errorf("write status response: %w", err)
	}

	return nil
}

// MetaData handles metadata requests
func (h *UpstreamHandler) MetaData(ctx context.Context, stream network.Stream, version uint64) error {
	defer stream.Close()

	// No request body for metadata
	if err := stream.CloseRead(); err != nil {
		h.logger.Warn("Failed to close read side", "err", err)
	}

	// Get our metadata
	metadata := h.GetMetaData()
	if metadata == nil {
		return errors.New("metadata not set")
	}

	// Write response based on version
	if version == 1 {
		if err := h.writeResponse(ctx, stream, metadata); err != nil {
			return fmt.Errorf("write metadata v1 response: %w", err)
		}
	} else if version == 2 {
		// For V2, convert to V2 format if needed
		// For now, just send V1 format
		if err := h.writeResponse(ctx, stream, metadata); err != nil {
			return fmt.Errorf("write metadata v2 response: %w", err)
		}
	} else {
		return fmt.Errorf("unsupported metadata version: %d", version)
	}

	return nil
}

// BlocksByRange handles blocks by range requests
func (h *UpstreamHandler) BlocksByRange(ctx context.Context, stream network.Stream) error {
	defer stream.Close()
	return h.handleBlocksByRange(ctx, stream)
}

// BlocksByRoot handles blocks by root requests
func (h *UpstreamHandler) BlocksByRoot(ctx context.Context, stream network.Stream) error {
	defer stream.Close()
	return h.handleBlocksByRoot(ctx, stream)
}

// BlobSidecarsByRange handles blob sidecars by range requests
func (h *UpstreamHandler) BlobSidecarsByRange(ctx context.Context, stream network.Stream) error {
	defer stream.Close()
	return h.handleBlobSidecarsByRange(ctx, stream)
}

// BlobSidecarsByRoot handles blob sidecars by root requests
func (h *UpstreamHandler) BlobSidecarsByRoot(ctx context.Context, stream network.Stream) error {
	defer stream.Close()
	return h.handleBlobSidecarsByRoot(ctx, stream)
}

// Helper methods for reading/writing streams

// readRequest reads a request from a stream
func (h *UpstreamHandler) readRequest(ctx context.Context, stream network.Stream, data ssz.Unmarshaler) error {
	return reqresp.ReadRequest(ctx, stream, h.cfg.Encoder, data, h.cfg.ReadTimeout)
}

// writeResponse writes a response to a stream
func (h *UpstreamHandler) writeResponse(ctx context.Context, stream network.Stream, data ssz.Marshaler) error {
	return reqresp.WriteResponse(ctx, stream, h.cfg.Encoder, data, h.cfg.WriteTimeout)
}