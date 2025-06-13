package reqresp

import (
	"context"
	"errors"
	"fmt"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// Protocol IDs for req/resp
const (
	ProtocolPrefix = "/eth2/beacon_chain/req"
	
	// Protocol suffixes
	SuffixSSZSnappy = "ssz_snappy"
	
	// Protocol names
	ProtocolPing          = "ping"
	ProtocolGoodbye       = "goodbye"
	ProtocolStatus        = "status"
	ProtocolMetadata      = "metadata"
	ProtocolBeaconBlocks  = "beacon_blocks_by_range"
	ProtocolBlocksByRoot  = "beacon_blocks_by_root"
	ProtocolBlobSidecars  = "blob_sidecars_by_range"
	ProtocolBlobsByRoot   = "blob_sidecars_by_root"
)

// Error types
var (
	ErrInvalidRequest     = errors.New("invalid request")
	ErrResourceUnavailable = errors.New("resource unavailable")
	ErrServerError        = errors.New("server error")
	ErrRateLimited        = errors.New("rate limited")
	ErrIODeadline         = errors.New("i/o deadline exceeded")
)

// Manager manages req/resp protocol handlers
type Manager struct {
	host      host.Host
	handler   Handler
	cfg       *Config
	protocols map[protocol.ID]ContextStreamHandler
	metrics   *StreamMetrics
}

// NewManager creates a new req/resp manager
func NewManager(h host.Host, handler Handler, cfg *Config) (*Manager, error) {
	if h == nil {
		return nil, errors.New("host is required")
	}
	if handler == nil {
		return nil, errors.New("handler is required")
	}
	if cfg == nil {
		return nil, errors.New("config is required")
	}

	m := &Manager{
		host:      h,
		handler:   handler,
		cfg:       cfg,
		protocols: make(map[protocol.ID]ContextStreamHandler),
	}

	// Initialize metrics
	if cfg.Meter != nil {
		requestCounter, err := cfg.Meter.Int64Counter("hermes_eth_reqresp_requests_total",
			metric.WithDescription("Total number of req/resp requests"),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create request counter: %w", err)
		}

		latencyHistogram, err := cfg.Meter.Float64Histogram("hermes_eth_reqresp_latency_seconds",
			metric.WithDescription("Latency of req/resp requests in seconds"),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create latency histogram: %w", err)
		}

		m.metrics = &StreamMetrics{
			RequestCounter:   requestCounter,
			LatencyHistogram: latencyHistogram,
		}
	}

	return m, nil
}

// RegisterHandlers registers all req/resp protocol handlers
func (m *Manager) RegisterHandlers() error {
	// Validate status and metadata are set
	if m.handler.GetStatus() == nil {
		return errors.New("status must be set before registering handlers")
	}
	if m.handler.GetMetaData() == nil {
		return errors.New("metadata must be set before registering handlers")
	}

	// Build protocol mappings
	forkDigest := m.cfg.ForkDigest
	
	protocols := map[string]ContextStreamHandler{
		buildProtocolID(forkDigest, ProtocolPing, 1):           m.wrapHandler("ping", m.handler.Ping),
		buildProtocolID(forkDigest, ProtocolGoodbye, 1):        m.wrapHandler("goodbye", m.handler.Goodbye),
		buildProtocolID(forkDigest, ProtocolStatus, 1):         m.wrapHandler("status", m.handler.Status),
		buildProtocolID(forkDigest, ProtocolMetadata, 1):       m.wrapHandler("metadata_v1", func(ctx context.Context, s network.Stream) error { return m.handler.MetaData(ctx, s, 1) }),
		buildProtocolID(forkDigest, ProtocolMetadata, 2):       m.wrapHandler("metadata_v2", func(ctx context.Context, s network.Stream) error { return m.handler.MetaData(ctx, s, 2) }),
		buildProtocolID(forkDigest, ProtocolBeaconBlocks, 2):   m.wrapHandler("blocks_by_range", m.handler.BlocksByRange),
		buildProtocolID(forkDigest, ProtocolBlocksByRoot, 2):   m.wrapHandler("blocks_by_root", m.handler.BlocksByRoot),
		buildProtocolID(forkDigest, ProtocolBlobSidecars, 1):   m.wrapHandler("blobs_by_range", m.handler.BlobSidecarsByRange),
		buildProtocolID(forkDigest, ProtocolBlobsByRoot, 1):    m.wrapHandler("blobs_by_root", m.handler.BlobSidecarsByRoot),
	}

	// Register handlers with host
	for protoID, handler := range protocols {
		m.protocols[protocol.ID(protoID)] = handler
		m.host.SetStreamHandler(protocol.ID(protoID), m.makeStreamHandler(handler))
	}

	return nil
}

// wrapHandler wraps a handler with telemetry and error handling
func (m *Manager) wrapHandler(name string, handler func(context.Context, network.Stream) error) ContextStreamHandler {
	return func(ctx context.Context, stream network.Stream) (map[string]any, error) {
		// Add telemetry attributes
		attrs := map[string]any{
			"protocol": name,
			"peer":     stream.Conn().RemotePeer().String(),
		}

		// Execute handler
		err := handler(ctx, stream)
		if err != nil {
			attrs["error"] = err.Error()
		}

		return attrs, err
	}
}

// makeStreamHandler creates a libp2p stream handler from a context stream handler
func (m *Manager) makeStreamHandler(handler ContextStreamHandler) network.StreamHandler {
	return func(stream network.Stream) {
		ctx := context.Background()
		
		// Start span if tracer is available
		if m.cfg.Tracer != nil {
			var span trace.Span
			ctx, span = m.cfg.Tracer.Start(ctx, "reqresp.handle",
				trace.WithAttributes(
					attribute.String("protocol", string(stream.Protocol())),
					attribute.String("peer", stream.Conn().RemotePeer().String()),
				),
			)
			defer span.End()
		}

		// Handle the stream
		attrs, err := handler(ctx, stream)
		
		// Record metrics
		if m.metrics != nil && m.metrics.RequestCounter != nil {
			labels := []attribute.KeyValue{
				attribute.String("protocol", string(stream.Protocol())),
			}
			if err != nil {
				labels = append(labels, attribute.String("status", "error"))
			} else {
				labels = append(labels, attribute.String("status", "success"))
			}
			m.metrics.RequestCounter.Add(ctx, 1, metric.WithAttributes(labels...))
		}

		// Record to data stream if available
		if m.cfg.DataStream != nil && attrs != nil {
			// Add standard attributes
			attrs["protocol"] = string(stream.Protocol())
			attrs["peer"] = stream.Conn().RemotePeer().String()
			if err != nil {
				attrs["error"] = err.Error()
			}
			// TODO: Convert attrs map to TraceEvent and call PutRecord
			// For now, we'll skip data stream recording
		}

		// Ensure stream is closed
		stream.Close()
	}
}

// UnregisterHandlers removes all registered handlers
func (m *Manager) UnregisterHandlers() {
	for protoID := range m.protocols {
		m.host.RemoveStreamHandler(protoID)
	}
	m.protocols = make(map[protocol.ID]ContextStreamHandler)
}

// Start starts the manager and underlying handler
func (m *Manager) Start(ctx context.Context) error {
	return m.handler.Start(ctx)
}

// Stop stops the manager and underlying handler
func (m *Manager) Stop() error {
	m.UnregisterHandlers()
	return m.handler.Stop()
}

// buildProtocolID constructs a protocol ID from components
func buildProtocolID(forkDigest [4]byte, protocolName string, version uint64) string {
	return fmt.Sprintf("%s/%s/%d/%s", ProtocolPrefix, protocolName, version, SuffixSSZSnappy)
}

// GetProtocolID returns the full protocol ID for a given protocol
func GetProtocolID(forkDigest [4]byte, protocolName string, version uint64) protocol.ID {
	return protocol.ID(buildProtocolID(forkDigest, protocolName, version))
}