package reqresp

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/OffchainLabs/prysm/v6/beacon-chain/p2p/encoder"
	pb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/time/rate"

	hermeshost "github.com/probe-lab/hermes/host"
)

// Config holds the configuration for the req/resp handler
type Config struct {
	ForkDigest    [4]byte
	Encoder       encoder.NetworkEncoding
	DataStream    hermeshost.DataStream
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	SubnetConfigs map[string]*SubnetConfig
	Tracer        trace.Tracer
	Meter         metric.Meter
}

// SubnetConfig holds configuration for attestation subnets
type SubnetConfig struct {
	Name                string
	AttestationSubnets  bitfield.Bitvector64
	SyncSubnets         bitfield.Bitvector4
	SubnetsPerNode      uint64
	NodeID              int
}

// Mode defines the handling mode for req/resp operations
type Mode string

const (
	// ModeDelegated forwards streams to another libp2p peer
	ModeDelegated Mode = "delegated"
	// ModeUpstream proxies requests through beacon API endpoints
	ModeUpstream Mode = "upstream"
)

// HandlerConfig holds configuration specific to the handler implementation
type HandlerConfig struct {
	Mode           Mode
	DelegatePeerID peer.ID      // For delegated mode
	BeaconAPIURL   string       // For upstream mode
}

// Handler defines the interface for req/resp protocol handlers
type Handler interface {
	// Protocol handlers
	Ping(ctx context.Context, stream network.Stream) error
	Goodbye(ctx context.Context, stream network.Stream) error
	Status(ctx context.Context, stream network.Stream) error
	MetaData(ctx context.Context, stream network.Stream, version uint64) error
	BlocksByRange(ctx context.Context, stream network.Stream) error
	BlocksByRoot(ctx context.Context, stream network.Stream) error
	BlobSidecarsByRange(ctx context.Context, stream network.Stream) error
	BlobSidecarsByRoot(ctx context.Context, stream network.Stream) error

	// Status and metadata management
	SetStatus(status *pb.Status)
	GetStatus() *pb.Status
	SetMetaData(metadata *pb.MetaDataV1)
	GetMetaData() *pb.MetaDataV1

	// Lifecycle
	Start(ctx context.Context) error
	Stop() error
}

// ContextStreamHandler represents a stream handler function with context
type ContextStreamHandler func(context.Context, network.Stream) (map[string]any, error)

// StreamMetrics holds metrics for stream handling
type StreamMetrics struct {
	RequestCounter   metric.Int64Counter
	LatencyHistogram metric.Float64Histogram
}

// StatusLimiter provides rate limiting for status requests
type StatusLimiter struct {
	limiter *rate.Limiter
}

// NewStatusLimiter creates a new status request rate limiter
func NewStatusLimiter() *StatusLimiter {
	// Allow 5 status requests per second with burst of 10
	return &StatusLimiter{
		limiter: rate.NewLimiter(5, 10),
	}
}

// Allow checks if a status request should be allowed
func (s *StatusLimiter) Allow() bool {
	return s.limiter.Allow()
}