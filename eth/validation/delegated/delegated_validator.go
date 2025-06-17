package delegated

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	ethtypes "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	lru "github.com/hashicorp/golang-lru/v2"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/prometheus/client_golang/prometheus"
	ssz "github.com/prysmaticlabs/fastssz"
	"github.com/sirupsen/logrus"

	"github.com/probe-lab/hermes/eth/validation/common"
	"github.com/probe-lab/hermes/host"
	"github.com/probe-lab/hermes/tele"
)

// DelegatedConfig holds configuration for DelegatedValidator
type DelegatedConfig struct {
	Logger             *logrus.Logger
	CacheSize          int
	MetricsRegistry    prometheus.Registerer
	DataStream         host.DataStream
	DataStreamRenderer host.DataStreamRenderer
	ForkVersion        [4]byte
}

// DelegatedValidator delegates validation to an external Prysm node
type DelegatedValidator struct {
	config       *DelegatedConfig
	logger       *logrus.Logger
	seenMessages *lru.Cache[string, time.Time]
	metrics      atomic.Value
	dataStream   host.DataStream
	dsr          host.DataStreamRenderer
	forkVersion  common.ForkVersion

	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.RWMutex
}

// NewDelegatedValidator creates a new delegated validator
func NewDelegatedValidator(config *DelegatedConfig) (*DelegatedValidator, error) {
	if config.Logger == nil {
		config.Logger = logrus.New()
	}

	cacheSize := config.CacheSize
	if cacheSize == 0 {
		cacheSize = common.DefaultCacheSize
	}

	seenCache, err := lru.New[string, time.Time](cacheSize)
	if err != nil {
		return nil, err
	}

	v := &DelegatedValidator{
		config:       config,
		logger:       config.Logger,
		seenMessages: seenCache,
		dataStream:   config.DataStream,
		dsr:          config.DataStreamRenderer,
		forkVersion:  common.ForkVersion(config.ForkVersion),
	}

	// Initialize base metrics
	metrics := &common.BaseMetrics{}
	v.metrics.Store(metrics)

	return v, nil
}

// Start starts the delegated validator
func (v *DelegatedValidator) Start(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.ctx != nil {
		return nil // Already started
	}

	v.ctx, v.cancel = context.WithCancel(ctx)
	v.logger.Info("Started delegated validator")

	return nil
}

// Stop stops the delegated validator
func (v *DelegatedValidator) Stop() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.cancel != nil {
		v.cancel()
		v.ctx = nil
		v.cancel = nil
	}

	v.logger.Info("Stopped delegated validator")
	return nil
}

// GetMetrics returns the validator metrics
func (v *DelegatedValidator) GetMetrics() common.ValidatorMetrics {
	if m := v.metrics.Load(); m != nil {
		return m.(common.ValidatorMetrics)
	}
	return nil
}

// ValidateMessage validates a gossipsub message using Prysm
func (v *DelegatedValidator) ValidateMessage(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	start := time.Now()
	messageType := common.ClassifyMessage(msg.GetTopic())

	// Record metrics
	defer func() {
		if m := v.GetMetrics(); m != nil {
			m.RecordValidationDuration(messageType, time.Since(start).Seconds())
		}
	}()

	// Check message deduplication
	msgID := string(msg.ID)
	if _, seen := v.seenMessages.Get(msgID); seen {
		v.recordResult(messageType, "duplicate")
		return pubsub.ValidationIgnore
	}
	v.seenMessages.Add(msgID, time.Now())

	// Validate based on message type
	var result pubsub.ValidationResult
	switch messageType {
	case common.MessageBeaconBlock:
		result = v.validateBeaconBlock(ctx, msg)
	case common.MessageAggregateAndProof:
		result = v.validateAggregateAndProof(ctx, msg)
	case common.MessageVoluntaryExit:
		result = v.validateVoluntaryExit(ctx, msg)
	case common.MessageProposerSlashing:
		result = v.validateProposerSlashing(ctx, msg)
	case common.MessageAttesterSlashing:
		result = v.validateAttesterSlashing(ctx, msg)
	case common.MessageAttestation:
		result = v.validateAttestation(ctx, msg)
	case common.MessageContributionAndProof:
		result = v.validateSyncContribution(ctx, msg)
	case common.MessageSyncCommittee:
		result = v.validateSyncCommittee(ctx, msg)
	case common.MessageBlsToExecutionChange:
		result = v.validateBlsToExecutionChange(ctx, msg)
	case common.MessageBlobSidecar:
		result = v.validateBlobSidecar(ctx, msg)
	default:
		v.logger.WithField("topic", msg.Topic).Warn("Unknown message type")
		result = pubsub.ValidationIgnore
	}

	// Record validation result
	resultStr := "accept"
	switch result {
	case pubsub.ValidationReject:
		resultStr = "reject"
	case pubsub.ValidationIgnore:
		resultStr = "ignore"
	}
	v.recordResult(messageType, resultStr)

	return result
}

func (v *DelegatedValidator) validateBeaconBlock(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	// In delegated mode, we accept all messages and forward them
	var (
		err error
		evt = &host.TraceEvent{
			Type:      "HANDLE_MESSAGE",
			Topic:     msg.GetTopic(),
			PeerID:    msg.ReceivedFrom,
			Timestamp: time.Now(),
		}
		block ssz.Unmarshaler
	)

	switch v.forkVersion {
	case common.Phase0ForkVersion:
		block = &ethtypes.SignedBeaconBlock{}
	case common.AltairForkVersion:
		block = &ethtypes.SignedBeaconBlockAltair{}
	case common.BellatrixForkVersion:
		block = &ethtypes.SignedBeaconBlockBellatrix{}
	case common.CapellaForkVersion:
		block = &ethtypes.SignedBeaconBlockCapella{}
	case common.DenebForkVersion:
		block = &ethtypes.SignedBeaconBlockDeneb{}
	case common.ElectraForkVersion:
		block = &ethtypes.SignedBeaconBlockElectra{}
	default:
		slog.Warn("Unrecognized fork version", "fork", v.forkVersion.String())
		return pubsub.ValidationAccept
	}

	evt, err = v.dsr.RenderPayload(evt, msg, block)
	if err != nil {
		slog.Warn(
			"failed rendering topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
		return pubsub.ValidationAccept
	}

	if err := v.dataStream.PutRecord(ctx, evt); err != nil {
		slog.Warn(
			"failed putting topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
	}

	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) validateAggregateAndProof(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	// In delegated mode, we accept all messages and forward them
	var (
		err error
		evt = &host.TraceEvent{
			Type:      "HANDLE_MESSAGE",
			Topic:     msg.GetTopic(),
			PeerID:    msg.ReceivedFrom,
			Timestamp: time.Now(),
		}
	)

	switch v.forkVersion {
	case common.ElectraForkVersion:
		evt, err = v.dsr.RenderPayload(evt, msg, &ethtypes.SignedAggregateAttestationAndProofElectra{})
	default:
		evt, err = v.dsr.RenderPayload(evt, msg, &ethtypes.SignedAggregateAttestationAndProof{})
	}

	if err != nil {
		slog.Warn(
			"failed rendering topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
		return pubsub.ValidationAccept
	}

	if err := v.dataStream.PutRecord(ctx, evt); err != nil {
		slog.Warn(
			"failed putting topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
	}

	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) validateVoluntaryExit(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	// In delegated mode, we accept all messages and forward them
	var (
		err error
		evt = &host.TraceEvent{
			Type:      "HANDLE_MESSAGE",
			Topic:     msg.GetTopic(),
			PeerID:    msg.ReceivedFrom,
			Timestamp: time.Now(),
		}
	)

	evt, err = v.dsr.RenderPayload(evt, msg, &ethtypes.VoluntaryExit{})
	if err != nil {
		slog.Warn(
			"failed rendering topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
		return pubsub.ValidationAccept
	}

	if err := v.dataStream.PutRecord(ctx, evt); err != nil {
		slog.Warn(
			"failed putting topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
	}

	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) validateProposerSlashing(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	// In delegated mode, we accept all messages and forward them
	var (
		err error
		evt = &host.TraceEvent{
			Type:      "HANDLE_MESSAGE",
			Topic:     msg.GetTopic(),
			PeerID:    msg.ReceivedFrom,
			Timestamp: time.Now(),
		}
	)

	evt, err = v.dsr.RenderPayload(evt, msg, &ethtypes.ProposerSlashing{})
	if err != nil {
		slog.Warn(
			"failed rendering topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
		return pubsub.ValidationAccept
	}

	if err := v.dataStream.PutRecord(ctx, evt); err != nil {
		slog.Warn(
			"failed putting topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
	}

	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) validateAttesterSlashing(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	// In delegated mode, we accept all messages and forward them
	var (
		err error
		evt = &host.TraceEvent{
			Type:      "HANDLE_MESSAGE",
			Topic:     msg.GetTopic(),
			PeerID:    msg.ReceivedFrom,
			Timestamp: time.Now(),
		}
	)

	evt, err = v.dsr.RenderPayload(evt, msg, &ethtypes.AttesterSlashing{})
	if err != nil {
		slog.Warn(
			"failed rendering topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
		return pubsub.ValidationAccept
	}

	if err := v.dataStream.PutRecord(ctx, evt); err != nil {
		slog.Warn(
			"failed putting topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
	}

	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) validateAttestation(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	// In delegated mode, we accept all messages and forward them
	var (
		err error
		evt = &host.TraceEvent{
			Type:      "HANDLE_MESSAGE",
			Topic:     msg.GetTopic(),
			PeerID:    msg.ReceivedFrom,
			Timestamp: time.Now(),
		}
	)

	switch v.forkVersion {
	case common.ElectraForkVersion:
		evt, err = v.dsr.RenderPayload(evt, msg, &ethtypes.SingleAttestation{})
	default:
		evt, err = v.dsr.RenderPayload(evt, msg, &ethtypes.Attestation{})
	}

	if err != nil {
		slog.Warn(
			"failed rendering topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
		return pubsub.ValidationAccept
	}

	if err := v.dataStream.PutRecord(ctx, evt); err != nil {
		slog.Warn(
			"failed putting topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
	}

	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) validateSyncContribution(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	// In delegated mode, we accept all messages and forward them
	var (
		err error
		evt = &host.TraceEvent{
			Type:      "HANDLE_MESSAGE",
			Topic:     msg.GetTopic(),
			PeerID:    msg.ReceivedFrom,
			Timestamp: time.Now(),
		}
	)

	evt, err = v.dsr.RenderPayload(evt, msg, &ethtypes.SignedContributionAndProof{})
	if err != nil {
		slog.Warn(
			"failed rendering topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
		return pubsub.ValidationAccept
	}

	if err := v.dataStream.PutRecord(ctx, evt); err != nil {
		slog.Warn(
			"failed putting topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
	}

	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) validateSyncCommittee(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	// In delegated mode, we accept all messages and forward them
	var (
		err error
		evt = &host.TraceEvent{
			Type:      "HANDLE_MESSAGE",
			Topic:     msg.GetTopic(),
			PeerID:    msg.ReceivedFrom,
			Timestamp: time.Now(),
		}
	)

	//lint:ignore SA1019 gRPC API deprecated but still supported until v8 (2026)
	evt, err = v.dsr.RenderPayload(evt, msg, &ethtypes.SyncCommitteeMessage{})
	if err != nil {
		slog.Warn(
			"failed rendering topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
		return pubsub.ValidationAccept
	}

	if err := v.dataStream.PutRecord(ctx, evt); err != nil {
		slog.Warn(
			"failed putting topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
	}

	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) validateBlsToExecutionChange(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	// In delegated mode, we accept all messages and forward them
	var (
		err error
		evt = &host.TraceEvent{
			Type:      "HANDLE_MESSAGE",
			Topic:     msg.GetTopic(),
			PeerID:    msg.ReceivedFrom,
			Timestamp: time.Now(),
		}
	)

	evt, err = v.dsr.RenderPayload(evt, msg, &ethtypes.BLSToExecutionChange{})
	if err != nil {
		slog.Warn(
			"failed rendering topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
		return pubsub.ValidationAccept
	}

	if err := v.dataStream.PutRecord(ctx, evt); err != nil {
		slog.Warn(
			"failed putting topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
		)
	}

	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) validateBlobSidecar(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	// In delegated mode, we accept all messages and forward them
	var (
		err error
		evt = &host.TraceEvent{
			Type:      "HANDLE_MESSAGE",
			Topic:     msg.GetTopic(),
			PeerID:    msg.ReceivedFrom,
			Timestamp: time.Now(),
		}
	)

	switch v.forkVersion {
	case common.DenebForkVersion, common.ElectraForkVersion:
		blob := ethtypes.BlobSidecar{}
		evt, err = v.dsr.RenderPayload(evt, msg, &blob)
		if err != nil {
			slog.Warn(
				"failed rendering topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
			)
			return pubsub.ValidationAccept
		}

		if err := v.dataStream.PutRecord(ctx, evt); err != nil {
			slog.Warn(
				"failed putting topic handler event", "topic", msg.GetTopic(), "err", tele.LogAttrError(err),
			)
		}
	default:
		slog.Warn("Blob sidecar for unsupported fork version", "fork", v.forkVersion[:])
	}

	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) recordResult(messageType common.MessageType, result string) {
	if m := v.GetMetrics(); m != nil {
		m.RecordValidation(messageType, result)
	}
}
