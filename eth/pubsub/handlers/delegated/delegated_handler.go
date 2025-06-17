package delegated

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/probe-lab/hermes/eth/pubsub/common"
)

// DelegatedConfig holds configuration for DelegatedHandler
type DelegatedConfig struct {
	Logger          *logrus.Logger
	CacheSize       int
	MetricsRegistry prometheus.Registerer
	ForkVersion     [4]byte
}

// DelegatedHandler delegates message handling to an external Prysm node
type DelegatedHandler struct {
	config       *DelegatedConfig
	logger       *logrus.Logger
	seenMessages *lru.Cache[string, time.Time]
	metrics      atomic.Value
	forkVersion  common.ForkVersion
	validators   map[common.MessageType]MessageValidator

	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.RWMutex
}

// NewDelegatedHandler creates a new delegated handler
func NewDelegatedHandler(config *DelegatedConfig) (*DelegatedHandler, error) {
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

	h := &DelegatedHandler{
		config:       config,
		logger:       config.Logger,
		seenMessages: seenCache,
		forkVersion:  common.ForkVersion(config.ForkVersion),
		validators:   make(map[common.MessageType]MessageValidator),
	}

	// Initialize validators
	h.initializeValidators()

	// Initialize base metrics
	metrics := &common.BaseMetrics{}
	h.metrics.Store(metrics)

	return h, nil
}

// Start starts the delegated handler
func (h *DelegatedHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.ctx != nil {
		return nil // Already started
	}

	h.ctx, h.cancel = context.WithCancel(ctx)
	h.logger.Info("Started delegated handler")

	return nil
}

// Stop stops the delegated handler
func (h *DelegatedHandler) Stop() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.cancel != nil {
		h.cancel()
		h.ctx = nil
		h.cancel = nil
	}

	h.logger.Info("Stopped delegated handler")
	return nil
}

// GetMetrics returns the handler metrics
func (h *DelegatedHandler) GetMetrics() common.ValidatorMetrics {
	if m := h.metrics.Load(); m != nil {
		return m.(common.ValidatorMetrics)
	}
	return nil
}

// initializeValidators initializes all message validators
func (h *DelegatedHandler) initializeValidators() {
	h.validators[common.MessageBeaconBlock] = NewBeaconBlockValidator(h)
	h.validators[common.MessageAttestation] = NewAttestationValidator(h)
	h.validators[common.MessageAggregateAndProof] = NewAggregateAndProofValidator(h)
	h.validators[common.MessageVoluntaryExit] = NewVoluntaryExitValidator(h)
	h.validators[common.MessageProposerSlashing] = NewProposerSlashingValidator(h)
	h.validators[common.MessageAttesterSlashing] = NewAttesterSlashingValidator(h)
	h.validators[common.MessageSyncCommittee] = NewSyncCommitteeMessageValidator(h)
	h.validators[common.MessageContributionAndProof] = NewContributionAndProofValidator(h)
	h.validators[common.MessageBlsToExecutionChange] = NewBlsToExecutionChangeValidator(h)
	h.validators[common.MessageBlobSidecar] = NewBlobSidecarValidator(h)
}

// validateWithType performs validation for a specific message type with deduplication
func (h *DelegatedHandler) validateWithType(ctx context.Context, msg *pubsub.Message, messageType common.MessageType) pubsub.ValidationResult {
	start := time.Now()

	// Record metrics
	defer func() {
		if m := h.GetMetrics(); m != nil {
			m.RecordValidationDuration(messageType, time.Since(start).Seconds())
		}
	}()

	// Check message deduplication
	msgID := string(msg.ID)
	if _, seen := h.seenMessages.Get(msgID); seen {
		h.recordResult(messageType, "duplicate")
		return pubsub.ValidationIgnore
	}

	// Get the validator for this message type
	validator, exists := h.validators[messageType]
	if !exists {
		h.logger.WithField("type", messageType).Warn("No validator for message type")
		h.recordResult(messageType, "ignore")
		return pubsub.ValidationIgnore
	}

	// Call the unified Handle method
	_, err := validator.Handle(ctx, msg.Data, msg.GetTopic())
	if err != nil {
		h.logger.WithField("type", messageType).WithError(err).Debug("Message validation failed")
		h.recordResult(messageType, "reject")
		return pubsub.ValidationReject
	}

	// Mark as seen after successful validation
	h.seenMessages.Add(msgID, time.Now())

	// In delegated mode, we accept all messages that decode successfully
	h.recordResult(messageType, "accept")
	return pubsub.ValidationAccept
}

// ValidateMessage maintains backward compatibility
func (h *DelegatedHandler) ValidateMessage(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	messageType := common.ClassifyMessage(msg.GetTopic())
	if messageType == common.UnknownMessage {
		h.logger.WithField("topic", msg.Topic).Warn("Unknown message type")
		return pubsub.ValidationIgnore
	}
	return h.validateWithType(ctx, msg, messageType)
}

// Typed validation methods

func (h *DelegatedHandler) ValidateBeaconBlock(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return h.validateWithType(ctx, msg, common.MessageBeaconBlock)
}

func (h *DelegatedHandler) ValidateAggregateAndProof(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return h.validateWithType(ctx, msg, common.MessageAggregateAndProof)
}

func (h *DelegatedHandler) ValidateAttestation(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return h.validateWithType(ctx, msg, common.MessageAttestation)
}

func (h *DelegatedHandler) ValidateVoluntaryExit(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return h.validateWithType(ctx, msg, common.MessageVoluntaryExit)
}

func (h *DelegatedHandler) ValidateProposerSlashing(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return h.validateWithType(ctx, msg, common.MessageProposerSlashing)
}

func (h *DelegatedHandler) ValidateAttesterSlashing(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return h.validateWithType(ctx, msg, common.MessageAttesterSlashing)
}

func (h *DelegatedHandler) ValidateSyncCommitteeMessage(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return h.validateWithType(ctx, msg, common.MessageSyncCommittee)
}

func (h *DelegatedHandler) ValidateContributionAndProof(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return h.validateWithType(ctx, msg, common.MessageContributionAndProof)
}

func (h *DelegatedHandler) ValidateBlsToExecutionChange(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return h.validateWithType(ctx, msg, common.MessageBlsToExecutionChange)
}

func (h *DelegatedHandler) ValidateBlobSidecar(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return h.validateWithType(ctx, msg, common.MessageBlobSidecar)
}


func (h *DelegatedHandler) recordResult(messageType common.MessageType, result string) {
	if m := h.GetMetrics(); m != nil {
		m.RecordValidation(messageType, result)
	}
}

// Unified Handle methods for each message type

func (h *DelegatedHandler) HandleBeaconBlock(ctx context.Context, msg *pubsub.Message) (interface{}, error) {
	validator := h.validators[common.MessageBeaconBlock]
	if validator == nil {
		return nil, fmt.Errorf("no validator for beacon block")
	}
	return validator.Handle(ctx, msg.Data, msg.GetTopic())
}

func (h *DelegatedHandler) HandleAttestation(ctx context.Context, msg *pubsub.Message) (interface{}, error) {
	validator := h.validators[common.MessageAttestation]
	if validator == nil {
		return nil, fmt.Errorf("no validator for attestation")
	}
	return validator.Handle(ctx, msg.Data, msg.GetTopic())
}

func (h *DelegatedHandler) HandleAggregateAndProof(ctx context.Context, msg *pubsub.Message) (interface{}, error) {
	validator := h.validators[common.MessageAggregateAndProof]
	if validator == nil {
		return nil, fmt.Errorf("no validator for aggregate and proof")
	}
	return validator.Handle(ctx, msg.Data, msg.GetTopic())
}

func (h *DelegatedHandler) HandleVoluntaryExit(ctx context.Context, msg *pubsub.Message) (interface{}, error) {
	validator := h.validators[common.MessageVoluntaryExit]
	if validator == nil {
		return nil, fmt.Errorf("no validator for voluntary exit")
	}
	return validator.Handle(ctx, msg.Data, msg.GetTopic())
}

func (h *DelegatedHandler) HandleAttesterSlashing(ctx context.Context, msg *pubsub.Message) (interface{}, error) {
	validator := h.validators[common.MessageAttesterSlashing]
	if validator == nil {
		return nil, fmt.Errorf("no validator for attester slashing")
	}
	return validator.Handle(ctx, msg.Data, msg.GetTopic())
}

func (h *DelegatedHandler) HandleProposerSlashing(ctx context.Context, msg *pubsub.Message) (interface{}, error) {
	validator := h.validators[common.MessageProposerSlashing]
	if validator == nil {
		return nil, fmt.Errorf("no validator for proposer slashing")
	}
	return validator.Handle(ctx, msg.Data, msg.GetTopic())
}

func (h *DelegatedHandler) HandleSyncCommitteeMessage(ctx context.Context, msg *pubsub.Message) (interface{}, error) {
	validator := h.validators[common.MessageSyncCommittee]
	if validator == nil {
		return nil, fmt.Errorf("no validator for sync committee message")
	}
	return validator.Handle(ctx, msg.Data, msg.GetTopic())
}

func (h *DelegatedHandler) HandleContributionAndProof(ctx context.Context, msg *pubsub.Message) (interface{}, error) {
	validator := h.validators[common.MessageContributionAndProof]
	if validator == nil {
		return nil, fmt.Errorf("no validator for contribution and proof")
	}
	return validator.Handle(ctx, msg.Data, msg.GetTopic())
}

func (h *DelegatedHandler) HandleBlsToExecutionChange(ctx context.Context, msg *pubsub.Message) (interface{}, error) {
	validator := h.validators[common.MessageBlsToExecutionChange]
	if validator == nil {
		return nil, fmt.Errorf("no validator for BLS to execution change")
	}
	return validator.Handle(ctx, msg.Data, msg.GetTopic())
}

func (h *DelegatedHandler) HandleBlobSidecar(ctx context.Context, msg *pubsub.Message) (interface{}, error) {
	validator := h.validators[common.MessageBlobSidecar]
	if validator == nil {
		return nil, fmt.Errorf("no validator for blob sidecar")
	}
	return validator.Handle(ctx, msg.Data, msg.GetTopic())
}