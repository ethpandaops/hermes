package delegated

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	
	"github.com/probe-lab/hermes/eth/validation/common"
)

// DelegatedConfig holds configuration for DelegatedValidator
type DelegatedConfig struct {
	PrysmClient      *PrysmClient
	Logger           *logrus.Logger
	CacheSize        int
	MetricsRegistry  prometheus.Registerer
}

// DelegatedValidator delegates validation to an external Prysm node
type DelegatedValidator struct {
	config       *DelegatedConfig
	logger       *logrus.Logger
	prysmClient  *PrysmClient
	seenMessages *lru.Cache[string, time.Time]
	metrics      atomic.Value
	
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
		prysmClient:  config.PrysmClient,
		seenMessages: seenCache,
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
	case common.BeaconBlockMessage:
		result = v.validateBeaconBlock(ctx, msg)
	case common.BeaconAggregateAndProofMessage:
		result = v.validateAggregateAndProof(ctx, msg)
	case common.VoluntaryExitMessage:
		result = v.validateVoluntaryExit(ctx, msg)
	case common.ProposerSlashingMessage:
		result = v.validateProposerSlashing(ctx, msg)
	case common.AttesterSlashingMessage:
		result = v.validateAttesterSlashing(ctx, msg)
	case common.BeaconAttestationMessage:
		result = v.validateAttestation(ctx, msg)
	case common.SyncCommitteeContributionMessage:
		result = v.validateSyncContribution(ctx, msg)
	case common.SyncCommitteeMessage:
		result = v.validateSyncCommittee(ctx, msg)
	case common.BlsToExecutionChangeMessage:
		result = v.validateBlsToExecutionChange(ctx, msg)
	case common.BlobSidecarMessage:
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
	block := &ethpb.SignedBeaconBlock{}
	if err := block.UnmarshalSSZ(msg.Data); err != nil {
		v.logger.WithError(err).Debug("Failed to unmarshal beacon block")
		return pubsub.ValidationReject
	}
	
	// TODO: Implement proper Prysm client calls
	// For now, accept all valid blocks
	_ = block
	
	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) validateAggregateAndProof(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	aggregateAndProof := &ethpb.SignedAggregateAttestationAndProof{}
	if err := aggregateAndProof.UnmarshalSSZ(msg.Data); err != nil {
		v.logger.WithError(err).Debug("Failed to unmarshal aggregate and proof")
		return pubsub.ValidationReject
	}
	
	resp, err := v.prysmClient.client.SubmitSignedAggregateSelectionProof(ctx, &ethpb.SignedAggregateSubmitRequest{
		SignedAggregateAndProof: aggregateAndProof,
	})
	
	if err != nil {
		v.logger.WithError(err).Debug("Prysm rejected aggregate and proof")
		return pubsub.ValidationReject
	}
	
	// Check response
	if resp != nil {
		return pubsub.ValidationAccept
	}
	
	return pubsub.ValidationIgnore
}

func (v *DelegatedValidator) validateVoluntaryExit(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	exit := &ethpb.SignedVoluntaryExit{}
	if err := exit.UnmarshalSSZ(msg.Data); err != nil {
		v.logger.WithError(err).Debug("Failed to unmarshal voluntary exit")
		return pubsub.ValidationReject
	}
	
	resp, err := v.prysmClient.client.ProposeExit(ctx, exit)
	if err != nil {
		v.logger.WithError(err).Debug("Prysm rejected voluntary exit")
		return pubsub.ValidationReject
	}
	
	if resp != nil {
		return pubsub.ValidationAccept
	}
	
	return pubsub.ValidationIgnore
}

func (v *DelegatedValidator) validateProposerSlashing(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	slashing := &ethpb.ProposerSlashing{}
	if err := slashing.UnmarshalSSZ(msg.Data); err != nil {
		v.logger.WithError(err).Debug("Failed to unmarshal proposer slashing")
		return pubsub.ValidationReject
	}
	
	// Prysm doesn't have a direct proposer slashing submission method
	// Accept if it parses correctly
	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) validateAttesterSlashing(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	slashing := &ethpb.AttesterSlashing{}
	if err := slashing.UnmarshalSSZ(msg.Data); err != nil {
		v.logger.WithError(err).Debug("Failed to unmarshal attester slashing")
		return pubsub.ValidationReject
	}
	
	// Prysm doesn't have a direct attester slashing submission method
	// Accept if it parses correctly
	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) validateAttestation(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	att := &ethpb.Attestation{}
	if err := att.UnmarshalSSZ(msg.Data); err != nil {
		v.logger.WithError(err).Debug("Failed to unmarshal attestation")
		return pubsub.ValidationReject
	}
	
	resp, err := v.prysmClient.client.ProposeAttestation(ctx, att)
	if err != nil {
		v.logger.WithError(err).Debug("Prysm rejected attestation")
		return pubsub.ValidationReject
	}
	
	if resp != nil && resp.AttestationDataRoot != nil {
		return pubsub.ValidationAccept
	}
	
	return pubsub.ValidationIgnore
}

func (v *DelegatedValidator) validateSyncContribution(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	contribution := &ethpb.SignedContributionAndProof{}
	if err := contribution.UnmarshalSSZ(msg.Data); err != nil {
		v.logger.WithError(err).Debug("Failed to unmarshal sync contribution")
		return pubsub.ValidationReject
	}
	
	// Prysm doesn't have a direct sync contribution submission endpoint
	// We'll accept it if it parses correctly
	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) validateSyncCommittee(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	syncMsg := &ethpb.SyncCommitteeMessage{}
	if err := syncMsg.UnmarshalSSZ(msg.Data); err != nil {
		v.logger.WithError(err).Debug("Failed to unmarshal sync committee message")
		return pubsub.ValidationReject
	}
	
	// Submit sync committee message
	_, err := v.prysmClient.client.SubmitSyncMessage(ctx, syncMsg)
	if err != nil {
		v.logger.WithError(err).Debug("Prysm rejected sync committee message")
		return pubsub.ValidationReject
	}
	
	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) validateBlsToExecutionChange(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	change := &ethpb.SignedBLSToExecutionChange{}
	if err := change.UnmarshalSSZ(msg.Data); err != nil {
		v.logger.WithError(err).Debug("Failed to unmarshal BLS to execution change")
		return pubsub.ValidationReject
	}
	
	// Prysm v6 should have this endpoint
	// For now, accept if it parses correctly
	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) validateBlobSidecar(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	// Extract subnet from topic
	subnet, err := common.ExtractBlobSubnet(msg.GetTopic())
	if err != nil {
		v.logger.WithError(err).Debug("Failed to extract blob subnet")
		return pubsub.ValidationReject
	}
	
	sidecar := &ethpb.BlobSidecar{}
	if err := sidecar.UnmarshalSSZ(msg.Data); err != nil {
		v.logger.WithError(err).Debug("Failed to unmarshal blob sidecar")
		return pubsub.ValidationReject
	}
	
	// Verify blob index matches subnet
	if uint64(sidecar.Index) != subnet {
		v.logger.Debug("Blob index doesn't match subnet")
		return pubsub.ValidationReject
	}
	
	// Accept if parsing succeeds and index matches
	// Full KZG validation would be done by Prysm if it had the endpoint
	return pubsub.ValidationAccept
}

func (v *DelegatedValidator) recordResult(messageType common.MessageType, result string) {
	if m := v.GetMetrics(); m != nil {
		m.RecordValidation(messageType, result)
	}
}