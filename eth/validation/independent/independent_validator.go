package independent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/probe-lab/hermes/eth/validation/common"
)

// IndependentValidator performs full in-process validation of gossipsub messages.
// It maintains its own beacon state, signature verification, and validation logic.
type IndependentValidator struct {
	// Configuration
	config *IndependentConfig
	logger *logrus.Logger

	// Core components
	signatureVerifier  *SignatureVerifier
	stateProvider      StateProvider
	stateSync          *BeaconStateSyncer
	committeeCache     *CommitteeCache
	attestationTracker *AttestationTracker
	messageClassifier  common.MessageClassifier

	// Message validators for each type
	validators map[common.MessageType]common.MessageValidator

	// Deduplication cache
	seenMessages *lru.Cache[string, time.Time]

	// Metrics
	metrics atomic.Value // stores *IndependentMetrics

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.RWMutex
}

// IndependentConfig contains configuration specific to independent validation
type IndependentConfig struct {
	// Logger
	Logger *logrus.Logger

	// Validation parameters
	AttestationThreshold int
	AttestationPercent   float64
	ValidationTimeout    time.Duration

	// Cache sizes
	SignatureCacheSize   int
	CommitteeCacheSize   int
	SeenMessageCacheSize int

	// State sync
	BeaconNodeEndpoint  string
	BeaconNodePortHTTP  int
	BeaconNodeUseTLS    bool
	StateUpdateInterval time.Duration

	// Performance
	EnableBatchProcessing    bool
	MaxConcurrentValidations int

	// Metrics
	MetricsRegistry prometheus.Registerer
}

// IndependentMetrics tracks metrics for independent validation
type IndependentMetrics struct {
	// Base metrics
	common.BaseMetrics

	// Additional metrics
	signatureCacheHits   uint64
	signatureCacheMisses uint64
	committeeCacheHits   uint64
	committeeCacheMisses uint64
	stateUpdates         uint64
	stateUpdateFailures  uint64
}

// RecordValidation records a validation result
func (m *IndependentMetrics) RecordValidation(messageType common.MessageType, result string) {
	atomic.AddUint64(&m.ValidationCount, 1)
	switch result {
	case "accept":
		atomic.AddUint64(&m.AcceptedCount, 1)
	case "reject":
		atomic.AddUint64(&m.RejectedCount, 1)
	case "error":
		atomic.AddUint64(&m.ErrorCount, 1)
	}
}

// RecordValidationDuration is a no-op for now
func (m *IndependentMetrics) RecordValidationDuration(messageType common.MessageType, duration float64) {
	// Could add histogram tracking here
}

// Validate validates the configuration
func (c *IndependentConfig) Validate() error {
	if c.BeaconNodeEndpoint == "" {
		return errors.New("beacon node endpoint required")
	}
	if c.SignatureCacheSize <= 0 {
		c.SignatureCacheSize = common.DefaultCacheSize
	}
	if c.CommitteeCacheSize <= 0 {
		c.CommitteeCacheSize = common.DefaultCacheSize
	}
	if c.SeenMessageCacheSize <= 0 {
		c.SeenMessageCacheSize = common.DefaultCacheSize
	}
	if c.StateUpdateInterval <= 0 {
		c.StateUpdateInterval = 30 * time.Second
	}
	if c.ValidationTimeout <= 0 {
		c.ValidationTimeout = 5 * time.Second
	}
	return nil
}

// NewIndependentValidator creates a new independent validator
func NewIndependentValidator(config *IndependentConfig) (*IndependentValidator, error) {
	if err := config.Validate(); err != nil {
		return nil, errors.Wrap(err, "invalid config")
	}

	if config.Logger == nil {
		config.Logger = logrus.New()
	}

	logger := config.Logger

	// Create deduplication cache
	seenCache, err := lru.New[string, time.Time](config.SeenMessageCacheSize)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create seen messages cache")
	}

	// Create state provider
	stateProvider := NewHTTPStateProvider(config.BeaconNodeEndpoint, config.BeaconNodePortHTTP, config.BeaconNodeUseTLS)

	// Initialize with empty genesis root (will be set after first state sync)
	sigVerifier, err := NewSignatureVerifier(logger, config.SignatureCacheSize, [32]byte{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create signature verifier")
	}

	// Create committee cache
	committeeCache, err := NewCommitteeCache(logger, config.CommitteeCacheSize)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create committee cache")
	}

	// Create attestation tracker
	attestationTracker, err := NewAttestationTracker(logger, config.CommitteeCacheSize)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create attestation tracker")
	}

	// Create beacon state syncer
	stateSync := NewBeaconStateSyncer(logger, config.BeaconNodeEndpoint, config.BeaconNodePortHTTP, config.BeaconNodeUseTLS, config.StateUpdateInterval)

	ctx, cancel := context.WithCancel(context.Background())

	validator := &IndependentValidator{
		config:             config,
		logger:             logger,
		signatureVerifier:  sigVerifier,
		stateProvider:      stateProvider,
		stateSync:          stateSync,
		committeeCache:     committeeCache,
		attestationTracker: attestationTracker,
		messageClassifier:  &defaultMessageClassifier{},
		validators:         make(map[common.MessageType]common.MessageValidator),
		seenMessages:       seenCache,
		ctx:                ctx,
		cancel:             cancel,
	}

	// Initialize message validators
	validator.initializeValidators()

	// Set initial metrics
	validator.metrics.Store(&IndependentMetrics{})

	return validator, nil
}

// Start initializes the validator and starts background services
func (v *IndependentValidator) Start(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.logger.Info("Starting independent validator")

	// Start state synchronization
	v.wg.Add(1)
	go v.stateSyncLoop()

	// Start cleanup routines
	v.wg.Add(1)
	go v.cleanupLoop()

	// Wait for initial state sync
	if err := v.waitForInitialSync(ctx); err != nil {
		return errors.Wrap(err, "failed to sync initial state")
	}

	v.logger.Info("Independent validator started successfully")
	return nil
}

// Stop gracefully shuts down the validator
func (v *IndependentValidator) Stop() error {
	v.logger.Info("Stopping independent validator")

	// Cancel context to stop background routines
	v.cancel()

	// Wait for routines to finish
	done := make(chan struct{})
	go func() {
		v.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		v.logger.Info("Independent validator stopped successfully")
		return nil
	case <-time.After(30 * time.Second):
		return errors.New("timeout waiting for validator to stop")
	}
}

// ValidateMessage validates a gossipsub message
func (v *IndependentValidator) ValidateMessage(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	// Update metrics
	metrics := v.getMetrics()
	atomic.AddUint64(&metrics.ValidationCount, 1)

	// Check if we've seen this message before
	msgID := v.computeMessageID(msg)
	if v.isDuplicate(msgID) {
		atomic.AddUint64(&metrics.RejectedCount, 1)
		return pubsub.ValidationIgnore
	}

	// Extract message type from topic
	msgType, err := v.messageClassifier.GetMessageType(msg.GetTopic())
	if err != nil {
		v.logger.WithError(err).Debug("Unknown message type")
		atomic.AddUint64(&metrics.ErrorCount, 1)
		return pubsub.ValidationIgnore
	}

	// Get validator for message type
	validator, exists := v.validators[msgType]
	if !exists {
		v.logger.WithField("type", msgType).Debug("No validator for message type")
		atomic.AddUint64(&metrics.ErrorCount, 1)
		return pubsub.ValidationIgnore
	}

	// Validate the message
	if err := validator.Validate(ctx, msg.Data, msg.GetTopic()); err != nil {
		v.logger.WithError(err).WithField("type", msgType).Debug("Message validation failed")
		atomic.AddUint64(&metrics.RejectedCount, 1)
		return pubsub.ValidationReject
	}

	// Mark message as seen
	v.markSeen(msgID)

	atomic.AddUint64(&metrics.AcceptedCount, 1)
	return pubsub.ValidationAccept
}

// GetMetrics returns validation metrics
func (v *IndependentValidator) GetMetrics() common.ValidatorMetrics {
	return v.getMetrics()
}

// Private methods

func (v *IndependentValidator) initializeValidators() {
	// Create validator instances for each message type
	v.validators[common.MessageVoluntaryExit] = NewVoluntaryExitValidator(v)
	v.validators[common.MessageProposerSlashing] = NewProposerSlashingValidator(v)
	v.validators[common.MessageAttesterSlashing] = NewAttesterSlashingValidator(v)
	v.validators[common.MessageBlsToExecutionChange] = NewBLSToExecutionChangeValidator(v)
	v.validators[common.MessageAttestation] = NewStandardAttestationValidator(v)
	v.validators[common.MessageAggregateAndProof] = NewAggregateAttestationValidator(v)
	v.validators[common.MessageBeaconBlock] = NewBeaconBlockValidator(v)
	v.validators[common.MessageSyncCommittee] = NewSyncCommitteeMessageValidator(v)
	v.validators[common.MessageContributionAndProof] = NewSyncCommitteeContributionValidator(v)

	// Blob validator with KZG
	blobValidator, err := NewBlobSidecarValidator(v)
	if err != nil {
		v.logger.WithError(err).Warn("Failed to create blob validator, blob validation disabled")
	} else {
		v.validators[common.MessageBlobSidecar] = blobValidator
	}
}

func (v *IndependentValidator) stateSyncLoop() {
	defer v.wg.Done()

	ticker := time.NewTicker(v.config.StateUpdateInterval)
	defer ticker.Stop()

	// Initial sync
	v.syncState()

	for {
		select {
		case <-v.ctx.Done():
			return
		case <-ticker.C:
			v.syncState()
		}
	}
}

func (v *IndependentValidator) syncState() {
	metrics := v.getMetrics()

	// Use longer timeout for state sync
	ctx, cancel := context.WithTimeout(v.ctx, 5*time.Minute)
	defer cancel()

	v.logger.Info("Starting beacon state sync")
	syncStart := time.Now()

	state, err := v.stateProvider.GetBeaconState(ctx, "head")
	if err != nil {
		v.logger.WithError(err).Error("Failed to sync beacon state")
		atomic.AddUint64(&metrics.stateUpdateFailures, 1)
		return
	}

	// Update state syncer with the new state
	v.stateSync.SetCurrentState(state)

	// Update signature verifier with current fork
	if state.Fork != nil {
		v.signatureVerifier.UpdateFork(state.Fork.CurrentVersion)
	}

	atomic.AddUint64(&metrics.stateUpdates, 1)
	v.logger.WithFields(logrus.Fields{
		"slot":       state.Slot,
		"epoch":      state.Epoch,
		"validators": len(state.Validators),
		"duration":   time.Since(syncStart),
	}).Info("Beacon state sync complete")
}

func (v *IndependentValidator) cleanupLoop() {
	defer v.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-v.ctx.Done():
			return
		case <-ticker.C:
			v.cleanupSeenMessages()
			v.attestationTracker.CleanupOldData(10 * time.Minute)
		}
	}
}

func (v *IndependentValidator) cleanupSeenMessages() {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	keys := v.seenMessages.Keys()

	for _, key := range keys {
		if seenTime, ok := v.seenMessages.Peek(key); ok {
			if now.Sub(seenTime) > 5*time.Minute {
				v.seenMessages.Remove(key)
			}
		}
	}
}

func (v *IndependentValidator) waitForInitialSync(ctx context.Context) error {
	// Wait up to 6 minutes for initial state sync (beacon state download can be large)
	timeout := 6 * time.Minute
	deadline := time.Now().Add(timeout)

	v.logger.Info("Waiting for initial beacon state sync...")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		if v.hasState() {
			v.logger.Info("Initial beacon state sync complete")
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			remaining := time.Until(deadline)
			v.logger.WithField("remaining", remaining.Round(time.Second)).Debug("Still waiting for initial state sync")
		}
	}

	return errors.New("timeout waiting for initial state sync")
}

func (v *IndependentValidator) hasState() bool {
	return v.stateSync.GetCurrentState() != nil
}

func (v *IndependentValidator) computeMessageID(msg *pubsub.Message) string {
	h := sha256.New()
	h.Write(msg.Data)
	h.Write([]byte(msg.GetFrom().String()))
	h.Write([]byte(msg.GetTopic()))
	return hex.EncodeToString(h.Sum(nil))
}

func (v *IndependentValidator) isDuplicate(msgID string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	_, exists := v.seenMessages.Get(msgID)
	return exists
}

func (v *IndependentValidator) markSeen(msgID string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.seenMessages.Add(msgID, time.Now())
}

func (v *IndependentValidator) getMetrics() *IndependentMetrics {
	return v.metrics.Load().(*IndependentMetrics)
}

// getCurrentSlot returns the current slot based on beacon state
func (v *IndependentValidator) getCurrentSlot() common.Slot {
	// This would normally calculate based on genesis time
	// For now, return a placeholder
	return 0
}

// defaultMessageClassifier extracts message types from topics
type defaultMessageClassifier struct{}

func (d *defaultMessageClassifier) GetMessageType(topic string) (common.MessageType, error) {
	return common.ClassifyMessage(topic), nil
}

// GetStateSync returns the state syncer (for testing)
func (v *IndependentValidator) GetStateSync() *BeaconStateSyncer {
	return v.stateSync
}

// GetCommitteeCache returns the committee cache (for testing)
func (v *IndependentValidator) GetCommitteeCache() *CommitteeCache {
	return v.committeeCache
}
