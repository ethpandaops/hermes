package independent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethpandaops/ethwallclock"
	lru "github.com/hashicorp/golang-lru/v2"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	ssz "github.com/prysmaticlabs/fastssz"
	"github.com/sirupsen/logrus"

	"github.com/probe-lab/hermes/eth/pubsub/common"
	"github.com/probe-lab/hermes/host"
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
	wallclock          *ethwallclock.EthereumBeaconChain

	// Message validators for each type
	validators map[common.MessageType]common.MessageValidator

	// Deduplication cache
	seenMessages *lru.Cache[string, time.Time]

	// Data forwarding
	dataStream  host.DataStream
	dsr         host.DataStreamRenderer
	forkVersion [4]byte

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

	// Data forwarding
	DataStream         host.DataStream
	DataStreamRenderer host.DataStreamRenderer
	ForkVersion        [4]byte
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
		dataStream:         config.DataStream,
		dsr:                config.DataStreamRenderer,
		forkVersion:        config.ForkVersion,
		ctx:                ctx,
		cancel:             cancel,
		wallclock:          nil, // Will be initialized after initial state sync
	}

	// Log fork version
	logger.WithField("forkVersion", fmt.Sprintf("%#x", config.ForkVersion)).Info("Initializing independent validator")

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

	// Perform initial state sync
	v.syncState()

	// Start cleanup routines
	v.wg.Add(1)
	go v.cleanupLoop()

	// Wait for initial state sync
	if err := v.waitForInitialSync(ctx); err != nil {
		return errors.Wrap(err, "failed to sync initial state")
	}

	// Initialize wallclock now that we have state
	if err := v.initializeWallclock(); err != nil {
		return errors.Wrap(err, "failed to initialize wallclock")
	}

	v.logger.Info("Independent validator started successfully")
	return nil
}

// Stop gracefully shuts down the validator
func (v *IndependentValidator) Stop() error {
	v.logger.Info("Stopping independent validator")

	// Stop wallclock if initialized
	if v.wallclock != nil {
		v.wallclock.Stop()
	}

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
// validateWithType performs validation for a specific message type
func (v *IndependentValidator) validateWithType(ctx context.Context, msg *pubsub.Message, msgType common.MessageType) pubsub.ValidationResult {
	// Update metrics
	metrics := v.getMetrics()
	atomic.AddUint64(&metrics.ValidationCount, 1)

	// Check if we've seen this message before
	msgID := v.computeMessageID(msg)
	if v.isDuplicate(msgID) {
		atomic.AddUint64(&metrics.RejectedCount, 1)
		return pubsub.ValidationIgnore
	}

	// Get validator for message type
	validator, exists := v.validators[msgType]
	if !exists {
		v.logger.WithField("type", msgType).Debug("No validator for message type")
		atomic.AddUint64(&metrics.ErrorCount, 1)
		return pubsub.ValidationIgnore
	}

	// Validate and decode the message using the new Handle method
	decoded, err := validator.Handle(ctx, msg.Data, msg.GetTopic())
	if err != nil {
		v.logger.WithError(err).WithField("type", msgType).Debug("Message validation failed")
		atomic.AddUint64(&metrics.RejectedCount, 1)
		return pubsub.ValidationReject
	}

	// Mark message as seen
	v.markSeen(msgID)

	// Send to data stream if configured
	if v.dataStream != nil && v.dsr != nil {
		// Create the event
		evt := &host.TraceEvent{
			Type:      "HANDLE_MESSAGE",
			Topic:     msg.GetTopic(),
			PeerID:    msg.GetFrom(),
			Timestamp: time.Now(),
		}

		// Render the payload
		if sszObj, ok := decoded.(ssz.Unmarshaler); ok {
			evt, err = v.dsr.RenderPayload(evt, msg, sszObj)
			if err != nil {
				v.logger.WithError(err).Debug("Failed to render payload")
			} else {
				// Send to data stream
				if err := v.dataStream.PutRecord(ctx, evt); err != nil {
					v.logger.WithError(err).Debug("Failed to send to data stream")
				}
			}
		}
	}

	atomic.AddUint64(&metrics.AcceptedCount, 1)
	return pubsub.ValidationAccept
}

// ValidateMessage maintains backward compatibility but delegates to typed methods
func (v *IndependentValidator) ValidateMessage(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	// Extract message type from topic
	msgType, err := v.messageClassifier.GetMessageType(msg.GetTopic())
	if err != nil {
		v.logger.WithError(err).Debug("Unknown message type")
		metrics := v.getMetrics()
		atomic.AddUint64(&metrics.ErrorCount, 1)
		return pubsub.ValidationIgnore
	}

	return v.validateWithType(ctx, msg, msgType)
}

// Typed handler methods

func (v *IndependentValidator) HandleBeaconBlock(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return v.validateWithType(ctx, msg, common.MessageBeaconBlock)
}

func (v *IndependentValidator) HandleAggregateAndProof(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return v.validateWithType(ctx, msg, common.MessageAggregateAndProof)
}

func (v *IndependentValidator) HandleAttestation(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return v.validateWithType(ctx, msg, common.MessageAttestation)
}

func (v *IndependentValidator) HandleVoluntaryExit(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return v.validateWithType(ctx, msg, common.MessageVoluntaryExit)
}

func (v *IndependentValidator) HandleProposerSlashing(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return v.validateWithType(ctx, msg, common.MessageProposerSlashing)
}

func (v *IndependentValidator) HandleAttesterSlashing(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return v.validateWithType(ctx, msg, common.MessageAttesterSlashing)
}

func (v *IndependentValidator) HandleSyncCommitteeMessage(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return v.validateWithType(ctx, msg, common.MessageSyncCommittee)
}

func (v *IndependentValidator) HandleContributionAndProof(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return v.validateWithType(ctx, msg, common.MessageContributionAndProof)
}

func (v *IndependentValidator) HandleBlsToExecutionChange(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return v.validateWithType(ctx, msg, common.MessageBlsToExecutionChange)
}

func (v *IndependentValidator) HandleBlobSidecar(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
	return v.validateWithType(ctx, msg, common.MessageBlobSidecar)
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
	// Choose attestation validator based on fork version
	if v.isElectraOrLater() {
		v.logger.Info("Using SingleAttestationValidator for Electra+ fork")
		v.validators[common.MessageAttestation] = NewSingleAttestationValidator(v)
	} else {
		v.logger.Info("Using StandardAttestationValidator for pre-Electra fork")
		v.validators[common.MessageAttestation] = NewStandardAttestationValidator(v)
	}
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

// initializeWallclock sets up the ethereum wallclock after initial state sync
func (v *IndependentValidator) initializeWallclock() error {
	state := v.stateSync.GetCurrentState()
	if state == nil {
		return errors.New("no beacon state available")
	}

	// Create wallclock with genesis time and slot duration
	wallclock := ethwallclock.NewEthereumBeaconChain(
		time.Unix(int64(state.GenesisTime), 0),
		12*time.Second, // seconds per slot
		32,             // slots per epoch
	)

	v.wallclock = wallclock

	// Register epoch change callback
	v.wallclock.OnEpochChanged(func(current ethwallclock.Epoch) {
		v.onEpochChanged(current)
	})

	v.logger.WithFields(logrus.Fields{
		"genesis_time":  state.GenesisTime,
		"current_slot":  state.Slot,
		"current_epoch": state.Epoch,
	}).Info("Wallclock initialized")

	return nil
}

// onEpochChanged is called when the wallclock detects an epoch transition
func (v *IndependentValidator) onEpochChanged(newEpoch ethwallclock.Epoch) {
	v.logger.WithField("epoch", newEpoch.Number()).Info("Epoch changed, fetching new state")

	// Use a goroutine to avoid blocking the wallclock callback
	go func() {
		// Create context with timeout for state fetch
		ctx, cancel := context.WithTimeout(v.ctx, 2*time.Minute)
		defer cancel()

		// Thread-safe state update
		if err := v.fetchAndUpdateState(ctx); err != nil {
			v.logger.WithError(err).Error("Failed to update state on epoch change")
			return
		}

		v.logger.WithField("epoch", newEpoch.Number()).Info("State updated for new epoch")
	}()
}

// fetchAndUpdateState fetches the latest state from the HTTP provider in a thread-safe manner
func (v *IndependentValidator) fetchAndUpdateState(ctx context.Context) error {
	metrics := v.getMetrics()

	v.logger.Info("Fetching latest beacon state")
	fetchStart := time.Now()

	// Fetch the head state
	state, err := v.stateProvider.GetBeaconState(ctx, "head")
	if err != nil {
		atomic.AddUint64(&metrics.stateUpdateFailures, 1)
		return errors.Wrap(err, "failed to fetch beacon state")
	}

	// Update state syncer with the new state (thread-safe)
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
		"duration":   time.Since(fetchStart),
	}).Info("Beacon state fetch complete")

	return nil
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

// isElectraOrLater checks if the current fork version is Electra or later
func (v *IndependentValidator) isElectraOrLater() bool {
	// Compare fork version bytes
	// Electra is 0x05000000, so any version >= 0x05 in the first byte is Electra or later
	return v.forkVersion[0] >= common.ElectraForkVersion[0]
}
