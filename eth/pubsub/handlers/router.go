package handlers

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/probe-lab/hermes/eth/pubsub/common"
	"github.com/probe-lab/hermes/eth/pubsub/handlers/delegated"
	"github.com/probe-lab/hermes/eth/pubsub/handlers/independent"
)

// RouterConfig holds configuration for the handling router
type RouterConfig struct {
	Mode            common.ValidatorMode
	Logger          *logrus.Logger
	MetricsRegistry prometheus.Registerer

	// Configuration for different handlers
	IndependentConfig *independent.IndependentConfig
	DelegatedConfig   *delegated.DelegatedConfig
}

// TypedValidator provides direct validation methods for each message type
type TypedValidator interface {
	common.Validator
	
	// Per-message-type validation methods
	ValidateBeaconBlock(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult
	ValidateAggregateAndProof(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult
	ValidateAttestation(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult
	ValidateVoluntaryExit(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult
	ValidateProposerSlashing(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult
	ValidateAttesterSlashing(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult
	ValidateSyncCommitteeMessage(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult
	ValidateContributionAndProof(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult
	ValidateBlsToExecutionChange(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult
	ValidateBlobSidecar(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult
}

// Router routes messages to handlers based on the configured mode
type Router struct {
	config         *RouterConfig
	logger         *logrus.Logger
	handler      common.Validator
	messageCounter uint64
}

// NewRouter creates a new message router
func NewRouter(config *RouterConfig) (*Router, error) {
	if config.Logger == nil {
		config.Logger = logrus.New()
	}

	r := &Router{
		config: config,
		logger: config.Logger,
	}

	// Initialize the appropriate handler based on mode
	var handler common.Validator
	var err error

	switch config.Mode {
	case common.ModeIndependent:
		if config.IndependentConfig == nil {
			return nil, errors.New("independent config required for independent mode")
		}
		handler, err = independent.NewIndependentValidator(config.IndependentConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create independent handler: %w", err)
		}

	case common.ModeDelegated:
		if config.DelegatedConfig == nil {
			return nil, errors.New("delegated config required for delegated mode")
		}
		handler, err = delegated.NewDelegatedHandler(config.DelegatedConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create delegated handler: %w", err)
		}

	default:
		return nil, fmt.Errorf("unknown handling mode: %v", config.Mode)
	}

	r.handler = handler
	return r, nil
}

// Start initializes the router and underlying handler
func (r *Router) Start(ctx context.Context) error {
	r.logger.WithField("mode", r.config.Mode).Info("Starting message handler")
	return r.handler.Start(ctx)
}

// Stop gracefully shuts down the router
func (r *Router) Stop() error {
	r.logger.Info("Stopping message handler")
	return r.handler.Stop()
}

// CreateTopicValidator returns a pubsub validator function for a specific topic
func (r *Router) CreateTopicValidator(topic string, messageType common.MessageType) pubsub.ValidatorEx {
	// Get the specific validator function for this message type
	validatorFunc := r.getValidatorForMessageType(messageType)
	
	return func(ctx context.Context, _ peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
		atomic.AddUint64(&r.messageCounter, 1)

		// Start timing
		start := time.Now()

		// Log handling attempt
		r.logger.WithFields(logrus.Fields{
			"topic":   topic,
			"type":    messageType,
			"peer":    msg.GetFrom().String(),
			"counter": atomic.LoadUint64(&r.messageCounter),
		}).Debug("Validating message")

		// Call the specific validator function
		result := validatorFunc(ctx, msg)

		// Calculate duration
		duration := time.Since(start)

		// Update metrics through handler interface
		if metrics := r.handler.GetMetrics(); metrics != nil {
			resultStr := "accept"
			switch result {
			case pubsub.ValidationReject:
				resultStr = "reject"
			case pubsub.ValidationIgnore:
				resultStr = "ignore"
			}
			metrics.RecordValidation(messageType, resultStr)
			metrics.RecordValidationDuration(messageType, float64(duration.Milliseconds()))
		}

		// Log handling result
		r.logger.WithFields(logrus.Fields{
			"topic":    topic,
			"result":   result,
			"duration": duration,
		}).Debug("Validation complete")

		return result
	}
}

// GetMessageType extracts the message type from a topic string
func GetMessageType(topic string) (common.MessageType, error) {
	// Use the ClassifyMessage function from utils
	msgType := common.ClassifyMessage(topic)
	if msgType == common.UnknownMessage {
		return 0, fmt.Errorf("unknown topic type: %s", topic)
	}
	return msgType, nil
}

// getValidatorForMessageType returns a specific validator function for the given message type
func (r *Router) getValidatorForMessageType(messageType common.MessageType) func(context.Context, *pubsub.Message) pubsub.ValidationResult {
	// Check if handler implements TypedValidator interface
	typedValidator, ok := r.handler.(TypedValidator)
	if !ok {
		// Fallback to generic validation if typed validator not implemented
		return func(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
			return r.handler.ValidateMessage(ctx, msg)
		}
	}

	// Return the specific validator function based on message type
	switch messageType {
	case common.MessageBeaconBlock:
		return typedValidator.ValidateBeaconBlock
	case common.MessageAggregateAndProof:
		return typedValidator.ValidateAggregateAndProof
	case common.MessageAttestation:
		return typedValidator.ValidateAttestation
	case common.MessageVoluntaryExit:
		return typedValidator.ValidateVoluntaryExit
	case common.MessageProposerSlashing:
		return typedValidator.ValidateProposerSlashing
	case common.MessageAttesterSlashing:
		return typedValidator.ValidateAttesterSlashing
	case common.MessageSyncCommittee:
		return typedValidator.ValidateSyncCommitteeMessage
	case common.MessageContributionAndProof:
		return typedValidator.ValidateContributionAndProof
	case common.MessageBlsToExecutionChange:
		return typedValidator.ValidateBlsToExecutionChange
	case common.MessageBlobSidecar:
		return typedValidator.ValidateBlobSidecar
	default:
		// Unknown message type, always reject
		return func(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult {
			return pubsub.ValidationReject
		}
	}
}

// GetTopicHandler returns the topic handler if the handler implements it
func (r *Router) GetTopicHandler() TopicHandler {
	// Check if the handler implements TopicHandler
	if handler, ok := r.handler.(TopicHandler); ok {
		return handler
	}
	return nil
}
