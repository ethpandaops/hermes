package validation

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
	
	"github.com/probe-lab/hermes/eth/validation/common"
	"github.com/probe-lab/hermes/eth/validation/delegated"
	"github.com/probe-lab/hermes/eth/validation/independent"
)

// RouterConfig holds configuration for the validation router
type RouterConfig struct {
	Mode            common.ValidatorMode
	Logger          *logrus.Logger
	MetricsRegistry prometheus.Registerer
	
	// Configuration for different validators
	IndependentConfig *independent.IndependentConfig
	DelegatedConfig   *delegated.DelegatedConfig
}

// Router routes validation requests based on the configured mode
type Router struct {
	config         *RouterConfig
	logger         *logrus.Logger
	validator      common.Validator
	messageCounter uint64
}

// NewRouter creates a new validation router
func NewRouter(config *RouterConfig) (*Router, error) {
	if config.Logger == nil {
		config.Logger = logrus.New()
	}
	
	r := &Router{
		config: config,
		logger: config.Logger,
	}

	// Initialize the appropriate validator based on mode
	var validator common.Validator
	var err error
	
	switch config.Mode {
	case common.ModeIndependent:
		if config.IndependentConfig == nil {
			return nil, errors.New("independent config required for independent mode")
		}
		validator, err = independent.NewIndependentValidator(config.IndependentConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create independent validator: %w", err)
		}
		
	case common.ModeDelegated:
		if config.DelegatedConfig == nil {
			return nil, errors.New("delegated config required for delegated mode")
		}
		validator, err = delegated.NewDelegatedValidator(config.DelegatedConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create delegated validator: %w", err)
		}
		
	default:
		return nil, fmt.Errorf("unknown validation mode: %v", config.Mode)
	}
	
	r.validator = validator
	return r, nil
}

// Start initializes the router and underlying validator
func (r *Router) Start(ctx context.Context) error {
	r.logger.WithField("mode", r.config.Mode).Info("Starting validation router")
	return r.validator.Start(ctx)
}

// Stop gracefully shuts down the router
func (r *Router) Stop() error {
	r.logger.Info("Stopping validation router")
	return r.validator.Stop()
}

// CreateTopicValidator returns a pubsub validator function for a specific topic
func (r *Router) CreateTopicValidator(topic string, messageType common.MessageType) pubsub.ValidatorEx {
	return func(ctx context.Context, _ peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
		atomic.AddUint64(&r.messageCounter, 1)
		
		// Start timing
		start := time.Now()
		
		// Log validation attempt
		r.logger.WithFields(logrus.Fields{
			"topic":   topic,
			"type":    messageType,
			"peer":    msg.GetFrom().String(),
			"counter": atomic.LoadUint64(&r.messageCounter),
		}).Debug("Validating message")

		// Route to appropriate validator
		result := r.validator.ValidateMessage(ctx, msg)
		
		// Calculate duration
		duration := time.Since(start).Seconds()
		
		// Update metrics through validator interface
		if metrics := r.validator.GetMetrics(); metrics != nil {
			resultStr := "accept"
			switch result {
			case pubsub.ValidationReject:
				resultStr = "reject"
			case pubsub.ValidationIgnore:
				resultStr = "ignore"
			}
			metrics.RecordValidation(messageType, resultStr)
			metrics.RecordValidationDuration(messageType, duration)
		}
		
		// Log validation result
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

