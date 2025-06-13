package common

import (
	"context"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
)

// Validator defines the interface for gossipsub message validation.
// Implementations can either validate messages independently or delegate to external services.
type Validator interface {
	// ValidateMessage validates a gossipsub message and returns the validation result.
	// This method should be thread-safe as it may be called concurrently.
	ValidateMessage(ctx context.Context, msg *pubsub.Message) pubsub.ValidationResult
	
	// Start initializes the validator and starts any background services.
	// This method should be called before ValidateMessage.
	Start(ctx context.Context) error
	
	// Stop gracefully shuts down the validator and cleans up resources.
	// After Stop is called, ValidateMessage should not be used.
	Stop() error
	
	// GetMetrics returns validation metrics for monitoring.
	// This is optional and implementations may return nil.
	GetMetrics() ValidatorMetrics
}

// ValidatorMetrics provides metrics about validation performance
type ValidatorMetrics interface {
	// GetValidationCount returns the total number of validations performed
	GetValidationCount() uint64
	
	// GetAcceptedCount returns the number of messages accepted
	GetAcceptedCount() uint64
	
	// GetRejectedCount returns the number of messages rejected
	GetRejectedCount() uint64
	
	// GetErrorCount returns the number of validation errors
	GetErrorCount() uint64
	
	// RecordValidation records a validation result
	RecordValidation(messageType MessageType, result string)
	
	// RecordValidationDuration records the duration of validation
	RecordValidationDuration(messageType MessageType, duration float64)
}

// ValidatorFactory creates validators based on configuration
type ValidatorFactory interface {
	// CreateValidator creates a new validator instance based on the config
	CreateValidator(config *Config) (Validator, error)
}

// MessageClassifier helps classify messages by type from topic strings
type MessageClassifier interface {
	// GetMessageType extracts the message type from a topic string
	GetMessageType(topic string) (MessageType, error)
}

// ValidatorMode represents the validation mode
type ValidatorMode string

const (
	// ModeIndependent performs full in-process validation
	ModeIndependent ValidatorMode = "independent"
	
	// ModeDelegated delegates validation to an external service
	ModeDelegated ValidatorMode = "delegated"
)

// BaseMetrics provides a basic implementation of ValidatorMetrics
type BaseMetrics struct {
	ValidationCount uint64
	AcceptedCount   uint64
	RejectedCount   uint64
	ErrorCount      uint64
}

func (m *BaseMetrics) GetValidationCount() uint64 { return m.ValidationCount }
func (m *BaseMetrics) GetAcceptedCount() uint64   { return m.AcceptedCount }
func (m *BaseMetrics) GetRejectedCount() uint64   { return m.RejectedCount }
func (m *BaseMetrics) GetErrorCount() uint64      { return m.ErrorCount }

// MessageValidator validates specific message types
type MessageValidator interface {
	// Validate validates a specific message type
	Validate(ctx context.Context, data []byte, topic string) error
}