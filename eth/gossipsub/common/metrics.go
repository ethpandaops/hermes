package common

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ValidationMetrics tracks validation performance and results
type ValidationMetrics struct {
	// Message validation counters
	messagesValidated *prometheus.CounterVec
	messagesAccepted  *prometheus.CounterVec
	messagesRejected  *prometheus.CounterVec
	messagesIgnored   *prometheus.CounterVec
	
	// Validation timing
	validationDuration *prometheus.HistogramVec
	
	// Signature verification metrics
	signaturesVerified   prometheus.Counter
	signaturesCached     prometheus.Counter
	signaturesFailed     prometheus.Counter
	
	// State sync metrics
	stateSyncSuccess     prometheus.Counter
	stateSyncFailure     prometheus.Counter
	stateSyncDuration    prometheus.Histogram
	currentSlot          prometheus.Gauge
	currentEpoch         prometheus.Gauge
	
	// Committee cache metrics
	committeeCacheHits   prometheus.Counter
	committeeCacheMisses prometheus.Counter
	committeeCacheSize   prometheus.Gauge
	
	// Attestation tracking metrics
	attestationsTracked  prometheus.Counter
	blocksTracked        prometheus.Gauge
	attestationsPerBlock prometheus.Histogram
	
	// KZG verification metrics
	kzgVerifications     prometheus.Counter
	kzgVerificationTime  prometheus.Histogram
	kzgFailures          prometheus.Counter
}

// NewValidationMetrics creates and registers validation metrics
func NewValidationMetrics() *ValidationMetrics {
	return &ValidationMetrics{
		messagesValidated: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "hermes_validation_messages_total",
				Help: "Total number of messages validated",
			},
			[]string{"message_type", "topic"},
		),
		messagesAccepted: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "hermes_validation_messages_accepted_total",
				Help: "Total number of messages accepted",
			},
			[]string{"message_type", "topic"},
		),
		messagesRejected: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "hermes_validation_messages_rejected_total",
				Help: "Total number of messages rejected",
			},
			[]string{"message_type", "topic", "reason"},
		),
		messagesIgnored: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "hermes_validation_messages_ignored_total",
				Help: "Total number of messages ignored",
			},
			[]string{"message_type", "topic"},
		),
		validationDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "hermes_validation_duration_seconds",
				Help:    "Time spent validating messages",
				Buckets: prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms to ~1s
			},
			[]string{"message_type"},
		),
		signaturesVerified: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "hermes_signatures_verified_total",
				Help: "Total number of signatures verified",
			},
		),
		signaturesCached: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "hermes_signatures_cached_total",
				Help: "Total number of signature verifications served from cache",
			},
		),
		signaturesFailed: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "hermes_signatures_failed_total",
				Help: "Total number of signature verification failures",
			},
		),
		stateSyncSuccess: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "hermes_state_sync_success_total",
				Help: "Total number of successful state syncs",
			},
		),
		stateSyncFailure: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "hermes_state_sync_failure_total",
				Help: "Total number of failed state syncs",
			},
		),
		stateSyncDuration: promauto.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "hermes_state_sync_duration_seconds",
				Help:    "Time spent syncing beacon state",
				Buckets: prometheus.ExponentialBuckets(0.1, 2, 10), // 100ms to ~100s
			},
		),
		currentSlot: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "hermes_validation_current_slot",
				Help: "Current slot from beacon state",
			},
		),
		currentEpoch: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "hermes_validation_current_epoch",
				Help: "Current epoch from beacon state",
			},
		),
		committeeCacheHits: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "hermes_committee_cache_hits_total",
				Help: "Total number of committee cache hits",
			},
		),
		committeeCacheMisses: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "hermes_committee_cache_misses_total",
				Help: "Total number of committee cache misses",
			},
		),
		committeeCacheSize: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "hermes_committee_cache_size",
				Help: "Current size of committee cache",
			},
		),
		attestationsTracked: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "hermes_attestations_tracked_total",
				Help: "Total number of attestations tracked",
			},
		),
		blocksTracked: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "hermes_blocks_tracked",
				Help: "Number of blocks currently being tracked for attestations",
			},
		),
		attestationsPerBlock: promauto.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "hermes_attestations_per_block",
				Help:    "Distribution of attestations per block",
				Buckets: prometheus.LinearBuckets(0, 10, 20), // 0 to 200 attestations
			},
		),
		kzgVerifications: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "hermes_kzg_verifications_total",
				Help: "Total number of KZG proof verifications",
			},
		),
		kzgVerificationTime: promauto.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "hermes_kzg_verification_duration_seconds",
				Help:    "Time spent verifying KZG proofs",
				Buckets: prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms to ~1s
			},
		),
		kzgFailures: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "hermes_kzg_failures_total",
				Help: "Total number of KZG verification failures",
			},
		),
	}
}

// Helper methods for common metric updates

func (m *ValidationMetrics) RecordValidation(messageType, topic string, accepted bool, duration float64) {
	m.messagesValidated.WithLabelValues(messageType, topic).Inc()
	m.validationDuration.WithLabelValues(messageType).Observe(duration)
	
	if accepted {
		m.messagesAccepted.WithLabelValues(messageType, topic).Inc()
	} else {
		m.messagesRejected.WithLabelValues(messageType, topic, "validation_failed").Inc()
	}
}

func (m *ValidationMetrics) RecordSignatureVerification(cached bool, success bool) {
	if cached {
		m.signaturesCached.Inc()
	} else {
		m.signaturesVerified.Inc()
	}
	
	if !success {
		m.signaturesFailed.Inc()
	}
}

func (m *ValidationMetrics) RecordStateSync(success bool, duration float64, slot, epoch uint64) {
	if success {
		m.stateSyncSuccess.Inc()
		m.currentSlot.Set(float64(slot))
		m.currentEpoch.Set(float64(epoch))
	} else {
		m.stateSyncFailure.Inc()
	}
	m.stateSyncDuration.Observe(duration)
}

func (m *ValidationMetrics) RecordCommitteeCacheLookup(hit bool) {
	if hit {
		m.committeeCacheHits.Inc()
	} else {
		m.committeeCacheMisses.Inc()
	}
}

func (m *ValidationMetrics) RecordAttestation(blockRoot [32]byte) {
	m.attestationsTracked.Inc()
}

func (m *ValidationMetrics) RecordKZGVerification(success bool, duration float64) {
	m.kzgVerifications.Inc()
	m.kzgVerificationTime.Observe(duration)
	if !success {
		m.kzgFailures.Inc()
	}
}

// Global metrics instance
var globalMetrics *ValidationMetrics

// InitMetrics initializes the global metrics instance
func InitMetrics() {
	if globalMetrics == nil {
		globalMetrics = NewValidationMetrics()
	}
}

// GetMetrics returns the global metrics instance
func GetMetrics() *ValidationMetrics {
	if globalMetrics == nil {
		InitMetrics()
	}
	return globalMetrics
}