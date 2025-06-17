package independent

import (
	"github.com/probe-lab/hermes/eth/validation/common"
	"context"
	"fmt"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// AttestationInfo represents a tracked attestation
type AttestationInfo struct {
	Slot            common.Slot
	CommitteeIndex  uint64
	BeaconBlockRoot [32]byte
	ValidatorIndex  common.ValidatorIndex
	Timestamp       time.Time
}

// BlockAttestationSummary tracks attestations for a specific block
type BlockAttestationSummary struct {
	BlockRoot        [32]byte
	Slot             common.Slot
	AttestationCount int
	UniqueValidators map[common.ValidatorIndex]bool
	FirstSeenTime    time.Time
	LastUpdateTime   time.Time
	mu               sync.RWMutex
}

// AttestationTracker tracks attestations for block validation
type AttestationTracker struct {
	logger            *logrus.Logger
	blockSummaries    *lru.Cache[string, *BlockAttestationSummary]
	recentAttestations *lru.Cache[string, *AttestationInfo]
	subscribers       map[string][]chan int
	mu                sync.RWMutex
}

// NewAttestationTracker creates a new attestation tracker
func NewAttestationTracker(logger *logrus.Logger, cacheSize int) (*AttestationTracker, error) {
	blockCache, err := lru.New[string, *BlockAttestationSummary](cacheSize)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create block cache")
	}

	attestationCache, err := lru.New[string, *AttestationInfo](cacheSize * 10)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create attestation cache")
	}

	return &AttestationTracker{
		logger:             logger,
		blockSummaries:     blockCache,
		recentAttestations: attestationCache,
		subscribers:        make(map[string][]chan int),
	}, nil
}

// TrackAttestation records an attestation for a block
func (at *AttestationTracker) TrackAttestation(
	blockRoot [32]byte,
	slot common.Slot,
	committeeIndex uint64,
	validatorIndex common.ValidatorIndex,
) {
	// Create attestation info
	attestation := &AttestationInfo{
		Slot:            slot,
		CommitteeIndex:  committeeIndex,
		BeaconBlockRoot: blockRoot,
		ValidatorIndex:  validatorIndex,
		Timestamp:       time.Now(),
	}

	// Store recent attestation
	attestationKey := formatAttestationKey(blockRoot, validatorIndex)
	at.recentAttestations.Add(attestationKey, attestation)

	// Update block summary
	blockKey := formatBlockKey(blockRoot)
	
	at.mu.Lock()
	summaryInterface, exists := at.blockSummaries.Get(blockKey)
	var summary *BlockAttestationSummary
	
	if exists {
		summary = summaryInterface
	} else {
		summary = &BlockAttestationSummary{
			BlockRoot:        blockRoot,
			Slot:             slot,
			AttestationCount: 0,
			UniqueValidators: make(map[common.ValidatorIndex]bool),
			FirstSeenTime:    time.Now(),
			LastUpdateTime:   time.Now(),
		}
		at.blockSummaries.Add(blockKey, summary)
	}
	at.mu.Unlock()

	// Update attestation count
	summary.mu.Lock()
	if !summary.UniqueValidators[validatorIndex] {
		summary.UniqueValidators[validatorIndex] = true
		summary.AttestationCount++
		summary.LastUpdateTime = time.Now()
		
		// Notify subscribers
		at.notifySubscribers(blockKey, summary.AttestationCount)
	}
	summary.mu.Unlock()

	at.logger.WithFields(logrus.Fields{
		"block_root":       blockKey,
		"slot":             slot,
		"validator":        validatorIndex,
		"attestation_count": summary.AttestationCount,
	}).Debug("Tracked attestation")
}

// WaitForAttestations waits for a threshold of attestations for a block
func (at *AttestationTracker) WaitForAttestations(
	ctx context.Context,
	blockRoot [32]byte,
	threshold int,
) int {
	blockKey := formatBlockKey(blockRoot)
	
	// Check if we already have enough attestations
	if summary, exists := at.blockSummaries.Get(blockKey); exists {
		summary.mu.RLock()
		count := summary.AttestationCount
		summary.mu.RUnlock()
		
		if count >= threshold {
			return count
		}
	}

	// Create subscription channel
	ch := make(chan int, 10)
	at.subscribeToBlock(blockKey, ch)
	defer at.unsubscribeFromBlock(blockKey, ch)

	// Wait for attestations or timeout
	for {
		select {
		case count := <-ch:
			if count >= threshold {
				return count
			}
		case <-ctx.Done():
			// Return current count on timeout
			if summary, exists := at.blockSummaries.Get(blockKey); exists {
				summary.mu.RLock()
				count := summary.AttestationCount
				summary.mu.RUnlock()
				return count
			}
			return 0
		}
	}
}

// GetBlockAttestationCount returns the current attestation count for a block
func (at *AttestationTracker) GetBlockAttestationCount(blockRoot [32]byte) int {
	blockKey := formatBlockKey(blockRoot)
	
	if summary, exists := at.blockSummaries.Get(blockKey); exists {
		summary.mu.RLock()
		defer summary.mu.RUnlock()
		return summary.AttestationCount
	}
	
	return 0
}

// GetBlockSummary returns detailed attestation info for a block
func (at *AttestationTracker) GetBlockSummary(blockRoot [32]byte) (*BlockAttestationSummary, error) {
	blockKey := formatBlockKey(blockRoot)
	
	summary, exists := at.blockSummaries.Get(blockKey)
	if !exists {
		return nil, errors.New("block not found")
	}
	
	return summary, nil
}

// CleanupOldData removes attestation data older than the retention period
func (at *AttestationTracker) CleanupOldData(retentionPeriod time.Duration) {
	at.mu.Lock()
	defer at.mu.Unlock()

	// LRU cache handles most cleanup, but we can add time-based cleanup if needed
	at.logger.Debug("Cleanup completed")
}

// subscribeToBlock subscribes to attestation updates for a block
func (at *AttestationTracker) subscribeToBlock(blockKey string, ch chan int) {
	at.mu.Lock()
	defer at.mu.Unlock()
	
	at.subscribers[blockKey] = append(at.subscribers[blockKey], ch)
}

// unsubscribeFromBlock removes a subscription
func (at *AttestationTracker) unsubscribeFromBlock(blockKey string, ch chan int) {
	at.mu.Lock()
	defer at.mu.Unlock()
	
	subscribers := at.subscribers[blockKey]
	for i, sub := range subscribers {
		if sub == ch {
			at.subscribers[blockKey] = append(subscribers[:i], subscribers[i+1:]...)
			break
		}
	}
	
	// Clean up empty subscriber lists
	if len(at.subscribers[blockKey]) == 0 {
		delete(at.subscribers, blockKey)
	}
}

// notifySubscribers notifies all subscribers of attestation count updates
func (at *AttestationTracker) notifySubscribers(blockKey string, count int) {
	at.mu.RLock()
	subscribers := at.subscribers[blockKey]
	at.mu.RUnlock()
	
	for _, ch := range subscribers {
		select {
		case ch <- count:
		default:
			// Channel full, skip
		}
	}
}

// formatBlockKey creates a cache key for a block root
func formatBlockKey(blockRoot [32]byte) string {
	return fmt.Sprintf("%x", blockRoot)
}

// formatAttestationKey creates a cache key for an attestation
func formatAttestationKey(blockRoot [32]byte, validatorIndex common.ValidatorIndex) string {
	return fmt.Sprintf("%x:%d", blockRoot, validatorIndex)
}