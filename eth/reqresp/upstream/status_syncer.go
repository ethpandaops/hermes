package upstream

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	pb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
)

// StatusSyncer periodically syncs status from beacon node
type StatusSyncer struct {
	client      *BeaconClient
	logger      *slog.Logger
	
	// Current status
	statusMu    sync.RWMutex
	status      *pb.Status
	
	// Update subscribers
	subscribersMu sync.RWMutex
	subscribers   []chan *pb.Status
	
	// Control
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// NewStatusSyncer creates a new status syncer
func NewStatusSyncer(client *BeaconClient, logger *slog.Logger) *StatusSyncer {
	return &StatusSyncer{
		client:      client,
		logger:      logger.With("component", "status_syncer"),
		subscribers: make([]chan *pb.Status, 0),
		done:        make(chan struct{}),
	}
}

// Start starts the status syncer
func (s *StatusSyncer) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	
	// Start sync loop
	go s.syncLoop()
	
	s.logger.Info("Status syncer started")
	return nil
}

// Stop stops the status syncer
func (s *StatusSyncer) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	
	// Wait for sync loop to finish
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		s.logger.Warn("Timeout waiting for status syncer to stop")
	}
	
	// Close all subscriber channels
	s.subscribersMu.Lock()
	for _, ch := range s.subscribers {
		close(ch)
	}
	s.subscribers = nil
	s.subscribersMu.Unlock()
	
	s.logger.Info("Status syncer stopped")
	return nil
}

// Subscribe returns a channel that receives status updates
func (s *StatusSyncer) Subscribe() <-chan *pb.Status {
	s.subscribersMu.Lock()
	defer s.subscribersMu.Unlock()
	
	ch := make(chan *pb.Status, 1)
	s.subscribers = append(s.subscribers, ch)
	
	// Send current status if available
	if s.status != nil {
		select {
		case ch <- s.status:
		default:
		}
	}
	
	return ch
}

// GetStatus returns the current status
func (s *StatusSyncer) GetStatus() *pb.Status {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	return s.status
}

// syncLoop periodically syncs status from beacon node
func (s *StatusSyncer) syncLoop() {
	defer close(s.done)
	
	// Initial sync
	if err := s.syncStatus(); err != nil {
		s.logger.Error("Initial status sync failed", "err", err)
	}
	
	// Create ticker for periodic updates (every slot = 12 seconds)
	ticker := time.NewTicker(12 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if err := s.syncStatus(); err != nil {
				s.logger.Error("Status sync failed", "err", err)
			}
		}
	}
}

// syncStatus fetches current status from beacon node
func (s *StatusSyncer) syncStatus() error {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	
	// Get head information
	head, err := s.client.GetHead(ctx)
	if err != nil {
		return fmt.Errorf("failed to get head: %w", err)
	}
	
	// Get finalized checkpoint
	finalized, err := s.client.GetFinalized(ctx)
	if err != nil {
		return fmt.Errorf("failed to get finalized: %w", err)
	}
	
	// Create status
	status := &pb.Status{
		// ForkDigest will be set by the parent handler
		ForkDigest:     nil,
		FinalizedRoot:  finalized.Root[:],
		FinalizedEpoch: primitives.Epoch(finalized.Epoch),
		HeadRoot:       head.Message.BodyRoot[:],
		HeadSlot:       primitives.Slot(head.Message.Slot),
	}
	
	// Update status
	s.statusMu.Lock()
	s.status = status
	s.statusMu.Unlock()
	
	// Notify subscribers
	s.notifySubscribers(status)
	
	s.logger.Debug("Status synced",
		"head_slot", status.HeadSlot,
		"finalized_epoch", status.FinalizedEpoch,
	)
	
	return nil
}

// notifySubscribers sends status update to all subscribers
func (s *StatusSyncer) notifySubscribers(status *pb.Status) {
	s.subscribersMu.RLock()
	defer s.subscribersMu.RUnlock()
	
	for _, ch := range s.subscribers {
		select {
		case ch <- status:
		default:
			// Channel full, skip
		}
	}
}

