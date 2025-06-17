package independent

import (
	"github.com/probe-lab/hermes/eth/validation/common"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	"github.com/sirupsen/logrus"
)

// BeaconState represents minimal beacon state needed for validation
type BeaconState struct {
	Slot                     common.Slot
	Epoch                    common.Epoch
	GenesisTime              uint64
	GenesisValidatorsRoot    [32]byte
	Fork                     *common.ForkInfo
	Validators               map[common.ValidatorIndex]*common.ValidatorInfo
	CurrentSyncCommittee     *SyncCommitteeInfo
	NextSyncCommittee        *SyncCommitteeInfo
	CurrentJustifiedCheckpoint *Checkpoint
	FinalizedCheckpoint      *Checkpoint
}


// SyncCommitteeInfo represents sync committee membership
type SyncCommitteeInfo struct {
	ValidatorIndices []common.ValidatorIndex
	AggregatePubkey  []byte
}

// Checkpoint represents a checkpoint
type Checkpoint struct {
	Epoch common.Epoch
	Root  [32]byte
}

// StateProvider defines the interface for fetching beacon state
type StateProvider interface {
	GetBeaconState(ctx context.Context, stateID string) (*BeaconState, error)
	GetValidatorSet(ctx context.Context, stateID string) (map[common.ValidatorIndex]*common.ValidatorInfo, error)
	GetCommittees(ctx context.Context, stateID string) (map[primitives.CommitteeIndex]*common.CommitteeAssignment, error)
}

// BeaconStateSyncer manages beacon state synchronization
type BeaconStateSyncer struct {
	logger        *logrus.Logger
	provider      StateProvider
	currentState  *BeaconState
	committees    map[common.Epoch]map[primitives.CommitteeIndex]*common.CommitteeAssignment
	updateInterval time.Duration
	mu            sync.RWMutex
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

// NewBeaconStateSyncer creates a new beacon state syncer
func NewBeaconStateSyncer(
	logger *logrus.Logger,
	beaconEndpoint string,
	port int,
	useTLS bool,
	updateInterval time.Duration,
) *BeaconStateSyncer {
	return &BeaconStateSyncer{
		logger:         logger,
		provider:       NewHTTPStateProvider(beaconEndpoint, port, useTLS),
		committees:     make(map[common.Epoch]map[primitives.CommitteeIndex]*common.CommitteeAssignment),
		updateInterval: updateInterval,
		stopCh:         make(chan struct{}),
	}
}

// Start begins the state synchronization process
func (bss *BeaconStateSyncer) Start(ctx context.Context) error {
	// Initial sync
	if err := bss.syncState(ctx); err != nil {
		return errors.Wrap(err, "initial state sync failed")
	}

	// Start periodic sync
	bss.wg.Add(1)
	go bss.syncLoop(ctx)

	return nil
}

// Stop gracefully stops the syncer
func (bss *BeaconStateSyncer) Stop() error {
	close(bss.stopCh)
	bss.wg.Wait()
	return nil
}

// syncLoop periodically syncs beacon state
func (bss *BeaconStateSyncer) syncLoop(ctx context.Context) {
	defer bss.wg.Done()

	ticker := time.NewTicker(bss.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := bss.syncState(ctx); err != nil {
				bss.logger.WithError(err).Error("State sync failed")
			}
		case <-bss.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// syncState fetches and updates the current beacon state
func (bss *BeaconStateSyncer) syncState(ctx context.Context) error {
	bss.logger.Info("BeaconStateSyncer: Starting state sync")
	syncStart := time.Now()

	// Fetch current state
	bss.logger.Info("BeaconStateSyncer: Calling provider.GetBeaconState")
	state, err := bss.provider.GetBeaconState(ctx, "head")
	if err != nil {
		bss.logger.WithError(err).Error("BeaconStateSyncer: Failed to fetch beacon state")
		return errors.Wrap(err, "failed to fetch beacon state")
	}
	
	bss.logger.WithField("fetch_duration", time.Since(syncStart)).Info("BeaconStateSyncer: Got beacon state from provider")

	// Fetch committees for current and next epoch
	currentEpoch := state.Epoch
	nextEpoch := currentEpoch + 1

	currentCommittees, err := bss.provider.GetCommittees(ctx, fmt.Sprintf("%d", currentEpoch))
	if err != nil {
		return errors.Wrap(err, "failed to fetch current epoch committees")
	}

	nextCommittees, err := bss.provider.GetCommittees(ctx, fmt.Sprintf("%d", nextEpoch))
	if err != nil {
		return errors.Wrap(err, "failed to fetch next epoch committees")
	}

	// Update state atomically
	bss.mu.Lock()
	bss.currentState = state
	bss.committees[currentEpoch] = currentCommittees
	bss.committees[nextEpoch] = nextCommittees
	
	// Clean up old committee data
	for epoch := range bss.committees {
		if epoch < currentEpoch-1 {
			delete(bss.committees, epoch)
		}
	}
	bss.mu.Unlock()

	bss.logger.WithFields(logrus.Fields{
		"slot":       state.Slot,
		"epoch":      state.Epoch,
		"validators": len(state.Validators),
	}).Info("Beacon state synced")

	return nil
}

// GetCurrentState returns the current beacon state
func (bss *BeaconStateSyncer) GetCurrentState() *BeaconState {
	bss.mu.RLock()
	defer bss.mu.RUnlock()
	return bss.currentState
}

// GetValidator returns validator info by index
func (bss *BeaconStateSyncer) GetValidator(index common.ValidatorIndex) (*common.ValidatorInfo, error) {
	bss.mu.RLock()
	defer bss.mu.RUnlock()

	if bss.currentState == nil {
		return nil, errors.New("no state available")
	}

	validator, ok := bss.currentState.Validators[index]
	if !ok {
		return nil, fmt.Errorf("validator %d not found", index)
	}

	return validator, nil
}

// GetCommittee returns committee assignment for a given slot and index
func (bss *BeaconStateSyncer) GetCommittee(slot common.Slot, committeeIndex primitives.CommitteeIndex) (*common.CommitteeAssignment, error) {
	epoch := common.SlotToEpoch(slot)
	
	bss.mu.RLock()
	defer bss.mu.RUnlock()

	epochCommittees, ok := bss.committees[epoch]
	if !ok {
		return nil, fmt.Errorf("committees not available for epoch %d", epoch)
	}

	committee, ok := epochCommittees[committeeIndex]
	if !ok {
		return nil, fmt.Errorf("committee %d not found for slot %d", committeeIndex, slot)
	}

	return committee, nil
}

// IsInSyncCommittee checks if a validator is in the current sync committee
func (bss *BeaconStateSyncer) IsInSyncCommittee(validatorIndex common.ValidatorIndex) bool {
	bss.mu.RLock()
	defer bss.mu.RUnlock()

	if bss.currentState == nil || bss.currentState.CurrentSyncCommittee == nil {
		return false
	}

	for _, idx := range bss.currentState.CurrentSyncCommittee.ValidatorIndices {
		if idx == validatorIndex {
			return true
		}
	}

	return false
}

// GetFork returns the current fork info
func (bss *BeaconStateSyncer) GetFork() *common.ForkInfo {
	bss.mu.RLock()
	defer bss.mu.RUnlock()

	if bss.currentState == nil {
		return nil
	}

	return bss.currentState.Fork
}

// SetCurrentState sets the current state (for testing)
func (bss *BeaconStateSyncer) SetCurrentState(state *BeaconState) {
	bss.mu.Lock()
	defer bss.mu.Unlock()
	bss.currentState = state
}