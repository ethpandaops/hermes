package independent

import (
	"github.com/probe-lab/hermes/eth/validation/common"
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/pkg/errors"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	"github.com/sirupsen/logrus"
)

// CommitteeCache provides fast committee lookups with pre-computation
type CommitteeCache struct {
	logger              *logrus.Logger
	slotCommitteeCache  *lru.Cache[string, *common.CommitteeAssignment]
	subnetCache         *lru.Cache[uint64, *common.CommitteeAssignment]
	syncCommitteeCache  *lru.Cache[common.Epoch, []common.ValidatorIndex]
	validatorCache      *lru.Cache[string, common.ValidatorIndex]
	mu                  sync.RWMutex
}

// NewCommitteeCache creates a new committee cache
func NewCommitteeCache(logger *logrus.Logger, cacheSize int) (*CommitteeCache, error) {
	slotCache, err := lru.New[string, *common.CommitteeAssignment](cacheSize)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create slot committee cache")
	}

	subnetCache, err := lru.New[uint64, *common.CommitteeAssignment](64) // 64 subnets max
	if err != nil {
		return nil, errors.Wrap(err, "failed to create subnet cache")
	}

	syncCache, err := lru.New[common.Epoch, []common.ValidatorIndex](10) // Keep a few epochs
	if err != nil {
		return nil, errors.Wrap(err, "failed to create sync committee cache")
	}

	validatorCache, err := lru.New[string, common.ValidatorIndex](cacheSize)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create validator cache")
	}

	return &CommitteeCache{
		logger:             logger,
		slotCommitteeCache: slotCache,
		subnetCache:        subnetCache,
		syncCommitteeCache: syncCache,
		validatorCache:     validatorCache,
	}, nil
}

// UpdateEpochCommittees updates committee assignments for an epoch
func (cc *CommitteeCache) UpdateEpochCommittees(
	epoch common.Epoch,
	committees map[primitives.CommitteeIndex]*common.CommitteeAssignment,
) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.logger.WithField("epoch", epoch).Debug("Updating committee cache")

	// Pre-compute and cache all committee assignments
	for committeeIndex, assignment := range committees {
		// Cache by slot and committee index
		cacheKey := fmt.Sprintf("%d:%d", assignment.Slot, committeeIndex)
		cc.slotCommitteeCache.Add(cacheKey, assignment)

		// Pre-compute subnet assignments
		subnetID := computeSubnetForAttestation(assignment.Slot, uint64(committeeIndex))
		cc.subnetCache.Add(subnetID, assignment)

		// Cache validator to committee mapping
		for position, validatorIndex := range assignment.ValidatorIndices {
			validatorKey := fmt.Sprintf("%d:%d", assignment.Slot, validatorIndex)
			cc.validatorCache.Add(validatorKey, common.ValidatorIndex(position))
		}
	}

	cc.logger.WithFields(logrus.Fields{
		"epoch":      epoch,
		"committees": len(committees),
	}).Info("Committee cache updated")
}

// UpdateSyncCommittee updates sync committee membership
func (cc *CommitteeCache) UpdateSyncCommittee(
	syncCommitteePeriod common.Epoch,
	validatorIndices []common.ValidatorIndex,
) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.syncCommitteeCache.Add(syncCommitteePeriod, validatorIndices)
}

// GetCommittee returns the committee for a given slot and index
func (cc *CommitteeCache) GetCommittee(
	slot common.Slot,
	committeeIndex primitives.CommitteeIndex,
) (*common.CommitteeAssignment, error) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	cacheKey := fmt.Sprintf("%d:%d", slot, committeeIndex)
	committee, ok := cc.slotCommitteeCache.Get(cacheKey)
	if !ok {
		return nil, fmt.Errorf("committee not found for slot %d index %d", slot, committeeIndex)
	}

	return committee, nil
}

// GetCommitteeBySubnet returns the committee for a given subnet
func (cc *CommitteeCache) GetCommitteeBySubnet(subnetID uint64) (*common.CommitteeAssignment, error) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	committee, ok := cc.subnetCache.Get(subnetID)
	if !ok {
		return nil, fmt.Errorf("committee not found for subnet %d", subnetID)
	}

	return committee, nil
}

// GetValidatorCommitteeIndex returns the committee index for a validator at a slot
func (cc *CommitteeCache) GetValidatorCommitteeIndex(
	slot common.Slot,
	validatorIndex common.ValidatorIndex,
) (primitives.CommitteeIndex, error) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	validatorKey := fmt.Sprintf("%d:%d", slot, validatorIndex)
	position, ok := cc.validatorCache.Get(validatorKey)
	if !ok {
		return 0, fmt.Errorf("validator %d not in any committee at slot %d", validatorIndex, slot)
	}

	return primitives.CommitteeIndex(position), nil
}

// IsInSyncCommittee checks if a validator is in the sync committee
func (cc *CommitteeCache) IsInSyncCommittee(
	syncCommitteePeriod common.Epoch,
	validatorIndex common.ValidatorIndex,
) bool {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	validators, ok := cc.syncCommitteeCache.Get(syncCommitteePeriod)
	if !ok {
		return false
	}

	for _, idx := range validators {
		if idx == validatorIndex {
			return true
		}
	}

	return false
}

// PreWarmCache pre-populates cache for upcoming epoch
func (cc *CommitteeCache) PreWarmCache(
	upcomingEpoch common.Epoch,
	committees map[primitives.CommitteeIndex]*common.CommitteeAssignment,
) {
	cc.logger.WithField("epoch", upcomingEpoch).Info("Pre-warming committee cache")
	cc.UpdateEpochCommittees(upcomingEpoch, committees)
}

// Clear removes all cached data
func (cc *CommitteeCache) Clear() {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.slotCommitteeCache.Purge()
	cc.subnetCache.Purge()
	cc.syncCommitteeCache.Purge()
	cc.validatorCache.Purge()
}

