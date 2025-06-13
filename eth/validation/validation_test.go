package validation_test

import (
	"testing"
	"time"

	"github.com/probe-lab/hermes/eth/validation"
	"github.com/probe-lab/hermes/eth/validation/common"
	"github.com/probe-lab/hermes/eth/validation/independent"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidationRouter(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	t.Run("IndependentMode", func(t *testing.T) {
		config := &validation.RouterConfig{
			Mode:   common.ModeIndependent,
			Logger: logger,
			IndependentConfig: &independent.IndependentConfig{
				Logger:              logger,
				AttestationThreshold: 10,
				ValidationTimeout:    5 * time.Second,
				SignatureCacheSize:   1000,
				CommitteeCacheSize:   1000,
				StateUpdateInterval:  30 * time.Second,
				BeaconNodeEndpoint:   "http://localhost:5052",
			},
		}

		// Test creating router with independent mode
		router, err := validation.NewRouter(config)
		require.NoError(t, err)
		assert.NotNil(t, router)

		// Skip start/stop as it requires actual beacon node
		t.Skip("Requires beacon node connection")
	})

	t.Run("DelegatedMode", func(t *testing.T) {
		// Skip delegated mode test as it requires PrysmClient
		t.Skip("Requires PrysmClient setup")
	})
}

func TestSignatureVerifier(t *testing.T) {
	logger := logrus.New()
	genesisRoot := [32]byte{1, 2, 3, 4}

	sv, err := independent.NewSignatureVerifier(logger, 100, genesisRoot)
	require.NoError(t, err)
	assert.NotNil(t, sv)

	// Skip testing AddPublicKey as it requires a valid BLS public key
	t.Skip("Requires valid BLS public key")
}

func TestAttestationTracker(t *testing.T) {
	logger := logrus.New()

	tracker, err := independent.NewAttestationTracker(logger, 100)
	require.NoError(t, err)
	assert.NotNil(t, tracker)

	// Test tracking attestation
	blockRoot := [32]byte{1, 2, 3}
	slot := common.Slot(100)
	committeeIndex := uint64(1)
	validatorIndex := common.ValidatorIndex(42)

	tracker.TrackAttestation(blockRoot, slot, committeeIndex, validatorIndex)

	// Check attestation count
	count := tracker.GetBlockAttestationCount(blockRoot)
	assert.Equal(t, 1, count)
}

func TestCommitteeCache(t *testing.T) {
	logger := logrus.New()

	cache, err := independent.NewCommitteeCache(logger, 100)
	require.NoError(t, err)
	assert.NotNil(t, cache)

	// Test updating committees
	epoch := common.Epoch(10)
	committees := make(map[primitives.CommitteeIndex]*common.CommitteeAssignment)
	
	committees[0] = &common.CommitteeAssignment{
		ValidatorIndices: []common.ValidatorIndex{1, 2, 3},
		CommitteeIndex:   0,
		Slot:            common.Slot(320), // epoch 10, slot 0
	}

	cache.UpdateEpochCommittees(epoch, committees)

	// Test retrieving committee
	committee, err := cache.GetCommittee(common.Slot(320), 0)
	require.NoError(t, err)
	assert.NotNil(t, committee)
	assert.Len(t, committee.ValidatorIndices, 3)
}

func TestValidationConfig(t *testing.T) {
	logger := logrus.New()
	
	// Test valid independent config
	t.Run("ValidIndependentConfig", func(t *testing.T) {
		config := &independent.IndependentConfig{
			Logger:              logger,
			AttestationThreshold: 10,
			ValidationTimeout:    5 * time.Second,
			SignatureCacheSize:   1000,
			CommitteeCacheSize:   1000,
			StateUpdateInterval:  30 * time.Second,
			BeaconNodeEndpoint:   "http://localhost:5052",
		}
		
		err := config.Validate()
		assert.NoError(t, err)
	})
	
	// Test invalid config (missing beacon endpoint)
	t.Run("InvalidConfig", func(t *testing.T) {
		config := &independent.IndependentConfig{
			Logger:              logger,
			AttestationThreshold: 10,
			ValidationTimeout:    5 * time.Second,
			SignatureCacheSize:   1000,
			CommitteeCacheSize:   1000,
			StateUpdateInterval:  30 * time.Second,
			BeaconNodeEndpoint:   "", // Invalid: empty endpoint
		}
		
		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "beacon node endpoint required")
	})
}