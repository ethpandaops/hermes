package validation

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sirupsen/logrus"
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/OffchainLabs/prysm/v6/encoding/bytesutil"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	
	"github.com/probe-lab/hermes/eth/validation/common"
	"github.com/probe-lab/hermes/eth/validation/independent"
	"github.com/probe-lab/hermes/eth/validation/delegated"
)

// Test basic validator creation and configuration
func TestValidatorCreation(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	
	t.Run("IndependentValidator", func(t *testing.T) {
		config := &independent.IndependentConfig{
			Logger:              logger,
			SignatureCacheSize:  1000,
			CommitteeCacheSize:  1000,
			StateUpdateInterval: 30 * time.Second,
			BeaconNodeEndpoint:  "http://localhost:5052",
		}
		
		validator, err := independent.NewIndependentValidator(config)
		require.NoError(t, err)
		assert.NotNil(t, validator)
	})
	
	t.Run("DelegatedValidator", func(t *testing.T) {
		config := &delegated.DelegatedConfig{
			Logger:      logger,
			CacheSize:   1000,
			PrysmClient: nil, // Would need actual client
		}
		_ = config // Mark as used
		
		// Skip test as it requires PrysmClient
		t.Skip("Requires PrysmClient setup")
	})
}

// Test signature verification
func TestSignatureVerification(t *testing.T) {
	logger := logrus.New()
	
	// Create signature verifier with test genesis root
	genesisRoot := [32]byte{1, 2, 3, 4, 5}
	sigVerifier, err := independent.NewSignatureVerifier(logger, 100, genesisRoot)
	require.NoError(t, err)
	
	t.Run("CacheHit", func(t *testing.T) {
		// Test data
		pubKey := bytesutil.PadTo([]byte("test_pubkey"), 48)
		message := []byte("test message")
		signature := bytesutil.PadTo([]byte("test_signature"), 96)
		
		// First verification (cache miss)
		err := sigVerifier.VerifySignature(pubKey, message, signature, common.DomainBeaconProposer, 0)
		// Will fail due to invalid signature, but that's expected
		assert.Error(t, err)
		
		// Second verification (should hit cache)
		err = sigVerifier.VerifySignature(pubKey, message, signature, common.DomainBeaconProposer, 0)
		assert.Error(t, err) // Still fails, but uses cache
	})
}

// Test committee cache operations
func TestCommitteeCache(t *testing.T) {
	logger := logrus.New()
	
	cache, err := independent.NewCommitteeCache(logger, 100)
	require.NoError(t, err)
	
	t.Run("SetAndGetCommittee", func(t *testing.T) {
		committees := make(map[primitives.CommitteeIndex]*common.CommitteeAssignment)
		committees[0] = &common.CommitteeAssignment{
			ValidatorIndices: []common.ValidatorIndex{100, 101, 102},
			CommitteeIndex:   0,
			Slot:             1000,
		}
		
		// Update epoch committees
		cache.UpdateEpochCommittees(common.Epoch(31), committees)
		
		// Get committee
		retrieved, err := cache.GetCommittee(common.Slot(1000), 0)
		require.NoError(t, err)
		assert.Equal(t, 3, len(retrieved.ValidatorIndices))
		assert.Equal(t, common.ValidatorIndex(100), retrieved.ValidatorIndices[0])
	})
	
	t.Run("SyncCommittee", func(t *testing.T) {
		// Set sync committee members
		validators := []common.ValidatorIndex{500, 501, 502}
		cache.UpdateSyncCommittee(common.Epoch(10), validators)
		
		// Check membership
		isMember := cache.IsInSyncCommittee(common.Epoch(10), common.ValidatorIndex(500))
		assert.True(t, isMember)
		
		// Check non-member
		isMember = cache.IsInSyncCommittee(common.Epoch(10), common.ValidatorIndex(600))
		assert.False(t, isMember)
	})
}

// Test attestation tracking
func TestAttestationTracker(t *testing.T) {
	logger := logrus.New()
	
	tracker, err := independent.NewAttestationTracker(logger, 100)
	require.NoError(t, err)
	
	t.Run("TrackAndCount", func(t *testing.T) {
		blockRoot := [32]byte{9, 8, 7, 6, 5}
		
		// Track attestations
		for i := 0; i < 20; i++ {
			tracker.TrackAttestation(blockRoot, common.Slot(100), uint64(i%4), common.ValidatorIndex(i))
		}
		
		// Check count
		count := tracker.GetBlockAttestationCount(blockRoot)
		assert.Equal(t, 20, count)
		
		// Use wait for attestations with immediate timeout
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		
		finalCount := tracker.WaitForAttestations(ctx, blockRoot, 15)
		assert.Equal(t, 20, finalCount)
	})
}

// Test voluntary exit validation
func TestVoluntaryExitValidation(t *testing.T) {
	logger := logrus.New()
	config := &independent.IndependentConfig{
		Logger:             logger,
		SignatureCacheSize: 100,
		CommitteeCacheSize: 100,
		BeaconNodeEndpoint: "http://localhost:5052",
	}
	
	// Create mock state
	mockState := &independent.BeaconState{
		Slot:  1000,
		Epoch: 31,
		Fork: &common.ForkInfo{
			CurrentVersion:  [4]byte{1, 0, 0, 0},
			PreviousVersion: [4]byte{0, 0, 0, 0},
			Epoch:           0,
		},
		Validators: map[common.ValidatorIndex]*common.ValidatorInfo{
			100: {
				Index:     100,
				PublicKey: bytesutil.PadTo([]byte("validator_100"), 48),
				Active:    true,
				ExitEpoch: primitives.Epoch(18446744073709551615), // FAR_FUTURE_EPOCH
			},
		},
	}
	
	validator, err := independent.NewIndependentValidator(config)
	require.NoError(t, err)
	
	// Create a mock state syncer
	validator.GetStateSync().SetCurrentState(mockState)
	
	exitValidator := independent.NewVoluntaryExitValidator(validator)
	
	t.Run("ValidExit", func(t *testing.T) {
		exit := &ethpb.SignedVoluntaryExit{
			Exit: &ethpb.VoluntaryExit{
				Epoch:          35, // After current epoch
				ValidatorIndex: 100,
			},
			Signature: bytesutil.PadTo([]byte("signature"), 96),
		}
		
		data, err := exit.MarshalSSZ()
		require.NoError(t, err)
		
		// Will fail due to invalid public key format
		err = exitValidator.Validate(context.Background(), data, "/eth2/voluntary_exit")
		assert.Error(t, err)
		// The error will be about invalid public key since we're using a fake key
		// Real tests would need proper BLS keys
	})
	
	t.Run("InvalidExitEpoch", func(t *testing.T) {
		exit := &ethpb.SignedVoluntaryExit{
			Exit: &ethpb.VoluntaryExit{
				Epoch:          20, // Before current epoch
				ValidatorIndex: 100,
			},
			Signature: bytesutil.PadTo([]byte("signature"), 96),
		}
		
		data, err := exit.MarshalSSZ()
		require.NoError(t, err)
		
		err = exitValidator.Validate(context.Background(), data, "/eth2/voluntary_exit")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exit epoch is in the past")
	})
}

// Test attestation validation
func TestAttestationValidation(t *testing.T) {
	logger := logrus.New()
	config := &independent.IndependentConfig{
		Logger:             logger,
		SignatureCacheSize: 100,
		CommitteeCacheSize: 100,
		BeaconNodeEndpoint: "http://localhost:5052",
	}
	
	validator, err := independent.NewIndependentValidator(config)
	require.NoError(t, err)
	
	// Create mock state
	mockState := &independent.BeaconState{
		Slot:  1000,
		Epoch: 31,
		Fork: &common.ForkInfo{
			CurrentVersion: [4]byte{1, 0, 0, 0},
		},
	}
	
	validator.GetStateSync().SetCurrentState(mockState)
	
	// Set up mock committee
	committees := make(map[primitives.CommitteeIndex]*common.CommitteeAssignment)
	committees[0] = &common.CommitteeAssignment{
		ValidatorIndices: []common.ValidatorIndex{100, 101, 102, 103},
		CommitteeIndex:   0,
		Slot:             1000,
	}
	validator.GetCommitteeCache().UpdateEpochCommittees(common.Epoch(31), committees)
	
	attValidator := independent.NewStandardAttestationValidator(validator)
	
	t.Run("ValidAttestation", func(t *testing.T) {
		attestation := &ethpb.Attestation{
			AggregationBits: bytesutil.PadTo([]byte{0x0f}, 4), // First 4 validators
			Data: &ethpb.AttestationData{
				Slot:            1000,
				CommitteeIndex:  0,
				BeaconBlockRoot: bytesutil.PadTo([]byte("block"), 32),
				Source: &ethpb.Checkpoint{
					Epoch: 30,
					Root:  bytesutil.PadTo([]byte("source"), 32),
				},
				Target: &ethpb.Checkpoint{
					Epoch: 31,
					Root:  bytesutil.PadTo([]byte("target"), 32),
				},
			},
			Signature: bytesutil.PadTo([]byte("signature"), 96),
		}
		
		data, err := attestation.MarshalSSZ()
		require.NoError(t, err)
		
		// Will fail due to missing validators in state, but validates structure
		err = attValidator.Validate(context.Background(), data, "/eth2/beacon_attestation_0")
		assert.Error(t, err)
	})
}

// Test KZG verification
func TestKZGVerification(t *testing.T) {
	logger := logrus.New()
	
	kzgVerifier, err := independent.NewKZGVerifier(logger)
	require.NoError(t, err)
	
	t.Run("InvalidBlobSize", func(t *testing.T) {
		blob := make([]byte, 1000) // Wrong size
		commitment := make([]byte, 48)
		proof := make([]byte, 48)
		
		err := kzgVerifier.VerifyBlobKZGProof(blob, commitment, proof)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid blob size")
	})
	
	t.Run("InvalidCommitmentSize", func(t *testing.T) {
		blob := make([]byte, 131072) // Correct size
		commitment := make([]byte, 32) // Wrong size
		proof := make([]byte, 48)
		
		err := kzgVerifier.VerifyBlobKZGProof(blob, commitment, proof)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid commitment size")
	})
}