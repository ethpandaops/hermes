package validation

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sirupsen/logrus"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/OffchainLabs/prysm/v6/encoding/bytesutil"
	"github.com/probe-lab/hermes/eth/validation/common"
	"github.com/probe-lab/hermes/eth/validation/independent"
	"github.com/probe-lab/hermes/eth/validation/delegated"
)

func TestValidationIntegration(t *testing.T) {
	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	
	// Create test config for independent validator
	config := &RouterConfig{
		Mode:   common.ValidatorMode("independent"),
		Logger: logger,
		IndependentConfig: &independent.IndependentConfig{
			Logger:               logger,
			AttestationThreshold: 10,
			SignatureCacheSize:   100,
			CommitteeCacheSize:   100,
			StateUpdateInterval:  30 * time.Second,
			BeaconNodeEndpoint:   "http://localhost:5052",
		},
	}
	
	// Create router
	router, err := NewRouter(config)
	require.NoError(t, err)

	ctx := context.Background()
	
	// Test voluntary exit validation
	t.Run("ValidateVoluntaryExit", func(t *testing.T) {
		// Create a test voluntary exit
		exit := &ethpb.SignedVoluntaryExit{
			Exit: &ethpb.VoluntaryExit{
				Epoch:          10,
				ValidatorIndex: 100,
			},
			Signature: bytesutil.PadTo([]byte("fake_signature"), 96),
		}

		// Marshal to SSZ
		data, err := exit.MarshalSSZ()
		require.NoError(t, err)

		// Create topic validator
		topic := "/eth2/00000000/voluntary_exit/ssz_snappy"
		validator := router.CreateTopicValidator(topic, common.VoluntaryExitMessage)

		// Create mock message
		msg := &pubsub.Message{
			Message: &pb.Message{
				Data:  data,
				Topic: &topic,
			},
		}
		
		// Validate should reject due to no beacon state
		result := validator(ctx, "", msg)
		assert.Equal(t, pubsub.ValidationReject, result) // Will reject due to no state
	})

	// Test attestation validation
	t.Run("ValidateAttestation", func(t *testing.T) {
		// Create a test attestation
		att := &ethpb.Attestation{
			AggregationBits: bytesutil.PadTo([]byte{0x01}, 32),
			Data: &ethpb.AttestationData{
				Slot:            100,
				CommitteeIndex:  0,
				BeaconBlockRoot: bytesutil.PadTo([]byte("block_root"), 32),
				Source: &ethpb.Checkpoint{
					Epoch: 1,
					Root:  bytesutil.PadTo([]byte("source_root"), 32),
				},
				Target: &ethpb.Checkpoint{
					Epoch: 3,
					Root:  bytesutil.PadTo([]byte("target_root"), 32),
				},
			},
			Signature: bytesutil.PadTo([]byte("fake_signature"), 96),
		}

		// Marshal to SSZ
		data, err := att.MarshalSSZ()
		require.NoError(t, err)

		// Create topic validator
		topic := "/eth2/00000000/beacon_attestation_0/ssz_snappy"
		validator := router.CreateTopicValidator(topic, common.BeaconAttestationMessage)

		// Create mock message
		msg := &pubsub.Message{
			Message: &pb.Message{
				Data:  data,
				Topic: &topic,
			},
		}
		
		// Validate should reject due to decoding error
		result := validator(ctx, "", msg)
		assert.Equal(t, pubsub.ValidationReject, result)
	})

	// Test blob sidecar validation
	t.Run("ValidateBlobSidecar", func(t *testing.T) {
		// Create a test blob sidecar
		blob := &ethpb.BlobSidecar{
			Index:                    0,
			Blob:                     make([]byte, 131072), // 128KB blob
			KzgCommitment:            bytesutil.PadTo([]byte("commitment"), 48),
			KzgProof:                 bytesutil.PadTo([]byte("proof"), 48),
			SignedBlockHeader: &ethpb.SignedBeaconBlockHeader{
				Header: &ethpb.BeaconBlockHeader{
					Slot:          100,
					ProposerIndex: 10,
					ParentRoot:    bytesutil.PadTo([]byte("parent"), 32),
					StateRoot:     bytesutil.PadTo([]byte("state"), 32),
					BodyRoot:      bytesutil.PadTo([]byte("body"), 32),
				},
				Signature: bytesutil.PadTo([]byte("fake_signature"), 96),
			},
			// KZG commitment inclusion proof requires 17 elements (depth of the tree)
			CommitmentInclusionProof: func() [][]byte {
				proof := make([][]byte, 17)
				for i := range proof {
					proof[i] = bytesutil.PadTo([]byte{byte(i)}, 32)
				}
				return proof
			}(),
		}

		// Marshal to SSZ
		data, err := blob.MarshalSSZ()
		require.NoError(t, err)

		// Create topic validator
		topic := "/eth2/00000000/blob_sidecar_0/ssz_snappy"
		validator := router.CreateTopicValidator(topic, common.BlobSidecarMessage)

		// Create mock message
		msg := &pubsub.Message{
			Message: &pb.Message{
				Data:  data,
				Topic: &topic,
			},
		}
		
		// Validate should reject due to invalid KZG proof
		result := validator(ctx, "", msg)
		assert.Equal(t, pubsub.ValidationReject, result)
	})

	// Test delegated mode
	t.Run("DelegatedMode", func(t *testing.T) {
		// Create delegated config
		delegatedConfig := &RouterConfig{
			Mode:   common.ValidatorMode("delegated"),
			Logger: logger,
			DelegatedConfig: &delegated.DelegatedConfig{
				Logger:    logger,
				CacheSize: 1000,
				// PrysmClient would need to be set up here
			},
		}

		// Skip test as it requires PrysmClient
		t.Skip("Requires PrysmClient setup")
		
		// Create router
		_, err := NewRouter(delegatedConfig)
		require.Error(t, err) // Should fail without PrysmClient
	})
}

// TestMessageTypeMapping verifies all message types are properly mapped
func TestMessageTypeMapping(t *testing.T) {
	tests := []struct {
		topic       string
		expectedType common.MessageType
	}{
		{"/eth2/00000000/beacon_block/ssz_snappy", common.BeaconBlockMessage},
		{"/eth2/00000000/beacon_aggregate_and_proof/ssz_snappy", common.BeaconAggregateAndProofMessage},
		{"/eth2/00000000/voluntary_exit/ssz_snappy", common.VoluntaryExitMessage},
		{"/eth2/00000000/proposer_slashing/ssz_snappy", common.ProposerSlashingMessage},
		{"/eth2/00000000/attester_slashing/ssz_snappy", common.AttesterSlashingMessage},
		{"/eth2/00000000/beacon_attestation_0/ssz_snappy", common.BeaconAttestationMessage},
		{"/eth2/00000000/sync_committee_0/ssz_snappy", common.SyncCommitteeMessage},
		{"/eth2/00000000/sync_committee_contribution_and_proof/ssz_snappy", common.SyncCommitteeContributionMessage},
		{"/eth2/00000000/bls_to_execution_change/ssz_snappy", common.BlsToExecutionChangeMessage},
		{"/eth2/00000000/blob_sidecar_0/ssz_snappy", common.BlobSidecarMessage},
	}

	for _, tt := range tests {
		t.Run(tt.topic, func(t *testing.T) {
			msgType := common.ClassifyMessage(tt.topic)
			assert.Equal(t, tt.expectedType, msgType)
		})
	}
}