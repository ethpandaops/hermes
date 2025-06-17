package independent

import (
	"github.com/probe-lab/hermes/eth/validation/common"
	"context"
	"fmt"

	"github.com/golang/snappy"
	"github.com/pkg/errors"
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
)

// StandardAttestationValidator validates individual attestation messages
type StandardAttestationValidator struct {
	validator *IndependentValidator
}

func NewStandardAttestationValidator(iv *IndependentValidator) *StandardAttestationValidator {
	return &StandardAttestationValidator{validator: iv}
}

func (v *StandardAttestationValidator) Validate(ctx context.Context, data []byte, topic string) error {
	// Decompress the snappy-compressed data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return errors.Wrap(err, "failed to decompress snappy data")
	}
	
	// Decode the attestation
	attestation := &ethpb.Attestation{}
	if err := attestation.UnmarshalSSZ(decompressed); err != nil {
		return errors.Wrap(err, "failed to decode attestation")
	}

	// Extract subnet ID from topic
	subnetID, err := extractSubnetID(topic)
	if err != nil {
		return errors.Wrap(err, "failed to extract subnet ID")
	}

	// Basic attestation validation
	if err := v.validateAttestationData(attestation.Data); err != nil {
		return errors.Wrap(err, "invalid attestation data")
	}

	// Get committee for this attestation
	committee, err := v.validator.committeeCache.GetCommittee(
		attestation.Data.Slot,
		attestation.Data.CommitteeIndex,
	)
	if err != nil {
		return errors.Wrap(err, "committee not found")
	}

	// Verify subnet assignment
	expectedSubnet := computeSubnetForAttestation(
		attestation.Data.Slot,
		uint64(attestation.Data.CommitteeIndex),
	)
	if expectedSubnet != subnetID {
		return fmt.Errorf("attestation on wrong subnet: expected %d, got %d", 
			expectedSubnet, subnetID)
	}

	// Verify aggregation bits (should have exactly one bit set for individual attestations)
	setBits := countSetBits(attestation.AggregationBits)
	if setBits != 1 {
		return fmt.Errorf("individual attestation must have exactly 1 bit set, got %d", setBits)
	}

	// Get the attester index
	attesterIndex := v.getAttesterIndex(committee, attestation.AggregationBits)
	if attesterIndex == nil {
		return errors.New("could not determine attester index")
	}

	// Verify signature
	if err := v.verifyAttestationSignature(attestation, *attesterIndex); err != nil {
		return errors.Wrap(err, "invalid attestation signature")
	}

	// Track this attestation for block validation
	v.trackAttestation(attestation, *attesterIndex)

	return nil
}

func (v *StandardAttestationValidator) validateAttestationData(data *ethpb.AttestationData) error {
	state := v.validator.stateSync.GetCurrentState()
	if state == nil {
		return errors.New("no beacon state available")
	}

	// Verify slot is not too far in the past or future
	currentSlot := state.Slot
	if data.Slot > currentSlot {
		return errors.New("attestation slot is in the future")
	}

	// Check attestation is recent (within epoch)
	if currentSlot > data.Slot+common.SLOTS_PER_EPOCH {
		return errors.New("attestation is too old")
	}

	// Verify target epoch
	expectedEpoch := common.SlotToEpoch(data.Slot)
	if data.Target.Epoch != expectedEpoch {
		return fmt.Errorf("target epoch %d does not match slot epoch %d", 
			data.Target.Epoch, expectedEpoch)
	}

	// Verify source is justified checkpoint
	if data.Source.Epoch > data.Target.Epoch {
		return errors.New("source epoch after target epoch")
	}

	return nil
}

func (v *StandardAttestationValidator) getAttesterIndex(
	committee *common.CommitteeAssignment,
	aggregationBits []byte,
) *common.ValidatorIndex {
	// Find the single set bit
	for i := 0; i < len(committee.ValidatorIndices) && i < len(aggregationBits)*8; i++ {
		byteIndex := i / 8
		bitIndex := i % 8
		
		if aggregationBits[byteIndex]&(1<<uint(bitIndex)) != 0 {
			idx := committee.ValidatorIndices[i]
			return &idx
		}
	}
	
	return nil
}

func (v *StandardAttestationValidator) verifyAttestationSignature(
	attestation *ethpb.Attestation,
	attesterIndex common.ValidatorIndex,
) error {
	// Get attester's public key
	attester, err := v.validator.stateSync.GetValidator(attesterIndex)
	if err != nil {
		return errors.Wrapf(err, "validator %d not found", attesterIndex)
	}

	// Get current state for domain computation
	currentState := v.validator.stateSync.GetCurrentState()
	if currentState == nil {
		return errors.New("no beacon state available")
	}
	
	// Compute domain
	domain, err := common.ComputeDomain(
		common.DomainBeaconAttester,
		currentState.Fork,
		currentState.GenesisValidatorsRoot,
	)
	if err != nil {
		return errors.Wrap(err, "failed to compute domain")
	}
	
	// Compute signing root
	signingRoot, err := common.ComputeSigningRoot(attestation.Data, domain)
	if err != nil {
		return errors.Wrap(err, "failed to compute signing root")
	}
	
	// Verify signature
	return v.validator.signatureVerifier.VerifySignature(
		attester.PublicKey,
		signingRoot[:],
		attestation.Signature,
		common.DomainBeaconAttester,
		attestation.Data.Target.Epoch,
	)
}

func (v *StandardAttestationValidator) trackAttestation(
	attestation *ethpb.Attestation,
	attesterIndex common.ValidatorIndex,
) {
	// Track attestation for the beacon block root
	blockRoot := [32]byte{}
	copy(blockRoot[:], attestation.Data.BeaconBlockRoot)

	v.validator.attestationTracker.TrackAttestation(
		blockRoot,
		attestation.Data.Slot,
		uint64(attestation.Data.CommitteeIndex),
		attesterIndex,
	)
}

// Helper functions

func extractSubnetID(topic string) (uint64, error) {
	// Topic format: /eth2/fork_digest/beacon_attestation_{subnet_id}/ssz_snappy
	// Extract subnet_id from the topic string
	
	// Simplified extraction - in production would parse properly
	var subnetID uint64
	_, err := fmt.Sscanf(topic, "/eth2/%*s/beacon_attestation_%d/ssz_snappy", &subnetID)
	if err != nil {
		return 0, err
	}
	
	return subnetID, nil
}

func countSetBits(bits []byte) int {
	count := 0
	for _, b := range bits {
		for i := 0; i < 8; i++ {
			if b&(1<<uint(i)) != 0 {
				count++
			}
		}
	}
	return count
}

func computeSubnetForAttestation(slot common.Slot, committeeIndex uint64) uint64 {
	// Simplified computation - actual implementation would follow spec
	committeesPerSlot := uint64(64) // This should be computed based on validator count
	committeeCount := uint64(slot)*committeesPerSlot + committeeIndex
	return committeeCount % common.ATTESTATION_SUBNET_COUNT
}

