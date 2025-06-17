package independent

import (
	"context"
	"fmt"

	"github.com/probe-lab/hermes/eth/pubsub/common"

	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/golang/snappy"
	"github.com/pkg/errors"
)

// SingleAttestationValidator validates individual attestation messages for Electra and later forks
type SingleAttestationValidator struct {
	validator *IndependentValidator
}

func NewSingleAttestationValidator(iv *IndependentValidator) *SingleAttestationValidator {
	return &SingleAttestationValidator{validator: iv}
}

func (v *SingleAttestationValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
	// Decompress the snappy-compressed data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decompress snappy data")
	}

	// Decode the single attestation
	attestation := &ethpb.SingleAttestation{}
	if err := attestation.UnmarshalSSZ(decompressed); err != nil {
		return nil, errors.Wrap(err, "failed to decode single attestation")
	}

	// Extract subnet ID from topic
	subnetID, err := extractSubnetIDForSingleAttestation(topic)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract subnet ID")
	}

	// Basic attestation validation
	if err := v.validateSingleAttestationData(attestation.Data); err != nil {
		return nil, errors.Wrap(err, "invalid attestation data")
	}

	// Get committee for this attestation
	committee, err := v.validator.committeeCache.GetCommittee(
		attestation.Data.Slot,
		attestation.Data.CommitteeIndex,
	)
	if err != nil {
		return nil, errors.Wrap(err, "committee not found")
	}

	// Verify attester is in committee
	attesterIndex := common.ValidatorIndex(attestation.AttesterIndex)
	found := false
	for _, validatorIndex := range committee.ValidatorIndices {
		if validatorIndex == attesterIndex {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("attester %d not in committee", attesterIndex)
	}

	// Verify subnet assignment
	expectedSubnet := computeSubnetForSingleAttestation(
		attestation.Data.Slot,
		uint64(attestation.Data.CommitteeIndex),
	)
	if expectedSubnet != subnetID {
		return nil, fmt.Errorf("attestation on wrong subnet: expected %d, got %d",
			expectedSubnet, subnetID)
	}

	// Verify signature
	if err := v.verifySingleAttestationSignature(attestation); err != nil {
		return nil, errors.Wrap(err, "invalid attestation signature")
	}

	// Track this attestation for block validation
	v.trackSingleAttestation(attestation)

	return attestation, nil
}

func (v *SingleAttestationValidator) validateSingleAttestationData(data *ethpb.AttestationData) error {
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

func (v *SingleAttestationValidator) verifySingleAttestationSignature(
	attestation *ethpb.SingleAttestation,
) error {
	// Get attester's public key
	attesterIndex := common.ValidatorIndex(attestation.AttesterIndex)
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

func (v *SingleAttestationValidator) trackSingleAttestation(
	attestation *ethpb.SingleAttestation,
) {
	// Track attestation for the beacon block root
	blockRoot := [32]byte{}
	copy(blockRoot[:], attestation.Data.BeaconBlockRoot)

	attesterIndex := common.ValidatorIndex(attestation.AttesterIndex)
	v.validator.attestationTracker.TrackAttestation(
		blockRoot,
		attestation.Data.Slot,
		uint64(attestation.Data.CommitteeIndex),
		attesterIndex,
	)
}

// Helper functions

func extractSubnetIDForSingleAttestation(topic string) (uint64, error) {
	// Topic format: /eth2/fork_digest/beacon_attestation_{subnet_id}/ssz_snappy
	// Extract subnet_id from the topic string
	var subnetID uint64
	_, err := fmt.Sscanf(topic, "/eth2/%*s/beacon_attestation_%d/ssz_snappy", &subnetID)
	if err != nil {
		return 0, err
	}

	return subnetID, nil
}

func computeSubnetForSingleAttestation(slot common.Slot, committeeIndex uint64) uint64 {
	// Simplified computation - actual implementation would follow spec
	committeesPerSlot := uint64(64) // This should be computed based on validator count
	committeeCount := uint64(slot)*committeesPerSlot + committeeIndex
	return committeeCount % common.ATTESTATION_SUBNET_COUNT
}
