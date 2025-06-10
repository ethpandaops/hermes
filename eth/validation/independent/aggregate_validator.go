package independent

import (
	"github.com/probe-lab/hermes/eth/validation/common"
	"context"
	"encoding/binary"

	"github.com/pkg/errors"
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
)

// AggregateAttestationValidator validates aggregate attestation messages
type AggregateAttestationValidator struct {
	validator *IndependentValidator
}

func NewAggregateAttestationValidator(iv *IndependentValidator) *AggregateAttestationValidator {
	return &AggregateAttestationValidator{validator: iv}
}

func (v *AggregateAttestationValidator) Validate(ctx context.Context, data []byte, topic string) error {
	// Decode the signed aggregate and proof
	aggProof := &ethpb.SignedAggregateAttestationAndProof{}
	if err := aggProof.UnmarshalSSZ(data); err != nil {
		return errors.Wrap(err, "failed to decode aggregate and proof")
	}

	aggregate := aggProof.Message.Aggregate
	aggregatorIndex := aggProof.Message.AggregatorIndex

	// Basic attestation validation
	if err := v.validateAttestationData(aggregate.Data); err != nil {
		return errors.Wrap(err, "invalid attestation data")
	}

	// Get committee for this attestation
	committee, err := v.validator.committeeCache.GetCommittee(
		aggregate.Data.Slot,
		aggregate.Data.CommitteeIndex,
	)
	if err != nil {
		return errors.Wrap(err, "committee not found")
	}

	// Verify aggregator is in the committee
	if !v.isInCommittee(aggregatorIndex, committee) {
		return errors.New("aggregator not in committee")
	}

	// Verify aggregator selection proof
	if err := v.verifyAggregatorSelection(
		aggProof.Message.SelectionProof,
		aggregate.Data.Slot,
		aggregatorIndex,
	); err != nil {
		return errors.Wrap(err, "invalid aggregator selection proof")
	}

	// Get attesters from aggregation bits
	attesterIndices := v.getAttesterIndices(committee, aggregate.AggregationBits)
	if len(attesterIndices) == 0 {
		return errors.New("no attesters in aggregate")
	}

	// Verify aggregate signature covers all attesters
	if err := v.verifyAggregateSignature(
		aggregate,
		attesterIndices,
		aggregate.Data.Target.Epoch,
	); err != nil {
		return errors.Wrap(err, "invalid aggregate signature")
	}

	// Verify aggregator signature
	if err := v.verifyAggregatorSignature(aggProof); err != nil {
		return errors.Wrap(err, "invalid aggregator signature")
	}

	// Track this attestation for block validation
	v.trackAggregateAttestation(aggregate, attesterIndices)

	return nil
}

func (v *AggregateAttestationValidator) validateAttestationData(data *ethpb.AttestationData) error {
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

	// Verify source checkpoint
	if data.Source.Epoch > data.Target.Epoch {
		return errors.New("source epoch after target epoch")
	}

	return nil
}

func (v *AggregateAttestationValidator) isInCommittee(
	validatorIndex common.ValidatorIndex,
	committee *common.CommitteeAssignment,
) bool {
	for _, idx := range committee.ValidatorIndices {
		if idx == validatorIndex {
			return true
		}
	}
	return false
}

func (v *AggregateAttestationValidator) verifyAggregatorSelection(
	selectionProof []byte,
	slot common.Slot,
	aggregatorIndex common.ValidatorIndex,
) error {
	// Get aggregator's public key
	aggregator, err := v.validator.stateSync.GetValidator(aggregatorIndex)
	if err != nil {
		return errors.Wrap(err, "aggregator not found")
	}

	// Compute signing root for slot
	slotBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(slotBytes, uint64(slot))
	
	epoch := common.SlotToEpoch(slot)
	return v.validator.signatureVerifier.VerifySignature(
		aggregator.PublicKey,
		slotBytes,
		selectionProof,
		common.DomainSelectionProof,
		epoch,
	)
}

func (v *AggregateAttestationValidator) getAttesterIndices(
	committee *common.CommitteeAssignment,
	aggregationBits []byte,
) []common.ValidatorIndex {
	var indices []common.ValidatorIndex
	
	// Convert aggregation bits to attester indices
	for i := 0; i < len(committee.ValidatorIndices) && i < len(aggregationBits)*8; i++ {
		byteIndex := i / 8
		bitIndex := i % 8
		
		if aggregationBits[byteIndex]&(1<<uint(bitIndex)) != 0 {
			indices = append(indices, committee.ValidatorIndices[i])
		}
	}
	
	return indices
}

func (v *AggregateAttestationValidator) verifyAggregateSignature(
	attestation *ethpb.Attestation,
	attesterIndices []common.ValidatorIndex,
	epoch common.Epoch,
) error {
	// Get public keys for all attesters
	pubKeys := make([][]byte, len(attesterIndices))
	for i, idx := range attesterIndices {
		validator, err := v.validator.stateSync.GetValidator(idx)
		if err != nil {
			return errors.Wrapf(err, "validator %d not found", idx)
		}
		pubKeys[i] = validator.PublicKey
	}

	// Get current state for domain computation
	currentState := v.validator.stateSync.GetCurrentState()
	if currentState == nil {
		return errors.New("no beacon state available")
	}
	
	// TODO: Implement proper domain computation
	// For now, use a placeholder domain
	domain := [32]byte{}
	_ = domain
	
	// TODO: Implement proper signing root computation
	// For now, use beacon block root as signing root
	signingRoot := [32]byte{}
	copy(signingRoot[:], attestation.Data.BeaconBlockRoot)

	// Verify aggregate signature
	return v.validator.signatureVerifier.VerifyAggregateSignature(
		pubKeys,
		signingRoot[:],
		attestation.Signature,
		common.DomainBeaconAttester,
		epoch,
	)
}

func (v *AggregateAttestationValidator) verifyAggregatorSignature(
	aggProof *ethpb.SignedAggregateAttestationAndProof,
) error {
	// Get aggregator's public key
	aggregator, err := v.validator.stateSync.GetValidator(aggProof.Message.AggregatorIndex)
	if err != nil {
		return errors.Wrap(err, "aggregator not found")
	}

	// Get current state for domain computation
	currentState := v.validator.stateSync.GetCurrentState()
	if currentState == nil {
		return errors.New("no beacon state available")
	}
	
	// Compute domain
	epoch := common.SlotToEpoch(aggProof.Message.Aggregate.Data.Slot)
	domain, err := common.ComputeDomain(
		common.DomainAggregateAndProof,
		currentState.Fork,
		currentState.GenesisValidatorsRoot,
	)
	if err != nil {
		return errors.Wrap(err, "failed to compute domain")
	}
	
	// Compute signing root
	signingRoot, err := common.ComputeSigningRoot(aggProof.Message, domain)
	if err != nil {
		return errors.Wrap(err, "failed to compute signing root")
	}
	return v.validator.signatureVerifier.VerifySignature(
		aggregator.PublicKey,
		signingRoot[:],
		aggProof.Signature,
		common.DomainAggregateAndProof,
		epoch,
	)
}

func (v *AggregateAttestationValidator) trackAggregateAttestation(
	attestation *ethpb.Attestation,
	attesterIndices []common.ValidatorIndex,
) {
	// Track attestations for the beacon block root
	blockRoot := [32]byte{}
	copy(blockRoot[:], attestation.Data.BeaconBlockRoot)

	// Track each attester's vote
	for _, idx := range attesterIndices {
		v.validator.attestationTracker.TrackAttestation(
			blockRoot,
			attestation.Data.Slot,
			uint64(attestation.Data.CommitteeIndex),
			idx,
		)
	}
}