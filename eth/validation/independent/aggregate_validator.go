package independent

import (
	"context"
	"fmt"

	"github.com/golang/snappy"
	"github.com/pkg/errors"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	"github.com/probe-lab/hermes/eth/validation/common"
)

// AggregateAndProofValidator validates aggregate and proof messages
type AggregateAndProofValidator struct {
	validator *IndependentValidator
}

// NewAggregateAttestationValidator creates a new aggregate attestation validator
func NewAggregateAttestationValidator(iv *IndependentValidator) *AggregateAndProofValidator {
	return &AggregateAndProofValidator{validator: iv}
}

// Validate validates an aggregate and proof
func (v *AggregateAndProofValidator) Validate(ctx context.Context, data []byte, topic string) error {
	// Decompress the snappy-compressed data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return errors.Wrap(err, "failed to decompress snappy data")
	}
	
	// Decode using consensus spec type
	aggregateAndProof := &phase0.SignedAggregateAndProof{}
	if err := aggregateAndProof.UnmarshalSSZ(decompressed); err != nil {
		return errors.Wrap(err, "failed to decode aggregate and proof")
	}

	if aggregateAndProof.Message == nil || aggregateAndProof.Message.Aggregate == nil {
		return errors.New("nil aggregate or proof")
	}

	msg := aggregateAndProof.Message
	aggregate := msg.Aggregate

	// Get current state
	state := v.validator.stateSync.GetCurrentState()
	if state == nil {
		return errors.New("no beacon state available")
	}

	// Basic validations
	currentSlot := state.Slot
	if common.Slot(aggregate.Data.Slot) > currentSlot {
		return fmt.Errorf("attestation slot %d is from the future (current slot: %d)", aggregate.Data.Slot, currentSlot)
	}

	// Verify aggregator is valid
	aggregatorIndex := msg.AggregatorIndex
	validatorInfo, exists := state.Validators[common.ValidatorIndex(aggregatorIndex)]
	if !exists {
		return fmt.Errorf("aggregator %d not found in validator set", aggregatorIndex)
	}

	// Check aggregator is active
	currentEpoch := state.Epoch
	if !validatorInfo.Active {
		return fmt.Errorf("aggregator %d is not active in epoch %d", aggregatorIndex, currentEpoch)
	}

	// Verify selection proof
	slot := aggregate.Data.Slot
	committeeIndex := aggregate.Data.Index

	// Compute selection proof domain
	domain, err := common.ComputeDomain(common.DomainSelectionProof, state.Fork, state.GenesisValidatorsRoot)
	if err != nil {
		return errors.Wrap(err, "failed to compute selection proof domain")
	}

	selectionData := struct {
		Slot  phase0.Slot
		Index phase0.CommitteeIndex
	}{
		Slot:  slot,
		Index: committeeIndex,
	}

	selectionRoot, err := common.ComputeSigningRoot(selectionData, domain)
	if err != nil {
		return errors.Wrap(err, "failed to compute selection root")
	}

	// Verify selection proof signature
	if err := v.validator.signatureVerifier.VerifySignature(
		validatorInfo.PublicKey,
		selectionRoot[:],
		msg.SelectionProof[:],
		common.DomainSelectionProof,
		common.Epoch(slot/32),
	); err != nil {
		return errors.Wrap(err, "invalid selection proof")
	}

	// Verify aggregate signature
	aggregateDomain, err := common.ComputeDomain(common.DomainAggregateAndProof, state.Fork, state.GenesisValidatorsRoot)
	if err != nil {
		return errors.Wrap(err, "failed to compute aggregate domain")
	}

	aggregateRoot, err := common.ComputeSigningRoot(msg, aggregateDomain)
	if err != nil {
		return errors.Wrap(err, "failed to compute aggregate signing root")
	}

	// Verify the aggregator's signature
	if err := v.validator.signatureVerifier.VerifySignature(
		validatorInfo.PublicKey,
		aggregateRoot[:],
		aggregateAndProof.Signature[:],
		common.DomainAggregateAndProof,
		common.Epoch(slot/32),
	); err != nil {
		return errors.Wrap(err, "invalid aggregate signature")
	}

	// Verify the aggregate attestation itself
	return v.verifyAggregateAttestation(ctx, aggregate, state)
}

func (v *AggregateAndProofValidator) verifyAggregateAttestation(ctx context.Context, attestation *phase0.Attestation, state *BeaconState) error {
	// Get attestation data
	data := attestation.Data
	
	// Verify attestation targets correct epoch
	targetEpoch := data.Target.Epoch
	currentEpoch := state.Epoch
	
	// Attestations can be included up to 32 epochs late
	if targetEpoch > phase0.Epoch(currentEpoch) {
		return fmt.Errorf("attestation targets future epoch %d (current: %d)", targetEpoch, currentEpoch)
	}
	
	if phase0.Epoch(currentEpoch) > targetEpoch+32 {
		return fmt.Errorf("attestation is too old, targets epoch %d (current: %d)", targetEpoch, currentEpoch)
	}

	// Get the committee for this attestation
	committee, err := v.validator.committeeCache.GetCommittee(common.Slot(data.Slot), primitives.CommitteeIndex(data.Index))
	if err != nil {
		return errors.Wrap(err, "failed to get committee")
	}

	if committee == nil {
		return fmt.Errorf("committee %d not found for slot %d", data.Index, data.Slot)
	}

	// Verify aggregation bits length matches committee size
	if attestation.AggregationBits.Len() != uint64(len(committee.ValidatorIndices)) {
		return fmt.Errorf("aggregation bits length %d doesn't match committee size %d",
			attestation.AggregationBits.Len(), len(committee.ValidatorIndices))
	}

	// Count number of participants
	numParticipants := 0
	for i := uint64(0); i < attestation.AggregationBits.Len(); i++ {
		if attestation.AggregationBits.BitAt(i) {
			numParticipants++
		}
	}

	if numParticipants == 0 {
		return errors.New("aggregate attestation has no participants")
	}

	// Note: Full BLS aggregate signature verification would be done here
	// but requires aggregating public keys of all participants

	return nil
}