package independent

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/golang/snappy"
	"github.com/pkg/errors"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/probe-lab/hermes/eth/validation/common"
)

// SyncCommitteeMessageValidator validates sync committee messages
type SyncCommitteeMessageValidator struct {
	validator *IndependentValidator
}

// NewSyncCommitteeMessageValidator creates a new sync committee message validator
func NewSyncCommitteeMessageValidator(iv *IndependentValidator) *SyncCommitteeMessageValidator {
	return &SyncCommitteeMessageValidator{validator: iv}
}

// Validate validates a sync committee message
func (v *SyncCommitteeMessageValidator) Validate(ctx context.Context, data []byte, topic string) error {
	// Decompress the snappy-compressed data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return errors.Wrap(err, "failed to decompress snappy data")
	}
	
	// Decode using consensus spec type
	msg := &altair.SyncCommitteeMessage{}
	if err := msg.UnmarshalSSZ(decompressed); err != nil {
		return errors.Wrap(err, "failed to decode sync committee message")
	}

	// Get current state
	state := v.validator.stateSync.GetCurrentState()
	if state == nil {
		return errors.New("current state not available")
	}

	// Validate slot
	currentSlot := state.Slot
	if common.Slot(msg.Slot) > currentSlot {
		return fmt.Errorf("sync committee message slot %d is from the future (current slot: %d)", msg.Slot, currentSlot)
	}

	// Get sync committee period
	period := uint64(msg.Slot) / (32 * 256) // SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD

	// Determine which sync committee to use
	currentPeriod := uint64(state.Slot) / (32 * 256)
	
	var syncCommittee *SyncCommitteeInfo
	if period == currentPeriod {
		syncCommittee = state.CurrentSyncCommittee
	} else if period == currentPeriod+1 {
		syncCommittee = state.NextSyncCommittee
	} else {
		return fmt.Errorf("sync committee message is for period %d, but current period is %d", period, currentPeriod)
	}

	if syncCommittee == nil {
		return errors.New("sync committee not available for validation period")
	}

	// Verify validator is in sync committee
	if msg.ValidatorIndex >= phase0.ValidatorIndex(len(syncCommittee.ValidatorIndices)) {
		return fmt.Errorf("validator index %d not in sync committee", msg.ValidatorIndex)
	}

	// Get validator's public key
	validatorInfo, exists := state.Validators[common.ValidatorIndex(msg.ValidatorIndex)]
	if !exists {
		return fmt.Errorf("validator %d not found in validator set", msg.ValidatorIndex)
	}

	// Create a simple container for slot and beacon block root
	containerBytes := make([]byte, 40) // 8 bytes for slot + 32 bytes for root
	binary.LittleEndian.PutUint64(containerBytes[0:8], uint64(msg.Slot))
	copy(containerBytes[8:40], msg.BeaconBlockRoot[:])

	// Verify signature
	return v.validator.signatureVerifier.VerifySignature(
		validatorInfo.PublicKey, 
		containerBytes, 
		msg.Signature[:],
		common.DomainSyncCommittee,
		state.Epoch,
	)
}

// SyncCommitteeContributionValidator validates sync committee contributions
type SyncCommitteeContributionValidator struct {
	validator *IndependentValidator
}

// NewSyncCommitteeContributionValidator creates a new sync committee contribution validator
func NewSyncCommitteeContributionValidator(iv *IndependentValidator) *SyncCommitteeContributionValidator {
	return &SyncCommitteeContributionValidator{validator: iv}
}

// Validate validates a sync committee contribution and proof
func (v *SyncCommitteeContributionValidator) Validate(ctx context.Context, data []byte, topic string) error {
	// Decompress the snappy-compressed data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return errors.Wrap(err, "failed to decompress snappy data")
	}
	
	// Decode using consensus spec type
	contributionAndProof := &altair.SignedContributionAndProof{}
	if err := contributionAndProof.UnmarshalSSZ(decompressed); err != nil {
		return errors.Wrap(err, "failed to decode contribution and proof")
	}

	if contributionAndProof.Message == nil || contributionAndProof.Message.Contribution == nil {
		return errors.New("nil contribution or proof")
	}

	msg := contributionAndProof.Message
	contribution := msg.Contribution

	// Get current state
	state := v.validator.stateSync.GetCurrentState()
	if state == nil {
		return errors.New("current state not available")
	}

	// Basic validations
	currentSlot := state.Slot
	if common.Slot(contribution.Slot) > currentSlot {
		return fmt.Errorf("contribution slot %d is from the future (current slot: %d)", contribution.Slot, currentSlot)
	}

	// Verify aggregator is valid
	aggregatorIndex := msg.AggregatorIndex
	validatorInfo, exists := state.Validators[common.ValidatorIndex(aggregatorIndex)]
	if !exists {
		return fmt.Errorf("aggregator %d not found in validator set", aggregatorIndex)
	}

	// Verify selection proof
	// Create selection data bytes (slot + subcommittee index)
	selectionBytes := make([]byte, 16) // 8 bytes for slot + 8 bytes for subcommittee index
	binary.LittleEndian.PutUint64(selectionBytes[0:8], uint64(contribution.Slot))
	binary.LittleEndian.PutUint64(selectionBytes[8:16], contribution.SubcommitteeIndex)

	if err := v.validator.signatureVerifier.VerifySignature(
		validatorInfo.PublicKey, 
		selectionBytes, 
		msg.SelectionProof[:],
		common.DomainSyncCommitteeSelectionProof,
		state.Epoch,
	); err != nil {
		return errors.Wrap(err, "invalid selection proof")
	}

	// Verify contribution signature
	// Serialize the contribution and proof message
	msgBytes, err := msg.MarshalSSZ()
	if err != nil {
		return errors.Wrap(err, "failed to serialize contribution and proof")
	}

	return v.validator.signatureVerifier.VerifySignature(
		validatorInfo.PublicKey, 
		msgBytes, 
		contributionAndProof.Signature[:],
		common.DomainContributionAndProof,
		state.Epoch,
	)
}

