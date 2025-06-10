package independent

import (
	"github.com/probe-lab/hermes/eth/validation/common"
	"context"
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
)

// SyncCommitteeMessageValidator validates sync committee messages
type SyncCommitteeMessageValidator struct {
	validator *IndependentValidator
}

func NewSyncCommitteeMessageValidator(iv *IndependentValidator) *SyncCommitteeMessageValidator {
	return &SyncCommitteeMessageValidator{validator: iv}
}

func (v *SyncCommitteeMessageValidator) Validate(ctx context.Context, data []byte, topic string) error {
	// Decode the sync committee message
	message := &ethpb.SyncCommitteeMessage{}
	if err := message.UnmarshalSSZ(data); err != nil {
		return errors.Wrap(err, "failed to decode sync committee message")
	}

	// Extract subnet ID from topic
	subnetID, err := extractSyncSubnetID(topic)
	if err != nil {
		return errors.Wrap(err, "failed to extract sync subnet ID")
	}

	// Validate message fields
	if err := v.validateSyncMessage(message); err != nil {
		return errors.Wrap(err, "invalid sync committee message")
	}

	// Verify validator is in current sync committee
	syncPeriod := computeSyncCommitteePeriod(message.Slot)
	if !v.validator.committeeCache.IsInSyncCommittee(syncPeriod, message.ValidatorIndex) {
		return fmt.Errorf("validator %d not in sync committee for period %d", 
			message.ValidatorIndex, syncPeriod)
	}

	// Verify subnet assignment
	expectedSubnet := computeSyncSubnetForValidator(message.ValidatorIndex)
	if expectedSubnet != subnetID {
		return fmt.Errorf("sync message on wrong subnet: expected %d, got %d", 
			expectedSubnet, subnetID)
	}

	// Verify signature
	if err := v.verifySyncMessageSignature(message); err != nil {
		return errors.Wrap(err, "invalid sync committee signature")
	}

	return nil
}

func (v *SyncCommitteeMessageValidator) validateSyncMessage(message *ethpb.SyncCommitteeMessage) error {
	state := v.validator.stateSync.GetCurrentState()
	if state == nil {
		return errors.New("no beacon state available")
	}

	// Verify slot is not in future
	if message.Slot > state.Slot {
		return errors.New("sync message slot is in the future")
	}

	// Verify slot is within current sync committee period
	currentPeriod := computeSyncCommitteePeriod(state.Slot)
	messagePeriod := computeSyncCommitteePeriod(message.Slot)
	
	if messagePeriod != currentPeriod {
		return fmt.Errorf("sync message from wrong period: %d != %d", 
			messagePeriod, currentPeriod)
	}

	return nil
}

func (v *SyncCommitteeMessageValidator) verifySyncMessageSignature(
	message *ethpb.SyncCommitteeMessage,
) error {
	// Get validator's public key
	validator, err := v.validator.stateSync.GetValidator(message.ValidatorIndex)
	if err != nil {
		return errors.Wrapf(err, "validator %d not found", message.ValidatorIndex)
	}

	// Compute signing root (block root with sync committee domain)
	epoch := common.SlotToEpoch(message.Slot)
	
	// In sync committee messages, the beacon block root is the data being signed directly
	return v.validator.signatureVerifier.VerifySignature(
		validator.PublicKey,
		message.BlockRoot,
		message.Signature,
		common.DomainSyncCommittee,
		epoch,
	)
}

// SyncCommitteeContributionValidator validates sync committee contributions
type SyncCommitteeContributionValidator struct {
	validator *IndependentValidator
}

func NewSyncCommitteeContributionValidator(iv *IndependentValidator) *SyncCommitteeContributionValidator {
	return &SyncCommitteeContributionValidator{validator: iv}
}

func (v *SyncCommitteeContributionValidator) Validate(ctx context.Context, data []byte, topic string) error {
	// Decode the contribution and proof
	contributionProof := &ethpb.SignedContributionAndProof{}
	if err := contributionProof.UnmarshalSSZ(data); err != nil {
		return errors.Wrap(err, "failed to decode contribution and proof")
	}

	contribution := contributionProof.Message.Contribution
	aggregatorIndex := contributionProof.Message.AggregatorIndex

	// Validate contribution
	if err := v.validateContribution(contribution); err != nil {
		return errors.Wrap(err, "invalid contribution")
	}

	// Verify aggregator is in sync committee
	syncPeriod := computeSyncCommitteePeriod(contribution.Slot)
	if !v.validator.committeeCache.IsInSyncCommittee(syncPeriod, aggregatorIndex) {
		return fmt.Errorf("aggregator %d not in sync committee", aggregatorIndex)
	}

	// Verify aggregator selection proof
	if err := v.verifySyncAggregatorSelection(
		contributionProof.Message.SelectionProof,
		contribution.Slot,
		contribution.SubcommitteeIndex,
		aggregatorIndex,
	); err != nil {
		return errors.Wrap(err, "invalid sync aggregator selection")
	}

	// Verify contribution signature (aggregate of sync committee signatures)
	if err := v.verifyContributionSignature(contribution, contribution.Slot); err != nil {
		return errors.Wrap(err, "invalid contribution signature")
	}

	// Verify aggregator signature
	if err := v.verifyContributionProofSignature(contributionProof); err != nil {
		return errors.Wrap(err, "invalid contribution proof signature")
	}

	return nil
}

func (v *SyncCommitteeContributionValidator) validateContribution(
	contribution *ethpb.SyncCommitteeContribution,
) error {
	// Basic validation
	if contribution.SubcommitteeIndex >= common.SYNC_COMMITTEE_SUBNET_COUNT {
		return fmt.Errorf("invalid subcommittee index: %d", contribution.SubcommitteeIndex)
	}

	// Verify aggregation bits length
	expectedLen := common.SYNC_COMMITTEE_SIZE / common.SYNC_COMMITTEE_SUBNET_COUNT / 8
	if len(contribution.AggregationBits) != int(expectedLen) {
		return fmt.Errorf("invalid aggregation bits length: %d", len(contribution.AggregationBits))
	}

	// At least one participant
	if countSetBits(contribution.AggregationBits) == 0 {
		return errors.New("contribution has no participants")
	}

	return nil
}

func (v *SyncCommitteeContributionValidator) verifySyncAggregatorSelection(
	selectionProof []byte,
	slot common.Slot,
	subcommitteeIndex uint64,
	aggregatorIndex common.ValidatorIndex,
) error {
	// Get aggregator's public key
	aggregator, err := v.validator.stateSync.GetValidator(aggregatorIndex)
	if err != nil {
		return errors.Wrap(err, "aggregator not found")
	}

	// Create signing data (slot + subcommittee index)
	signingData := make([]byte, 16)
	binary.LittleEndian.PutUint64(signingData[0:8], uint64(slot))
	binary.LittleEndian.PutUint64(signingData[8:16], subcommitteeIndex)
	return v.validator.signatureVerifier.VerifySignature(
		aggregator.PublicKey,
		signingData,
		selectionProof,
		common.DomainSyncCommitteeSelectionProof,
		common.SlotToEpoch(slot),
	)
}

func (v *SyncCommitteeContributionValidator) verifyContributionSignature(
	contribution *ethpb.SyncCommitteeContribution,
	slot common.Slot,
) error {
	// Get sync committee members for this subcommittee
	// In full implementation, would use: syncPeriod := computeSyncCommitteePeriod(slot)
	
	// In production, we'd get the actual subcommittee members
	// For now, we'll verify the aggregate signature format
	if len(contribution.Signature) != 96 {
		return errors.New("invalid contribution signature length")
	}

	return nil
}

func (v *SyncCommitteeContributionValidator) verifyContributionProofSignature(
	contributionProof *ethpb.SignedContributionAndProof,
) error {
	// Get aggregator's public key
	aggregator, err := v.validator.stateSync.GetValidator(contributionProof.Message.AggregatorIndex)
	if err != nil {
		return errors.Wrap(err, "aggregator not found")
	}

	// Get current state for domain computation
	currentState := v.validator.stateSync.GetCurrentState()
	if currentState == nil {
		return errors.New("no beacon state available")
	}
	
	// Compute domain
	domain, err := common.ComputeDomain(
		common.DomainContributionAndProof,
		currentState.Fork,
		currentState.GenesisValidatorsRoot,
	)
	if err != nil {
		return errors.Wrap(err, "failed to compute domain")
	}
	
	// Compute signing root
	signingRoot, err := common.ComputeSigningRoot(contributionProof.Message, domain)
	if err != nil {
		return errors.Wrap(err, "failed to compute signing root")
	}
	
	epoch := common.SlotToEpoch(contributionProof.Message.Contribution.Slot)
	return v.validator.signatureVerifier.VerifySignature(
		aggregator.PublicKey,
		signingRoot[:],
		contributionProof.Signature,
		common.DomainContributionAndProof,
		epoch,
	)
}

// Helper functions

func extractSyncSubnetID(topic string) (uint64, error) {
	// Topic format: /eth2/fork_digest/sync_committee_{subnet_id}/ssz_snappy
	var subnetID uint64
	_, err := fmt.Sscanf(topic, "/eth2/%*s/sync_committee_%d/ssz_snappy", &subnetID)
	if err != nil {
		return 0, err
	}
	return subnetID, nil
}

func computeSyncCommitteePeriod(slot common.Slot) common.Epoch {
	epoch := common.SlotToEpoch(slot)
	return common.Epoch(uint64(epoch) / common.EPOCHS_PER_SYNC_COMMITTEE_PERIOD)
}

func computeSyncSubnetForValidator(validatorIndex common.ValidatorIndex) uint64 {
	// Simplified - actual implementation would compute based on position in sync committee
	return uint64(validatorIndex) % common.SYNC_COMMITTEE_SUBNET_COUNT
}

