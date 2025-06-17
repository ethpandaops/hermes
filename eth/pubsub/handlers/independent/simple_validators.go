package independent

import (
	"bytes"
	"context"
	"fmt"

	"github.com/golang/snappy"
	"github.com/pkg/errors"
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	
	"github.com/probe-lab/hermes/eth/pubsub/common"
)

// VoluntaryExitValidator validates voluntary exit messages
type VoluntaryExitValidator struct {
	validator *IndependentValidator
}

func NewVoluntaryExitValidator(iv *IndependentValidator) *VoluntaryExitValidator {
	return &VoluntaryExitValidator{validator: iv}
}

func (v *VoluntaryExitValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
	// Decompress the snappy-compressed data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decompress snappy data")
	}
	
	// Decode the signed voluntary exit
	exit := &ethpb.SignedVoluntaryExit{}
	if err := exit.UnmarshalSSZ(decompressed); err != nil {
		return nil, errors.Wrap(err, "failed to decode voluntary exit")
	}

	// Get validator info from state
	state := v.validator.stateSync.GetCurrentState()
	if state == nil {
		return nil, errors.New("no beacon state available")
	}
	
	validatorIdx := exit.Exit.ValidatorIndex
	validator, exists := state.Validators[common.ValidatorIndex(validatorIdx)]
	if !exists {
		return nil, errors.New("validator not found")
	}

	// Check validator is active (would need to calculate based on activation/exit epochs)
	// For now, skip this check

	// Check validator is not already exited
	if validator.ExitEpoch != 18446744073709551615 { // FAR_FUTURE_EPOCH
		return nil, errors.New("validator already has exit epoch set")
	}

	// Check epoch is valid (not too far in future)
	currentEpoch := v.validator.stateSync.GetCurrentState().Epoch
	if exit.Exit.Epoch < currentEpoch {
		return nil, errors.New("exit epoch is in the past")
	}

	// Compute signing root and verify signature
	currentState := v.validator.stateSync.GetCurrentState()
	if currentState == nil {
		return nil, errors.New("no beacon state available")
	}
	
	domain, err := common.ComputeDomain(
		common.DomainVoluntaryExit,
		currentState.Fork,
		currentState.GenesisValidatorsRoot,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute domain")
	}
	
	signingRoot, err := common.ComputeSigningRoot(exit.Exit, domain)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute signing root")
	}
	
	err = v.validator.signatureVerifier.VerifySignature(
		validator.PublicKey,
		signingRoot[:],
		exit.Signature,
		common.DomainVoluntaryExit,
		exit.Exit.Epoch,
	)
	if err != nil {
		return nil, err
	}
	return exit, nil
}

// ProposerSlashingValidator validates proposer slashing messages
type ProposerSlashingValidator struct {
	validator *IndependentValidator
}

func NewProposerSlashingValidator(iv *IndependentValidator) *ProposerSlashingValidator {
	return &ProposerSlashingValidator{validator: iv}
}

func (v *ProposerSlashingValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
	// Decompress the snappy-compressed data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decompress snappy data")
	}
	
	// Decode the proposer slashing
	slashing := &ethpb.ProposerSlashing{}
	if err := slashing.UnmarshalSSZ(decompressed); err != nil {
		return nil, errors.Wrap(err, "failed to decode proposer slashing")
	}

	// Verify headers are different
	if slashing.Header_1.Header.Slot != slashing.Header_2.Header.Slot {
		return nil, errors.New("proposer slashing headers must be for same slot")
	}

	// Verify headers have same proposer
	if slashing.Header_1.Header.ProposerIndex != slashing.Header_2.Header.ProposerIndex {
		return nil, errors.New("proposer slashing headers must have same proposer")
	}

	// Verify headers are different (double proposal)
	h1Root, _ := slashing.Header_1.Header.HashTreeRoot()
	h2Root, _ := slashing.Header_2.Header.HashTreeRoot()
	if bytes.Equal(h1Root[:], h2Root[:]) {
		return nil, errors.New("proposer slashing headers are identical")
	}

	// Get proposer info
	proposerIndex := slashing.Header_1.Header.ProposerIndex
	proposer, err := v.validator.stateSync.GetValidator(proposerIndex)
	if err != nil {
		return nil, errors.Wrap(err, "proposer not found")
	}

	// Check proposer is slashable
	if !proposer.Active || proposer.Slashed {
		return nil, errors.New("proposer is not slashable")
	}

	// Get current state for domain computation
	currentState := v.validator.stateSync.GetCurrentState()
	if currentState == nil {
		return nil, errors.New("no beacon state available")
	}
	
	// Compute domain
	epoch := common.SlotToEpoch(slashing.Header_1.Header.Slot)
	domain, err := common.ComputeDomain(
		common.DomainBeaconProposer,
		currentState.Fork,
		currentState.GenesisValidatorsRoot,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute domain")
	}

	// Verify first header signature
	signingRoot1, err := common.ComputeSigningRoot(slashing.Header_1.Header, domain)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute signing root for header 1")
	}
	
	if err := v.validator.signatureVerifier.VerifySignature(
		proposer.PublicKey,
		signingRoot1[:],
		slashing.Header_1.Signature,
		common.DomainBeaconProposer,
		epoch,
	); err != nil {
		return nil, errors.Wrap(err, "invalid signature for header 1")
	}

	// Verify second header signature
	signingRoot2, err := common.ComputeSigningRoot(slashing.Header_2.Header, domain)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute signing root for header 2")
	}
	
	if err := v.validator.signatureVerifier.VerifySignature(
		proposer.PublicKey,
		signingRoot2[:],
		slashing.Header_2.Signature,
		common.DomainBeaconProposer,
		epoch,
	); err != nil {
		return nil, errors.Wrap(err, "invalid signature for header 2")
	}

	return slashing, nil
}

// AttesterSlashingValidator validates attester slashing messages
type AttesterSlashingValidator struct {
	validator *IndependentValidator
}

func NewAttesterSlashingValidator(iv *IndependentValidator) *AttesterSlashingValidator {
	return &AttesterSlashingValidator{validator: iv}
}

func (v *AttesterSlashingValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
	// Decompress the snappy-compressed data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decompress snappy data")
	}
	
	// Decode the attester slashing
	slashing := &ethpb.AttesterSlashing{}
	if err := slashing.UnmarshalSSZ(decompressed); err != nil {
		return nil, errors.Wrap(err, "failed to decode attester slashing")
	}

	// Verify slashable attestations
	att1 := slashing.Attestation_1
	att2 := slashing.Attestation_2

	// Check if attestations are slashable (double vote or surround vote)
	if !isSlashableAttestationPair(att1, att2) {
		return nil, errors.New("attestations are not slashable")
	}

	// Get indices of validators in both attestations
	indices1 := getAttestingIndices(att1)
	indices2 := getAttestingIndices(att2)

	// Find intersection (validators who signed both)
	slashedIndices := intersection(indices1, indices2)
	if len(slashedIndices) == 0 {
		return nil, errors.New("no validators signed both attestations")
	}

	// Verify all slashed validators are slashable
	for _, idx := range slashedIndices {
		validator, err := v.validator.stateSync.GetValidator(common.ValidatorIndex(idx))
		if err != nil {
			return nil, errors.Wrapf(err, "validator %d not found", idx)
		}

		if !validator.Active || validator.Slashed {
			return nil, fmt.Errorf("validator %d is not slashable", idx)
		}
	}

	// Verify signatures for both attestations
	domain := common.DomainBeaconAttester

	// Verify first attestation
	if err := v.verifyIndexedAttestation(att1, domain); err != nil {
		return nil, errors.Wrap(err, "invalid signature for attestation 1")
	}

	// Verify second attestation
	if err := v.verifyIndexedAttestation(att2, domain); err != nil {
		return nil, errors.Wrap(err, "invalid signature for attestation 2")
	}

	return slashing, nil
}

func (v *AttesterSlashingValidator) verifyIndexedAttestation(
	att *ethpb.IndexedAttestation,
	domain common.DomainType,
) error {
	// Get public keys for all attesters
	pubKeys := make([][]byte, len(att.AttestingIndices))
	for i, idx := range att.AttestingIndices {
		validator, err := v.validator.stateSync.GetValidator(common.ValidatorIndex(idx))
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
	
	// Compute domain
	domainBytes, err := common.ComputeDomain(
		domain,
		currentState.Fork,
		currentState.GenesisValidatorsRoot,
	)
	if err != nil {
		return errors.Wrap(err, "failed to compute domain")
	}
	
	// Compute signing root
	signingRoot, err := common.ComputeSigningRoot(att.Data, domainBytes)
	if err != nil {
		return errors.Wrap(err, "failed to compute signing root")
	}

	// Verify aggregate signature
	return v.validator.signatureVerifier.VerifyAggregateSignature(
		pubKeys,
		signingRoot[:],
		att.Signature,
		domain,
		att.Data.Target.Epoch,
	)
}

// Helper functions


func isSlashableAttestationPair(att1, att2 *ethpb.IndexedAttestation) bool {
	// Double vote: same target epoch
	if att1.Data.Target.Epoch == att2.Data.Target.Epoch {
		return true
	}

	// Surround vote: att1 surrounds att2
	if att1.Data.Source.Epoch < att2.Data.Source.Epoch &&
		att1.Data.Target.Epoch > att2.Data.Target.Epoch {
		return true
	}

	// Surround vote: att2 surrounds att1
	if att2.Data.Source.Epoch < att1.Data.Source.Epoch &&
		att2.Data.Target.Epoch > att1.Data.Target.Epoch {
		return true
	}

	return false
}

func getAttestingIndices(att *ethpb.IndexedAttestation) []common.ValidatorIndex {
	indices := make([]common.ValidatorIndex, len(att.AttestingIndices))
	for i, idx := range att.AttestingIndices {
		indices[i] = common.ValidatorIndex(idx)
	}
	return indices
}

func intersection(a, b []common.ValidatorIndex) []common.ValidatorIndex {
	m := make(map[common.ValidatorIndex]bool)
	for _, idx := range a {
		m[idx] = true
	}

	var result []common.ValidatorIndex
	for _, idx := range b {
		if m[idx] {
			result = append(result, idx)
		}
	}
	return result
}

// BLSToExecutionChangeValidator validates BLS to execution change messages
type BLSToExecutionChangeValidator struct {
	validator *IndependentValidator
}

func NewBLSToExecutionChangeValidator(iv *IndependentValidator) *BLSToExecutionChangeValidator {
	return &BLSToExecutionChangeValidator{validator: iv}
}

func (v *BLSToExecutionChangeValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
	// Decompress the snappy-compressed data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decompress snappy data")
	}
	
	// Decode the signed BLS to execution change
	change := &ethpb.SignedBLSToExecutionChange{}
	if err := change.UnmarshalSSZ(decompressed); err != nil {
		return nil, errors.Wrap(err, "failed to decode BLS to execution change")
	}

	if change.Message == nil {
		return nil, errors.New("nil message")
	}

	// Get validator info
	state := v.validator.stateSync.GetCurrentState()
	if state == nil {
		return nil, errors.New("no beacon state available")
	}

	validatorIdx := change.Message.ValidatorIndex
	if validatorIdx >= primitives.ValidatorIndex(len(state.Validators)) {
		return nil, errors.New("validator index out of range")
	}

	validator := state.Validators[validatorIdx]

	// Verify the from pubkey matches
	if !bytes.Equal(validator.PublicKey, change.Message.FromBlsPubkey) {
		return nil, errors.New("from BLS pubkey doesn't match validator")
	}

	// Verify withdrawal credentials prefix
	if validator.WithdrawalCredentials[0] != common.BLS_WITHDRAWAL_PREFIX {
		return nil, errors.New("validator doesn't have BLS withdrawal credentials")
	}

	// Verify signature
	domain, err := common.ComputeDomain(
		common.DomainBlsToExecutionChange,
		state.Fork,
		state.GenesisValidatorsRoot,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute domain")
	}

	signingRoot, err := common.ComputeSigningRoot(change.Message, domain)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compute signing root")
	}

	if err := v.validator.signatureVerifier.VerifySignature(
		validator.PublicKey,
		signingRoot[:],
		change.Signature,
		common.DomainBlsToExecutionChange,
		state.Epoch,
	); err != nil {
		return nil, errors.Wrap(err, "invalid signature")
	}

	return change, nil
}

func hasBLSWithdrawalCredentials(credentials []byte) bool {
	return len(credentials) == 32 && credentials[0] == common.BLS_WITHDRAWAL_PREFIX
}