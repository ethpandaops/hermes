package delegated

import (
	"context"
	"fmt"

	"github.com/golang/snappy"
	ethtypes "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	ssz "github.com/prysmaticlabs/fastssz"

	"github.com/probe-lab/hermes/eth/pubsub/common"
)

// MessageValidator validates and handles specific message types
type MessageValidator interface {
	// Handle validates and decodes a message, returning the decoded object
	Handle(ctx context.Context, data []byte, topic string) (interface{}, error)
}

// BeaconBlockValidator validates beacon block messages
type BeaconBlockValidator struct {
	handler *DelegatedHandler
}

func NewBeaconBlockValidator(h *DelegatedHandler) *BeaconBlockValidator {
	return &BeaconBlockValidator{handler: h}
}

func (v *BeaconBlockValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
	// Decompress snappy data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress beacon block: %w", err)
	}

	var block ssz.Unmarshaler
	
	switch v.handler.forkVersion {
	case common.Phase0ForkVersion:
		block = &ethtypes.SignedBeaconBlock{}
	case common.AltairForkVersion:
		block = &ethtypes.SignedBeaconBlockAltair{}
	case common.BellatrixForkVersion:
		block = &ethtypes.SignedBeaconBlockBellatrix{}
	case common.CapellaForkVersion:
		block = &ethtypes.SignedBeaconBlockCapella{}
	case common.DenebForkVersion:
		block = &ethtypes.SignedBeaconBlockDeneb{}
	case common.ElectraForkVersion:
		block = &ethtypes.SignedBeaconBlockElectra{}
	default:
		return nil, fmt.Errorf("unrecognized fork version: %#x", v.handler.forkVersion)
	}
	
	if err := block.UnmarshalSSZ(decompressed); err != nil {
		return nil, fmt.Errorf("unmarshal beacon block: %w", err)
	}
	
	return block, nil
}

// AttestationValidator validates attestation messages
type AttestationValidator struct {
	handler *DelegatedHandler
}

func NewAttestationValidator(h *DelegatedHandler) *AttestationValidator {
	return &AttestationValidator{handler: h}
}

func (v *AttestationValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
	// Decompress snappy data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress attestation: %w", err)
	}

	var attestation ssz.Unmarshaler
	
	switch v.handler.forkVersion {
	case common.ElectraForkVersion:
		attestation = &ethtypes.SingleAttestation{}
	default:
		attestation = &ethtypes.Attestation{}
	}
	
	if err := attestation.UnmarshalSSZ(decompressed); err != nil {
		return nil, fmt.Errorf("unmarshal attestation: %w", err)
	}
	
	return attestation, nil
}

// AggregateAndProofValidator validates aggregate and proof messages
type AggregateAndProofValidator struct {
	handler *DelegatedHandler
}

func NewAggregateAndProofValidator(h *DelegatedHandler) *AggregateAndProofValidator {
	return &AggregateAndProofValidator{handler: h}
}

func (v *AggregateAndProofValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
	// Decompress snappy data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress aggregate and proof: %w", err)
	}

	var aggregateAndProof ssz.Unmarshaler
	
	switch v.handler.forkVersion {
	case common.ElectraForkVersion:
		aggregateAndProof = &ethtypes.SignedAggregateAttestationAndProofElectra{}
	default:
		aggregateAndProof = &ethtypes.SignedAggregateAttestationAndProof{}
	}
	
	if err := aggregateAndProof.UnmarshalSSZ(decompressed); err != nil {
		return nil, fmt.Errorf("unmarshal aggregate and proof: %w", err)
	}
	
	return aggregateAndProof, nil
}

// VoluntaryExitValidator validates voluntary exit messages
type VoluntaryExitValidator struct {
	handler *DelegatedHandler
}

func NewVoluntaryExitValidator(h *DelegatedHandler) *VoluntaryExitValidator {
	return &VoluntaryExitValidator{handler: h}
}

func (v *VoluntaryExitValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
	// Decompress snappy data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress voluntary exit: %w", err)
	}

	exit := &ethtypes.SignedVoluntaryExit{}
	
	if err := exit.UnmarshalSSZ(decompressed); err != nil {
		return nil, fmt.Errorf("unmarshal voluntary exit: %w", err)
	}
	
	return exit, nil
}

// AttesterSlashingValidator validates attester slashing messages
type AttesterSlashingValidator struct {
	handler *DelegatedHandler
}

func NewAttesterSlashingValidator(h *DelegatedHandler) *AttesterSlashingValidator {
	return &AttesterSlashingValidator{handler: h}
}

func (v *AttesterSlashingValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
	// Decompress snappy data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress attester slashing: %w", err)
	}

	var slashing ssz.Unmarshaler
	
	switch v.handler.forkVersion {
	case common.ElectraForkVersion:
		slashing = &ethtypes.AttesterSlashingElectra{}
	default:
		slashing = &ethtypes.AttesterSlashing{}
	}
	
	if err := slashing.UnmarshalSSZ(decompressed); err != nil {
		return nil, fmt.Errorf("unmarshal attester slashing: %w", err)
	}
	
	return slashing, nil
}

// ProposerSlashingValidator validates proposer slashing messages
type ProposerSlashingValidator struct {
	handler *DelegatedHandler
}

func NewProposerSlashingValidator(h *DelegatedHandler) *ProposerSlashingValidator {
	return &ProposerSlashingValidator{handler: h}
}

func (v *ProposerSlashingValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
	// Decompress snappy data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress proposer slashing: %w", err)
	}

	slashing := &ethtypes.ProposerSlashing{}
	
	if err := slashing.UnmarshalSSZ(decompressed); err != nil {
		return nil, fmt.Errorf("unmarshal proposer slashing: %w", err)
	}
	
	return slashing, nil
}

// SyncCommitteeMessageValidator validates sync committee messages
type SyncCommitteeMessageValidator struct {
	handler *DelegatedHandler
}

func NewSyncCommitteeMessageValidator(h *DelegatedHandler) *SyncCommitteeMessageValidator {
	return &SyncCommitteeMessageValidator{handler: h}
}

func (v *SyncCommitteeMessageValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
	// Decompress snappy data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress sync committee message: %w", err)
	}

	syncMsg := &ethtypes.SyncCommitteeMessage{}
	
	if err := syncMsg.UnmarshalSSZ(decompressed); err != nil {
		return nil, fmt.Errorf("unmarshal sync committee message: %w", err)
	}
	
	return syncMsg, nil
}

// ContributionAndProofValidator validates contribution and proof messages
type ContributionAndProofValidator struct {
	handler *DelegatedHandler
}

func NewContributionAndProofValidator(h *DelegatedHandler) *ContributionAndProofValidator {
	return &ContributionAndProofValidator{handler: h}
}

func (v *ContributionAndProofValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
	// Decompress snappy data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress contribution and proof: %w", err)
	}

	contribution := &ethtypes.SignedContributionAndProof{}
	
	if err := contribution.UnmarshalSSZ(decompressed); err != nil {
		return nil, fmt.Errorf("unmarshal contribution and proof: %w", err)
	}
	
	return contribution, nil
}

// BlsToExecutionChangeValidator validates BLS to execution change messages
type BlsToExecutionChangeValidator struct {
	handler *DelegatedHandler
}

func NewBlsToExecutionChangeValidator(h *DelegatedHandler) *BlsToExecutionChangeValidator {
	return &BlsToExecutionChangeValidator{handler: h}
}

func (v *BlsToExecutionChangeValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
	// Decompress snappy data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress BLS to execution change: %w", err)
	}

	change := &ethtypes.SignedBLSToExecutionChange{}
	
	if err := change.UnmarshalSSZ(decompressed); err != nil {
		return nil, fmt.Errorf("unmarshal BLS to execution change: %w", err)
	}
	
	return change, nil
}

// BlobSidecarValidator validates blob sidecar messages
type BlobSidecarValidator struct {
	handler *DelegatedHandler
}

func NewBlobSidecarValidator(h *DelegatedHandler) *BlobSidecarValidator {
	return &BlobSidecarValidator{handler: h}
}

func (v *BlobSidecarValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
	// Decompress snappy data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress blob sidecar: %w", err)
	}

	blob := &ethtypes.BlobSidecar{}
	
	if err := blob.UnmarshalSSZ(decompressed); err != nil {
		return nil, fmt.Errorf("unmarshal blob sidecar: %w", err)
	}
	
	return blob, nil
}