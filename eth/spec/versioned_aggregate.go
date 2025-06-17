package spec

import (
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/probe-lab/hermes/eth/pubsub/common"
)

// VersionedAggregateAndProof represents an aggregate and proof that can be from any fork
type VersionedAggregateAndProof struct {
	Version common.ForkVersion
	
	// Pre-Electra uses SignedAggregateAttestationAndProof
	PreElectra *ethpb.SignedAggregateAttestationAndProof
	
	// Electra+ uses SignedAggregateAttestationAndProofElectra
	Electra *ethpb.SignedAggregateAttestationAndProofElectra
}

// NewVersionedAggregateAndProof creates a new versioned aggregate and proof for the given fork
func NewVersionedAggregateAndProof(version common.ForkVersion) (*VersionedAggregateAndProof, error) {
	va := &VersionedAggregateAndProof{Version: version}
	
	// Electra and later use different type
	if version[0] >= common.ElectraForkVersion[0] {
		va.Electra = &ethpb.SignedAggregateAttestationAndProofElectra{}
	} else {
		va.PreElectra = &ethpb.SignedAggregateAttestationAndProof{}
	}
	
	return va, nil
}

// UnmarshalSSZ unmarshals the aggregate based on the version
func (va *VersionedAggregateAndProof) UnmarshalSSZ(data []byte) error {
	if va.Version[0] >= common.ElectraForkVersion[0] {
		if va.Electra == nil {
			va.Electra = &ethpb.SignedAggregateAttestationAndProofElectra{}
		}
		return va.Electra.UnmarshalSSZ(data)
	} else {
		if va.PreElectra == nil {
			va.PreElectra = &ethpb.SignedAggregateAttestationAndProof{}
		}
		return va.PreElectra.UnmarshalSSZ(data)
	}
}