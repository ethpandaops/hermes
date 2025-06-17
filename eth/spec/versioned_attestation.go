package spec

import (
	"fmt"

	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/probe-lab/hermes/eth/pubsub/common"
)

// VersionedAttestation represents an attestation that can be from any fork
type VersionedAttestation struct {
	Version common.ForkVersion
	
	// Pre-Electra uses Attestation
	Attestation *ethpb.Attestation
	
	// Electra+ uses SingleAttestation  
	SingleAttestation *ethpb.SingleAttestation
}

// NewVersionedAttestation creates a new versioned attestation for the given fork
func NewVersionedAttestation(version common.ForkVersion) (*VersionedAttestation, error) {
	va := &VersionedAttestation{Version: version}
	
	// Electra and later use SingleAttestation
	if version[0] >= common.ElectraForkVersion[0] {
		va.SingleAttestation = &ethpb.SingleAttestation{}
	} else {
		va.Attestation = &ethpb.Attestation{}
	}
	
	return va, nil
}

// UnmarshalSSZ unmarshals the attestation based on the version
func (va *VersionedAttestation) UnmarshalSSZ(data []byte) error {
	if va.Version[0] >= common.ElectraForkVersion[0] {
		if va.SingleAttestation == nil {
			va.SingleAttestation = &ethpb.SingleAttestation{}
		}
		return va.SingleAttestation.UnmarshalSSZ(data)
	} else {
		if va.Attestation == nil {
			va.Attestation = &ethpb.Attestation{}
		}
		return va.Attestation.UnmarshalSSZ(data)
	}
}

// GetData returns the attestation data regardless of version
func (va *VersionedAttestation) GetData() (*ethpb.AttestationData, error) {
	if va.Version[0] >= common.ElectraForkVersion[0] {
		if va.SingleAttestation == nil {
			return nil, fmt.Errorf("nil single attestation")
		}
		return va.SingleAttestation.Data, nil
	} else {
		if va.Attestation == nil {
			return nil, fmt.Errorf("nil attestation")
		}
		return va.Attestation.Data, nil
	}
}

// GetSignature returns the signature regardless of version
func (va *VersionedAttestation) GetSignature() ([]byte, error) {
	if va.Version[0] >= common.ElectraForkVersion[0] {
		if va.SingleAttestation == nil {
			return nil, fmt.Errorf("nil single attestation")
		}
		return va.SingleAttestation.Signature, nil
	} else {
		if va.Attestation == nil {
			return nil, fmt.Errorf("nil attestation")
		}
		return va.Attestation.Signature, nil
	}
}

// IsElectraOrLater returns true if this is an Electra+ attestation
func (va *VersionedAttestation) IsElectraOrLater() bool {
	return va.Version[0] >= common.ElectraForkVersion[0]
}