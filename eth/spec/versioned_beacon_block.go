package spec

import (
	"fmt"

	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/probe-lab/hermes/eth/pubsub/common"
)

// VersionedBeaconBlock represents a beacon block that can be from any fork
type VersionedBeaconBlock struct {
	Version common.ForkVersion
	
	// Only one of these will be set based on Version
	Phase0    *ethpb.SignedBeaconBlock
	Altair    *ethpb.SignedBeaconBlockAltair
	Bellatrix *ethpb.SignedBeaconBlockBellatrix
	Capella   *ethpb.SignedBeaconBlockCapella
	Deneb     *ethpb.SignedBeaconBlockDeneb
	Electra   *ethpb.SignedBeaconBlockElectra
}

// NewVersionedBeaconBlock creates a new versioned beacon block for the given fork
func NewVersionedBeaconBlock(version common.ForkVersion) (*VersionedBeaconBlock, error) {
	vb := &VersionedBeaconBlock{Version: version}
	
	switch version {
	case common.Phase0ForkVersion:
		vb.Phase0 = &ethpb.SignedBeaconBlock{}
	case common.AltairForkVersion:
		vb.Altair = &ethpb.SignedBeaconBlockAltair{}
	case common.BellatrixForkVersion:
		vb.Bellatrix = &ethpb.SignedBeaconBlockBellatrix{}
	case common.CapellaForkVersion:
		vb.Capella = &ethpb.SignedBeaconBlockCapella{}
	case common.DenebForkVersion:
		vb.Deneb = &ethpb.SignedBeaconBlockDeneb{}
	case common.ElectraForkVersion:
		vb.Electra = &ethpb.SignedBeaconBlockElectra{}
	default:
		return nil, fmt.Errorf("unsupported fork version: %s", version)
	}
	
	return vb, nil
}

// UnmarshalSSZ unmarshals the block based on the version
func (vb *VersionedBeaconBlock) UnmarshalSSZ(data []byte) error {
	switch vb.Version {
	case common.Phase0ForkVersion:
		return vb.Phase0.UnmarshalSSZ(data)
	case common.AltairForkVersion:
		return vb.Altair.UnmarshalSSZ(data)
	case common.BellatrixForkVersion:
		return vb.Bellatrix.UnmarshalSSZ(data)
	case common.CapellaForkVersion:
		return vb.Capella.UnmarshalSSZ(data)
	case common.DenebForkVersion:
		return vb.Deneb.UnmarshalSSZ(data)
	case common.ElectraForkVersion:
		return vb.Electra.UnmarshalSSZ(data)
	default:
		return fmt.Errorf("unsupported fork version: %s", vb.Version)
	}
}

// GetSlot returns the slot of the block regardless of version
func (vb *VersionedBeaconBlock) GetSlot() (common.Slot, error) {
	switch vb.Version {
	case common.Phase0ForkVersion:
		if vb.Phase0 == nil || vb.Phase0.Block == nil {
			return 0, fmt.Errorf("nil phase0 block")
		}
		return vb.Phase0.Block.Slot, nil
	case common.AltairForkVersion:
		if vb.Altair == nil || vb.Altair.Block == nil {
			return 0, fmt.Errorf("nil altair block")
		}
		return vb.Altair.Block.Slot, nil
	case common.BellatrixForkVersion:
		if vb.Bellatrix == nil || vb.Bellatrix.Block == nil {
			return 0, fmt.Errorf("nil bellatrix block")
		}
		return vb.Bellatrix.Block.Slot, nil
	case common.CapellaForkVersion:
		if vb.Capella == nil || vb.Capella.Block == nil {
			return 0, fmt.Errorf("nil capella block")
		}
		return vb.Capella.Block.Slot, nil
	case common.DenebForkVersion:
		if vb.Deneb == nil || vb.Deneb.Block == nil {
			return 0, fmt.Errorf("nil deneb block")
		}
		return vb.Deneb.Block.Slot, nil
	case common.ElectraForkVersion:
		if vb.Electra == nil || vb.Electra.Block == nil {
			return 0, fmt.Errorf("nil electra block")
		}
		return vb.Electra.Block.Slot, nil
	default:
		return 0, fmt.Errorf("unsupported fork version: %s", vb.Version)
	}
}