package independent

import (
	"context"
	"fmt"

	"github.com/golang/snappy"
	"github.com/pkg/errors"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/probe-lab/hermes/eth/validation/common"
)

// BeaconBlockValidator validates beacon block messages
type BeaconBlockValidator struct {
	validator *IndependentValidator
}

// NewBeaconBlockValidator creates a new beacon block validator
func NewBeaconBlockValidator(iv *IndependentValidator) *BeaconBlockValidator {
	return &BeaconBlockValidator{validator: iv}
}

// Validate validates a beacon block
func (v *BeaconBlockValidator) Validate(ctx context.Context, data []byte, topic string) error {
	// Decompress the snappy-compressed data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return errors.Wrap(err, "failed to decompress snappy data")
	}
	
	// First, try to determine the fork version from the topic or current slot
	// For now, we'll try each version in order from newest to oldest
	
	var block interface{}
	var slot phase0.Slot
	var proposerIndex phase0.ValidatorIndex
	var signature phase0.BLSSignature
	
	// Try Electra first (newest)
	electraBlock := &electra.SignedBeaconBlock{}
	if err = electraBlock.UnmarshalSSZ(decompressed); err == nil {
		block = electraBlock
		if electraBlock.Message != nil {
			slot = electraBlock.Message.Slot
			proposerIndex = electraBlock.Message.ProposerIndex
			signature = electraBlock.Signature
		}
	} else {
		// Try Deneb
		denebBlock := &deneb.SignedBeaconBlock{}
		if err = denebBlock.UnmarshalSSZ(decompressed); err == nil {
			block = denebBlock
			if denebBlock.Message != nil {
				slot = denebBlock.Message.Slot
				proposerIndex = denebBlock.Message.ProposerIndex
				signature = denebBlock.Signature
			}
		} else {
			// Try Capella
			capellaBlock := &capella.SignedBeaconBlock{}
			if err = capellaBlock.UnmarshalSSZ(decompressed); err == nil {
				block = capellaBlock
				if capellaBlock.Message != nil {
					slot = capellaBlock.Message.Slot
					proposerIndex = capellaBlock.Message.ProposerIndex
					signature = capellaBlock.Signature
				}
			} else {
				// Try Bellatrix
				bellatrixBlock := &bellatrix.SignedBeaconBlock{}
				if err = bellatrixBlock.UnmarshalSSZ(decompressed); err == nil {
					block = bellatrixBlock
					if bellatrixBlock.Message != nil {
						slot = bellatrixBlock.Message.Slot
						proposerIndex = bellatrixBlock.Message.ProposerIndex
						signature = bellatrixBlock.Signature
					}
				} else {
					// Try Altair
					altairBlock := &altair.SignedBeaconBlock{}
					if err = altairBlock.UnmarshalSSZ(decompressed); err == nil {
						block = altairBlock
						if altairBlock.Message != nil {
							slot = altairBlock.Message.Slot
							proposerIndex = altairBlock.Message.ProposerIndex
							signature = altairBlock.Signature
						}
					} else {
						// Try Phase0
						phase0Block := &phase0.SignedBeaconBlock{}
						if err = phase0Block.UnmarshalSSZ(decompressed); err == nil {
							block = phase0Block
							if phase0Block.Message != nil {
								slot = phase0Block.Message.Slot
								proposerIndex = phase0Block.Message.ProposerIndex
								signature = phase0Block.Signature
							}
						} else {
							return errors.Wrap(err, "failed to decode beacon block")
						}
					}
				}
			}
		}
	}
	
	if block == nil {
		return errors.New("nil block after decoding")
	}

	// Get current state
	state := v.validator.stateSync.GetCurrentState()
	if state == nil {
		return errors.New("current state not available")
	}

	// Basic validations
	// 1. Check slot is not from the future
	currentSlot := state.Slot
	if common.Slot(slot) > currentSlot {
		return fmt.Errorf("block slot %d is from the future (current slot: %d)", slot, currentSlot)
	}

	// 2. Check slot is recent (not too old)
	if currentSlot > common.Slot(slot) && currentSlot-common.Slot(slot) > 64 { // 64 slots = ~13 minutes
		return fmt.Errorf("block slot %d is too old (current slot: %d)", slot, currentSlot)
	}

	// 3. Verify proposer signature
	// Get the proposer's public key
	validatorInfo, exists := state.Validators[common.ValidatorIndex(proposerIndex)]
	if !exists {
		return fmt.Errorf("proposer %d not found in validator set", proposerIndex)
	}

	// Get the correct message for signing based on type
	var messageBytes []byte
	switch b := block.(type) {
	case *electra.SignedBeaconBlock:
		messageBytes, err = b.Message.MarshalSSZ()
	case *deneb.SignedBeaconBlock:
		messageBytes, err = b.Message.MarshalSSZ()
	case *capella.SignedBeaconBlock:
		messageBytes, err = b.Message.MarshalSSZ()
	case *bellatrix.SignedBeaconBlock:
		messageBytes, err = b.Message.MarshalSSZ()
	case *altair.SignedBeaconBlock:
		messageBytes, err = b.Message.MarshalSSZ()
	case *phase0.SignedBeaconBlock:
		messageBytes, err = b.Message.MarshalSSZ()
	default:
		return errors.New("unknown block type")
	}
	
	if err != nil {
		return errors.Wrap(err, "failed to serialize block message")
	}

	// Verify the signature
	return v.validator.signatureVerifier.VerifySignature(
		validatorInfo.PublicKey, 
		messageBytes, 
		signature[:],
		common.DomainBeaconProposer,
		common.Epoch(slot/32),
	)
}

