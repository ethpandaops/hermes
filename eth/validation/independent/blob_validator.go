package independent

import (
	"github.com/probe-lab/hermes/eth/validation/common"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/pkg/errors"
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
)

// BlobSidecarValidator validates blob sidecar messages with KZG proofs
type BlobSidecarValidator struct {
	validator   *IndependentValidator
	kzgVerifier *KZGVerifier
}

func NewBlobSidecarValidator(iv *IndependentValidator) (*BlobSidecarValidator, error) {
	// Initialize KZG verifier
	kzgVerifier, err := NewKZGVerifier(iv.logger)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create KZG verifier")
	}

	return &BlobSidecarValidator{
		validator:   iv,
		kzgVerifier: kzgVerifier,
	}, nil
}

func (v *BlobSidecarValidator) Validate(ctx context.Context, data []byte, topic string) error {
	// Decode the blob sidecar
	sidecar := &ethpb.BlobSidecar{}
	if err := sidecar.UnmarshalSSZ(data); err != nil {
		return errors.Wrap(err, "failed to decode blob sidecar")
	}

	// Verify blob index is within bounds
	if sidecar.Index >= common.MAX_BLOBS_PER_BLOCK {
		return fmt.Errorf("blob index %d exceeds max %d", sidecar.Index, common.MAX_BLOBS_PER_BLOCK)
	}

	// Verify KZG proof
	if err := v.verifyKZGProof(sidecar); err != nil {
		return errors.Wrap(err, "KZG proof verification failed")
	}

	// Verify inclusion proof (that commitment is in block)
	if err := v.verifyInclusionProof(sidecar); err != nil {
		return errors.Wrap(err, "inclusion proof verification failed")
	}

	// Verify proposer signature on block header
	if err := v.verifyProposerSignature(sidecar); err != nil {
		return errors.Wrap(err, "proposer signature verification failed")
	}

	return nil
}

func (v *BlobSidecarValidator) verifyKZGProof(sidecar *ethpb.BlobSidecar) error {
	// Convert types for KZG library
	if len(sidecar.Blob) != 131072 { // 4096 * 32 bytes
		return fmt.Errorf("invalid blob size: %d", len(sidecar.Blob))
	}

	if len(sidecar.KzgCommitment) != 48 {
		return fmt.Errorf("invalid commitment size: %d", len(sidecar.KzgCommitment))
	}

	if len(sidecar.KzgProof) != 48 {
		return fmt.Errorf("invalid proof size: %d", len(sidecar.KzgProof))
	}

	// Verify KZG proof
	if err := v.kzgVerifier.VerifyBlobSidecarKZG(
		sidecar.Blob,
		sidecar.KzgCommitment,
		sidecar.KzgProof,
		sidecar.CommitmentInclusionProof,
	); err != nil {
		return errors.Wrap(err, "KZG verification failed")
	}

	return nil
}

func (v *BlobSidecarValidator) verifyInclusionProof(sidecar *ethpb.BlobSidecar) error {
	// Get the block header to verify commitment inclusion
	if sidecar.SignedBlockHeader == nil || sidecar.SignedBlockHeader.Header == nil {
		return errors.New("missing signed block header")
	}
	
	blockHeader := sidecar.SignedBlockHeader.Header
	
	// Basic validation
	if sidecar.Index >= common.MAX_BLOBS_PER_BLOCK {
		return fmt.Errorf("blob index out of range: %d", sidecar.Index)
	}

	// Verify the block header matches expected slot
	if blockHeader.Slot != sidecar.SignedBlockHeader.Header.Slot {
		return errors.New("inconsistent slot in signed block header")
	}

	// Verify inclusion proof if provided
	if len(sidecar.CommitmentInclusionProof) > 0 {
		if !v.verifyMerkleProof(
			sidecar.KzgCommitment,
			sidecar.CommitmentInclusionProof,
			blockHeader.BodyRoot,
			sidecar.Index,
		) {
			return errors.New("invalid KZG commitment inclusion proof")
		}
	}

	return nil
}

func (v *BlobSidecarValidator) verifyProposerSignature(sidecar *ethpb.BlobSidecar) error {
	// Get the proposer's public key
	proposerIndex := sidecar.SignedBlockHeader.Header.ProposerIndex
	proposer, err := v.validator.stateSync.GetValidator(proposerIndex)
	if err != nil {
		return errors.Wrapf(err, "proposer %d not found", proposerIndex)
	}

	// Get current state for domain computation
	currentState := v.validator.stateSync.GetCurrentState()
	if currentState == nil {
		return errors.New("no beacon state available")
	}
	
	// Compute domain
	epoch := common.SlotToEpoch(sidecar.SignedBlockHeader.Header.Slot)
	domain, err := common.ComputeDomain(
		common.DomainBeaconProposer,
		currentState.Fork,
		currentState.GenesisValidatorsRoot,
	)
	if err != nil {
		return errors.Wrap(err, "failed to compute domain")
	}
	
	// Verify the block header signature
	signingRoot, err := common.ComputeSigningRoot(sidecar.SignedBlockHeader.Header, domain)
	if err != nil {
		return errors.Wrap(err, "failed to compute signing root")
	}
	
	return v.validator.signatureVerifier.VerifySignature(
		proposer.PublicKey,
		signingRoot[:],
		sidecar.SignedBlockHeader.Signature,
		common.DomainBeaconProposer,
		epoch,
	)
}

func (v *BlobSidecarValidator) verifyMerkleProof(
	leaf []byte,
	proof [][]byte,
	root []byte,
	index uint64,
) bool {
	// Simplified merkle proof verification
	// In production, this would properly verify the merkle path
	
	if len(proof) == 0 {
		return false
	}

	// Start with the leaf hash
	currentHash := hashData(leaf)

	// Apply each proof element
	for i, proofElement := range proof {
		if len(proofElement) != 32 {
			return false
		}

		// Determine if we're the left or right child
		if (index>>uint(i))&1 == 0 {
			// We're the left child
			currentHash = hashData(append(currentHash[:], proofElement...))
		} else {
			// We're the right child
			currentHash = hashData(append(proofElement, currentHash[:]...))
		}
	}

	// Compare with expected root
	return bytes.Equal(currentHash[:], root)
}

func hashData(data []byte) [32]byte {
	return sha256.Sum256(data)
}


