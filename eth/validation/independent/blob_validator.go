package independent

import (
	"github.com/probe-lab/hermes/eth/validation/common"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/golang/snappy"
	"github.com/pkg/errors"
	"github.com/attestantio/go-eth2-client/spec/deneb"
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
	// Decompress the snappy-compressed data
	decompressed, err := snappy.Decode(nil, data)
	if err != nil {
		return errors.Wrap(err, "failed to decompress snappy data")
	}
	
	// Decode the blob sidecar using consensus-spec types
	sidecar := &deneb.BlobSidecar{}
	if err := sidecar.UnmarshalSSZ(decompressed); err != nil {
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

func (v *BlobSidecarValidator) verifyKZGProof(sidecar *deneb.BlobSidecar) error {
	// Verify the KZG proof
	err := v.kzgVerifier.VerifyBlobKZGProof(sidecar.Blob[:], sidecar.KZGCommitment[:], sidecar.KZGProof[:])
	if err != nil {
		return errors.Wrap(err, "failed to verify KZG proof")
	}
	
	return nil
}

func (v *BlobSidecarValidator) verifyInclusionProof(sidecar *deneb.BlobSidecar) error {
	// Verify the inclusion proof that proves the KZG commitment is in the beacon block
	
	// First, hash the KZG commitment
	commitmentHash := sha256.Sum256(sidecar.KZGCommitment[:])
	
	// Build the Merkle branch
	branch := make([][]byte, len(sidecar.KZGCommitmentInclusionProof))
	for i, proof := range sidecar.KZGCommitmentInclusionProof {
		branch[i] = proof[:]
	}
	
	// The leaf is at index = blob_index + NUMBER_OF_COLUMNS
	// For mainnet, NUMBER_OF_COLUMNS = 0, so leaf_index = blob_index
	leafIndex := uint64(sidecar.Index)
	
	// Verify the Merkle proof
	// This proves that the commitment at blob_index is included in the beacon block body
	if !verifyMerkleBranch(commitmentHash[:], branch, 17, leafIndex, sidecar.SignedBlockHeader.Message.BodyRoot[:]) { // KZG commitments depth is 17
		return errors.New("invalid inclusion proof")
	}
	
	return nil
}

func (v *BlobSidecarValidator) verifyProposerSignature(sidecar *deneb.BlobSidecar) error {
	// Get current state instead of parent state
	state := v.validator.stateSync.GetCurrentState()
	if state == nil {
		return errors.New("current state not available")
	}
	
	// Get the proposer index
	proposerIndex := sidecar.SignedBlockHeader.Message.ProposerIndex
	
	// Get the proposer's public key
	validatorInfo, exists := state.Validators[common.ValidatorIndex(proposerIndex)]
	if !exists {
		return fmt.Errorf("proposer %d not found in validator set", proposerIndex)
	}
	
	// Serialize the block header for signing
	headerBytes, err := sidecar.SignedBlockHeader.Message.MarshalSSZ()
	if err != nil {
		return errors.Wrap(err, "failed to serialize block header")
	}
	
	// Verify the signature
	return v.validator.signatureVerifier.VerifySignature(
		validatorInfo.PublicKey, 
		headerBytes, 
		sidecar.SignedBlockHeader.Signature[:],
		common.DomainBeaconProposer,
		state.Epoch,
	)
}

// Helper function to verify a Merkle branch
func verifyMerkleBranch(leaf []byte, branch [][]byte, depth uint64, index uint64, root []byte) bool {
	value := leaf
	for i := uint64(0); i < depth; i++ {
		if (index>>i)&1 == 1 {
			value = hashTreeRoot(branch[i], value)
		} else {
			value = hashTreeRoot(value, branch[i])
		}
	}
	return bytes.Equal(value, root)
}

// Helper function to compute hash tree root of two values
func hashTreeRoot(a, b []byte) []byte {
	hasher := sha256.New()
	hasher.Write(a)
	hasher.Write(b)
	return hasher.Sum(nil)
}

