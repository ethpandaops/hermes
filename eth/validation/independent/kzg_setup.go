package independent

import (
	"crypto/sha256"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// KZG trusted setup is embedded in go-ethereum's kzg4844 package

// KZGVerifier handles KZG proof verification for blob sidecars
type KZGVerifier struct {
	logger *logrus.Logger
	// We'll use go-ethereum's kzg4844 package which has the trusted setup built-in
}

// NewKZGVerifier creates a new KZG verifier
func NewKZGVerifier(logger *logrus.Logger) (*KZGVerifier, error) {
	// go-ethereum's kzg4844 package has the mainnet trusted setup built-in
	// so we don't need to load it separately
	return &KZGVerifier{
		logger: logger,
	}, nil
}

// VerifyBlobKZGProof verifies a blob's KZG proof
func (v *KZGVerifier) VerifyBlobKZGProof(blob []byte, commitment []byte, proof []byte) error {
	if len(blob) != 131072 { // 128KB
		return fmt.Errorf("invalid blob size: %d", len(blob))
	}
	
	if len(commitment) != 48 {
		return fmt.Errorf("invalid commitment size: %d", len(commitment))
	}
	
	if len(proof) != 48 {
		return fmt.Errorf("invalid proof size: %d", len(proof))
	}

	// Convert to the types expected by kzg4844
	var (
		blobArray       kzg4844.Blob
		commitmentArray kzg4844.Commitment
		proofArray      kzg4844.Proof
	)
	
	copy(blobArray[:], blob)
	copy(commitmentArray[:], commitment)
	copy(proofArray[:], proof)

	// Verify the KZG proof
	err := kzg4844.VerifyBlobProof(&blobArray, commitmentArray, proofArray)
	if err != nil {
		return errors.Wrap(err, "failed to verify blob KZG proof")
	}
	
	return nil
}

// VerifyBlobKZGCommitment verifies that a commitment matches a blob
func (v *KZGVerifier) VerifyBlobKZGCommitment(blob []byte, commitment []byte) error {
	if len(blob) != 131072 { // 128KB
		return fmt.Errorf("invalid blob size: %d", len(blob))
	}
	
	if len(commitment) != 48 {
		return fmt.Errorf("invalid commitment size: %d", len(commitment))
	}

	// Convert blob to the type expected by kzg4844
	var blobArray kzg4844.Blob
	copy(blobArray[:], blob)

	// Compute commitment from blob
	computedCommitment, err := kzg4844.BlobToCommitment(&blobArray)
	if err != nil {
		return errors.Wrap(err, "failed to compute blob commitment")
	}

	// Compare commitments
	var expectedCommitment kzg4844.Commitment
	copy(expectedCommitment[:], commitment)
	
	if computedCommitment != expectedCommitment {
		return errors.New("commitment does not match blob")
	}
	
	return nil
}

// ComputeVersionedHash computes the versioned hash for a commitment
func (v *KZGVerifier) ComputeVersionedHash(commitment []byte) ([]byte, error) {
	if len(commitment) != 48 {
		return nil, fmt.Errorf("invalid commitment size: %d", len(commitment))
	}

	// The versioned hash is sha256(commitment)[1:] with version byte prepended
	// Version byte for blob commitments is 0x01
	var commitmentArray kzg4844.Commitment
	copy(commitmentArray[:], commitment)
	
	// go-ethereum's implementation includes the version byte
	hash := kzg4844.CalcBlobHashV1(sha256.New(), &commitmentArray)
	
	return hash[:], nil
}

// VerifyBlobSidecarKZG performs full KZG validation for a blob sidecar
func (v *KZGVerifier) VerifyBlobSidecarKZG(blob []byte, commitment []byte, proof []byte, inclusionProof [][]byte) error {
	// Verify the KZG proof
	if err := v.VerifyBlobKZGProof(blob, commitment, proof); err != nil {
		return errors.Wrap(err, "KZG proof verification failed")
	}
	
	// Verify the commitment matches the blob
	if err := v.VerifyBlobKZGCommitment(blob, commitment); err != nil {
		return errors.Wrap(err, "commitment verification failed")
	}
	
	// Note: Inclusion proof verification would require the beacon block body root
	// This is handled separately in the blob sidecar validator
	
	v.logger.Debug("KZG verification passed for blob sidecar")
	return nil
}