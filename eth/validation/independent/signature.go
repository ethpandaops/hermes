package independent

import (
	"github.com/probe-lab/hermes/eth/validation/common"
	"encoding/binary"
	"fmt"
	"sync"

	bls "github.com/herumi/bls-eth-go-binary/bls"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/pkg/errors"
	"github.com/OffchainLabs/prysm/v6/crypto/hash"
	"github.com/sirupsen/logrus"
)

func init() {
	// Initialize BLS library with ETH2 settings
	if err := bls.Init(bls.BLS12_381); err != nil {
		panic(fmt.Sprintf("failed to initialize BLS: %v", err))
	}
	if err := bls.SetETHmode(bls.EthModeDraft07); err != nil {
		panic(fmt.Sprintf("failed to set ETH mode: %v", err))
	}
}

// SignatureVerifier handles BLS signature verification with caching
type SignatureVerifier struct {
	logger       *logrus.Logger
	pubKeyCache  *lru.Cache[common.ValidatorIndex, *bls.PublicKey]
	domainCache  *lru.Cache[string, [32]byte]
	genesisRoot  [32]byte
	currentFork  [4]byte
	mu           sync.RWMutex
}

// NewSignatureVerifier creates a new signature verifier
func NewSignatureVerifier(logger *logrus.Logger, cacheSize int, genesisRoot [32]byte) (*SignatureVerifier, error) {
	pubKeyCache, err := lru.New[common.ValidatorIndex, *bls.PublicKey](cacheSize)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create pubkey cache")
	}

	domainCache, err := lru.New[string, [32]byte](256)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create domain cache")
	}

	return &SignatureVerifier{
		logger:      logger,
		pubKeyCache: pubKeyCache,
		domainCache: domainCache,
		genesisRoot: genesisRoot,
	}, nil
}

// UpdateFork updates the current fork version
func (sv *SignatureVerifier) UpdateFork(forkVersion [4]byte) {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	sv.currentFork = forkVersion
	// Clear domain cache as domains will change
	sv.domainCache.Purge()
}

// AddPublicKey adds a validator's public key to the cache
func (sv *SignatureVerifier) AddPublicKey(index common.ValidatorIndex, pubKeyBytes []byte) error {
	pubKey := &bls.PublicKey{}
	if err := pubKey.Deserialize(pubKeyBytes); err != nil {
		return errors.Wrap(err, "failed to deserialize public key")
	}
	
	sv.pubKeyCache.Add(index, pubKey)
	return nil
}

// VerifySignature verifies a BLS signature
func (sv *SignatureVerifier) VerifySignature(
	pubKeyBytes []byte,
	message []byte,
	signature []byte,
	domain common.DomainType,
	epoch common.Epoch,
) error {
	// Deserialize public key
	pubKey := &bls.PublicKey{}
	if err := pubKey.Deserialize(pubKeyBytes); err != nil {
		return errors.Wrap(err, "invalid public key")
	}

	// Deserialize signature
	sig := &bls.Sign{}
	if err := sig.Deserialize(signature); err != nil {
		return errors.Wrap(err, "invalid signature")
	}

	// Compute domain
	domainBytes, err := sv.computeDomain(domain, epoch)
	if err != nil {
		return errors.Wrap(err, "failed to compute domain")
	}

	// Compute signing root
	signingRoot := computeSigningRoot(message, domainBytes)

	// Verify signature
	if !sig.VerifyByte(pubKey, signingRoot[:]) {
		return errors.New("signature verification failed")
	}

	return nil
}

// VerifySignatureWithIndex verifies a signature using cached public key
func (sv *SignatureVerifier) VerifySignatureWithIndex(
	validatorIndex common.ValidatorIndex,
	message []byte,
	signature []byte,
	domain common.DomainType,
	epoch common.Epoch,
) error {
	pubKey, ok := sv.pubKeyCache.Get(validatorIndex)
	if !ok {
		return fmt.Errorf("public key not found for validator %d", validatorIndex)
	}

	// Deserialize signature
	sig := &bls.Sign{}
	if err := sig.Deserialize(signature); err != nil {
		return errors.Wrap(err, "invalid signature")
	}

	// Compute domain
	domainBytes, err := sv.computeDomain(domain, epoch)
	if err != nil {
		return errors.Wrap(err, "failed to compute domain")
	}

	// Compute signing root
	signingRoot := computeSigningRoot(message, domainBytes)

	// Verify signature
	if !sig.VerifyByte(pubKey, signingRoot[:]) {
		return errors.New("signature verification failed")
	}

	return nil
}

// VerifyAggregateSignature verifies an aggregate BLS signature
func (sv *SignatureVerifier) VerifyAggregateSignature(
	pubKeys [][]byte,
	message []byte,
	signature []byte,
	domain common.DomainType,
	epoch common.Epoch,
) error {
	if len(pubKeys) == 0 {
		return errors.New("no public keys provided")
	}

	// Deserialize aggregate signature
	aggSig := &bls.Sign{}
	if err := aggSig.Deserialize(signature); err != nil {
		return errors.Wrap(err, "invalid aggregate signature")
	}

	// Compute domain
	domainBytes, err := sv.computeDomain(domain, epoch)
	if err != nil {
		return errors.Wrap(err, "failed to compute domain")
	}

	// Compute signing root
	signingRoot := computeSigningRoot(message, domainBytes)

	// Aggregate public keys
	aggregatedPubKey := &bls.PublicKey{}
	for i, pubKeyBytes := range pubKeys {
		pubKey := &bls.PublicKey{}
		if err := pubKey.Deserialize(pubKeyBytes); err != nil {
			return errors.Wrapf(err, "invalid public key at index %d", i)
		}
		
		if i == 0 {
			*aggregatedPubKey = *pubKey
		} else {
			aggregatedPubKey.Add(pubKey)
		}
	}

	// Verify aggregate signature
	if !aggSig.VerifyByte(aggregatedPubKey, signingRoot[:]) {
		return errors.New("aggregate signature verification failed")
	}

	return nil
}

// computeDomain computes the signature domain
func (sv *SignatureVerifier) computeDomain(domainType common.DomainType, epoch common.Epoch) ([32]byte, error) {
	sv.mu.RLock()
	forkVersion := sv.currentFork
	sv.mu.RUnlock()

	// Cache key combines domain type, fork version, and genesis root
	cacheKey := fmt.Sprintf("%d:%x:%x", domainType, forkVersion, sv.genesisRoot)
	
	if domain, ok := sv.domainCache.Get(cacheKey); ok {
		return domain, nil
	}

	// Compute fork data root
	forkDataRoot := computeForkDataRoot(forkVersion, sv.genesisRoot)
	
	// Compute domain
	var domain [32]byte
	copy(domain[0:4], uint32ToBytes(uint32(domainType)))
	copy(domain[4:], forkDataRoot[0:28])
	
	sv.domainCache.Add(cacheKey, domain)
	return domain, nil
}

// computeSigningRoot computes the signing root for a message
func computeSigningRoot(message []byte, domain [32]byte) [32]byte {
	container := make([]byte, 64)
	messageHash := hash.Hash(message)
	copy(container[0:32], messageHash[:])
	copy(container[32:64], domain[:])
	return hash.Hash(container)
}

// computeForkDataRoot computes the fork data root
func computeForkDataRoot(currentVersion [4]byte, genesisValidatorsRoot [32]byte) [32]byte {
	forkData := make([]byte, 36)
	copy(forkData[0:4], currentVersion[:])
	copy(forkData[4:36], genesisValidatorsRoot[:])
	return hash.Hash(forkData)
}

// uint32ToBytes converts uint32 to little-endian bytes
func uint32ToBytes(n uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return b
}