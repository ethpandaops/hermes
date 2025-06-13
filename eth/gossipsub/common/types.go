package common

import (
	"time"

	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
)


// Config holds the validation configuration
type Config struct {
	Mode                  ValidatorMode
	AttestationThreshold  int           // Minimum attestations for block validation
	AttestationPercent    float64       // Or percentage of committee
	ValidationTimeout     time.Duration // Max wait time for attestations
	EnableBatchProcessing bool          // Enable batch signature verification
	CacheSize             int           // Size of various caches
	StateUpdateInterval   time.Duration // How often to sync beacon state
}


// MessageType represents different gossipsub message types
type MessageType int

const (
	MessageBeaconBlock MessageType = iota
	MessageAggregateAndProof
	MessageAttestation
	MessageVoluntaryExit
	MessageProposerSlashing
	MessageAttesterSlashing
	MessageSyncCommittee
	MessageContributionAndProof
	MessageBlsToExecutionChange
	MessageBlobSidecar
)

// ValidatorIndex is an alias for clarity
type ValidatorIndex = primitives.ValidatorIndex

// Epoch is an alias for clarity  
type Epoch = primitives.Epoch

// Slot is an alias for clarity
type Slot = primitives.Slot

// DomainType represents signature domain types
type DomainType uint32

const (
	DomainBeaconProposer              DomainType = 0x00000000
	DomainBeaconAttester              DomainType = 0x01000000
	DomainRandao                      DomainType = 0x02000000
	DomainDeposit                     DomainType = 0x03000000
	DomainVoluntaryExit               DomainType = 0x04000000
	DomainSelectionProof              DomainType = 0x05000000
	DomainAggregateAndProof           DomainType = 0x06000000
	DomainSyncCommittee               DomainType = 0x07000000
	DomainSyncCommitteeSelectionProof DomainType = 0x08000000
	DomainContributionAndProof        DomainType = 0x09000000
	DomainBlsToExecutionChange        DomainType = 0x0A000000
)

// ValidatorInfo holds validator information
type ValidatorInfo struct {
	Index                 ValidatorIndex
	PublicKey             []byte
	Active                bool
	Slashed               bool
	ExitEpoch             Epoch
	WithdrawalCredentials []byte
}

// CommitteeAssignment represents committee membership
type CommitteeAssignment struct {
	ValidatorIndices []ValidatorIndex
	CommitteeIndex   primitives.CommitteeIndex
	Slot             Slot
}

// ForkInfo contains fork version information
type ForkInfo struct {
	PreviousVersion [4]byte
	CurrentVersion  [4]byte
	Epoch           Epoch
}