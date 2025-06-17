package common

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/OffchainLabs/prysm/v6/crypto/hash"
	ssz "github.com/prysmaticlabs/fastssz"
)

// Constants for message classification
const (
	UnknownMessage MessageType = -1

	BeaconBlockMessage               = MessageBeaconBlock
	BeaconAggregateAndProofMessage   = MessageAggregateAndProof
	BeaconAttestationMessage         = MessageAttestation
	VoluntaryExitMessage             = MessageVoluntaryExit
	ProposerSlashingMessage          = MessageProposerSlashing
	AttesterSlashingMessage          = MessageAttesterSlashing
	SyncCommitteeMessage             = MessageSyncCommittee
	SyncCommitteeContributionMessage = MessageContributionAndProof
	BlsToExecutionChangeMessage      = MessageBlsToExecutionChange
	BlobSidecarMessage               = MessageBlobSidecar
)

// DefaultCacheSize is the default size for LRU caches
const DefaultCacheSize = 10000

// Constants for epoch calculations
const SLOTS_PER_EPOCH = 32
const ATTESTATION_SUBNET_COUNT = 64
const SYNC_COMMITTEE_SUBNET_COUNT = 4
const EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256
const MAX_BLOBS_PER_BLOCK = 6
const SYNC_COMMITTEE_SIZE = 512

// Constants for BLS
const BLS_WITHDRAWAL_PREFIX = byte(0x00)

// ClassifyMessage determines the message type from a gossipsub topic
func ClassifyMessage(topic string) MessageType {
	// Topic format: /eth2/{fork_digest}/{topic_name}/ssz_snappy
	// Extract the topic_name part

	parts := strings.Split(topic, "/")
	if len(parts) < 4 {
		return UnknownMessage
	}

	topicName := parts[3]

	switch topicName {
	case "beacon_block":
		return BeaconBlockMessage
	case "beacon_aggregate_and_proof":
		return BeaconAggregateAndProofMessage
	case "voluntary_exit":
		return VoluntaryExitMessage
	case "proposer_slashing":
		return ProposerSlashingMessage
	case "attester_slashing":
		return AttesterSlashingMessage
	case "sync_committee_contribution_and_proof":
		return SyncCommitteeContributionMessage
	case "bls_to_execution_change":
		return BlsToExecutionChangeMessage
	default:
		// Check for sync committee messages (sync_committee_{subnet_id})
		if strings.HasPrefix(topicName, "sync_committee_") && len(topicName) > 15 {
			return SyncCommitteeMessage
		}
		// Check for blob sidecars (blob_sidecar_{subnet_id})
		if strings.HasPrefix(topicName, "blob_sidecar_") && len(topicName) > 13 {
			return BlobSidecarMessage
		}
		// Check if it matches attestation pattern
		if strings.HasPrefix(topicName, "beacon_attestation_") {
			return BeaconAttestationMessage
		}
	}

	return UnknownMessage
}

// ExtractBlobSubnet extracts the subnet ID from a blob sidecar topic
func ExtractBlobSubnet(topic string) (uint64, error) {
	// Topic format: /eth2/{fork_digest}/blob_sidecar_{subnet_id}/ssz_snappy
	parts := strings.Split(topic, "/")
	if len(parts) < 4 {
		return 0, fmt.Errorf("invalid topic format")
	}

	topicName := parts[3]
	if !strings.HasPrefix(topicName, "blob_sidecar_") {
		return 0, fmt.Errorf("not a blob sidecar topic")
	}

	subnetStr := strings.TrimPrefix(topicName, "blob_sidecar_")
	subnet, err := strconv.ParseUint(subnetStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid subnet ID: %w", err)
	}

	return subnet, nil
}

// ExtractAttestationSubnet extracts the subnet ID from an attestation topic
func ExtractAttestationSubnet(topic string) (uint64, error) {
	// Topic format: /eth2/{fork_digest}/beacon_attestation_{subnet_id}/ssz_snappy
	parts := strings.Split(topic, "/")
	if len(parts) < 4 {
		return 0, fmt.Errorf("invalid topic format")
	}

	topicName := parts[3]
	if !strings.HasPrefix(topicName, "beacon_attestation_") {
		return 0, fmt.Errorf("not an attestation topic")
	}

	subnetStr := strings.TrimPrefix(topicName, "beacon_attestation_")
	subnet, err := strconv.ParseUint(subnetStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid subnet ID: %w", err)
	}

	return subnet, nil
}

// ExtractSyncSubnet extracts the subnet ID from a sync committee topic
func ExtractSyncSubnet(topic string) (uint64, error) {
	// Topic format: /eth2/{fork_digest}/sync_committee_{subnet_id}/ssz_snappy
	parts := strings.Split(topic, "/")
	if len(parts) < 4 {
		return 0, fmt.Errorf("invalid topic format")
	}

	topicName := parts[3]
	if !strings.HasPrefix(topicName, "sync_committee_") {
		return 0, fmt.Errorf("not a sync committee topic")
	}

	subnetStr := strings.TrimPrefix(topicName, "sync_committee_")
	subnet, err := strconv.ParseUint(subnetStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid subnet ID: %w", err)
	}

	return subnet, nil
}

// BytesToHex converts bytes to hex string with 0x prefix
func BytesToHex(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

// HexToBytes converts hex string (with or without 0x prefix) to bytes
func HexToBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	return hex.DecodeString(s)
}

// GetMessageTypeName returns a human-readable name for a message type
func GetMessageTypeName(msgType MessageType) string {
	switch msgType {
	case BeaconBlockMessage:
		return "beacon_block"
	case BeaconAggregateAndProofMessage:
		return "beacon_aggregate_and_proof"
	case BeaconAttestationMessage:
		return "beacon_attestation"
	case VoluntaryExitMessage:
		return "voluntary_exit"
	case ProposerSlashingMessage:
		return "proposer_slashing"
	case AttesterSlashingMessage:
		return "attester_slashing"
	case SyncCommitteeMessage:
		return "sync_committee"
	case SyncCommitteeContributionMessage:
		return "sync_committee_contribution"
	case BlsToExecutionChangeMessage:
		return "bls_to_execution_change"
	case BlobSidecarMessage:
		return "blob_sidecar"
	default:
		return "unknown"
	}
}

// SlotToEpoch converts a slot to epoch
func SlotToEpoch(slot Slot) Epoch {
	return Epoch(slot / SLOTS_PER_EPOCH)
}

// EpochToSlot converts an epoch to the first slot of that epoch
func EpochToSlot(epoch Epoch) Slot {
	return Slot(epoch * SLOTS_PER_EPOCH)
}

// ComputeDomain computes the signature domain
func ComputeDomain(domainType DomainType, fork *ForkInfo, genesisValidatorRoot [32]byte) ([32]byte, error) {
	// Get the current fork version
	var forkVersion [4]byte
	if fork != nil {
		forkVersion = fork.CurrentVersion
	}

	// Compute fork data root
	forkDataRoot := computeForkDataRoot(forkVersion, genesisValidatorRoot)

	// Compute domain
	var domain [32]byte
	copy(domain[0:4], uint32ToBytes(uint32(domainType)))
	copy(domain[4:], forkDataRoot[0:28])

	return domain, nil
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
	b[0] = byte(n)
	b[1] = byte(n >> 8)
	b[2] = byte(n >> 16)
	b[3] = byte(n >> 24)
	return b
}

// ComputeSigningRoot computes the signing root for an object
func ComputeSigningRoot(obj interface{}, domain [32]byte) ([32]byte, error) {
	// Get the SSZ root of the object
	var objRoot [32]byte

	// Check if obj implements ssz.HashRoot interface
	if hashable, ok := obj.(ssz.HashRoot); ok {
		root, err := hashable.HashTreeRoot()
		if err != nil {
			return [32]byte{}, fmt.Errorf("failed to compute hash tree root: %w", err)
		}
		objRoot = root
	} else {
		return [32]byte{}, fmt.Errorf("object does not implement ssz.HashRoot interface")
	}

	// Create signing container: obj_root + domain
	container := make([]byte, 64)
	copy(container[0:32], objRoot[:])
	copy(container[32:64], domain[:])

	// Return the hash of the container
	return hash.Hash(container), nil
}
