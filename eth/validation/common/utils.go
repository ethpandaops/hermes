package common

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
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
	case "beacon_attestation_0", "beacon_attestation_1", "beacon_attestation_2",
		"beacon_attestation_3", "beacon_attestation_4", "beacon_attestation_5",
		"beacon_attestation_6", "beacon_attestation_7", "beacon_attestation_8",
		"beacon_attestation_9", "beacon_attestation_10", "beacon_attestation_11",
		"beacon_attestation_12", "beacon_attestation_13", "beacon_attestation_14",
		"beacon_attestation_15", "beacon_attestation_16", "beacon_attestation_17",
		"beacon_attestation_18", "beacon_attestation_19", "beacon_attestation_20",
		"beacon_attestation_21", "beacon_attestation_22", "beacon_attestation_23",
		"beacon_attestation_24", "beacon_attestation_25", "beacon_attestation_26",
		"beacon_attestation_27", "beacon_attestation_28", "beacon_attestation_29",
		"beacon_attestation_30", "beacon_attestation_31", "beacon_attestation_32",
		"beacon_attestation_33", "beacon_attestation_34", "beacon_attestation_35",
		"beacon_attestation_36", "beacon_attestation_37", "beacon_attestation_38",
		"beacon_attestation_39", "beacon_attestation_40", "beacon_attestation_41",
		"beacon_attestation_42", "beacon_attestation_43", "beacon_attestation_44",
		"beacon_attestation_45", "beacon_attestation_46", "beacon_attestation_47",
		"beacon_attestation_48", "beacon_attestation_49", "beacon_attestation_50",
		"beacon_attestation_51", "beacon_attestation_52", "beacon_attestation_53",
		"beacon_attestation_54", "beacon_attestation_55", "beacon_attestation_56",
		"beacon_attestation_57", "beacon_attestation_58", "beacon_attestation_59",
		"beacon_attestation_60", "beacon_attestation_61", "beacon_attestation_62",
		"beacon_attestation_63":
		return BeaconAttestationMessage
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
	// This is a simplified version - in production would use proper domain computation
	var domain [32]byte
	// Convert domain type to bytes
	domainBytes := make([]byte, 4)
	domainBytes[0] = byte(domainType)
	domainBytes[1] = byte(domainType >> 8)
	domainBytes[2] = byte(domainType >> 16)
	domainBytes[3] = byte(domainType >> 24)
	copy(domain[:4], domainBytes)
	if fork != nil {
		copy(domain[4:8], fork.CurrentVersion[:])
	}
	copy(domain[8:], genesisValidatorRoot[:24])
	return domain, nil
}

// ComputeSigningRoot computes the signing root for an object
func ComputeSigningRoot(obj interface{}, domain [32]byte) ([32]byte, error) {
	// This is a simplified version - in production would use proper SSZ hashing
	// For now, return a dummy root
	var root [32]byte
	return root, nil
}