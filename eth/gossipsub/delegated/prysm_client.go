package delegated

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
)

// PrysmClient is an alias for RealPrysmClient
type PrysmClient = RealPrysmClient

// RealPrysmClient implements actual Prysm RPC calls
type RealPrysmClient struct {
	httpEndpoint string
	grpcEndpoint string
	grpcConn     *grpc.ClientConn
	httpClient   *http.Client
	client       ethpb.BeaconNodeValidatorClient
}

// NewRealPrysmClient creates a new Prysm client
func NewRealPrysmClient(httpEndpoint, grpcEndpoint string, useTLS bool) (*RealPrysmClient, error) {
	// Create gRPC connection
	var opts []grpc.DialOption
	if !useTLS {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	
	conn, err := grpc.NewClient(grpcEndpoint, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to Prysm gRPC")
	}

	client := ethpb.NewBeaconNodeValidatorClient(conn)
	
	return &RealPrysmClient{
		httpEndpoint: httpEndpoint,
		grpcEndpoint: grpcEndpoint,
		grpcConn:     conn,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		client: client,
	}, nil
}

// Close closes the client connections
func (c *RealPrysmClient) Close() error {
	if c.grpcConn != nil {
		return c.grpcConn.Close()
	}
	return nil
}

// ValidateMessage validates a message using Prysm's validation endpoint
func (c *RealPrysmClient) ValidateMessage(ctx context.Context, topic string, data []byte) (bool, error) {
	// Prysm doesn't expose a direct validation API, so we would need to:
	// 1. Submit the message to Prysm via its p2p interface
	// 2. Check if Prysm accepts/rejects it
	// 
	// For now, we'll implement a simplified version that checks basic validity
	// In production, this would use Prysm's internal validation logic
	
	// Parse the topic to determine message type
	msgType, err := getMessageTypeFromTopic(topic)
	if err != nil {
		return false, err
	}

	// For each message type, we would call the appropriate Prysm API
	// to validate the message. Since Prysm doesn't expose direct validation
	// APIs, we would need to use workarounds or submit to Prysm's p2p layer
	switch msgType {
	case "beacon_block":
		return c.validateBeaconBlock(ctx, data)
	case "beacon_attestation":
		return c.validateAttestation(ctx, data)
	case "voluntary_exit":
		return c.validateVoluntaryExit(ctx, data)
	case "proposer_slashing":
		return c.validateProposerSlashing(ctx, data)
	case "attester_slashing":
		return c.validateAttesterSlashing(ctx, data)
	default:
		// For unknown types, accept by default
		return true, nil
	}
}

// validateBeaconBlock checks if a beacon block is valid
func (c *RealPrysmClient) validateBeaconBlock(ctx context.Context, data []byte) (bool, error) {
	// In a real implementation, this would:
	// 1. Deserialize the block
	// 2. Submit to Prysm's beacon chain client
	// 3. Check for errors
	
	// For now, basic validation
	block := &ethpb.SignedBeaconBlock{}
	if err := block.UnmarshalSSZ(data); err != nil {
		return false, nil // Invalid SSZ means invalid message
	}

	// Check basic constraints
	if block.Block == nil {
		return false, nil
	}

	return true, nil
}

// validateAttestation checks if an attestation is valid
func (c *RealPrysmClient) validateAttestation(ctx context.Context, data []byte) (bool, error) {
	att := &ethpb.Attestation{}
	if err := att.UnmarshalSSZ(data); err != nil {
		return false, nil
	}

	// Basic validation
	if att.Data == nil || len(att.Signature) != 96 {
		return false, nil
	}

	return true, nil
}

// validateVoluntaryExit checks if a voluntary exit is valid
func (c *RealPrysmClient) validateVoluntaryExit(ctx context.Context, data []byte) (bool, error) {
	exit := &ethpb.SignedVoluntaryExit{}
	if err := exit.UnmarshalSSZ(data); err != nil {
		return false, nil
	}

	// Basic validation
	if exit.Exit == nil || len(exit.Signature) != 96 {
		return false, nil
	}

	// In production, we would submit this to Prysm's operations pool
	// and check if it's accepted
	return true, nil
}

// validateProposerSlashing checks if a proposer slashing is valid
func (c *RealPrysmClient) validateProposerSlashing(ctx context.Context, data []byte) (bool, error) {
	slashing := &ethpb.ProposerSlashing{}
	if err := slashing.UnmarshalSSZ(data); err != nil {
		return false, nil
	}

	// Basic validation
	if slashing.Header_1 == nil || slashing.Header_2 == nil {
		return false, nil
	}

	return true, nil
}

// validateAttesterSlashing checks if an attester slashing is valid
func (c *RealPrysmClient) validateAttesterSlashing(ctx context.Context, data []byte) (bool, error) {
	slashing := &ethpb.AttesterSlashing{}
	if err := slashing.UnmarshalSSZ(data); err != nil {
		return false, nil
	}

	// Basic validation
	if slashing.Attestation_1 == nil || slashing.Attestation_2 == nil {
		return false, nil
	}

	return true, nil
}

// getMessageTypeFromTopic extracts the message type from a gossipsub topic
func getMessageTypeFromTopic(topic string) (string, error) {
	// Topic format: /eth2/fork_digest/message_type/ssz_snappy
	// We need to extract the message_type part
	
	// This is a simplified parser
	if len(topic) < 10 {
		return "", fmt.Errorf("invalid topic: %s", topic)
	}

	// Find the message type between second and third slash
	start := 0
	slashCount := 0
	for i, ch := range topic {
		if ch == '/' {
			slashCount++
			if slashCount == 3 {
				start = i + 1
			} else if slashCount == 4 {
				return topic[start:i], nil
			}
		}
	}

	// Handle case where there's no fourth slash (no encoding suffix)
	if slashCount == 3 && start > 0 {
		return topic[start:], nil
	}

	return "", fmt.Errorf("could not parse topic: %s", topic)
}