package handlers

import (
	"context"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	ssz "github.com/prysmaticlabs/fastssz"
)

// TopicHandler defines the interface for handling different message types
type TopicHandler interface {
	HandleBeaconBlock(ctx context.Context, msg *pubsub.Message) (ssz.Unmarshaler, error)
	HandleAttestation(ctx context.Context, msg *pubsub.Message) (ssz.Unmarshaler, error)
	HandleAggregateAndProof(ctx context.Context, msg *pubsub.Message) (ssz.Unmarshaler, error)
	HandleVoluntaryExit(ctx context.Context, msg *pubsub.Message) (ssz.Unmarshaler, error)
	HandleProposerSlashing(ctx context.Context, msg *pubsub.Message) (ssz.Unmarshaler, error)
	HandleAttesterSlashing(ctx context.Context, msg *pubsub.Message) (ssz.Unmarshaler, error)
	HandleSyncCommitteeMessage(ctx context.Context, msg *pubsub.Message) (ssz.Unmarshaler, error)
	HandleContributionAndProof(ctx context.Context, msg *pubsub.Message) (ssz.Unmarshaler, error)
	HandleBlsToExecutionChange(ctx context.Context, msg *pubsub.Message) (ssz.Unmarshaler, error)
	HandleBlobSidecar(ctx context.Context, msg *pubsub.Message) (ssz.Unmarshaler, error)
}