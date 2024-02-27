package eth

import (
	"context"
	"fmt"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pubsubpb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/p2p"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/p2p/encoder"
	"github.com/thejerf/suture/v4"

	"github.com/probe-lab/hermes/host"
)

type PubSubConfig struct {
	ForkDigest [4]byte
	Encoder    encoder.NetworkEncoding
}

func (p PubSubConfig) Validate() error {
	if len(p.ForkDigest) == 0 {
		return fmt.Errorf("empty fork digest")
	}

	if p.Encoder == nil {
		return fmt.Errorf("nil encoder")
	}

	return nil
}

type PubSub struct {
	host *host.Host
	cfg  *PubSubConfig
	gs   *pubsub.PubSub
}

func NewPubSub(h *host.Host, cfg *PubSubConfig) (*PubSub, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate configuration: %w", err)
	}

	ps := &PubSub{
		host: h,
		cfg:  cfg,
	}

	return ps, nil
}

func (p *PubSub) Serve(ctx context.Context) error {
	if p.gs == nil {
		return fmt.Errorf("node's pubsub service uninitialized gossip sub: %w", suture.ErrTerminateSupervisorTree)
	}

	topicFormats := []string{
		p2p.BlockSubnetTopicFormat,
		p2p.AggregateAndProofSubnetTopicFormat,
		p2p.ExitSubnetTopicFormat,
		p2p.ProposerSlashingSubnetTopicFormat,
		p2p.AttesterSlashingSubnetTopicFormat,
		p2p.SyncContributionAndProofSubnetTopicFormat,
		p2p.BlsToExecutionChangeSubnetTopicFormat,
		// Not supported topics yet:
		// p2p.AttestationSubnetTopicFormat,
		// p2p.SyncCommitteeSubnetTopicFormat,
		// p2p.BlobSubnetTopicFormat,
	}

	supervisor := suture.NewSimple("pubsub")

	for _, topicFormat := range topicFormats {
		topicName := fmt.Sprintf(topicFormat, p.cfg.ForkDigest) + p.cfg.Encoder.ProtocolSuffix()
		topic, err := p.gs.Join(topicName)
		if err != nil {
			return fmt.Errorf("join pubsub topic %s: %w", topicName, err)
		}
		defer logDeferErr(topic.Close, fmt.Sprintf("failed closing %s topic", topicName))

		sub, err := topic.Subscribe()
		if err != nil {
			return fmt.Errorf("subscribe to pubsub topic %s: %w", topicName, err)
		}

		ts := &host.TopicSubscription{
			Topic:   topicName,
			LocalID: p.host.ID(),
			Sub:     sub,
			Handler: host.NoopHandler,
		}

		supervisor.Add(ts)
	}

	return supervisor.Serve(ctx)
}

var _ pubsub.SubscriptionFilter = (*Node)(nil)

// CanSubscribe originally returns true if the topic is of interest, and we could subscribe to it.
func (n *Node) CanSubscribe(topic string) bool {
	return true
}

// FilterIncomingSubscriptions is invoked for all RPCs containing subscription notifications.
// This method returns only the topics of interest and may return an error if the subscription
// request contains too many topics.
func (n *Node) FilterIncomingSubscriptions(id peer.ID, subs []*pubsubpb.RPC_SubOpts) ([]*pubsubpb.RPC_SubOpts, error) {
	if len(subs) > n.cfg.PubSubSubscriptionRequestLimit {
		return nil, pubsub.ErrTooManySubscriptions
	}

	return pubsub.FilterSubscriptions(subs, n.CanSubscribe), nil
}