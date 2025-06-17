package eth

import (
	"context"
	"fmt"
	"time"

	"github.com/OffchainLabs/prysm/v6/beacon-chain/p2p/encoder"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pubsubpb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/thejerf/suture/v4"

	"github.com/probe-lab/hermes/host"
)

type PubSubConfig struct {
	Topics         []string
	ForkVersion    ForkVersion
	Encoder        encoder.NetworkEncoding
	SecondsPerSlot time.Duration
	GenesisTime    time.Time
	DataStream     host.DataStream
}

func (p PubSubConfig) Validate() error {
	if p.Encoder == nil {
		return fmt.Errorf("nil encoder")
	}

	if p.SecondsPerSlot == 0 {
		return fmt.Errorf("seconds per slot must not be 0")
	}

	if p.GenesisTime.IsZero() {
		return fmt.Errorf("genesis time must not be zero time")
	}

	if p.DataStream == nil {
		return fmt.Errorf("datastream implementation required")
	}

	return nil
}

type PubSub struct {
	host *host.Host
	cfg  *PubSubConfig
	gs   *pubsub.PubSub
	dsr  host.DataStreamRenderer
}

func NewPubSub(h *host.Host, cfg *PubSubConfig) (*PubSub, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate configuration: %w", err)
	}

	var dsr host.DataStreamRenderer

	switch cfg.DataStream.OutputType() {
	case host.DataStreamOutputTypeFull:
		dsr = NewFullOutput(cfg)
	// TODO: If wanted, add a new S3ParquetOutput
	default:
		dsr = NewKinesisOutput(cfg)
	}

	return &PubSub{
		host: h,
		cfg:  cfg,
		dsr:  dsr,
	}, nil
}

func (p *PubSub) Serve(ctx context.Context) error {
	if p.gs == nil {
		return fmt.Errorf("node's pubsub service uninitialized gossip sub: %w", suture.ErrTerminateSupervisorTree)
	}

	supervisor := suture.NewSimple("pubsub")

	for _, topicName := range p.cfg.Topics {
		topic, err := p.gs.Join(topicName)
		if err != nil {
			return fmt.Errorf("join pubsub topic %s: %w", topicName, err)
		}
		defer logDeferErr(topic.Close, fmt.Sprintf("failed closing %s topic", topicName))

		// get the handler for the specific topic
		topicHandler := p.mapPubSubTopicWithHandlers(topicName)

		sub, err := topic.Subscribe()
		if err != nil {
			return fmt.Errorf("subscribe to pubsub topic %s: %w", topicName, err)
		}

		ts := &host.TopicSubscription{
			Topic:   topicName,
			LocalID: p.host.ID(),
			Sub:     sub,
			Handler: topicHandler,
		}

		supervisor.Add(ts)
	}

	return supervisor.Serve(ctx)
}

func (p *PubSub) mapPubSubTopicWithHandlers(topic string) host.TopicHandler {
	// Message processing is now handled by the validators during the validation phase
	// These handlers are no longer needed, so we return a no-op handler
	return p.host.TracedTopicHandler(host.NoopHandler)
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
