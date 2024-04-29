package eth

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pubsubpb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/p2p"
	"github.com/prysmaticlabs/prysm/v5/beacon-chain/p2p/encoder"
	"github.com/prysmaticlabs/prysm/v5/consensus-types/primitives"
	ethtypes "github.com/prysmaticlabs/prysm/v5/proto/prysm/v1alpha1"
	"github.com/thejerf/suture/v4"

	"github.com/probe-lab/hermes/host"
	"github.com/probe-lab/hermes/tele"
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
	switch {
	// Ensure hotter topics are at the top of the switch statement.
	case strings.Contains(topic, p2p.GossipAttestationMessage):
		return p.handleBeaconAttestation
	case strings.Contains(topic, p2p.GossipBlockMessage):
		return p.handleBeaconBlock
	default:
		return p.host.TracedTopicHandler(host.NoopHandler)
	}
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

func (p *PubSub) handleBeaconAttestation(ctx context.Context, msg *pubsub.Message) error {
	now := time.Now()

	attestation := &ethtypes.Attestation{}
	if err := p.cfg.Encoder.DecodeGossip(msg.Data, attestation); err != nil {
		return fmt.Errorf("error decoding phase0 attestation gossip message: %w", err)
	}

	evt := &host.TraceEvent{
		Type:      "HANDLE_MESSAGE",
		PeerID:    p.host.ID(),
		Timestamp: now,
		Payload: map[string]any{
			"PeerID":      msg.ReceivedFrom.String(),
			"MsgID":       hex.EncodeToString([]byte(msg.ID)),
			"MsgSize":     len(msg.Data),
			"Topic":       msg.GetTopic(),
			"Seq":         msg.GetSeqno(),
			"Attestation": attestation,
			"Timestamp":   now,
		},
	}

	if err := p.cfg.DataStream.PutEvent(ctx, evt); err != nil {
		slog.Warn("failed putting topic handler event", tele.LogAttrError(err))
	}

	return nil

}

func (p *PubSub) handleBeaconBlock(ctx context.Context, msg *pubsub.Message) error {
	now := time.Now()

	genericBlock, root, err := p.getSignedBeaconBlockForForkDigest(msg.Data)
	if err != nil {
		return err
	}

	slot := genericBlock.GetSlot()
	ProposerIndex := genericBlock.GetProposerIndex()

	slotStart := p.cfg.GenesisTime.Add(time.Duration(slot) * p.cfg.SecondsPerSlot)

	evt := &host.TraceEvent{
		Type:      "HANDLE_MESSAGE",
		PeerID:    p.host.ID(),
		Timestamp: now,
		Payload: map[string]any{
			"PeerID":     msg.ReceivedFrom.String(),
			"MsgID":      hex.EncodeToString([]byte(msg.ID)),
			"MsgSize":    len(msg.Data),
			"Topic":      msg.GetTopic(),
			"Seq":        msg.GetSeqno(),
			"ValIdx":     ProposerIndex,
			"Slot":       slot,
			"Root":       root,
			"TimeInSlot": now.Sub(slotStart).Seconds(),
			"Timestamp":  now,
		},
	}

	if err := p.cfg.DataStream.PutEvent(ctx, evt); err != nil {
		slog.Warn("failed putting topic handler event", tele.LogAttrError(err))
	}

	return nil
}

type GenericSignedBeaconBlock interface {
	GetBlock() GenericBeaconBlock
}

type GenericBeaconBlock interface {
	GetSlot() primitives.Slot
	GetProposerIndex() primitives.ValidatorIndex
}

func (p *PubSub) getSignedBeaconBlockForForkDigest(msgData []byte) (genericSbb GenericBeaconBlock, root [32]byte, err error) {
	// get the correct fork

	switch p.cfg.ForkVersion {
	case Phase0ForkVersion:
		phase0Sbb := ethtypes.SignedBeaconBlock{}
		err = p.cfg.Encoder.DecodeGossip(msgData, &phase0Sbb)
		if err != nil {
			return genericSbb, [32]byte{}, fmt.Errorf("error decoding phase0 beacon block gossip message: %w", err)
		}
		genericSbb = phase0Sbb.GetBlock()
		root, err = phase0Sbb.Block.HashTreeRoot()
		if err != nil {
			return genericSbb, [32]byte{}, fmt.Errorf("invalid hash tree root: %w", err)
		}
		return genericSbb, root, nil

	case AltairForkVersion:
		altairSbb := ethtypes.SignedBeaconBlockAltair{}
		err = p.cfg.Encoder.DecodeGossip(msgData, &altairSbb)
		if err != nil {
			return genericSbb, [32]byte{}, fmt.Errorf("error decoding altair beacon block gossip message: %w", err)
		}
		genericSbb = altairSbb.GetBlock()
		root, err = altairSbb.Block.HashTreeRoot()
		if err != nil {
			return genericSbb, [32]byte{}, fmt.Errorf("invalid hash tree root: %w", err)
		}
		return genericSbb, root, nil

	case BellatrixForkVersion:
		BellatrixSbb := ethtypes.SignedBeaconBlockBellatrix{}
		err = p.cfg.Encoder.DecodeGossip(msgData, &BellatrixSbb)
		if err != nil {
			return genericSbb, [32]byte{}, fmt.Errorf("error decoding bellatrix beacon block gossip message: %w", err)
		}
		genericSbb = BellatrixSbb.GetBlock()
		root, err = BellatrixSbb.Block.HashTreeRoot()
		if err != nil {
			return genericSbb, [32]byte{}, fmt.Errorf("invalid hash tree root: %w", err)
		}
		return genericSbb, root, nil

	case CapellaForkVersion:
		capellaSbb := ethtypes.SignedBeaconBlockCapella{}
		err = p.cfg.Encoder.DecodeGossip(msgData, &capellaSbb)
		if err != nil {
			return genericSbb, [32]byte{}, fmt.Errorf("error decoding capella beacon block gossip message: %w", err)
		}
		genericSbb = capellaSbb.GetBlock()
		root, err = capellaSbb.Block.HashTreeRoot()
		if err != nil {
			return genericSbb, [32]byte{}, fmt.Errorf("invalid hash tree root: %w", err)
		}
		return genericSbb, root, nil

	case DenebForkVersion:
		denebSbb := ethtypes.SignedBeaconBlockDeneb{}
		err = p.cfg.Encoder.DecodeGossip(msgData, &denebSbb)
		if err != nil {
			return genericSbb, [32]byte{}, fmt.Errorf("error decoding deneb beacon block gossip message: %w", err)
		}
		genericSbb = denebSbb.GetBlock()
		root, err = denebSbb.Block.HashTreeRoot()
		if err != nil {
			return genericSbb, [32]byte{}, fmt.Errorf("invalid hash tree root: %w", err)
		}
		return genericSbb, root, nil

	default:
		return genericSbb, [32]byte{}, fmt.Errorf("non recognized fork-version: %d", p.cfg.ForkVersion[:])
	}
}
