package eth

import (
	"context"
	"encoding/hex"
	"log/slog"
	"strings"
	"time"

	pb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/prysmaticlabs/go-bitfield"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/probe-lab/hermes/tele"
)

const (
	peerstoreKeyConnectedAt  = "connected_at"
	peerstoreKeyIsHandshaked = "is_handshaked"
)

// The Hermes Ethereum [Node] implements the [network.Notifiee] interface.
// This means it will be notified about new connections.
var _ network.Notifiee = (*Node)(nil)

func (n *Node) Connected(net network.Network, c network.Conn) {
	slog.Debug("Connected with peer", tele.LogAttrPeerID(c.RemotePeer()), "total", len(n.host.Network().Peers()), "dir", c.Stat().Direction)

	if err := n.host.Peerstore().Put(c.RemotePeer(), peerstoreKeyConnectedAt, time.Now()); err != nil {
		slog.Warn("Failed to store connection timestamp in peerstore", tele.LogAttrError(err))
	}

	// Handle both inbound and outbound connections
	// Consensus clients may initiate connections to Hermes, so we need to handshake with them too
	go n.handleNewConnection(c.RemotePeer())
}

func (n *Node) Disconnected(net network.Network, c network.Conn) {
	if n.pryInfo != nil && c.RemotePeer() == n.pryInfo.ID {
		slog.Warn("Beacon node disconnected")
	}

	if !c.Stat().Opened.IsZero() {
		av := n.host.AgentVersion(c.RemotePeer())
		parts := strings.Split(av, "/")
		if len(parts) > 0 {
			switch strings.ToLower(parts[0]) {
			case "prysm", "lighthouse", "nimbus", "lodestar", "grandine", "teku", "erigon":
				av = strings.ToLower(parts[0])
			default:
				av = "other"
			}
		} else {
			av = "unknown"
		}
		n.connAge.Record(context.TODO(), time.Since(c.Stat().Opened).Seconds(), metric.WithAttributes(attribute.String("agent", av)))
	}

	ps := n.host.Peerstore()
	if _, err := ps.Get(c.RemotePeer(), peerstoreKeyIsHandshaked); err == nil {
		if val, err := ps.Get(c.RemotePeer(), peerstoreKeyConnectedAt); err == nil {
			slog.Info("Disconnected from handshaked peer", tele.LogAttrPeerID(c.RemotePeer()))
			n.connDurHist.Record(context.Background(), time.Since(val.(time.Time)).Hours())
		}
	}
}

func (n *Node) Listen(net network.Network, maddr ma.Multiaddr) {}

func (n *Node) ListenClose(net network.Network, maddr ma.Multiaddr) {}

// handleNewConnection validates the newly established connection to the given
// peer.
func (n *Node) handleNewConnection(pid peer.ID) {
	// before we add the peer to our pool, we'll perform a handshake

	ctx, cancel := context.WithTimeout(context.Background(), n.cfg.DialTimeout)
	defer cancel()

	ps := n.host.Peerstore()

	// Determine connection direction for logging
	conns := n.host.Network().ConnsToPeer(pid)
	direction := "unknown"
	if len(conns) > 0 {
		direction = conns[0].Stat().Direction.String()
	}
	
	slog.Debug("Starting handshake", tele.LogAttrPeerID(pid), "direction", direction)

	// Status is required - it validates the peer is on the same network
	st, err := n.reqResp.Status(ctx, pid)
	if err != nil {
		slog.Warn("Status request failed during handshake", tele.LogAttrPeerID(pid), "direction", direction, tele.LogAttrError(err))
		// the handshake failed, we disconnect and remove it from our pool
		ps.RemovePeer(pid)
		_ = n.host.Network().ClosePeer(pid)
		return
	}

	// Get agent version for logging
	av := n.host.AgentVersion(pid)
	if av == "" {
		av = "n.a."
	}

	// Ping and MetaData are optional - some clients may have different implementations
	// or timing requirements. We'll try them but won't disconnect if they fail.
	pingErr := n.reqResp.Ping(ctx, pid)
	if pingErr != nil {
		slog.Debug("Ping failed during handshake (non-critical)", tele.LogAttrPeerID(pid), "agent", av, tele.LogAttrError(pingErr))
	}

	md, mdErr := n.reqResp.MetaData(ctx, pid)
	if mdErr != nil {
		slog.Debug("MetaData request failed during handshake (non-critical)", tele.LogAttrPeerID(pid), "agent", av, tele.LogAttrError(mdErr))
		// Create a placeholder metadata for logging
		md = &pb.MetaDataV1{
			SeqNumber: 0,
			Attnets:   bitfield.NewBitvector64(),
		}
	}

	// Mark as handshaked since we got a valid status response
	if err := ps.Put(pid, peerstoreKeyIsHandshaked, true); err != nil {
		slog.Warn("Failed to store handshaked marker in peerstore", tele.LogAttrError(err))
	}

	slog.Info("Performed successful handshake", tele.LogAttrPeerID(pid), "direction", direction, "seq", md.SeqNumber, "attnets", hex.EncodeToString(md.Attnets.Bytes()), "agent", av, "fork-digest", hex.EncodeToString(st.ForkDigest), "ping_ok", pingErr == nil, "metadata_ok", mdErr == nil)
}
