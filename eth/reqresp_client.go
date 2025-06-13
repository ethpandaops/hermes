package eth

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	pb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/probe-lab/hermes/eth/reqresp"
	hermeshost "github.com/probe-lab/hermes/host"
)

// Status performs a status request to the given peer
func (n *Node) Status(ctx context.Context, pid peer.ID) (status *pb.Status, err error) {
	defer func() {
		av, err := n.host.Peerstore().Get(pid, "AgentVersion")
		if err != nil {
			av = "unknown"
		}

		reqData := map[string]any{
			"AgentVersion": av,
			"PeerID":       pid.String(),
		}
		if status != nil {
			reqData["ForkDigest"] = hex.EncodeToString(status.ForkDigest)
			reqData["HeadRoot"] = hex.EncodeToString(status.HeadRoot)
			reqData["HeadSlot"] = status.HeadSlot
			reqData["FinalizedRoot"] = hex.EncodeToString(status.FinalizedRoot)
			reqData["FinalizedEpoch"] = status.FinalizedEpoch
		}

		if err != nil {
			reqData["Error"] = err.Error()
		}

		traceEvt := &hermeshost.TraceEvent{
			Type:      "REQUEST_STATUS",
			PeerID:    n.host.ID(),
			Timestamp: time.Now(),
			Payload:   reqData,
		}

		if n.ds != nil {
			if dsErr := n.ds.PutRecord(ctx, traceEvt); dsErr != nil {
				slog.Warn("Failed to put record", "error", dsErr)
			}
		}
	}()

	protocolID := reqresp.GetProtocolID(n.cfg.ForkDigest, reqresp.ProtocolStatus, 1)
	stream, err := n.host.NewStream(ctx, pid, protocolID)
	if err != nil {
		return nil, fmt.Errorf("new stream: %w", err)
	}
	defer stream.Close()

	// Write our status
	ourStatus := n.reqRespHandler.GetStatus()
	if ourStatus == nil {
		return nil, fmt.Errorf("our status not available")
	}
	
	if err := reqresp.WriteRequest(ctx, stream, n.reqRespConfig.Encoder, ourStatus, n.reqRespConfig.WriteTimeout); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	// Read their status
	theirStatus := &pb.Status{}
	if err := reqresp.ReadResponse(ctx, stream, n.reqRespConfig.Encoder, theirStatus, n.reqRespConfig.ReadTimeout); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return theirStatus, nil
}

// Ping performs a ping request to the given peer
func (n *Node) Ping(ctx context.Context, pid peer.ID) error {
	protocolID := reqresp.GetProtocolID(n.cfg.ForkDigest, reqresp.ProtocolPing, 1)
	stream, err := n.host.NewStream(ctx, pid, protocolID)
	if err != nil {
		return fmt.Errorf("new stream: %w", err)
	}
	defer stream.Close()

	// Get our metadata sequence number
	metadata := n.reqRespHandler.GetMetaData()
	if metadata == nil {
		return fmt.Errorf("metadata not available")
	}

	// Write ping with our seq number
	ping := primitives.SSZUint64(metadata.SeqNumber)
	if err := reqresp.WriteRequest(ctx, stream, n.reqRespConfig.Encoder, &ping, n.reqRespConfig.WriteTimeout); err != nil {
		return fmt.Errorf("write request: %w", err)
	}

	// Read pong
	pong := primitives.SSZUint64(0)
	if err := reqresp.ReadResponse(ctx, stream, n.reqRespConfig.Encoder, &pong, n.reqRespConfig.ReadTimeout); err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	return nil
}

// MetaData performs a metadata request to the given peer
func (n *Node) MetaData(ctx context.Context, pid peer.ID) (*pb.MetaDataV1, error) {
	protocolID := reqresp.GetProtocolID(n.cfg.ForkDigest, reqresp.ProtocolMetadata, 1)
	stream, err := n.host.NewStream(ctx, pid, protocolID)
	if err != nil {
		return nil, fmt.Errorf("new stream: %w", err)
	}
	defer stream.Close()

	// No request body for metadata
	if err := stream.CloseWrite(); err != nil {
		return nil, fmt.Errorf("close write: %w", err)
	}

	// Read metadata response
	metadata := &pb.MetaDataV1{}
	if err := reqresp.ReadResponse(ctx, stream, n.reqRespConfig.Encoder, metadata, n.reqRespConfig.ReadTimeout); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return metadata, nil
}