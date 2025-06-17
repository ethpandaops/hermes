package upstream

import (
	"bytes"
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/OffchainLabs/prysm/v6/beacon-chain/p2p/types"
	"github.com/OffchainLabs/prysm/v6/config/params"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	pb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"

	"github.com/probe-lab/hermes/eth/reqresp"
)

// handleBlocksByRange implements the BeaconBlocksByRange req/resp handler
func (h *UpstreamHandler) handleBlocksByRange(ctx context.Context, stream network.Stream) error {
	// Read the request
	var req pb.BeaconBlocksByRangeRequest
	if err := h.readRequest(ctx, stream, &req); err != nil {
		return fmt.Errorf("read blocks by range request: %w", err)
	}

	// Validate request
	if req.Count == 0 {
		return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
	}

	// Check against max request blocks limit
	maxBlocks := params.BeaconConfig().MaxRequestBlocks
	denebSlot := primitives.Slot(uint64(params.BeaconConfig().DenebForkEpoch) * uint64(params.BeaconConfig().SlotsPerEpoch))
	if req.StartSlot >= denebSlot {
		// Use Deneb limit for post-Deneb slots
		maxBlocks = params.BeaconConfig().MaxRequestBlocksDeneb
	}
	
	if req.Count > maxBlocks {
		return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
	}

	// Fetch blocks from beacon API
	blocks, err := h.beaconClient.GetBlocksByRange(ctx, uint64(req.StartSlot), req.Count)
	if err != nil {
		h.logger.Error("Failed to fetch blocks by range", "err", err, "start", req.StartSlot, "count", req.Count)
		return h.writeErrorResponse(stream, reqresp.ResponseCodeServerError)
	}

	// Write success response code first
	if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
		return fmt.Errorf("write response code: %w", err)
	}

	// Write each block as a chunk
	for _, versionedBlock := range blocks {
		// Get SSZ bytes based on version
		var sszData []byte
		
		switch versionedBlock.Version {
		case 0: // Phase0
			if versionedBlock.Phase0 != nil {
				sszData, err = versionedBlock.Phase0.MarshalSSZ()
			}
		case 1: // Altair
			if versionedBlock.Altair != nil {
				sszData, err = versionedBlock.Altair.MarshalSSZ()
			}
		case 2: // Bellatrix
			if versionedBlock.Bellatrix != nil {
				sszData, err = versionedBlock.Bellatrix.MarshalSSZ()
			}
		case 3: // Capella
			if versionedBlock.Capella != nil {
				sszData, err = versionedBlock.Capella.MarshalSSZ()
			}
		case 4: // Deneb
			if versionedBlock.Deneb != nil {
				sszData, err = versionedBlock.Deneb.MarshalSSZ()
			}
		case 5: // Electra
			if versionedBlock.Electra != nil {
				sszData, err = versionedBlock.Electra.MarshalSSZ()
			}
		default:
			return fmt.Errorf("unsupported block version: %d", versionedBlock.Version)
		}
		
		if err != nil {
			return fmt.Errorf("marshal block to SSZ: %w", err)
		}

		// Write fork digest (4 bytes) + SSZ encoded block
		if _, err := stream.Write(h.cfg.ForkDigest[:]); err != nil {
			return fmt.Errorf("write fork digest: %w", err)
		}

		// Write the SSZ data with length prefix
		// The encoder expects a Marshaler, but we already have the marshaled data
		// So we write the length prefix manually
		buf := new(bytes.Buffer)
		if _, err := h.cfg.Encoder.EncodeWithMaxLength(buf, &sszWrapper{data: sszData}); err != nil {
			return fmt.Errorf("encode block chunk: %w", err)
		}
		if _, err := stream.Write(buf.Bytes()); err != nil {
			return fmt.Errorf("write block chunk: %w", err)
		}
	}

	return nil
}

// handleBlocksByRoot implements the BeaconBlocksByRoot req/resp handler
func (h *UpstreamHandler) handleBlocksByRoot(ctx context.Context, stream network.Stream) error {
	// Read the request
	var req types.BeaconBlockByRootsReq
	if err := h.readRequest(ctx, stream, &req); err != nil {
		return fmt.Errorf("read blocks by root request: %w", err)
	}

	// Validate request
	if len(req) == 0 {
		return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
	}
	
	// Check against max request blocks limit
	if uint64(len(req)) > params.BeaconConfig().MaxRequestBlocks {
		return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
	}

	// Convert request to phase0.Root slice
	roots := make([]phase0.Root, len(req))
	for i, root := range req {
		copy(roots[i][:], root[:])
	}

	// Fetch blocks from beacon API
	blocks, err := h.beaconClient.GetBlocksByRoot(ctx, roots)
	if err != nil {
		h.logger.Error("Failed to fetch blocks by root", "err", err, "count", len(req))
		return h.writeErrorResponse(stream, reqresp.ResponseCodeServerError)
	}

	// Write success response code first
	if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
		return fmt.Errorf("write response code: %w", err)
	}

	// Write each block as a chunk
	for _, versionedBlock := range blocks {
		// Get SSZ bytes based on version
		var sszData []byte
		
		switch versionedBlock.Version {
		case 0: // Phase0
			if versionedBlock.Phase0 != nil {
				sszData, err = versionedBlock.Phase0.MarshalSSZ()
			}
		case 1: // Altair
			if versionedBlock.Altair != nil {
				sszData, err = versionedBlock.Altair.MarshalSSZ()
			}
		case 2: // Bellatrix
			if versionedBlock.Bellatrix != nil {
				sszData, err = versionedBlock.Bellatrix.MarshalSSZ()
			}
		case 3: // Capella
			if versionedBlock.Capella != nil {
				sszData, err = versionedBlock.Capella.MarshalSSZ()
			}
		case 4: // Deneb
			if versionedBlock.Deneb != nil {
				sszData, err = versionedBlock.Deneb.MarshalSSZ()
			}
		case 5: // Electra
			if versionedBlock.Electra != nil {
				sszData, err = versionedBlock.Electra.MarshalSSZ()
			}
		default:
			return fmt.Errorf("unsupported block version: %d", versionedBlock.Version)
		}
		
		if err != nil {
			return fmt.Errorf("marshal block to SSZ: %w", err)
		}

		// Write fork digest (4 bytes) + SSZ encoded block
		if _, err := stream.Write(h.cfg.ForkDigest[:]); err != nil {
			return fmt.Errorf("write fork digest: %w", err)
		}

		// Write the SSZ data with length prefix
		// The encoder expects a Marshaler, but we already have the marshaled data
		// So we write the length prefix manually
		buf := new(bytes.Buffer)
		if _, err := h.cfg.Encoder.EncodeWithMaxLength(buf, &sszWrapper{data: sszData}); err != nil {
			return fmt.Errorf("encode block chunk: %w", err)
		}
		if _, err := stream.Write(buf.Bytes()); err != nil {
			return fmt.Errorf("write block chunk: %w", err)
		}
	}

	return nil
}

// writeErrorResponse writes an error response to the stream
func (h *UpstreamHandler) writeErrorResponse(stream network.Stream, code uint8) error {
	return reqresp.WriteErrorResponse(stream, code, h.cfg.WriteTimeout)
}