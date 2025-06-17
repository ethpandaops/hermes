package upstream

import (
	"bytes"
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/OffchainLabs/prysm/v6/beacon-chain/p2p/types"
	"github.com/OffchainLabs/prysm/v6/config/params"
	pb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"

	"github.com/probe-lab/hermes/eth/reqresp"
)

// Constants for blob sidecars
const (
	// MaxBlobSidecarsPerRequest is the maximum number of blob sidecars that can be requested
	// This is based on MAX_REQUEST_BLOB_SIDECARS = MAX_REQUEST_BLOCKS_DENEB * MAX_BLOBS_PER_BLOCK
	// For mainnet: 128 * 6 = 768
	MaxBlobSidecarsPerRequest = 768
)

// handleBlobSidecarsByRange implements the BlobSidecarsByRange req/resp handler
func (h *UpstreamHandler) handleBlobSidecarsByRange(ctx context.Context, stream network.Stream) error {
	// Read the request
	var req pb.BlobSidecarsByRangeRequest
	if err := h.readRequest(ctx, stream, &req); err != nil {
		return fmt.Errorf("read blob sidecars by range request: %w", err)
	}

	// Validate request
	if req.Count == 0 {
		return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
	}
	
	// Check against max blob sidecars limit
	// MAX_REQUEST_BLOB_SIDECARS = MAX_REQUEST_BLOCKS_DENEB * MAX_BLOBS_PER_BLOCK
	// For current slot (we don't have the exact slot so we use a reasonable default)
	maxBlobsPerBlock := 6 // This is the mainnet value
	maxBlobSidecars := params.BeaconConfig().MaxRequestBlocksDeneb * uint64(maxBlobsPerBlock)
	if req.Count > maxBlobSidecars {
		return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
	}

	// Fetch blob sidecars from beacon API
	blobs, err := h.beaconClient.GetBlobSidecarsByRange(ctx, uint64(req.StartSlot), req.Count)
	if err != nil {
		h.logger.Error("Failed to fetch blob sidecars by range", "err", err, "start", req.StartSlot, "count", req.Count)
		return h.writeErrorResponse(stream, reqresp.ResponseCodeServerError)
	}

	// Write success response code first
	if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
		return fmt.Errorf("write response code: %w", err)
	}

	// Write each blob sidecar as a chunk
	for _, blob := range blobs {
		// Marshal blob sidecar to SSZ
		sszData, err := blob.MarshalSSZ()
		if err != nil {
			return fmt.Errorf("marshal blob sidecar to SSZ: %w", err)
		}

		// Write fork digest (4 bytes) + SSZ encoded blob sidecar
		if _, err := stream.Write(h.cfg.ForkDigest[:]); err != nil {
			return fmt.Errorf("write fork digest: %w", err)
		}

		// Write the SSZ data with length prefix
		buf := new(bytes.Buffer)
		if _, err := h.cfg.Encoder.EncodeWithMaxLength(buf, &sszWrapper{data: sszData}); err != nil {
			return fmt.Errorf("encode blob sidecar chunk: %w", err)
		}
		if _, err := stream.Write(buf.Bytes()); err != nil {
			return fmt.Errorf("write blob sidecar chunk: %w", err)
		}
	}

	return nil
}

// handleBlobSidecarsByRoot implements the BlobSidecarsByRoot req/resp handler
func (h *UpstreamHandler) handleBlobSidecarsByRoot(ctx context.Context, stream network.Stream) error {
	// Read the request
	var req types.BlobSidecarsByRootReq
	if err := h.readRequest(ctx, stream, &req); err != nil {
		return fmt.Errorf("read blob sidecars by root request: %w", err)
	}

	// Validate request
	if len(req) == 0 {
		return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
	}
	
	// Check against max blob sidecars limit
	if len(req) > MaxBlobSidecarsPerRequest {
		return h.writeErrorResponse(stream, reqresp.ResponseCodeInvalidRequest)
	}

	// Extract unique block roots and blob indices from request
	rootMap := make(map[phase0.Root][]uint64)
	for _, item := range req {
		var root phase0.Root
		copy(root[:], item.BlockRoot)
		rootMap[root] = append(rootMap[root], item.Index)
	}

	// Convert to slices for API call
	roots := make([]phase0.Root, 0, len(rootMap))
	for root := range rootMap {
		roots = append(roots, root)
	}

	// Fetch all blob sidecars for the requested roots
	// The beacon client will filter by indices internally
	allBlobs, err := h.beaconClient.GetBlobSidecarsByRoot(ctx, roots, nil)
	if err != nil {
		h.logger.Error("Failed to fetch blob sidecars by root", "err", err, "count", len(req))
		return h.writeErrorResponse(stream, reqresp.ResponseCodeServerError)
	}

	// Filter blobs to match exactly what was requested
	requestedBlobs := make(map[string]bool)
	for _, item := range req {
		key := fmt.Sprintf("%x:%d", item.BlockRoot, item.Index)
		requestedBlobs[key] = true
	}

	// Write success response code first
	if _, err := stream.Write([]byte{reqresp.ResponseCodeSuccess}); err != nil {
		return fmt.Errorf("write response code: %w", err)
	}

	// Write each matching blob sidecar as a chunk
	for _, blob := range allBlobs {
		// Check if this blob was requested
		key := fmt.Sprintf("%x:%d", blob.SignedBlockHeader.Message.BodyRoot, blob.Index)
		if !requestedBlobs[key] {
			continue
		}

		// Marshal blob sidecar to SSZ
		sszData, err := blob.MarshalSSZ()
		if err != nil {
			return fmt.Errorf("marshal blob sidecar to SSZ: %w", err)
		}

		// Write fork digest (4 bytes) + SSZ encoded blob sidecar
		if _, err := stream.Write(h.cfg.ForkDigest[:]); err != nil {
			return fmt.Errorf("write fork digest: %w", err)
		}

		// Write the SSZ data with length prefix
		buf := new(bytes.Buffer)
		if _, err := h.cfg.Encoder.EncodeWithMaxLength(buf, &sszWrapper{data: sszData}); err != nil {
			return fmt.Errorf("encode blob sidecar chunk: %w", err)
		}
		if _, err := stream.Write(buf.Bytes()); err != nil {
			return fmt.Errorf("write blob sidecar chunk: %w", err)
		}
	}

	return nil
}