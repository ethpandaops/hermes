package upstream

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// BeaconClient provides access to beacon node API endpoints
type BeaconClient struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

// NewBeaconClient creates a new beacon API client
func NewBeaconClient(baseURL string, logger *slog.Logger) (*BeaconClient, error) {
	return &BeaconClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger.With("component", "beacon_client"),
	}, nil
}

// GetHead returns the current head information
func (c *BeaconClient) GetHead(ctx context.Context) (*phase0.SignedBeaconBlockHeader, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/eth/v1/beacon/headers/head", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bad status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Data struct {
			Root      string                         `json:"root"`
			Canonical bool                           `json:"canonical"`
			Header    phase0.SignedBeaconBlockHeader `json:"header"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result.Data.Header, nil
}

// GetFinalized returns the current finalized checkpoint
func (c *BeaconClient) GetFinalized(ctx context.Context) (*phase0.Checkpoint, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/eth/v1/beacon/states/finalized/finality_checkpoints", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bad status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Data struct {
			PreviousJustified phase0.Checkpoint `json:"previous_justified"`
			CurrentJustified  phase0.Checkpoint `json:"current_justified"`
			Finalized         phase0.Checkpoint `json:"finalized"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &result.Data.Finalized, nil
}

// GetBlocksByRange fetches blocks in a range
func (c *BeaconClient) GetBlocksByRange(ctx context.Context, start, count uint64) ([]*spec.VersionedSignedBeaconBlock, error) {
	blocks := make([]*spec.VersionedSignedBeaconBlock, 0, count)
	
	// Fetch blocks one by one
	// Note: Beacon API doesn't have a native range endpoint, so we fetch individually
	for i := uint64(0); i < count; i++ {
		slot := start + i
		req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/eth/v2/beacon/blocks/"+strconv.FormatUint(slot, 10), nil)
		if err != nil {
			return nil, fmt.Errorf("create request for slot %d: %w", slot, err)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("do request for slot %d: %w", slot, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			// Skip missing slots
			continue
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("bad status %d for slot %d: %s", resp.StatusCode, slot, body)
		}

		// Parse version from header
		version := strings.ToLower(resp.Header.Get("Eth-Consensus-Version"))
		
		// Read the response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("read body for slot %d: %w", slot, err)
		}

		// Decode based on version
		block, err := c.decodeVersionedBlock(body, version)
		if err != nil {
			return nil, fmt.Errorf("decode block for slot %d: %w", slot, err)
		}
		
		blocks = append(blocks, block)
	}
	
	return blocks, nil
}

// GetBlocksByRoot fetches blocks by their roots
func (c *BeaconClient) GetBlocksByRoot(ctx context.Context, roots []phase0.Root) ([]*spec.VersionedSignedBeaconBlock, error) {
	blocks := make([]*spec.VersionedSignedBeaconBlock, 0, len(roots))
	
	// Fetch blocks one by one
	for _, root := range roots {
		req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/eth/v2/beacon/blocks/0x"+hex.EncodeToString(root[:]), nil)
		if err != nil {
			return nil, fmt.Errorf("create request for root %x: %w", root, err)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("do request for root %x: %w", root, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			// Skip missing blocks
			continue
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("bad status %d for root %x: %s", resp.StatusCode, root, body)
		}

		// Parse version from header
		version := strings.ToLower(resp.Header.Get("Eth-Consensus-Version"))
		
		// Read the response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("read body for root %x: %w", root, err)
		}

		// Decode based on version
		block, err := c.decodeVersionedBlock(body, version)
		if err != nil {
			return nil, fmt.Errorf("decode block for root %x: %w", root, err)
		}
		
		blocks = append(blocks, block)
	}
	
	return blocks, nil
}

// decodeVersionedBlock decodes a block based on its version
func (c *BeaconClient) decodeVersionedBlock(data []byte, version string) (*spec.VersionedSignedBeaconBlock, error) {
	// The API returns a wrapper object with the data field
	var wrapper struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("unmarshal wrapper: %w", err)
	}

	versionedBlock := &spec.VersionedSignedBeaconBlock{}

	switch version {
	case "phase0":
		var block phase0.SignedBeaconBlock
		if err := json.Unmarshal(wrapper.Data, &block); err != nil {
			return nil, fmt.Errorf("unmarshal phase0 block: %w", err)
		}
		versionedBlock.Version = spec.DataVersionPhase0
		versionedBlock.Phase0 = &block

	case "altair":
		var block altair.SignedBeaconBlock
		if err := json.Unmarshal(wrapper.Data, &block); err != nil {
			return nil, fmt.Errorf("unmarshal altair block: %w", err)
		}
		versionedBlock.Version = spec.DataVersionAltair
		versionedBlock.Altair = &block

	case "bellatrix":
		var block bellatrix.SignedBeaconBlock
		if err := json.Unmarshal(wrapper.Data, &block); err != nil {
			return nil, fmt.Errorf("unmarshal bellatrix block: %w", err)
		}
		versionedBlock.Version = spec.DataVersionBellatrix
		versionedBlock.Bellatrix = &block

	case "capella":
		var block capella.SignedBeaconBlock
		if err := json.Unmarshal(wrapper.Data, &block); err != nil {
			return nil, fmt.Errorf("unmarshal capella block: %w", err)
		}
		versionedBlock.Version = spec.DataVersionCapella
		versionedBlock.Capella = &block

	case "deneb":
		var block deneb.SignedBeaconBlock
		if err := json.Unmarshal(wrapper.Data, &block); err != nil {
			return nil, fmt.Errorf("unmarshal deneb block: %w", err)
		}
		versionedBlock.Version = spec.DataVersionDeneb
		versionedBlock.Deneb = &block

	case "electra":
		var block electra.SignedBeaconBlock
		if err := json.Unmarshal(wrapper.Data, &block); err != nil {
			return nil, fmt.Errorf("unmarshal electra block: %w", err)
		}
		versionedBlock.Version = spec.DataVersionElectra
		versionedBlock.Electra = &block

	default:
		return nil, fmt.Errorf("unknown version: %s", version)
	}

	return versionedBlock, nil
}

// GetBlobSidecarsByRange fetches blob sidecars in a range
func (c *BeaconClient) GetBlobSidecarsByRange(ctx context.Context, start, count uint64) ([]*deneb.BlobSidecar, error) {
	// Use the beacon API blob sidecars endpoint
	// Format: /eth/v1/beacon/blob_sidecars?start_slot={start}&count={count}
	url := fmt.Sprintf("%s/eth/v1/beacon/blob_sidecars?start_slot=%d&count=%d", c.baseURL, start, count)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("bad status %d: %s", resp.StatusCode, body)
	}

	var result struct {
		Data []*deneb.BlobSidecar `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return result.Data, nil
}

// GetBlobSidecarsByRoot fetches blob sidecars by their block roots and indices
func (c *BeaconClient) GetBlobSidecarsByRoot(ctx context.Context, blockRoots []phase0.Root, indices []uint64) ([]*deneb.BlobSidecar, error) {
	blobs := make([]*deneb.BlobSidecar, 0)

	// For each block root, fetch all blob sidecars
	for _, root := range blockRoots {
		// Format: /eth/v1/beacon/blob_sidecars/{block_id}
		url := fmt.Sprintf("%s/eth/v1/beacon/blob_sidecars/0x%s", c.baseURL, hex.EncodeToString(root[:]))
		
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("create request for root %x: %w", root, err)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("do request for root %x: %w", root, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			// Skip if no blobs for this block
			continue
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("bad status %d for root %x: %s", resp.StatusCode, root, body)
		}

		var result struct {
			Data []*deneb.BlobSidecar `json:"data"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, fmt.Errorf("decode response for root %x: %w", root, err)
		}

		// If indices are specified, filter the results
		if len(indices) > 0 {
			indexSet := make(map[uint64]bool)
			for _, idx := range indices {
				indexSet[idx] = true
			}
			
			for _, blob := range result.Data {
				if indexSet[uint64(blob.Index)] {
					blobs = append(blobs, blob)
				}
			}
		} else {
			// Add all blobs
			blobs = append(blobs, result.Data...)
		}
	}

	return blobs, nil
}