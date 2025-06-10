package independent

import (
	"github.com/probe-lab/hermes/eth/validation/common"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	ethpb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/OffchainLabs/prysm/v6/beacon-chain/state"
	state_native "github.com/OffchainLabs/prysm/v6/beacon-chain/state/state-native"
	"github.com/OffchainLabs/prysm/v6/runtime/version"
	"github.com/sirupsen/logrus"
)

// HTTPStateProvider fetches beacon state from HTTP API
type HTTPStateProvider struct {
	endpoint   string
	httpClient *http.Client
	logger     *logrus.Logger
}

// NewHTTPStateProvider creates a new HTTP-based state provider
func NewHTTPStateProvider(endpoint string) *HTTPStateProvider {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	
	return &HTTPStateProvider{
		endpoint: endpoint,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute, // 5 minutes timeout for large state
		},
		logger: logger,
	}
}

// GetBeaconState fetches the beacon state for a given state ID
func (p *HTTPStateProvider) GetBeaconState(ctx context.Context, stateID string) (*BeaconState, error) {
	p.logger.WithFields(logrus.Fields{
		"stateID": stateID,
		"endpoint": p.endpoint,
	}).Info("Starting beacon state fetch")
	
	// First, get the state version to know which decoder to use
	versionURL := fmt.Sprintf("%s/eth/v1/beacon/states/%s/fork", p.endpoint, stateID)
	p.logger.WithField("url", versionURL).Debug("Fetching state version")
	
	req, err := http.NewRequestWithContext(ctx, "GET", versionURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create version request")
	}
	
	versionStart := time.Now()
	p.logger.WithField("timeout", p.httpClient.Timeout).Info("Making HTTP request for state version")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		p.logger.WithError(err).Error("HTTP request failed for state version")
		return nil, errors.Wrap(err, "failed to fetch state version")
	}
	defer resp.Body.Close()
	p.logger.WithField("status", resp.StatusCode).Info("Got HTTP response for state version")
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	
	// Parse the version header
	stateVersion := resp.Header.Get("Eth-Consensus-Version")
	if stateVersion == "" {
		stateVersion = "phase0" // Default to phase0 if not specified
	}
	p.logger.WithFields(logrus.Fields{
		"version": stateVersion,
		"duration": time.Since(versionStart),
	}).Info("Got state version")
	
	// Now fetch the actual state via SSZ
	url := fmt.Sprintf("%s/eth/v2/debug/beacon/states/%s", p.endpoint, stateID)
	p.logger.WithField("url", url).Info("Fetching beacon state SSZ (this may take a while...)")
	
	req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Accept", "application/octet-stream")
	
	fetchStart := time.Now()
	p.logger.Info("Making HTTP request for beacon state SSZ")
	resp, err = p.httpClient.Do(req)
	if err != nil {
		p.logger.WithError(err).Error("HTTP request failed for beacon state")
		return nil, errors.Wrap(err, "failed to fetch beacon state")
	}
	defer resp.Body.Close()
	p.logger.WithField("status", resp.StatusCode).Info("Got HTTP response for beacon state")
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	
	// Log content length if available
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		p.logger.WithField("size", contentLength).Info("Downloading beacon state SSZ")
	}
	
	// Read the SSZ bytes with progress tracking
	p.logger.Debug("Reading SSZ data from response body")
	
	// Create a progress reader to track download
	progressReader := &progressReader{
		reader: resp.Body,
		total:  resp.ContentLength,
		logger: p.logger,
		start:  time.Now(),
	}
	
	sszData, err := io.ReadAll(progressReader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read SSZ data")
	}
	
	p.logger.WithFields(logrus.Fields{
		"size_bytes": len(sszData),
		"size_mb": len(sszData) / 1024 / 1024,
		"download_duration": time.Since(fetchStart),
	}).Info("Downloaded beacon state SSZ")
	
	// Decode based on version
	var beaconState state.BeaconState
	
	p.logger.WithField("version", stateVersion).Info("Starting SSZ decode")
	decodeStart := time.Now()
	
	switch stateVersion {
	case "deneb":
		denebState := &ethpb.BeaconStateDeneb{}
		if err := denebState.UnmarshalSSZ(sszData); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal Deneb state")
		}
		beaconState, err = state_native.InitializeFromProtoDeneb(denebState)
		if err != nil {
			return nil, errors.Wrap(err, "failed to initialize Deneb state")
		}
	case "capella":
		capellaState := &ethpb.BeaconStateCapella{}
		if err := capellaState.UnmarshalSSZ(sszData); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal Capella state")
		}
		beaconState, err = state_native.InitializeFromProtoCapella(capellaState)
		if err != nil {
			return nil, errors.Wrap(err, "failed to initialize Capella state")
		}
	case "bellatrix":
		bellatrixState := &ethpb.BeaconStateBellatrix{}
		if err := bellatrixState.UnmarshalSSZ(sszData); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal Bellatrix state")
		}
		beaconState, err = state_native.InitializeFromProtoBellatrix(bellatrixState)
		if err != nil {
			return nil, errors.Wrap(err, "failed to initialize Bellatrix state")
		}
	case "altair":
		altairState := &ethpb.BeaconStateAltair{}
		if err := altairState.UnmarshalSSZ(sszData); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal Altair state")
		}
		beaconState, err = state_native.InitializeFromProtoAltair(altairState)
		if err != nil {
			return nil, errors.Wrap(err, "failed to initialize Altair state")
		}
	default: // phase0
		phase0State := &ethpb.BeaconState{}
		if err := phase0State.UnmarshalSSZ(sszData); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal Phase0 state")
		}
		beaconState, err = state_native.InitializeFromProtoPhase0(phase0State)
		if err != nil {
			return nil, errors.Wrap(err, "failed to initialize Phase0 state")
		}
	}
	
	p.logger.WithField("decode_duration", time.Since(decodeStart)).Info("SSZ decode complete")
	
	// Convert to our internal representation
	p.logger.Debug("Converting to internal state representation")
	return p.convertToInternalState(beaconState)
}

func (p *HTTPStateProvider) convertToInternalState(st state.BeaconState) (*BeaconState, error) {
	conversionStart := time.Now()
	
	// Get basic info
	slot := st.Slot()
	epoch := slot / primitives.Slot(common.SLOTS_PER_EPOCH)
	
	genesisTime := st.GenesisTime()
	genesisValidatorsRoot := st.GenesisValidatorsRoot()
	
	// Get fork info
	fork := st.Fork()
	
	// Extract validator info
	validators := make(map[common.ValidatorIndex]*common.ValidatorInfo)
	vals := st.Validators()
	p.logger.WithField("validator_count", len(vals)).Debug("Converting validators")
	
	for i, val := range vals {
		validators[common.ValidatorIndex(i)] = &common.ValidatorInfo{
			Index:                 common.ValidatorIndex(i),
			PublicKey:             val.PublicKey,
			Active:                val.ActivationEpoch <= primitives.Epoch(epoch) && primitives.Epoch(epoch) < val.ExitEpoch,
			Slashed:               val.Slashed,
			ExitEpoch:             val.ExitEpoch,
			WithdrawalCredentials: val.WithdrawalCredentials,
		}
	}
	
	// Get sync committee if available
	var currentSyncCommittee, nextSyncCommittee *SyncCommitteeInfo
	if st.Version() >= version.Altair {
		currSyncCommittee, err := st.CurrentSyncCommittee()
		if err == nil && currSyncCommittee != nil {
			currentSyncCommittee = &SyncCommitteeInfo{
				ValidatorIndices: make([]common.ValidatorIndex, len(currSyncCommittee.Pubkeys)),
				AggregatePubkey:  currSyncCommittee.AggregatePubkey,
			}
			// Convert pubkeys to validator indices
			// Note: This is simplified - in reality you'd need to map pubkeys to indices
			for i := range currSyncCommittee.Pubkeys {
				currentSyncCommittee.ValidatorIndices[i] = common.ValidatorIndex(i)
			}
		}
		
		nextComm, err := st.NextSyncCommittee()
		if err == nil && nextComm != nil {
			nextSyncCommittee = &SyncCommitteeInfo{
				ValidatorIndices: make([]common.ValidatorIndex, len(nextComm.Pubkeys)),
				AggregatePubkey:  nextComm.AggregatePubkey,
			}
			// Convert pubkeys to validator indices
			for i := range nextComm.Pubkeys {
				nextSyncCommittee.ValidatorIndices[i] = common.ValidatorIndex(i)
			}
		}
	}
	
	// Get checkpoints
	currentJustifiedCheckpoint := st.CurrentJustifiedCheckpoint()
	finalizedCheckpoint := st.FinalizedCheckpoint()
	
	// Convert byte slices to fixed arrays
	var genesisRoot [32]byte
	copy(genesisRoot[:], genesisValidatorsRoot)
	
	var prevVersion, currVersion [4]byte
	copy(prevVersion[:], fork.PreviousVersion)
	copy(currVersion[:], fork.CurrentVersion)
	
	var justifiedRoot, finalizedRoot [32]byte
	copy(justifiedRoot[:], currentJustifiedCheckpoint.Root)
	copy(finalizedRoot[:], finalizedCheckpoint.Root)
	
	p.logger.WithFields(logrus.Fields{
		"slot": slot,
		"epoch": epoch,
		"validators": len(validators),
		"conversion_duration": time.Since(conversionStart),
	}).Info("Beacon state conversion complete")
	
	return &BeaconState{
		Slot:                  slot,
		Epoch:                 common.Epoch(epoch),
		GenesisTime:           genesisTime,
		GenesisValidatorsRoot: genesisRoot,
		Fork: &common.ForkInfo{
			PreviousVersion: prevVersion,
			CurrentVersion:  currVersion,
			Epoch:           fork.Epoch,
		},
		Validators:           validators,
		CurrentSyncCommittee: currentSyncCommittee,
		NextSyncCommittee:    nextSyncCommittee,
		CurrentJustifiedCheckpoint: &Checkpoint{
			Epoch: currentJustifiedCheckpoint.Epoch,
			Root:  justifiedRoot,
		},
		FinalizedCheckpoint: &Checkpoint{
			Epoch: finalizedCheckpoint.Epoch,
			Root:  finalizedRoot,
		},
	}, nil
}

// GetValidatorSet fetches validators for a given state ID
func (p *HTTPStateProvider) GetValidatorSet(ctx context.Context, stateID string) (map[common.ValidatorIndex]*common.ValidatorInfo, error) {
	state, err := p.GetBeaconState(ctx, stateID)
	if err != nil {
		return nil, err
	}
	return state.Validators, nil
}

// GetCommittees fetches committee assignments for a given state ID
func (p *HTTPStateProvider) GetCommittees(ctx context.Context, stateID string) (map[primitives.CommitteeIndex]*common.CommitteeAssignment, error) {
	// Committees are computed from state, not stored directly
	// This would need to be implemented based on the committee computation logic
	return make(map[primitives.CommitteeIndex]*common.CommitteeAssignment), nil
}

// progressReader wraps an io.Reader to track download progress
type progressReader struct {
	reader    io.Reader
	total     int64
	read      int64
	lastLog   time.Time
	logger    *logrus.Logger
	start     time.Time
}

func (pr *progressReader) Read(p []byte) (int, error) {
	// Log first read
	if pr.read == 0 && len(p) > 0 {
		pr.logger.Info("Starting to read beacon state data")
		pr.lastLog = time.Now()
	}
	
	n, err := pr.reader.Read(p)
	pr.read += int64(n)
	
	// Log progress every 5 seconds
	if time.Since(pr.lastLog) > 5*time.Second {
		if pr.total > 0 {
			percent := float64(pr.read) * 100 / float64(pr.total)
			mbRead := pr.read / 1024 / 1024
			mbTotal := pr.total / 1024 / 1024
			elapsed := time.Since(pr.start)
			rate := float64(pr.read) / elapsed.Seconds() / 1024 / 1024 // MB/s
			
			pr.logger.WithFields(logrus.Fields{
				"progress": fmt.Sprintf("%.1f%%", percent),
				"downloaded_mb": mbRead,
				"total_mb": mbTotal,
				"rate_mb_s": fmt.Sprintf("%.1f", rate),
				"elapsed": elapsed.Round(time.Second),
			}).Info("Downloading beacon state")
		} else {
			mbRead := pr.read / 1024 / 1024
			elapsed := time.Since(pr.start)
			rate := float64(pr.read) / elapsed.Seconds() / 1024 / 1024 // MB/s
			
			pr.logger.WithFields(logrus.Fields{
				"downloaded_mb": mbRead,
				"rate_mb_s": fmt.Sprintf("%.1f", rate),
				"elapsed": elapsed.Round(time.Second),
			}).Info("Downloading beacon state (unknown size)")
		}
		pr.lastLog = time.Now()
	}
	
	return n, err
}