package independent

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	httpclient "github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/probe-lab/hermes/eth/validation/common"
)

// HTTPStateProvider fetches beacon state from HTTP API using attestant client
type HTTPStateProvider struct {
	client eth2client.Service
	logger *logrus.Logger
}

// NewHTTPStateProvider creates a new HTTP-based state provider
func NewHTTPStateProvider(endpoint string, port int, useTLS bool) *HTTPStateProvider {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	
	// Build the full endpoint URL
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	fullEndpoint := fmt.Sprintf("%s://%s:%d", scheme, endpoint, port)
	
	// Create custom HTTP client with TLS configuration
	httpClient := &http.Client{
		Timeout: 5 * time.Minute,
	}
	
	if useTLS {
		// Configure TLS
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, // Should be configurable in production
			},
		}
	}
	
	// Create attestant HTTP client
	client, err := httpclient.New(context.Background(),
		httpclient.WithAddress(fullEndpoint),
		httpclient.WithHTTPClient(httpClient),
		httpclient.WithTimeout(5*time.Minute),
		httpclient.WithLogLevel(0), // Disable internal logging
	)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create HTTP client")
	}
	
	return &HTTPStateProvider{
		client: client,
		logger: logger,
	}
}

// GetBeaconState fetches the beacon state for a given state ID
func (p *HTTPStateProvider) GetBeaconState(ctx context.Context, stateID string) (*BeaconState, error) {
	p.logger.WithFields(logrus.Fields{
		"stateID": stateID,
	}).Info("Starting beacon state fetch using attestant client")
	
	// Create a spec provider if the client supports it
	specProvider, isSpecProvider := p.client.(eth2client.SpecProvider)
	if !isSpecProvider {
		return nil, errors.New("client does not support spec operations")
	}
	
	// Get the spec to know about slots per epoch
	specResp, err := specProvider.Spec(ctx, &api.SpecOpts{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch spec")
	}
	
	slotsPerEpoch, exists := specResp.Data["SLOTS_PER_EPOCH"].(uint64)
	if !exists {
		slotsPerEpoch = 32 // Default value
	}
	
	// Check if client supports beacon state operations
	beaconStateProvider, isBeaconStateProvider := p.client.(eth2client.BeaconStateProvider)
	if !isBeaconStateProvider {
		return nil, errors.New("client does not support beacon state operations")
	}
	
	// Fetch the beacon state
	p.logger.Info("Fetching beacon state from client")
	fetchStart := time.Now()
	
	stateResp, err := beaconStateProvider.BeaconState(ctx, &api.BeaconStateOpts{
		State: stateID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch beacon state")
	}
	
	if stateResp == nil || stateResp.Data == nil {
		return nil, errors.New("received nil beacon state")
	}
	
	p.logger.WithFields(logrus.Fields{
		"fetch_duration": time.Since(fetchStart),
		"version": stateResp.Data.Version,
	}).Info("Beacon state fetched successfully")
	
	// Convert to our internal representation
	return p.convertToInternalState(stateResp.Data, slotsPerEpoch)
}

func (p *HTTPStateProvider) convertToInternalState(state *spec.VersionedBeaconState, slotsPerEpoch uint64) (*BeaconState, error) {
	conversionStart := time.Now()
	
	// Extract common fields based on version
	var (
		slot                  phase0.Slot
		genesisTime           uint64
		genesisValidatorsRoot phase0.Root
		fork                  *phase0.Fork
		validators            []*phase0.Validator
		currentJustified      *phase0.Checkpoint
		finalized            *phase0.Checkpoint
	)
	
	// Handle different versions
	switch state.Version {
	case spec.DataVersionPhase0:
		if state.Phase0 == nil {
			return nil, errors.New("phase0 state is nil")
		}
		slot = state.Phase0.Slot
		genesisTime = state.Phase0.GenesisTime
		genesisValidatorsRoot = state.Phase0.GenesisValidatorsRoot
		fork = state.Phase0.Fork
		validators = state.Phase0.Validators
		currentJustified = state.Phase0.CurrentJustifiedCheckpoint
		finalized = state.Phase0.FinalizedCheckpoint
		
	case spec.DataVersionAltair:
		if state.Altair == nil {
			return nil, errors.New("altair state is nil")
		}
		slot = state.Altair.Slot
		genesisTime = state.Altair.GenesisTime
		genesisValidatorsRoot = state.Altair.GenesisValidatorsRoot
		fork = state.Altair.Fork
		validators = state.Altair.Validators
		currentJustified = state.Altair.CurrentJustifiedCheckpoint
		finalized = state.Altair.FinalizedCheckpoint
		
	case spec.DataVersionBellatrix:
		if state.Bellatrix == nil {
			return nil, errors.New("bellatrix state is nil")
		}
		slot = state.Bellatrix.Slot
		genesisTime = state.Bellatrix.GenesisTime
		genesisValidatorsRoot = state.Bellatrix.GenesisValidatorsRoot
		fork = state.Bellatrix.Fork
		validators = state.Bellatrix.Validators
		currentJustified = state.Bellatrix.CurrentJustifiedCheckpoint
		finalized = state.Bellatrix.FinalizedCheckpoint
		
	case spec.DataVersionCapella:
		if state.Capella == nil {
			return nil, errors.New("capella state is nil")
		}
		slot = state.Capella.Slot
		genesisTime = state.Capella.GenesisTime
		genesisValidatorsRoot = state.Capella.GenesisValidatorsRoot
		fork = state.Capella.Fork
		validators = state.Capella.Validators
		currentJustified = state.Capella.CurrentJustifiedCheckpoint
		finalized = state.Capella.FinalizedCheckpoint
		
	case spec.DataVersionDeneb:
		if state.Deneb == nil {
			return nil, errors.New("deneb state is nil")
		}
		slot = state.Deneb.Slot
		genesisTime = state.Deneb.GenesisTime
		genesisValidatorsRoot = state.Deneb.GenesisValidatorsRoot
		fork = state.Deneb.Fork
		validators = state.Deneb.Validators
		currentJustified = state.Deneb.CurrentJustifiedCheckpoint
		finalized = state.Deneb.FinalizedCheckpoint
		
	case spec.DataVersionElectra:
		if state.Electra == nil {
			return nil, errors.New("electra state is nil")
		}
		slot = state.Electra.Slot
		genesisTime = state.Electra.GenesisTime
		genesisValidatorsRoot = state.Electra.GenesisValidatorsRoot
		fork = state.Electra.Fork
		validators = state.Electra.Validators
		currentJustified = state.Electra.CurrentJustifiedCheckpoint
		finalized = state.Electra.FinalizedCheckpoint
		
	default:
		return nil, fmt.Errorf("unsupported state version: %v", state.Version)
	}
	
	// Calculate epoch
	epoch := uint64(slot) / slotsPerEpoch
	
	// Convert validators
	validatorMap := make(map[common.ValidatorIndex]*common.ValidatorInfo)
	for i, val := range validators {
		validatorMap[common.ValidatorIndex(i)] = &common.ValidatorInfo{
			Index:                 common.ValidatorIndex(i),
			PublicKey:             val.PublicKey[:],
			Active:                val.ActivationEpoch <= phase0.Epoch(epoch) && phase0.Epoch(epoch) < val.ExitEpoch,
			Slashed:               val.Slashed,
			ExitEpoch:             primitives.Epoch(val.ExitEpoch),
			WithdrawalCredentials: val.WithdrawalCredentials[:],
		}
	}
	
	// Get sync committees if available (Altair+)
	var currentSyncCommittee, nextSyncCommittee *SyncCommitteeInfo
	switch state.Version {
	case spec.DataVersionAltair:
		if state.Altair.CurrentSyncCommittee != nil {
			currentSyncCommittee = &SyncCommitteeInfo{
				ValidatorIndices: make([]common.ValidatorIndex, len(state.Altair.CurrentSyncCommittee.Pubkeys)),
				AggregatePubkey:  state.Altair.CurrentSyncCommittee.AggregatePubkey[:],
			}
			// Note: Actual validator indices would need to be looked up from pubkeys
		}
		if state.Altair.NextSyncCommittee != nil {
			nextSyncCommittee = &SyncCommitteeInfo{
				ValidatorIndices: make([]common.ValidatorIndex, len(state.Altair.NextSyncCommittee.Pubkeys)),
				AggregatePubkey:  state.Altair.NextSyncCommittee.AggregatePubkey[:],
			}
		}
	case spec.DataVersionBellatrix:
		if state.Bellatrix.CurrentSyncCommittee != nil {
			currentSyncCommittee = &SyncCommitteeInfo{
				ValidatorIndices: make([]common.ValidatorIndex, len(state.Bellatrix.CurrentSyncCommittee.Pubkeys)),
				AggregatePubkey:  state.Bellatrix.CurrentSyncCommittee.AggregatePubkey[:],
			}
		}
		if state.Bellatrix.NextSyncCommittee != nil {
			nextSyncCommittee = &SyncCommitteeInfo{
				ValidatorIndices: make([]common.ValidatorIndex, len(state.Bellatrix.NextSyncCommittee.Pubkeys)),
				AggregatePubkey:  state.Bellatrix.NextSyncCommittee.AggregatePubkey[:],
			}
		}
	case spec.DataVersionCapella:
		if state.Capella.CurrentSyncCommittee != nil {
			currentSyncCommittee = &SyncCommitteeInfo{
				ValidatorIndices: make([]common.ValidatorIndex, len(state.Capella.CurrentSyncCommittee.Pubkeys)),
				AggregatePubkey:  state.Capella.CurrentSyncCommittee.AggregatePubkey[:],
			}
		}
		if state.Capella.NextSyncCommittee != nil {
			nextSyncCommittee = &SyncCommitteeInfo{
				ValidatorIndices: make([]common.ValidatorIndex, len(state.Capella.NextSyncCommittee.Pubkeys)),
				AggregatePubkey:  state.Capella.NextSyncCommittee.AggregatePubkey[:],
			}
		}
	case spec.DataVersionDeneb:
		if state.Deneb.CurrentSyncCommittee != nil {
			currentSyncCommittee = &SyncCommitteeInfo{
				ValidatorIndices: make([]common.ValidatorIndex, len(state.Deneb.CurrentSyncCommittee.Pubkeys)),
				AggregatePubkey:  state.Deneb.CurrentSyncCommittee.AggregatePubkey[:],
			}
		}
		if state.Deneb.NextSyncCommittee != nil {
			nextSyncCommittee = &SyncCommitteeInfo{
				ValidatorIndices: make([]common.ValidatorIndex, len(state.Deneb.NextSyncCommittee.Pubkeys)),
				AggregatePubkey:  state.Deneb.NextSyncCommittee.AggregatePubkey[:],
			}
		}
	case spec.DataVersionElectra:
		if state.Electra.CurrentSyncCommittee != nil {
			currentSyncCommittee = &SyncCommitteeInfo{
				ValidatorIndices: make([]common.ValidatorIndex, len(state.Electra.CurrentSyncCommittee.Pubkeys)),
				AggregatePubkey:  state.Electra.CurrentSyncCommittee.AggregatePubkey[:],
			}
		}
		if state.Electra.NextSyncCommittee != nil {
			nextSyncCommittee = &SyncCommitteeInfo{
				ValidatorIndices: make([]common.ValidatorIndex, len(state.Electra.NextSyncCommittee.Pubkeys)),
				AggregatePubkey:  state.Electra.NextSyncCommittee.AggregatePubkey[:],
			}
		}
	}
	
	p.logger.WithFields(logrus.Fields{
		"slot":       slot,
		"epoch":      epoch,
		"validators": len(validators),
		"conversion_duration": time.Since(conversionStart),
	}).Info("Beacon state conversion complete")
	
	return &BeaconState{
		Slot:                  primitives.Slot(slot),
		Epoch:                 common.Epoch(epoch),
		GenesisTime:           genesisTime,
		GenesisValidatorsRoot: [32]byte(genesisValidatorsRoot),
		Fork: &common.ForkInfo{
			PreviousVersion: [4]byte(fork.PreviousVersion),
			CurrentVersion:  [4]byte(fork.CurrentVersion),
			Epoch:           primitives.Epoch(fork.Epoch),
		},
		Validators:           validatorMap,
		CurrentSyncCommittee: currentSyncCommittee,
		NextSyncCommittee:    nextSyncCommittee,
		CurrentJustifiedCheckpoint: &Checkpoint{
			Epoch: common.Epoch(currentJustified.Epoch),
			Root:  [32]byte(currentJustified.Root),
		},
		FinalizedCheckpoint: &Checkpoint{
			Epoch: common.Epoch(finalized.Epoch),
			Root:  [32]byte(finalized.Root),
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