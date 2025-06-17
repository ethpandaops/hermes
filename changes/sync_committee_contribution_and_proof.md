# Sync Committee Contribution and Proof Validation Analysis

## 1. What the Validation Spec Requires

The `sync_committee_contribution_and_proof` topic validation specification requires the following checks:

### MUST Requirements (from validation-specs/pubsub/sync_committee_contribution_and_proof.md)

1. **[IGNORE] Current Slot Check**: The contribution's slot is for the current slot (with a `MAXIMUM_GOSSIP_CLOCK_DISPARITY` allowance)
   - `contribution.slot == current_slot`

2. **[REJECT] Subcommittee Index Range**: The subcommittee index is in the allowed range
   - `contribution.subcommittee_index < SYNC_COMMITTEE_SUBNET_COUNT` (where SYNC_COMMITTEE_SUBNET_COUNT = 4)

3. **[REJECT] Has Participants**: The contribution has participants
   - `any(contribution.aggregation_bits)`

4. **[REJECT] Valid Aggregator Selection**: `contribution_and_proof.selection_proof` selects the validator as an aggregator for the slot
   - `is_sync_committee_aggregator(contribution_and_proof.selection_proof)` returns `True`

5. **[REJECT] Aggregator in Subcommittee**: The aggregator's validator index is in the declared subcommittee of the current sync committee
   - `state.validators[contribution_and_proof.aggregator_index].pubkey in get_sync_subcommittee_pubkeys(state, contribution.subcommittee_index)`

6. **[IGNORE] Duplicate Check**: A valid sync committee contribution with equal `slot`, `beacon_block_root` and `subcommittee_index` whose `aggregation_bits` is non-strict superset has NOT already been seen

7. **[IGNORE] First From Aggregator**: The sync committee contribution is the first valid contribution received for the aggregator with index `contribution_and_proof.aggregator_index` for the slot `contribution.slot` and subcommittee index `contribution.subcommittee_index`
   - Requires maintaining a cache of size `SYNC_COMMITTEE_SIZE` (512)

8. **[REJECT] Valid Selection Proof**: The `contribution_and_proof.selection_proof` is a valid signature of the `SyncAggregatorSelectionData` derived from the `contribution` by the validator with index `contribution_and_proof.aggregator_index`

9. **[REJECT] Valid Aggregator Signature**: The aggregator signature, `signed_contribution_and_proof.signature`, is valid

10. **[REJECT] Valid Aggregate Signature**: The aggregate signature is valid for the message `beacon_block_root` and aggregate pubkey derived from the participation info in `aggregation_bits` for the subcommittee specified by the `contribution.subcommittee_index`

## 2. What Currently Exists in Hermes

### Independent Mode (`eth/pubsub/handlers/independent/sync_committee_validator.go`)

The current implementation includes a `SyncCommitteeContributionValidator` (lines 100-184) with the following validations:

**Implemented:**
- ✅ Basic SSZ decoding and decompression
- ✅ Nil checks for contribution and proof
- ✅ Future slot check (partial implementation of requirement 1)
- ✅ Aggregator exists in validator set check
- ✅ Selection proof signature verification (requirement 8)
- ✅ Contribution and proof signature verification (requirement 9)

**Missing or Incomplete:**
- ❌ Exact current slot check with MAXIMUM_GOSSIP_CLOCK_DISPARITY
- ❌ Subcommittee index range validation (requirement 2)
- ❌ Aggregation bits participants check (requirement 3)
- ❌ `is_sync_committee_aggregator` check (requirement 4)
- ❌ Aggregator membership in subcommittee check (requirement 5)
- ❌ Duplicate contribution tracking (requirement 6)
- ❌ First-from-aggregator tracking (requirement 7)
- ❌ Aggregate signature validation (requirement 10)

### Delegated Mode (`eth/pubsub/handlers/delegated/validators.go`)

The current implementation includes a `ContributionAndProofValidator` (lines 233-256) that:

**Implemented:**
- ✅ Basic SSZ decoding and decompression
- ✅ Returns decoded object

**Missing:**
- ❌ All validation logic (delegated mode only decodes, doesn't validate)

## 3. What Needs to Change

### Independent Mode Changes

#### File: `eth/pubsub/handlers/independent/sync_committee_validator.go`

1. **Add helper functions:**
```go
// isSyncCommitteeAggregator checks if the selection proof indicates the validator is an aggregator
func isSyncCommitteeAggregator(selectionProof [96]byte) bool {
    // Hash the selection proof and check if it meets the aggregator threshold
    hash := sha256.Sum256(selectionProof[:])
    // The modulo should be less than TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE * 256 / SYNC_COMMITTEE_SIZE
    // This is typically 16 * 256 / 512 = 8
    return binary.LittleEndian.Uint64(hash[:8])%8 == 0
}

// getSyncSubcommitteePubkeys returns the public keys for a specific sync subcommittee
func getSyncSubcommitteePubkeys(syncCommittee *SyncCommitteeInfo, subcommitteeIndex uint64) [][]byte {
    // SYNC_COMMITTEE_SIZE = 512, SYNC_COMMITTEE_SUBNET_COUNT = 4
    // So each subcommittee has 128 validators
    subcommitteeSize := 512 / 4 // 128
    startIdx := subcommitteeIndex * subcommitteeSize
    endIdx := startIdx + subcommitteeSize
    
    pubkeys := make([][]byte, 0, subcommitteeSize)
    for i := startIdx; i < endIdx && i < uint64(len(syncCommittee.ValidatorIndices)); i++ {
        validatorIndex := syncCommittee.ValidatorIndices[i]
        // Need to get pubkey from validator set
        pubkeys = append(pubkeys, validatorIndex.Pubkey)
    }
    return pubkeys
}
```

2. **Add caching structures:**
```go
type contributionKey struct {
    slot              phase0.Slot
    beaconBlockRoot   [32]byte
    subcommitteeIndex uint64
}

type aggregatorContributionKey struct {
    aggregatorIndex   phase0.ValidatorIndex
    slot              phase0.Slot
    subcommitteeIndex uint64
}

// Add to IndependentValidator struct:
seenContributions         *lru.Cache[contributionKey, []byte]          // For requirement 6
aggregatorContributions   *lru.Cache[aggregatorContributionKey, bool]  // For requirement 7
```

3. **Update validation logic in `Handle` method:**
```go
func (v *SyncCommitteeContributionValidator) Handle(ctx context.Context, data []byte, topic string) (interface{}, error) {
    // ... existing decompression and decoding ...

    // 1. Check current slot with MAXIMUM_GOSSIP_CLOCK_DISPARITY
    currentSlot := v.validator.wallclock.GetCurrentSlot()
    if !isWithinClockDisparity(contribution.Slot, currentSlot) {
        return nil, errors.New("[IGNORE] contribution slot outside clock disparity")
    }

    // 2. Check subcommittee index range
    if contribution.SubcommitteeIndex >= SYNC_COMMITTEE_SUBNET_COUNT {
        return nil, fmt.Errorf("[REJECT] invalid subcommittee index %d", contribution.SubcommitteeIndex)
    }

    // 3. Check has participants
    if !hasParticipants(contribution.AggregationBits) {
        return nil, errors.New("[REJECT] contribution has no participants")
    }

    // 4. Check is_sync_committee_aggregator
    if !isSyncCommitteeAggregator(msg.SelectionProof) {
        return nil, errors.New("[REJECT] validator is not a valid aggregator")
    }

    // 5. Check aggregator is in subcommittee
    syncCommittee := getSyncCommitteeForSlot(state, contribution.Slot)
    subcommitteePubkeys := getSyncSubcommitteePubkeys(syncCommittee, contribution.SubcommitteeIndex)
    if !isPubkeyInList(validatorInfo.PublicKey, subcommitteePubkeys) {
        return nil, errors.New("[REJECT] aggregator not in subcommittee")
    }

    // 6. Check for duplicate contributions
    contribKey := contributionKey{
        slot:              contribution.Slot,
        beaconBlockRoot:   contribution.BeaconBlockRoot,
        subcommitteeIndex: contribution.SubcommitteeIndex,
    }
    if isDuplicateContribution(v.validator.seenContributions, contribKey, contribution.AggregationBits) {
        return nil, errors.New("[IGNORE] duplicate contribution")
    }

    // 7. Check first from aggregator
    aggKey := aggregatorContributionKey{
        aggregatorIndex:   msg.AggregatorIndex,
        slot:              contribution.Slot,
        subcommitteeIndex: contribution.SubcommitteeIndex,
    }
    if seen, _ := v.validator.aggregatorContributions.Get(aggKey); seen {
        return nil, errors.New("[IGNORE] not first contribution from aggregator")
    }

    // ... existing signature validations ...

    // 10. Validate aggregate signature
    if err := v.validateAggregateSignature(contribution, syncCommittee); err != nil {
        return nil, errors.Wrap(err, "[REJECT] invalid aggregate signature")
    }

    // Mark as seen
    v.validator.seenContributions.Add(contribKey, contribution.AggregationBits)
    v.validator.aggregatorContributions.Add(aggKey, true)

    return contributionAndProof, nil
}
```

### Delegated Mode Changes

For delegated mode, the current implementation is sufficient as it only needs to decode the message and forward it to the beacon node for validation. No changes required.

## 4. Specific Code Examples and File Locations

### Files to Modify:

1. **`eth/pubsub/handlers/independent/sync_committee_validator.go`**
   - Add helper functions for aggregator selection and subcommittee membership
   - Enhance validation logic with all required checks
   - Add aggregate signature validation

2. **`eth/pubsub/handlers/independent/independent_validator.go`**
   - Add caching structures for tracking seen contributions and aggregator submissions
   - Initialize caches in `NewIndependentValidator`
   - Add cleanup logic for caches in `cleanupLoop`

3. **`eth/pubsub/handlers/independent/beacon_state.go`**
   - Ensure `SyncCommitteeInfo` structure includes validator indices to pubkey mapping
   - Add helper to get sync committee for a specific slot

4. **`eth/pubsub/common/constants.go` (if not exists, create it)**
   - Add missing constants:
```go
const (
    SYNC_COMMITTEE_SUBNET_COUNT = 4
    SYNC_COMMITTEE_SIZE = 512
    TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE = 16
    MAXIMUM_GOSSIP_CLOCK_DISPARITY = 500 * time.Millisecond
)
```

## 5. Dependencies on Missing Components

### Required Components:

1. **Wallclock Integration**: The current implementation has `wallclock` but needs to use it for accurate current slot determination with clock disparity allowance.

2. **Sync Committee State Access**: Need to ensure the state contains proper sync committee information including:
   - Validator indices in each subcommittee
   - Mapping from validator index to public key for subcommittee members

3. **BLS Aggregate Signature Verification**: Need to implement or use existing BLS library for verifying aggregate signatures over multiple public keys.

4. **Enhanced Caching**: Need to add two new LRU caches:
   - Seen contributions cache (keyed by slot + beacon_block_root + subcommittee_index)
   - Aggregator submissions cache (keyed by aggregator_index + slot + subcommittee_index)

### Missing Helper Functions to Implement:

```go
// Check if slot is within clock disparity
func isWithinClockDisparity(messageSlot, currentSlot phase0.Slot) bool {
    // Allow messages from current slot or within MAXIMUM_GOSSIP_CLOCK_DISPARITY
    return messageSlot == currentSlot || 
           (messageSlot > currentSlot && time.Duration(messageSlot-currentSlot)*12*time.Second <= MAXIMUM_GOSSIP_CLOCK_DISPARITY)
}

// Check if aggregation bits has any participants
func hasParticipants(bits []byte) bool {
    for _, b := range bits {
        if b != 0 {
            return true
        }
    }
    return false
}

// Check if contribution is duplicate (non-strict superset)
func isDuplicateContribution(cache *lru.Cache[contributionKey, []byte], key contributionKey, newBits []byte) bool {
    if existingBits, found := cache.Get(key); found {
        return !isStrictSuperset(newBits, existingBits)
    }
    return false
}

// Validate aggregate signature for sync committee contribution
func (v *SyncCommitteeContributionValidator) validateAggregateSignature(
    contribution *altair.SyncCommitteeContribution,
    syncCommittee *SyncCommitteeInfo,
) error {
    // Get participating validator public keys based on aggregation bits
    participatingPubkeys := getParticipatingPubkeys(contribution, syncCommittee)
    
    // Aggregate the public keys
    aggregatedPubkey := bls.AggregatePublicKeys(participatingPubkeys)
    
    // Create signing data (beacon block root)
    signingRoot := computeSyncCommitteeMessageSigningRoot(contribution.BeaconBlockRoot, contribution.Slot)
    
    // Verify aggregate signature
    return v.validator.signatureVerifier.VerifyAggregateSignature(
        aggregatedPubkey,
        signingRoot,
        contribution.Signature[:],
        common.DomainSyncCommittee,
        // epoch calculation from slot
    )
}
```

## Summary

The current Hermes implementation has a basic structure for sync committee contribution validation but lacks most of the required validation rules from the specification. The independent mode needs significant enhancements to implement all 10 validation requirements, while the delegated mode is correctly implemented as a simple decoder/forwarder.

Key missing pieces include:
- Proper current slot validation with clock disparity
- Aggregator selection verification
- Subcommittee membership checks
- Duplicate and first-from-aggregator tracking
- Aggregate signature validation

These changes will require adding new helper functions, caching structures, and integrating with the wallclock for accurate timing checks.