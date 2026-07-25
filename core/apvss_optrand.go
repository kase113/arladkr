package core

import (
	"fmt"
	"sort"
	"strings"
)

func OptrandShareVerify(cfg Config, art *DealerArtifact) error {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return err
	}
	if !strings.EqualFold(strings.TrimSpace(c.APVSSProvider), "optrand") {
		return fmt.Errorf("optrand provider required, got %q", c.APVSSProvider)
	}
	if art != nil && len(art.Fingerprint) == 0 {
		art.Fingerprint = fingerprintDealerArtifact(art)
	}
	if art == nil {
		return fmt.Errorf("nil dealer artifact")
	}
	if art.Dealer != art.Descriptor.Dealer {
		return fmt.Errorf("dealer mismatch: artifact=%d descriptor=%d", art.Dealer, art.Descriptor.Dealer)
	}
	if !ValidateDescriptor(c, art.Descriptor) {
		return fmt.Errorf("descriptor validation failed for dealer=%d", art.Dealer)
	}
	if !bytesEq(hashBytes([]byte("rladkr-root"), art.Payload), art.Descriptor.Header.Root) {
		return fmt.Errorf("payload root mismatch for dealer=%d", art.Dealer)
	}
	transcript, err := decodeDealerTranscript(art.Payload)
	if err != nil {
		return fmt.Errorf("transcript decode failed for dealer=%d: %w", art.Dealer, err)
	}
	if transcript.Dealer != art.Dealer {
		return fmt.Errorf("transcript dealer mismatch for dealer=%d", art.Dealer)
	}
	if transcript.Version != 1 || transcript.Provider != "" {
		return fmt.Errorf(
			"optrand transcript provider/schema mismatch: provider=%q version=%d",
			transcript.Provider,
			transcript.Version,
		)
	}
	shareThreshold := len(c.runtime.receiverOrder) - c.FNew
	if shareThreshold <= 0 {
		shareThreshold = 1
	}
	if transcript.Threshold != shareThreshold {
		return fmt.Errorf(
			"transcript threshold mismatch for dealer=%d: have=%d need=%d",
			art.Dealer,
			transcript.Threshold,
			shareThreshold,
		)
	}
	for _, receiver := range c.runtime.receiverOrder {
		if ct, ok := art.Ciphertexts[receiver]; !ok || len(ct) == 0 {
			return fmt.Errorf("missing ciphertext for dealer=%d receiver=%d", art.Dealer, receiver)
		}
	}
	if c.runtime != nil {
		c.runtime.rememberValidatedArtifact(art.Descriptor.Digest, art.Fingerprint)
	}
	return nil
}

func BuildOptrandAggregatedTranscript(
	cfg Config,
	dealers []int,
	artifacts map[int]*DealerArtifact,
) (*ListBackedAggregateTranscript, error) {
	return buildOptrandAggregatedTranscript(cfg, dealers, artifacts, false)
}

func BuildTrustedOptrandAggregatedTranscript(
	cfg Config,
	dealers []int,
	artifacts map[int]*DealerArtifact,
) (*ListBackedAggregateTranscript, error) {
	return buildOptrandAggregatedTranscript(cfg, dealers, artifacts, true)
}

func buildOptrandAggregatedTranscript(
	cfg Config,
	dealers []int,
	artifacts map[int]*DealerArtifact,
	trusted bool,
) (*ListBackedAggregateTranscript, error) {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	if c.runtime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}
	if len(dealers) == 0 {
		return nil, fmt.Errorf("empty dealers")
	}
	threshold := c.FOld + 1
	if threshold <= 0 {
		threshold = 1
	}
	canonDealers := sortedUnique(dealers)
	if len(canonDealers) < threshold {
		return nil, fmt.Errorf("insufficient dealers for aggregate: have=%d need=%d", len(canonDealers), threshold)
	}

	perDealer := make(map[int][]byte, len(canonDealers))
	digestParts := make([][]byte, 0, 2+len(canonDealers))
	digestParts = append(digestParts, []byte("optrand-agg"), encodeInts(canonDealers))
	for _, dealer := range canonDealers {
		art, ok := artifacts[dealer]
		if !ok || art == nil {
			return nil, fmt.Errorf("missing dealer artifact for dealer=%d", dealer)
		}
		if !trusted {
			if err := OptrandShareVerify(c, art); err != nil {
				return nil, err
			}
		} else if art.Dealer != dealer || art.Descriptor.Dealer != dealer || !bytesEq(art.Descriptor.Digest, digestDescriptor(art.Descriptor)) {
			return nil, fmt.Errorf("trusted artifact descriptor mismatch for dealer=%d", dealer)
		}
		dig := art.ContributionDigest
		if len(dig) == 0 {
			dig = optrandContributionDigest(art)
		}
		perDealer[dealer] = dig
		digestParts = append(digestParts, dig)
	}
	return &ListBackedAggregateTranscript{
		Dealers:             canonDealers,
		ContributionDigests: perDealer,
		AggregateDigest:     hashBytes(digestParts...),
		Trusted:             trusted,
	}, nil
}

func VerifyOptrandAggregatedTranscript(
	cfg Config,
	agg *ListBackedAggregateTranscript,
	artifacts map[int]*DealerArtifact,
) error {
	if agg == nil {
		return fmt.Errorf("nil aggregate")
	}
	if len(agg.Dealers) == 0 {
		return fmt.Errorf("empty aggregate dealers")
	}
	if len(agg.AggregateDigest) == 0 {
		return fmt.Errorf("empty aggregate digest")
	}
	if agg.Trusted {
		return verifyTrustedOptrandAggregatedTranscript(cfg, agg, artifacts)
	}
	expected, err := BuildOptrandAggregatedTranscript(cfg, agg.Dealers, artifacts)
	if err != nil {
		return err
	}
	if !bytesEq(expected.AggregateDigest, agg.AggregateDigest) {
		return fmt.Errorf("aggregate digest mismatch")
	}
	if len(expected.ContributionDigests) != len(agg.ContributionDigests) {
		return fmt.Errorf("aggregate contribution count mismatch")
	}
	for dealer, expDig := range expected.ContributionDigests {
		gotDig, ok := agg.ContributionDigests[dealer]
		if !ok || !bytesEq(expDig, gotDig) {
			return fmt.Errorf("aggregate contribution mismatch for dealer=%d", dealer)
		}
	}
	return nil
}

func verifyTrustedOptrandAggregatedTranscript(
	cfg Config,
	agg *ListBackedAggregateTranscript,
	artifacts map[int]*DealerArtifact,
) error {
	canonDealers := sortedUnique(agg.Dealers)
	if len(canonDealers) != len(agg.Dealers) {
		return fmt.Errorf("trusted aggregate dealers must be canonical unique list")
	}
	if len(agg.ContributionDigests) != len(canonDealers) {
		return fmt.Errorf("trusted aggregate contribution count mismatch")
	}
	digestParts := make([][]byte, 0, 2+len(canonDealers))
	digestParts = append(digestParts, []byte("optrand-agg"), encodeInts(canonDealers))
	for _, dealer := range canonDealers {
		art, ok := artifacts[dealer]
		if !ok || art == nil {
			return fmt.Errorf("missing dealer artifact for dealer=%d", dealer)
		}
		if art.Dealer != dealer || art.Descriptor.Dealer != dealer {
			return fmt.Errorf("trusted artifact descriptor mismatch for dealer=%d", dealer)
		}
		if len(art.Descriptor.Digest) == 0 || !bytesEq(art.Descriptor.Digest, digestDescriptor(art.Descriptor)) {
			return fmt.Errorf("trusted artifact descriptor digest mismatch for dealer=%d", dealer)
		}
		if !ValidateDescriptor(cfg, art.Descriptor) {
			return fmt.Errorf("descriptor validation failed for dealer=%d", dealer)
		}
		expectedDig := art.ContributionDigest
		if len(expectedDig) == 0 && len(art.Payload) > 0 {
			expectedDig = optrandContributionDigest(art)
		}
		if len(expectedDig) == 0 {
			return fmt.Errorf("missing contribution digest for dealer=%d", dealer)
		}
		gotDig, ok := agg.ContributionDigests[dealer]
		if !ok || !bytesEq(expectedDig, gotDig) {
			return fmt.Errorf("trusted aggregate contribution mismatch for dealer=%d", dealer)
		}
		digestParts = append(digestParts, gotDig)
	}
	if !bytesEq(hashBytes(digestParts...), agg.AggregateDigest) {
		return fmt.Errorf("trusted aggregate digest mismatch")
	}
	return nil
}

func RecoverOptrandFromVerifiedAggregate(agg *APVSSAggregate) (*APVSSRecovered, error) {
	if agg == nil {
		return nil, fmt.Errorf("nil APVSS aggregate")
	}
	if agg.Provider != "optrand" {
		return nil, fmt.Errorf("unexpected APVSS provider: %s", agg.Provider)
	}
	if agg.ListTranscript == nil {
		return nil, fmt.Errorf("missing optrand aggregate transcript")
	}
	tx := agg.ListTranscript
	if !bytesEq(agg.AggregateDigest, tx.AggregateDigest) {
		return nil, fmt.Errorf("aggregate digest mismatch")
	}
	if len(agg.Dealers) != len(tx.Dealers) {
		return nil, fmt.Errorf("aggregate dealer count mismatch")
	}
	if len(tx.ContributionDigests) != len(tx.Dealers) {
		return nil, fmt.Errorf("aggregate contribution count mismatch")
	}
	for i := range agg.Dealers {
		dealer := agg.Dealers[i]
		if dealer != tx.Dealers[i] {
			return nil, fmt.Errorf("aggregate dealer order mismatch")
		}
		if len(tx.ContributionDigests[dealer]) == 0 {
			return nil, fmt.Errorf("missing contribution digest for dealer=%d", dealer)
		}
	}
	aggDigestParts := make([][]byte, 0, 2+len(tx.Dealers))
	aggDigestParts = append(aggDigestParts, []byte("optrand-agg"), encodeInts(tx.Dealers))
	for _, dealer := range tx.Dealers {
		aggDigestParts = append(aggDigestParts, tx.ContributionDigests[dealer])
	}
	expectedAggDigest := hashBytes(aggDigestParts...)
	if !bytesEq(expectedAggDigest, agg.AggregateDigest) {
		return nil, fmt.Errorf("aggregate digest mismatch")
	}

	contrib := make(map[int][]byte, len(tx.ContributionDigests))
	digestParts := make([][]byte, 0, 2+2*len(agg.Dealers))
	digestParts = append(digestParts, []byte("optrand-rec"), agg.AggregateDigest)
	for _, dealer := range agg.Dealers {
		dig := tx.ContributionDigests[dealer]
		contrib[dealer] = append([]byte(nil), dig...)
		digestParts = append(digestParts, encodeInts([]int{dealer}), dig)
	}
	return &APVSSRecovered{
		OutputKind:          APVSSOutputEmulated,
		AggregateDigest:     append([]byte(nil), agg.AggregateDigest...),
		RecoveredMaterial:   hashBytes(digestParts...),
		ContributionDigests: contrib,
	}, nil
}

func optrandContributionDigest(art *DealerArtifact) []byte {
	if art == nil {
		return hashBytes([]byte("optrand-contrib-nil"))
	}
	receivers := make([]int, 0, len(art.Ciphertexts))
	for receiver := range art.Ciphertexts {
		receivers = append(receivers, receiver)
	}
	sort.Ints(receivers)
	parts := make([][]byte, 0, 5+2*len(receivers))
	parts = append(parts,
		[]byte("optrand-contrib"),
		[]byte(fmt.Sprintf("dealer=%d", art.Dealer)),
		art.Descriptor.Digest,
		art.Descriptor.Header.Root,
		art.Descriptor.Header.Commitment,
	)
	for _, receiver := range receivers {
		parts = append(parts, []byte(fmt.Sprintf("receiver=%d", receiver)))
		parts = append(parts, hashBytes([]byte("ct"), art.Ciphertexts[receiver]))
	}
	return hashBytes(parts...)
}

func scalarShamirContributionDigest(art *DealerArtifact) []byte {
	if art == nil {
		return scalarShamirHash("scalar-shamir-contribution-v1", []byte("nil"))
	}
	receivers := make([]int, 0, len(art.Ciphertexts))
	for receiver := range art.Ciphertexts {
		receivers = append(receivers, receiver)
	}
	sort.Ints(receivers)
	parts := make([][]byte, 0, 6+len(receivers))
	parts = append(parts,
		[]byte(fmt.Sprintf("dealer=%d", art.Dealer)),
		art.Descriptor.Digest,
		art.Descriptor.Header.Root,
		art.Descriptor.Header.Commitment,
		art.Payload,
		encodeInts(receivers),
	)
	for _, receiver := range receivers {
		parts = append(parts, hashBytes([]byte("ct"), art.Ciphertexts[receiver]))
	}
	return scalarShamirHash("scalar-shamir-contribution-v1", parts...)
}

func dealerContributionDigest(provider string, art *DealerArtifact) []byte {
	if strings.EqualFold(strings.TrimSpace(provider), "scalar-shamir") {
		return scalarShamirContributionDigest(art)
	}
	return optrandContributionDigest(art)
}

func fingerprintDealerArtifact(art *DealerArtifact) []byte {
	if art == nil {
		return hashBytes([]byte("rladkr-artifact-fp-nil"))
	}
	receivers := make([]int, 0, len(art.Ciphertexts))
	for receiver := range art.Ciphertexts {
		receivers = append(receivers, receiver)
	}
	sort.Ints(receivers)
	parts := make([][]byte, 0, 8+2*len(receivers))
	parts = append(parts,
		[]byte("rladkr-artifact-fp"),
		[]byte(fmt.Sprintf("dealer=%d", art.Dealer)),
		art.Descriptor.Digest,
		art.Descriptor.Header.Root,
		art.Descriptor.Header.Commitment,
		art.Descriptor.Header.MetadataHash,
		art.Payload,
		art.ContributionDigest,
	)
	for _, receiver := range receivers {
		parts = append(parts, []byte(fmt.Sprintf("receiver=%d", receiver)))
		parts = append(parts, art.Ciphertexts[receiver])
	}
	return hashBytes(parts...)
}
