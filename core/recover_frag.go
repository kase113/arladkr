package core

import "fmt"

func BuildAggFragResponses(cfg Config, rlo *AggRLO, artifacts map[int]*DealerArtifact) ([]AggFragResponse, error) {
	if rlo == nil {
		return nil, fmt.Errorf("nil AggRLO")
	}
	if len(rlo.Header.Dealers) == 0 {
		return nil, fmt.Errorf("empty AggRLO dealers")
	}
	return buildAggFragResponsesForDealers(cfg, rlo, artifacts, sortedUnique(rlo.Header.Dealers))
}

func buildAggFragResponsesForDealers(cfg Config, rlo *AggRLO, artifacts map[int]*DealerArtifact, dealers []int) ([]AggFragResponse, error) {
	if rlo == nil {
		return nil, fmt.Errorf("nil AggRLO")
	}
	switch rlo.Aggregate.Provider {
	case "optrand", "scalar-shamir":
		return buildListBackedAggFragResponses(cfg, rlo, artifacts, dealers, rlo.Aggregate.Provider)
	case "bls-pvss":
		return buildBlsAggFragResponses(cfg, rlo, dealers)
	default:
		return nil, fmt.Errorf("unsupported aggregate provider: %s", rlo.Aggregate.Provider)
	}
}

func VerifyAggFragResponses(cfg Config, rlo *AggRLO, responses []AggFragResponse, artifacts map[int]*DealerArtifact) error {
	if rlo == nil {
		return fmt.Errorf("nil AggRLO")
	}
	switch rlo.Aggregate.Provider {
	case "optrand", "scalar-shamir":
		return verifyListBackedAggFragResponses(cfg, rlo, responses, artifacts, rlo.Aggregate.Provider)
	case "bls-pvss":
		return verifyBlsAggFragResponses(cfg, rlo, responses)
	default:
		return fmt.Errorf("unsupported aggregate provider: %s", rlo.Aggregate.Provider)
	}
}

func buildListBackedAggFragResponses(
	cfg Config,
	rlo *AggRLO,
	artifacts map[int]*DealerArtifact,
	dealers []int,
	provider string,
) ([]AggFragResponse, error) {
	tx := rlo.Aggregate.ListTranscript
	if tx == nil {
		return nil, fmt.Errorf("missing %s list-backed aggregate transcript", provider)
	}
	dealers = sortedUnique(dealers)
	out := make([]AggFragResponse, 0, len(dealers))
	for _, dealer := range dealers {
		art, ok := artifacts[dealer]
		if !ok || art == nil {
			return nil, fmt.Errorf("missing artifact for dealer=%d", dealer)
		}
		dig := tx.ContributionDigests[dealer]
		if len(dig) == 0 {
			return nil, fmt.Errorf("missing contribution digest for dealer=%d", dealer)
		}
		out = append(out, AggFragResponse{
			Provider:           provider,
			Dealer:             dealer,
			ContributionDigest: append([]byte(nil), dig...),
			Payload:            append([]byte(nil), art.Payload...),
			Ciphertexts:        cloneBytesMap(art.Ciphertexts),
		})
	}
	return out, nil
}

func verifyListBackedAggFragResponses(
	cfg Config,
	rlo *AggRLO,
	responses []AggFragResponse,
	artifacts map[int]*DealerArtifact,
	provider string,
) error {
	tx := rlo.Aggregate.ListTranscript
	if tx == nil {
		return fmt.Errorf("missing %s list-backed aggregate transcript", provider)
	}
	dealers := sortedUnique(rlo.Header.Dealers)
	if len(responses) != len(dealers) {
		return fmt.Errorf("AggFrag response count mismatch: have=%d want=%d", len(responses), len(dealers))
	}
	respByDealer := make(map[int]AggFragResponse, len(responses))
	for _, resp := range responses {
		if resp.Provider != provider {
			return fmt.Errorf("unexpected response provider for dealer=%d: %s", resp.Dealer, resp.Provider)
		}
		if _, exists := respByDealer[resp.Dealer]; exists {
			return fmt.Errorf("duplicate AggFrag response for dealer=%d", resp.Dealer)
		}
		respByDealer[resp.Dealer] = resp
	}
	for _, dealer := range dealers {
		resp, ok := respByDealer[dealer]
		if !ok {
			return fmt.Errorf("missing AggFrag response for dealer=%d", dealer)
		}
		art, ok := artifacts[dealer]
		if !ok || art == nil {
			return fmt.Errorf("missing artifact for dealer=%d", dealer)
		}
		fullArt := &DealerArtifact{
			Dealer:             dealer,
			Descriptor:         art.Descriptor,
			Payload:            append([]byte(nil), resp.Payload...),
			Ciphertexts:        cloneBytesMap(resp.Ciphertexts),
			ContributionDigest: append([]byte(nil), resp.ContributionDigest...),
		}
		fullArt.Fingerprint = fingerprintDealerArtifact(fullArt)
		expected := tx.ContributionDigests[dealer]
		if !bytesEq(resp.ContributionDigest, expected) {
			return fmt.Errorf("AggFrag contribution digest mismatch for dealer=%d", dealer)
		}
		var contributionDigest []byte
		switch provider {
		case "optrand":
			if err := OptrandShareVerify(cfg, fullArt); err != nil {
				return fmt.Errorf("AggFrag verify dealer=%d: %w", dealer, err)
			}
			contributionDigest = optrandContributionDigest(fullArt)
		case "scalar-shamir":
			if err := NewScalarShamirAPVSS().Ver(cfg, scalarShamirTranscriptFromArtifact(fullArt), fullArt); err != nil {
				return fmt.Errorf("AggFrag verify dealer=%d: %w", dealer, err)
			}
			contributionDigest = scalarShamirContributionDigest(fullArt)
		default:
			return fmt.Errorf("unsupported list-backed aggregate provider: %s", provider)
		}
		if !bytesEq(contributionDigest, expected) {
			return fmt.Errorf("AggFrag reconstructed contribution mismatch for dealer=%d", dealer)
		}
	}
	return nil
}

func isListBackedAPVSSProvider(provider string) bool {
	return provider == "optrand" || provider == "scalar-shamir"
}

func buildBlsAggFragResponses(cfg Config, rlo *AggRLO, dealers []int) ([]AggFragResponse, error) {
	tx := rlo.Aggregate.BlsPVSSTranscript
	if tx == nil {
		return nil, fmt.Errorf("missing bls aggregate transcript")
	}
	dealers = sortedUnique(dealers)
	out := make([]AggFragResponse, 0, len(dealers))
	for _, dealer := range dealers {
		per := tx.PerDealer[dealer]
		if per == nil {
			return nil, fmt.Errorf("missing BLS per-dealer transcript for dealer=%d", dealer)
		}
		if err := blsPVSSVerify(cfg, per); err != nil {
			return nil, fmt.Errorf("invalid BLS per-dealer transcript for dealer=%d: %w", dealer, err)
		}
		payload, err := encodeBlsPVSSDealerTranscript(per)
		if err != nil {
			return nil, fmt.Errorf("encode BLS response for dealer=%d: %w", dealer, err)
		}
		out = append(out, AggFragResponse{
			Provider:           "bls-pvss",
			Dealer:             dealer,
			ContributionDigest: hashBytes([]byte("bls-pvss-contribution"), payload),
			Payload:            payload,
		})
	}
	return out, nil
}

func verifyBlsAggFragResponses(cfg Config, rlo *AggRLO, responses []AggFragResponse) error {
	tx := rlo.Aggregate.BlsPVSSTranscript
	if tx == nil {
		return fmt.Errorf("missing bls aggregate transcript")
	}
	dealers := sortedUnique(rlo.Header.Dealers)
	if len(responses) != len(dealers) {
		return fmt.Errorf("AggFrag response count mismatch: have=%d want=%d", len(responses), len(dealers))
	}
	respByDealer := make(map[int]AggFragResponse, len(responses))
	for _, resp := range responses {
		if resp.Provider != "bls-pvss" {
			return fmt.Errorf("unexpected response provider for dealer=%d: %s", resp.Dealer, resp.Provider)
		}
		if _, exists := respByDealer[resp.Dealer]; exists {
			return fmt.Errorf("duplicate AggFrag response for dealer=%d", resp.Dealer)
		}
		respByDealer[resp.Dealer] = resp
	}
	for _, dealer := range dealers {
		per := tx.PerDealer[dealer]
		if per == nil {
			return fmt.Errorf("missing BLS per-dealer transcript for dealer=%d", dealer)
		}
		resp, ok := respByDealer[dealer]
		if !ok {
			return fmt.Errorf("missing AggFrag response for dealer=%d", dealer)
		}
		decoded, err := decodeBlsPVSSDealerTranscript(resp.Payload)
		if err != nil {
			return fmt.Errorf("decode BLS AggFrag payload for dealer=%d: %w", dealer, err)
		}
		if decoded.Dealer != dealer {
			return fmt.Errorf("BLS AggFrag dealer mismatch: payload=%d response=%d", decoded.Dealer, dealer)
		}
		if err := blsPVSSVerify(cfg, decoded); err != nil {
			return fmt.Errorf("verify BLS AggFrag payload for dealer=%d: %w", dealer, err)
		}
		canonicalPayload, err := encodeBlsPVSSDealerTranscript(decoded)
		if err != nil {
			return fmt.Errorf("re-encode BLS AggFrag payload for dealer=%d: %w", dealer, err)
		}
		if !bytesEq(resp.Payload, canonicalPayload) {
			return fmt.Errorf("non-canonical BLS AggFrag payload for dealer=%d", dealer)
		}
		responseDigest := hashBytes([]byte("bls-pvss-contribution"), resp.Payload)
		if !bytesEq(resp.ContributionDigest, responseDigest) {
			return fmt.Errorf("BLS AggFrag contribution digest mismatch for dealer=%d", dealer)
		}
		expectedPayload, err := encodeBlsPVSSDealerTranscript(per)
		if err != nil {
			return fmt.Errorf("encode expected BLS AggFrag payload for dealer=%d: %w", dealer, err)
		}
		expectedDigest := hashBytes([]byte("bls-pvss-contribution"), expectedPayload)
		if !bytesEq(responseDigest, expectedDigest) {
			return fmt.Errorf("BLS AggFrag payload is not bound to aggregate dealer=%d", dealer)
		}
	}
	return nil
}
