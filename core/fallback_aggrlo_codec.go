package core

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type fallbackAggRLOPayload struct {
	Dealers         []int            `json:"dealers"`
	AggDigest       string           `json:"agg_digest"`
	RLODigest       string           `json:"rlo_digest"`
	ARCHeaderShares []ARCHeaderShare `json:"arc_header_shares,omitempty"`
}

func fallbackProposalCacheKey(cfg Config, dealers []int) string {
	return fmt.Sprintf("%s|epoch=%d|dealers=%x", cfg.SID, cfg.Epoch, encodeInts(sortedUnique(dealers)))
}

func BuildFallbackAggRLOProposal(
	cfg Config,
	dealers []int,
	artifacts map[int]*DealerArtifact,
) ([]byte, error) {
	canon := sortedUnique(dealers)
	if cfg.runtime != nil {
		if cached, ok := cfg.runtime.cachedFallbackProposal(fallbackProposalCacheKey(cfg, canon)); ok {
			return cached, nil
		}
	}
	rlo, _, err := buildAggRLOForDealers(cfg, canon, artifacts)
	if err != nil {
		return nil, err
	}
	payload := fallbackAggRLOPayload{
		Dealers:         canon,
		AggDigest:       hex.EncodeToString(rlo.Aggregate.AggregateDigest),
		RLODigest:       hex.EncodeToString(rlo.Digest),
		ARCHeaderShares: buildARCHeaderShares(cfg.Epoch, digestAggHeaderForLock(rlo.Header), rlo.Lock.ShareSignatures),
	}
	blob, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if cfg.runtime != nil {
		cfg.runtime.rememberFallbackProposal(fallbackProposalCacheKey(cfg, canon), blob)
	}
	return blob, nil
}

func ValidateFallbackAggRLOProposal(
	blob []byte,
	cfg Config,
	targetSize int,
	artifacts map[int]*DealerArtifact,
) ([]int, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("empty AggRLO proposal blob")
	}
	var payload fallbackAggRLOPayload
	if err := json.Unmarshal(blob, &payload); err != nil {
		return nil, err
	}
	canon := sortedUnique(payload.Dealers)
	if len(canon) == 0 {
		return nil, fmt.Errorf("empty dealer set in AggRLO proposal")
	}
	if targetSize > 0 && len(canon) != targetSize {
		return nil, fmt.Errorf("AggRLO proposal size mismatch: have=%d need=%d", len(canon), targetSize)
	}
	aggDigest, err := hex.DecodeString(payload.AggDigest)
	if err != nil {
		return nil, fmt.Errorf("invalid agg digest encoding: %w", err)
	}
	rloDigest, err := hex.DecodeString(payload.RLODigest)
	if err != nil {
		return nil, fmt.Errorf("invalid rlo digest encoding: %w", err)
	}

	rlo, _, err := buildAggRLOForDealers(cfg, canon, artifacts)
	if err != nil {
		return nil, err
	}
	if !bytesEq(rlo.Aggregate.AggregateDigest, aggDigest) {
		return nil, fmt.Errorf("AggRLO proposal aggregate digest mismatch")
	}
	if !bytesEq(rlo.Digest, rloDigest) {
		return nil, fmt.Errorf("AggRLO proposal digest mismatch")
	}
	if len(payload.ARCHeaderShares) > 0 {
		cacheARCHeaderShares(cfg, payload.ARCHeaderShares)
	}
	if cfg.runtime != nil {
		cfg.runtime.rememberFallbackProposal(fallbackProposalCacheKey(cfg, canon), blob)
	}
	return canon, nil
}
