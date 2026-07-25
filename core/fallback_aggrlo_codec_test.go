package core

import (
	"encoding/json"
	"testing"
)

func TestFallbackAggRLOProposalBuildAndValidate(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}

	dealers := stableFirst(cfg.OldCommittee, cfg.Kappa)
	blob, err := BuildFallbackAggRLOProposal(cfg, dealers, artifacts)
	if err != nil {
		t.Fatalf("BuildFallbackAggRLOProposal failed: %v", err)
	}

	set, err := ValidateFallbackAggRLOProposal(blob, cfg, cfg.Kappa, artifacts)
	if err != nil {
		t.Fatalf("ValidateFallbackAggRLOProposal failed: %v", err)
	}
	if len(set) != cfg.Kappa {
		t.Fatalf("set size mismatch: got=%d want=%d", len(set), cfg.Kappa)
	}
}

func TestFallbackAggRLOProposalRejectsTamper(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	dealers := stableFirst(cfg.OldCommittee, cfg.Kappa)
	blob, err := BuildFallbackAggRLOProposal(cfg, dealers, artifacts)
	if err != nil {
		t.Fatalf("BuildFallbackAggRLOProposal failed: %v", err)
	}
	var payload fallbackAggRLOPayload
	if err := json.Unmarshal(blob, &payload); err != nil {
		t.Fatalf("unmarshal payload failed: %v", err)
	}
	payload.RLODigest = payload.RLODigest + "00"
	bad, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal tampered payload failed: %v", err)
	}
	if _, err := ValidateFallbackAggRLOProposal(bad, cfg, cfg.Kappa, artifacts); err == nil {
		t.Fatalf("expected tampered AggRLO proposal to fail")
	}
}
