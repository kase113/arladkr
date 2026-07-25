package core

import (
	"context"
	"testing"
	"time"

	dmvba "dumbomvba_go/core"
)

func TestSelectDealersForLockAggRequiresFastlaneReadyPool(t *testing.T) {
	cfg := baseTestConfig()
	if len(cfg.OldCommittee) != 4 || cfg.FOld != 1 || cfg.FNew != 1 || cfg.Kappa != 2 || cfg.FastlaneMin != 3 {
		t.Fatalf("unexpected fixture: n=%d f_o=%d f_n=%d Kappa=%d FastlaneMin=%d", len(cfg.OldCommittee), cfg.FOld, cfg.FNew, cfg.Kappa, cfg.FastlaneMin)
	}
	if _, err := selectDealersForLockAgg(cfg, []readyCandidate{{dealer: 0}, {dealer: 1}}); err == nil {
		t.Fatalf("selectDealersForLockAgg accepted fewer than FastlaneMin=%d candidates", cfg.FastlaneMin)
	}
	unnormalized := cfg
	unnormalized.FastlaneMin = 0
	if _, err := selectDealersForLockAgg(unnormalized, []readyCandidate{{dealer: 0}, {dealer: 1}}); err == nil {
		t.Fatal("selectDealersForLockAgg did not derive the ready-pool minimum from n-f")
	}
	candidates := []readyCandidate{{dealer: 0}, {dealer: 1}, {dealer: 2}}
	dealers, err := selectDealersForLockAgg(cfg, candidates)
	if err != nil {
		t.Fatalf("selectDealersForLockAgg failed: %v", err)
	}
	if len(dealers) != cfg.Kappa {
		t.Fatalf("selected dealer count=%d, want Kappa=%d", len(dealers), cfg.Kappa)
	}
}

func TestFallbackSeedDealersRequiresFastlaneReadyPool(t *testing.T) {
	cfg := baseTestConfig()
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}

	descriptors, readyArtifacts := readySubset(t, cfg, artifacts, 2)
	if dealers := fallbackSeedDealers(cfg, descriptors, readyArtifacts); dealers != nil {
		t.Fatalf("fallbackSeedDealers accepted fewer than FastlaneMin=%d candidates: %v", cfg.FastlaneMin, dealers)
	}

	descriptors, readyArtifacts = readySubset(t, cfg, artifacts, 3)
	dealers := fallbackSeedDealers(cfg, descriptors, readyArtifacts)
	if len(dealers) != cfg.Kappa {
		t.Fatalf("fallback seed dealer count=%d, want Kappa=%d", len(dealers), cfg.Kappa)
	}
}

func TestExtractDecidedDealersFromACSRequiresFastlaneReadyPool(t *testing.T) {
	cfg := baseTestConfig()
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	acsVecs := [][]*dmvba.ProposalValue{{{Payload: []byte("agreed")}}}

	descriptors, readyArtifacts := readySubset(t, cfg, artifacts, 2)
	if dealers := extractDecidedDealersFromACS(acsVecs, cfg, descriptors, readyArtifacts); dealers != nil {
		t.Fatalf("extractDecidedDealersFromACS accepted fewer than FastlaneMin=%d candidates: %v", cfg.FastlaneMin, dealers)
	}

	descriptors, readyArtifacts = readySubset(t, cfg, artifacts, 3)
	dealers := extractDecidedDealersFromACS(
		acsVecs,
		cfg,
		descriptors,
		readyArtifacts,
	)
	if len(dealers) != cfg.Kappa {
		t.Fatalf("decided dealer count=%d, want Kappa=%d", len(dealers), cfg.Kappa)
	}
}

func readySubset(t *testing.T, cfg Config, artifacts map[int]*DealerArtifact, count int) (map[int]Descriptor, map[int]*DealerArtifact) {
	t.Helper()
	descriptors := make(map[int]Descriptor, count)
	readyArtifacts := make(map[int]*DealerArtifact, count)
	for _, dealer := range cfg.OldCommittee[:count] {
		artifact := artifacts[dealer]
		if artifact == nil {
			t.Fatalf("missing dealer artifact %d", dealer)
		}
		descriptors[dealer] = artifact.Descriptor
		readyArtifacts[dealer] = artifact
	}
	return descriptors, readyArtifacts
}

func TestAgreeAgg_DefaultRunsDumboMVBA(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	descriptors := make(map[int]Descriptor, len(artifacts))
	for dealer, art := range artifacts {
		descriptors[dealer] = art.Descriptor
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := AgreeAgg(ctx, cfg, descriptors, artifacts)
	if err != nil {
		t.Fatalf("AgreeAgg failed: %v", err)
	}
	prepared, err := PrepareFallbackState(cfg, descriptors, artifacts)
	if err != nil {
		t.Fatalf("PrepareFallbackState failed: %v", err)
	}
	if out == nil || out.AggRLO == nil {
		t.Fatalf("AgreeAgg returned nil AggRLO")
	}
	if out.Mode != "fallback-mvba" {
		t.Fatalf("unexpected agreement mode: %s", out.Mode)
	}
	if !sameIntSet(out.AggRLO.Header.Dealers, prepared.Header.Dealers) {
		t.Fatalf("AggRLO dealers mismatch: have=%v want=%v", out.AggRLO.Header.Dealers, prepared.Header.Dealers)
	}
	if len(out.AggRLO.Digest) == 0 {
		t.Fatalf("AgreeAgg AggRLO digest is empty")
	}
	if !bytesEq(out.PreparedFallback, prepared.Digest) {
		t.Fatalf("prepared fallback digest mismatch")
	}
	if len(out.PerNode) != len(cfg.OldCommittee) {
		t.Fatalf("per-node outputs mismatch: %d != %d", len(out.PerNode), len(cfg.OldCommittee))
	}
}

func TestAgreeAgg_FallbackReturnsCanonicalAggRLO(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.ForceFallback = true
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	descriptors := make(map[int]Descriptor, len(artifacts))
	for dealer, art := range artifacts {
		descriptors[dealer] = art.Descriptor
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	out, err := AgreeAgg(ctx, cfg, descriptors, artifacts)
	if err != nil {
		t.Fatalf("AgreeAgg fallback failed: %v", err)
	}
	if out == nil || out.AggRLO == nil {
		t.Fatalf("AgreeAgg fallback returned nil AggRLO")
	}
	if out.Mode != "fallback-mvba" {
		t.Fatalf("unexpected fallback agreement mode: %s", out.Mode)
	}
	if len(out.PreparedFallback) == 0 {
		t.Fatalf("prepared fallback digest should not be empty")
	}
	if !bytesEq(out.PreparedFallback, out.AggRLO.Digest) {
		t.Fatalf("fallback should decide the prepared AggRLO digest in force-fallback mode")
	}
	if len(out.PerNode) == 0 {
		t.Fatalf("fallback per-node outputs empty")
	}
}

func TestRunEpoch_BindsRecoverAggToAgreementAggRLO(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := RunEpoch(ctx, cfg)
	if err != nil {
		t.Fatalf("RunEpoch failed: %v", err)
	}
	if !sameIntSet(res.AggRLODealers, res.LockedSet) {
		t.Fatalf("RunEpoch locked set should come directly from agreed AggRLO: locked=%v aggrlo=%v", res.LockedSet, res.AggRLODealers)
	}
}
