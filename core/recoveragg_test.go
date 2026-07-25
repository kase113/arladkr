package core

import (
	"context"
	"testing"
	"time"
)

func TestRecoverAgg_BuildsSingleAggregateObject(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	lockedSet := stableFirst(cfg.OldCommittee, cfg.Kappa)
	out, err := RecoverAgg(cfg, lockedSet, artifacts)
	if err != nil {
		t.Fatalf("RecoverAgg failed: %v", err)
	}
	if out == nil {
		t.Fatalf("RecoverAgg output is nil")
	}
	if out.AggRLO == nil {
		t.Fatalf("RecoverAgg AggRLO is nil")
	}
	if len(out.AggRLO.Digest) == 0 {
		t.Fatalf("RecoverAgg AggRLO digest is empty")
	}
	if out.Recovered == nil || len(out.Recovered.RecoveredMaterial) == 0 {
		t.Fatalf("RecoverAgg recovered material is empty")
	}
	if len(out.AggRLO.Header.Dealers) != len(lockedSet) {
		t.Fatalf("RecoverAgg dealer size mismatch: have=%d want=%d", len(out.AggRLO.Header.Dealers), len(lockedSet))
	}
}

func TestRunEpoch_ExposeRecoverAggOutputs(t *testing.T) {
	cfg := baseTestConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := RunEpoch(ctx, cfg)
	if err != nil {
		t.Fatalf("RunEpoch failed: %v", err)
	}
	if len(res.AggRLODigest) == 0 {
		t.Fatalf("epoch AggRLO digest is empty")
	}
	if len(res.RecoveredAggregate) == 0 {
		t.Fatalf("epoch recovered aggregate material is empty")
	}
	if len(res.AggRLODealers) == 0 {
		t.Fatalf("epoch AggRLO dealers are empty")
	}
	if len(res.AggRLODealers) != len(res.LockedSet) {
		t.Fatalf("AggRLO dealers size mismatch: have=%d locked=%d", len(res.AggRLODealers), len(res.LockedSet))
	}
	if res.AggRLOReadyLatency <= 0 {
		t.Fatalf("epoch AggRLO ready latency should be positive")
	}
	if !res.RecoverAggSuccess {
		t.Fatalf("epoch RecoverAgg should be marked success")
	}
	if res.AdmitAggAttempts <= 0 {
		t.Fatalf("epoch AdmitAgg attempts should be positive")
	}
	if res.AdmitAggPasses <= 0 {
		t.Fatalf("epoch AdmitAgg passes should be positive")
	}
	if res.AdmitAggPasses > res.AdmitAggAttempts {
		t.Fatalf("epoch AdmitAgg passes exceed attempts: passes=%d attempts=%d", res.AdmitAggPasses, res.AdmitAggAttempts)
	}
}

func TestRecoverAndDeriveFromAggRLO(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	lockedSet := stableFirst(cfg.OldCommittee, cfg.Kappa)
	recoverOut, err := RecoverAgg(cfg, lockedSet, artifacts)
	if err != nil {
		t.Fatalf("RecoverAgg failed: %v", err)
	}
	sampled, recovered, shares, pk, err := RecoverAndDeriveFromAggRLO(cfg, recoverOut, artifacts)
	if err != nil {
		t.Fatalf("RecoverAndDeriveFromAggRLO failed: %v", err)
	}
	if len(sampled) == 0 || len(recovered) == 0 || len(shares) == 0 || len(pk) == 0 {
		t.Fatalf("derive outputs should not be empty")
	}
	for _, dealer := range sampled {
		if !containsInt(recoverOut.AggRLO.Header.Dealers, dealer) {
			t.Fatalf("sampled dealer %d is not in AggRLO dealers", dealer)
		}
	}
}

func TestRecoverAndDeriveFromAggRLO_RejectsRecoveredMaterialTamper(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	lockedSet := stableFirst(cfg.OldCommittee, cfg.Kappa)
	recoverOut, err := RecoverAgg(cfg, lockedSet, artifacts)
	if err != nil {
		t.Fatalf("RecoverAgg failed: %v", err)
	}
	if recoverOut.Recovered == nil || len(recoverOut.Recovered.RecoveredMaterial) == 0 {
		t.Fatalf("recoverOut material is empty")
	}
	recoverOut.Recovered.RecoveredMaterial = hashBytes(
		[]byte("tamper"),
		recoverOut.Recovered.RecoveredMaterial,
	)
	if _, _, _, _, err := RecoverAndDeriveFromAggRLO(cfg, recoverOut, artifacts); err == nil {
		t.Fatalf("expected RecoverAndDeriveFromAggRLO to reject tampered recovered material")
	}
}

func TestRecoverAndDeriveFromAggRLO_AggregateModeUsesSingleRecoveredObject(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.DeriveMode = "aggregate"
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	lockedSet := stableFirst(cfg.OldCommittee, cfg.Kappa)
	recoverOut, err := RecoverAgg(cfg, lockedSet, artifacts)
	if err != nil {
		t.Fatalf("RecoverAgg failed: %v", err)
	}
	sampled, recovered, shares, pk, err := RecoverAndDeriveFromAggRLO(cfg, recoverOut, artifacts)
	if err != nil {
		t.Fatalf("RecoverAndDeriveFromAggRLO aggregate failed: %v", err)
	}
	if len(sampled) != len(recoverOut.AggRLO.Header.Dealers) {
		t.Fatalf("sampled dealer set mismatch: have=%d want=%d", len(sampled), len(recoverOut.AggRLO.Header.Dealers))
	}
	if len(recovered) != 1 || len(recovered[-1]) == 0 {
		t.Fatalf("aggregate mode should expose exactly one recovered aggregate object")
	}
	if len(shares) != len(cfg.NewCommittee) {
		t.Fatalf("share count mismatch: %d", len(shares))
	}
	if len(pk) == 0 {
		t.Fatalf("new public key should not be empty")
	}
}

func TestRecoverAndDeriveFromAggRLO_AggregateModeRejectsDigestMismatch(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.DeriveMode = "aggregate"
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	lockedSet := stableFirst(cfg.OldCommittee, cfg.Kappa)
	recoverOut, err := RecoverAgg(cfg, lockedSet, artifacts)
	if err != nil {
		t.Fatalf("RecoverAgg failed: %v", err)
	}
	recoverOut.Recovered.AggregateDigest = hashBytes([]byte("tamper"), recoverOut.Recovered.AggregateDigest)
	if _, _, _, _, err := RecoverAndDeriveFromAggRLO(cfg, recoverOut, artifacts); err == nil {
		t.Fatalf("expected aggregate mode to reject recovered digest mismatch")
	}
}

func TestRecoverAgreedAggRLO_RejectsAggregateContributionTamper(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	lockedSet := stableFirst(cfg.OldCommittee, cfg.Kappa)
	recoverOut, err := RecoverAgg(cfg, lockedSet, artifacts)
	if err != nil {
		t.Fatalf("RecoverAgg failed: %v", err)
	}
	tampered := *recoverOut.AggRLO
	tampered.Aggregate = recoverOut.AggRLO.Aggregate
	tx := *recoverOut.AggRLO.Aggregate.ListTranscript
	tx.ContributionDigests = make(map[int][]byte, len(recoverOut.AggRLO.Aggregate.ListTranscript.ContributionDigests))
	for dealer, dig := range recoverOut.AggRLO.Aggregate.ListTranscript.ContributionDigests {
		tx.ContributionDigests[dealer] = append([]byte(nil), dig...)
	}
	dealer := tx.Dealers[0]
	tx.ContributionDigests[dealer] = hashBytes([]byte("tamper"), tx.ContributionDigests[dealer])
	tampered.Aggregate.ListTranscript = &tx

	if _, err := RecoverAgreedAggRLO(cfg, &tampered, artifacts); err == nil {
		t.Fatalf("expected RecoverAgreedAggRLO to reject contribution digest tamper")
	}
}

func TestBuildAndVerifyAggFragResponses_Optrand(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.RecoverResponseMode = "local"
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	lockedSet := stableFirst(cfg.OldCommittee, cfg.Kappa)
	recoverOut, err := RecoverAgg(cfg, lockedSet, artifacts)
	if err != nil {
		t.Fatalf("RecoverAgg failed: %v", err)
	}
	if len(recoverOut.AggFragResponses) != len(lockedSet) {
		t.Fatalf("AggFrag response count mismatch: have=%d want=%d", len(recoverOut.AggFragResponses), len(lockedSet))
	}
	if recoverOut.RecoverVerifyLatency <= 0 {
		t.Fatalf("RecoverVerifyLatency should be positive")
	}
	if recoverOut.RecoverMaterializeLatency <= 0 {
		t.Fatalf("RecoverMaterializeLatency should be positive")
	}
}

func TestBuildAggFragResponsesForDealers_BuildsOnlyRequestedSubset(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	lockedSet := stableFirst(cfg.OldCommittee, cfg.Kappa)
	apvss := newAPVSSFromConfig(cfg)
	agg, err := apvss.Agg(cfg, lockedSet, artifacts)
	if err != nil {
		t.Fatalf("Agg failed: %v", err)
	}
	rlo, _, err := BuildAggRLO(cfg, lockedSet, agg)
	if err != nil {
		t.Fatalf("BuildAggRLO failed: %v", err)
	}
	subset := lockedSet[:2]
	responses, err := buildAggFragResponsesForDealers(cfg, rlo, artifacts, subset)
	if err != nil {
		t.Fatalf("buildAggFragResponsesForDealers failed: %v", err)
	}
	if len(responses) != len(subset) {
		t.Fatalf("subset response count mismatch: have=%d want=%d", len(responses), len(subset))
	}
	for i, resp := range responses {
		if resp.Dealer != subset[i] {
			t.Fatalf("response dealer mismatch at %d: have=%d want=%d", i, resp.Dealer, subset[i])
		}
	}
}

func TestVerifyAggFragResponses_RejectsPayloadTamper(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.RecoverResponseMode = "local"
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	lockedSet := stableFirst(cfg.OldCommittee, cfg.Kappa)
	recoverOut, err := RecoverAgg(cfg, lockedSet, artifacts)
	if err != nil {
		t.Fatalf("RecoverAgg failed: %v", err)
	}
	responses := append([]AggFragResponse(nil), recoverOut.AggFragResponses...)
	responses[0].Payload = hashBytes([]byte("tamper"), responses[0].Payload)
	if err := VerifyAggFragResponses(cfg, recoverOut.AggRLO, responses, artifacts); err == nil {
		t.Fatalf("expected VerifyAggFragResponses to reject tampered payload")
	}
}

func TestCollectAggFragResponses_NetworkMode(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.AgreementTransport = "tcp-loopback"
	cfg.RecoverResponseMode = "network"
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	lockedSet := stableFirst(cfg.OldCommittee, cfg.Kappa)
	apvss := newAPVSSFromConfig(cfg)
	agg, err := apvss.Agg(cfg, lockedSet, artifacts)
	if err != nil {
		t.Fatalf("Agg failed: %v", err)
	}
	rlo, _, err := BuildAggRLO(cfg, lockedSet, agg)
	if err != nil {
		t.Fatalf("BuildAggRLO failed: %v", err)
	}
	responses, err := CollectAggFragResponses(context.Background(), cfg, rlo, artifacts)
	if err != nil {
		t.Fatalf("CollectAggFragResponses(network) failed: %v", err)
	}
	if len(responses) != len(lockedSet) {
		t.Fatalf("network response count mismatch: have=%d want=%d", len(responses), len(lockedSet))
	}
	if err := VerifyAggFragResponses(cfg, rlo, responses, artifacts); err != nil {
		t.Fatalf("VerifyAggFragResponses(network) failed: %v", err)
	}
}

func TestRecoverAgreedAggRLO_SkipsOnlyExactValidatedAggRLO(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	lockedSet := stableFirst(cfg.OldCommittee, cfg.Kappa)
	apvss := newAPVSSFromConfig(cfg)
	agg, err := apvss.Agg(cfg, lockedSet, artifacts)
	if err != nil {
		t.Fatalf("Agg failed: %v", err)
	}
	rlo, _, err := BuildAggRLO(cfg, lockedSet, agg)
	if err != nil {
		t.Fatalf("BuildAggRLO failed: %v", err)
	}
	if err := AdmitLocallyConstructedAgg(cfg, rlo); err != nil {
		t.Fatalf("AdmitLocallyConstructedAgg failed: %v", err)
	}
	if _, err := RecoverAgreedAggRLO(cfg, rlo, artifacts); err != nil {
		t.Fatalf("RecoverAgreedAggRLO should accept exact validated AggRLO: %v", err)
	}

	tampered := *rlo
	tampered.Aggregate = rlo.Aggregate
	tx := *rlo.Aggregate.ListTranscript
	tx.ContributionDigests = make(map[int][]byte, len(rlo.Aggregate.ListTranscript.ContributionDigests))
	for dealer, dig := range rlo.Aggregate.ListTranscript.ContributionDigests {
		tx.ContributionDigests[dealer] = append([]byte(nil), dig...)
	}
	dealer := tx.Dealers[0]
	tx.ContributionDigests[dealer] = hashBytes([]byte("tamper"), tx.ContributionDigests[dealer])
	tampered.Aggregate.ListTranscript = &tx
	if _, err := RecoverAgreedAggRLO(cfg, &tampered, artifacts); err == nil {
		t.Fatalf("tampered AggRLO must not bypass AdmitAgg via local validation cache")
	}
}
