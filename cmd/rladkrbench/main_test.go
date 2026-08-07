package main

import (
	"rladkr_go/core"
	"strings"
	"testing"
)

func TestAdmitAggPassRatio(t *testing.T) {
	if got := admitAggPassRatio(0, 0); got != 0 {
		t.Fatalf("expected 0 ratio on zero attempts, got %.4f", got)
	}
	if got := admitAggPassRatio(3, 4); got != 0.75 {
		t.Fatalf("expected 0.75 ratio, got %.4f", got)
	}
}

func TestFormatBenchResultIncludesEffectiveKappa(t *testing.T) {
	effective := core.NormalizeConfig(core.Config{FOld: 1, FNew: 1, Kappa: 0}).Kappa
	line := formatBenchResult(benchResultInput{kappa: effective, runs: 1})
	if !strings.Contains(line, " kappa=2 ") {
		t.Fatalf("benchmark output missing effective kappa: %s", line)
	}
}

func TestFormatBenchResultIncludesAPVSSModeAndBackendStatus(t *testing.T) {
	t.Setenv("RLADKR_CV_PRIMARY_GRACE_MS", "")
	line := formatBenchResult(benchResultInput{
		runs:                  1,
		apvssMode:             core.APVSSModeFullPublicVE,
		apvssBackendStatus:    "functional-prototype-backend-gate-pending",
		apvssFullProofProfile: core.APVSSFullProofExact,
		apvssFallbackProfile:  "none",
		securityProfile:       "static-cv-sapvss-full-proof-prototype-unreviewed",
	})
	for _, field := range []string{
		"cv_candidate_mode=" + core.CVAggregateCandidateMode,
		"cv_primary_grace_ms=10000",
		"cv_primary_pool_grace_ms=250",
		"apvss_mode=full-public-ve",
		"apvss_backend_status=functional-prototype-backend-gate-pending",
		"apvss_full_proof_profile=exact",
		"apvss_fallback_profile=none",
		"security_profile=static-cv-sapvss-full-proof-prototype-unreviewed",
	} {
		if !strings.Contains(line, field) {
			t.Fatalf("benchmark result missing %q: %s", field, line)
		}
	}
}

func TestSummarizeConsensusHashBindsEpochSequence(t *testing.T) {
	first := summarizeConsensusHash([]runStat{{consensusHash: "a"}, {consensusHash: "b"}})
	second := summarizeConsensusHash([]runStat{{consensusHash: "b"}, {consensusHash: "a"}})
	if first == "none" || first == "mixed" || first == second {
		t.Fatalf("sequence digest is not ordered: first=%q second=%q", first, second)
	}
}

func TestFormatBenchResultReportsCommitteeFaultThresholds(t *testing.T) {
	asymmetric := formatBenchResult(benchResultInput{fOld: 1, fNew: 2, runs: 1})
	for _, token := range []string{" f_old=1 ", " f_new=2 "} {
		if !strings.Contains(asymmetric, token) {
			t.Fatalf("asymmetric benchmark output missing %q: %s", token, asymmetric)
		}
	}

	balanced := formatBenchResult(benchResultInput{fOld: 1, fNew: 1, runs: 1})
	for _, token := range []string{" f_old=1 ", " f_new=1 "} {
		if !strings.Contains(balanced, token) {
			t.Fatalf("balanced benchmark output missing %q: %s", token, balanced)
		}
	}
}

func TestFormatBenchResultIncludesARLADKRMetrics(t *testing.T) {
	stats := []runStat{
		{
			latencyMs:             100,
			setupMs:               10,
			recoverBarrierWaitMs:  20,
			recoverServiceGraceMs: 30,
			completedNodes:        4,
			decidedSetMean:        3,
			aggRLOReadyMs:         5,
			admitAggAttempts:      2,
			admitAggPasses:        2,
			recoverAggSuccess:     1,
		},
		{
			latencyMs:             200,
			setupMs:               20,
			recoverBarrierWaitMs:  40,
			recoverServiceGraceMs: 60,
			completedNodes:        4,
			decidedSetMean:        3,
			aggRLOReadyMs:         7,
			admitAggAttempts:      2,
			admitAggPasses:        1,
			recoverAggSuccess:     1,
		},
	}
	line := formatBenchResult(benchResultInput{
		n:                     4,
		fOld:                  1,
		fNew:                  1,
		kappa:                 2,
		runs:                  2,
		timeoutMs:             90000,
		apvssProvider:         "cv-sapvss",
		apvssOutput:           "scalar",
		securityProfile:       "static-cv-sapvss-phase1-materialized",
		deriveMode:            "scalar",
		successRuns:           2,
		attemptedEpochs:       3,
		totalAttemptLatencyMs: 600,
		stats:                 stats,
	})
	for _, token := range []string{
		"mean_aggrlo_ready_ms=",
		"admitagg_pass_ratio=",
		"recoveragg_success_ratio=",
		"mean_recover_service_grace_ms=45.00",
		"mean_online_protocol_ms=105.00",
		"mean_online_phase_wall_ms=60.00",
		"mean_all_latency_ms=200.00",
		"protocol=ARLADKR-GO",
		"apvss_provider=cv-sapvss",
		"apvss_output=scalar",
		"security_profile=static-cv-sapvss-phase1-materialized",
		"derive_mode=scalar",
	} {
		if !strings.Contains(line, token) {
			t.Fatalf("benchmark output missing token %q: %s", token, line)
		}
	}
}

func TestFormatBenchResultIncludesCVPhaseLabels(t *testing.T) {
	line := formatBenchResult(benchResultInput{
		runs: 1,
		stats: []runStat{{
			cvComponentCount: 2, cvARCHolderCount: 3, cvRecoveredShardCount: 2,
			cvVerifiedReceiptCount: 2, cvLeafBuildMs: 7, cvComponentDisperseMs: 1, cvComponentCollectionMs: 2,
			cvAggregateDisperseMs: 3, cvAggregateAgreementMs: 4, cvRecoverShardMs: 5,
			cvReceiptMs: 6, cvAPVSSACKCount: 5, cvAPVSSFallbackCount: 2,
			cvAPVSSProofBytes: 101, cvAPVSSLeafWireBytes: 202,
			cvAggregateGateWaitMs: 7, cvAggregateLeafLoadMs: 8, cvAggregateBuildMs: 9,
			cvAggregateRSMs: 10, cvAggregateHeaderTokenMs: 11, cvAggregateOfferSendMs: 12,
			cvAggregateARCWaitMs: 13, cvAggregateCertificateMs: 14,
			phaseSentBytes: map[string]float64{"component_disperse": 10, "component_collection": 11,
				"aggregate_disperse": 12, "arc_share": 13, "recover_shard": 14, "receipt": 15},
		}},
	})
	for _, token := range []string{
		"mean_cv_component_count=2", "mean_cv_arc_holder_count=3",
		"mean_cv_recovered_shard_count=2", "mean_cv_verified_receipt_count=2",
		"leaf_build_ms=7", "component_disperse_ms=1", "component_collection_ms=2", "aggregate_disperse_ms=3",
		"aggregate_agreement_ms=4", "recover_shard_ms=5", "receipt_ms=6",
		"mean_apvss_ack_count=5.00", "mean_apvss_fallback_count=2.00",
		"mean_apvss_proof_bytes=101", "mean_apvss_leaf_wire_bytes=202",
		"aggregate_gate_wait_ms=7.00", "aggregate_leaf_load_ms=8.00",
		"aggregate_build_ms=9.00", "aggregate_rs_ms=10.00",
		"aggregate_header_token_ms=11.00", "aggregate_offer_send_ms=12.00",
		"aggregate_arc_wait_ms=13.00", "aggregate_certificate_ms=14.00",
		"mean_component_disperse_sent_bytes=10", "mean_component_collection_sent_bytes=11",
		"mean_aggregate_disperse_sent_bytes=12", "mean_arc_share_sent_bytes=13",
		"mean_recover_shard_sent_bytes=14", "mean_receipt_sent_bytes=15",
	} {
		if !strings.Contains(line, token) {
			t.Fatalf("CV benchmark output missing %q: %s", token, line)
		}
	}
}

func TestFormatBenchResultUsesConfiguredMaterializedARCLabel(t *testing.T) {
	line := formatBenchResult(benchResultInput{
		arcMode: "materialized",
		runs:    1,
	})
	if !strings.Contains(line, "arc_mode=materialized") {
		t.Fatalf("benchmark output mislabels materialized ARC: %s", line)
	}
}
