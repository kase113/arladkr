package core

import (
	"testing"
	"time"
)

func TestCVServiceExperimentMetricsSeparateRecoveryPurposes(t *testing.T) {
	service := &cvAPDBNetworkServiceV2{}
	service.recordRecoveryBytesV2(cvRecoveryProposerCatalogV2, true, 11)
	service.recordRecoveryBytesV2(cvRecoveryProposerCatalogV2, false, 12)
	service.recordRecoveryLatencyV2(cvRecoveryProposerCatalogV2, 13*time.Millisecond)
	service.recordRecoveryBytesV2(cvRecoveryValidatorComponentV2, true, 21)
	service.recordRecoveryBytesV2(cvRecoveryValidatorComponentV2, false, 22)
	service.recordRecoveryLatencyV2(cvRecoveryValidatorComponentV2, 23*time.Millisecond)
	service.recordRecoveryBytesV2(cvRecoveryValidatorAggregateV2, true, 31)
	service.recordRecoveryBytesV2(cvRecoveryValidatorAggregateV2, false, 32)
	service.recordRecoveryLatencyV2(cvRecoveryValidatorAggregateV2, 33*time.Millisecond)
	service.recordRecoveryBytesV2(cvRecoveryNewAggregateV2, true, 34)
	service.recordRecoveryBytesV2(cvRecoveryNewAggregateV2, false, 35)
	service.recordRecoveryLatencyV2(cvRecoveryNewAggregateV2, 36*time.Millisecond)
	service.recordRecoveryBytesV2(cvRecoveryUnclassifiedV2, true, 100)
	service.recordRecoveryLatencyV2(cvRecoveryUnclassifiedV2, time.Second)
	service.recordCertificateFormationV2(cvCertificateARCV2, 41*time.Millisecond)
	service.recordCertificateFormationV2(cvCertificateValidationV2, 42*time.Millisecond)
	service.recordCertificateFormationV2(cvCertificateDecisionV2, 43*time.Millisecond)

	metrics := service.experimentMetricsV2()
	if metrics.proposerRecoverySentBytes != 11 || metrics.proposerRecoveryRecvBytes != 12 ||
		metrics.proposerRecoveryLatency != 13*time.Millisecond {
		t.Fatalf("proposer recovery metrics=%+v", metrics)
	}
	if metrics.validatorComponentRecoverySentBytes != 21 || metrics.validatorComponentRecoveryRecvBytes != 22 ||
		metrics.validatorComponentRecoveryLatency != 23*time.Millisecond ||
		metrics.validatorAggregateRecoverySentBytes != 31 || metrics.validatorAggregateRecoveryRecvBytes != 32 ||
		metrics.validatorAggregateRecoveryLatency != 33*time.Millisecond ||
		metrics.newAggregateRecoverySentBytes != 34 || metrics.newAggregateRecoveryRecvBytes != 35 ||
		metrics.newAggregateRecoveryLatency != 36*time.Millisecond {
		t.Fatalf("validator recovery metrics=%+v", metrics)
	}
	if metrics.arcFormationLatency != 41*time.Millisecond ||
		metrics.validationCertificateLatency != 42*time.Millisecond ||
		metrics.decisionCertificateLatency != 43*time.Millisecond {
		t.Fatalf("certificate formation metrics=%+v", metrics)
	}
}

func TestCVAddCostBreakdownMapsProtocolTerms(t *testing.T) {
	sent := make(map[string]uint64)
	recv := make(map[string]uint64)
	metrics := cvServiceExperimentMetricsV2{
		componentDispersalSentBytes: 11, componentDispersalRecvBytes: 12,
		aggregateDispersalSentBytes: 13, aggregateDispersalRecvBytes: 14,
		newAggregateRecoverySentBytes: 15, newAggregateRecoveryRecvBytes: 16,
		tagSentBytes: map[string]uint64{
			cvTagCoinShareV2: 21, cvTagValidationRequestV2: 22, cvTagCertifiedCandidateV2: 23,
			cvTagCertifiedCandidateACKV2: 26,
			cvTagHandoffV2:               24, cvTagAggregateShareV2: 25, cvTagAPDBStoreV2: 999,
		},
		tagRecvBytes: map[string]uint64{
			cvTagPoolOfferV2: 31, cvTagValidationSignatureV2: 32, cvTagCertifiedCandidateV2: 33,
			cvTagCertifiedCandidateACKV2: 36,
			cvTagDecisionShareV2:         34, cvTagAggregateShareV2: 35, cvTagAPDBStoreV2: 999,
		},
	}
	cvAddCostBreakdownV2(sent, recv, metrics)
	for name, want := range map[string]uint64{
		"component_apdb_dispersal": 11, "aggregate_apdb_dispersal": 13,
		"new_aggregate_recovery": 15, "pool_coin": 21, "validation_request": 22,
		"candidate_relay": 49, "decision_handoff": 24, "new_share_exchange": 25,
	} {
		if sent[name] != want {
			t.Fatalf("sent %s=%d want %d", name, sent[name], want)
		}
	}
	for name, want := range map[string]uint64{
		"component_apdb_dispersal": 12, "aggregate_apdb_dispersal": 14,
		"new_aggregate_recovery": 16, "pool_coin": 31, "validation_request": 32,
		"candidate_relay": 69, "decision_handoff": 34, "new_share_exchange": 35,
	} {
		if recv[name] != want {
			t.Fatalf("recv %s=%d want %d", name, recv[name], want)
		}
	}
}
