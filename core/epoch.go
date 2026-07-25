package core

import (
	"context"
	"fmt"
	"os"
	"time"
)

func PrepareRuntime(cfg Config) error {
	cfg = NormalizeConfig(cfg)
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	return ensureRuntime(&cfg)
}

func PrepareConfigRuntime(cfg Config) (Config, error) {
	cfg = NormalizeConfig(cfg)
	if err := ValidateConfig(cfg); err != nil {
		return cfg, err
	}
	if err := ensureRuntime(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func RunEpoch(ctx context.Context, cfg Config) (*EpochResult, error) {
	start := time.Now()
	setupStart := start
	cfg = NormalizeConfig(cfg)
	if cfg.APVSSProvider == "cv-sapvss" {
		return RunCVEpoch(ctx, cfg)
	}
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if err := ensureRuntime(&cfg); err != nil {
		return nil, err
	}
	if shouldPreopenProtocolTransport(cfg) {
		transport, err := newAgreementTransport(cfg, cfg.runtime.oldOrder, len(cfg.runtime.oldOrder)*32)
		if err != nil {
			return nil, err
		}
		cfg.protocolTransport = transport
		defer transport.Close()
	}
	cfg.runtime.setCommPhase("setup")
	setupLatency := time.Since(setupStart)
	traceBenchFinalize(cfg.SID, cfg.LocalNodeIDs, "after_setup", "ok")

	disperseStart := time.Now()
	cfg.runtime.setCommPhase("disperse")
	artifacts, disperseBreakdown, err := BuildDealerArtifactsDetailed(cfg)
	if err != nil {
		return nil, err
	}
	descriptors := make(map[int]Descriptor, len(artifacts))
	for dealer, art := range artifacts {
		descriptors[dealer] = art.Descriptor
	}
	disperseLatency := time.Since(disperseStart)
	traceBenchFinalize(
		cfg.SID,
		cfg.LocalNodeIDs,
		"after_disperse",
		fmt.Sprintf("artifacts=%d", len(artifacts)),
	)

	agreeStart := time.Now()
	cfg.runtime.setCommPhase("agree")
	agreeOut, err := AgreeAgg(ctx, cfg, descriptors, artifacts)
	if err != nil {
		return nil, err
	}
	if agreeOut == nil || agreeOut.AggRLO == nil {
		return nil, fmt.Errorf("agreement returned nil AggRLO")
	}
	agreeLatency := time.Since(agreeStart)
	lockedSet := append([]int(nil), agreeOut.AggRLO.Header.Dealers...)
	for i := range agreeOut.PerNode {
		if agreeOut.PerNode[i].Latency <= 0 {
			agreeOut.PerNode[i].Latency = time.Since(start)
		}
	}
	traceBenchFinalize(
		cfg.SID,
		cfg.LocalNodeIDs,
		"after_agree",
		fmt.Sprintf("mode=%s locked=%d pernode=%d", agreeOut.Mode, len(lockedSet), len(agreeOut.PerNode)),
	)
	recoverBarrierStart := time.Now()
	if err := waitForRecoverBarrier(cfg.LocalNodeIDs); err != nil {
		return nil, err
	}
	recoverBarrierWaitLatency := time.Since(recoverBarrierStart)

	recoverStart := time.Now()
	cfg.runtime.setCommPhase("recover")
	recoverAggOut, err := RecoverAgreedAggRLO(cfg, agreeOut.AggRLO, artifacts)
	if err != nil {
		return nil, err
	}
	recoverOnlyLatency := time.Since(recoverStart)
	sampled, recovered, shares, pk, err := RecoverAndDeriveFromAggRLO(cfg, recoverAggOut, artifacts)
	if err != nil {
		return nil, err
	}
	recoverLatency := time.Since(recoverStart)
	traceBenchFinalize(
		cfg.SID,
		cfg.LocalNodeIDs,
		"after_recover",
		fmt.Sprintf("sampled=%d recovered=%d shares=%d", len(sampled), len(recovered), len(shares)),
	)

	deriveStart := time.Now()
	cfg.runtime.setCommPhase("derive")
	eraseBufs := collectEraseBuffers(recovered, shares)
	states, err := UpdateAndEraseReceiverStates(cfg, cfg.runtime.receiverStates, pk, eraseBufs...)
	if err != nil {
		return nil, err
	}
	if err := persistReceiverStates(cfg, states); err != nil {
		return nil, err
	}
	deriveLatency := time.Since(deriveStart)
	traceBenchFinalize(
		cfg.SID,
		cfg.LocalNodeIDs,
		"after_derive",
		fmt.Sprintf("states=%d", len(states)),
	)
	admitAttempts, admitPasses := cfg.runtime.admitAggStats()
	totalSentBytes, totalRecvBytes := cfg.runtime.commStats()
	phaseSentBytes, phaseRecvBytes := cfg.runtime.phaseCommStats()
	recoverServiceGraceLatency := lingerSuccessfulRecoverService(cfg)

	return &EpochResult{
		AgreementMode:      agreeOut.Mode,
		AblationMode:       cfg.AblationMode,
		LockedSet:          append([]int(nil), lockedSet...),
		SampledSet:         sampled,
		AggRLODealers:      append([]int(nil), recoverAggOut.AggRLO.Header.Dealers...),
		RecoveredPayloads:  recovered,
		RecoveredAggregate: append([]byte(nil), recoverAggOut.Recovered.RecoveredMaterial...),
		AggRLODigest:       append([]byte(nil), recoverAggOut.AggRLO.Digest...),
		AggRLOReadyLatency: recoverAggOut.AggRLOReadyLatency,
		AdmitAggAttempts:   admitAttempts, AdmitAggPasses: admitPasses, RecoverAggSuccess: true,
		SetupLatency:                    setupLatency,
		DisperseLatency:                 disperseLatency,
		DisperseLocalBuildLatency:       disperseBreakdown.LocalBuildLatency,
		DisperseBroadcastLatency:        disperseBreakdown.BroadcastLatency,
		DisperseReadWaitLatency:         disperseBreakdown.ReadWaitLatency,
		DisperseTrustedReadyLatency:     disperseBreakdown.TrustedReadyLatency,
		DisperseAggregatePrewarmLatency: disperseBreakdown.AggregatePrewarmLatency,
		LockAggLatency:                  agreeOut.LockAggLatency,
		LockAggReadyCandidatesLatency:   agreeOut.LockAggBreakdown.ReadyCandidatesLatency,
		LockAggBuildAggregateLatency:    agreeOut.LockAggBreakdown.AggBuildLatency,
		LockAggARCSharePrepareLatency:   agreeOut.LockAggBreakdown.ARCSharePrepareLatency,
		LockAggARCShareAttachLatency:    agreeOut.LockAggBreakdown.ARCShareAttachLatency,
		LockAggCandidateCount:           agreeOut.LockAggBreakdown.CandidateCount,
		LockAggARCShareSignedCount:      agreeOut.LockAggBreakdown.ARCShareSignedCount,
		LockAggShareSignLatency:         agreeOut.LockAggBreakdown.AggLockSignLatency,
		LockAggCertRecoverLatency:       agreeOut.LockAggBreakdown.AggLockRecoverLatency,
		LockAggLocalAdmitLatency:        agreeOut.LockAggBreakdown.LocalAdmitLatency,
		MVBAOnlyLatency:                 agreeOut.MVBAOnlyLatency,
		MVBAPeerWaitLatency:             agreeOut.MVBAPeerWait,
		AgreeAggLatency:                 agreeLatency,
		RecoverBarrierWaitLatency:       recoverBarrierWaitLatency,
		RecoverServiceGraceLatency:      recoverServiceGraceLatency,
		RecoverLatency:                  recoverLatency,
		RecoverOnlyLatency:              recoverOnlyLatency,
		RecoverVerifyLatency:            recoverAggOut.RecoverVerifyLatency,
		RecoverCollectLatency:           recoverAggOut.RecoverCollectLatency,
		RecoverVerifyOnlyLatency:        recoverAggOut.RecoverVerifyOnlyLatency,
		RecoverMaterializeLatency:       recoverAggOut.RecoverMaterializeLatency,
		DeriveLatency:                   deriveLatency,
		TotalSentBytes:                  totalSentBytes,
		TotalRecvBytes:                  totalRecvBytes,
		PhaseSentBytes:                  phaseSentBytes,
		PhaseRecvBytes:                  phaseRecvBytes,
		NewShares:                       shares,
		NewPublicKey:                    pk,
		PerNode:                         agreeOut.PerNode,
		ReceiverStates:                  states,
	}, nil
}

func lingerSuccessfulRecoverService(cfg Config) time.Duration {
	if cfg.RecoverResponseMode != "" && cfg.RecoverResponseMode != "network" {
		return 0
	}
	grace := durationEnvMs("RLADKR_RECOVER_SERVICE_GRACE_MS", 0)
	if grace <= 0 {
		return 0
	}
	start := time.Now()
	time.Sleep(grace)
	return time.Since(start)
}

func shouldPreopenProtocolTransport(cfg Config) bool {
	if shouldUseNetworkDisperse(cfg) {
		return true
	}
	return cfg.RecoverResponseMode == "" || cfg.RecoverResponseMode == "network"
}

func traceBenchFinalize(sid string, localNodeIDs []int, phase string, detail string) {
	if os.Getenv("RLADKR_BENCH_DEBUG_FINALIZE") == "" {
		return
	}
	nodeLabel := "all"
	if len(localNodeIDs) == 1 {
		nodeLabel = fmt.Sprintf("%d", localNodeIDs[0])
	}
	fmt.Fprintf(
		os.Stderr,
		"BENCH_FINALIZE sid=%s node=%s phase=%s detail=%s\n",
		sid,
		nodeLabel,
		phase,
		detail,
	)
}

func persistReceiverStates(cfg Config, states map[int]ReceiverState) error {
	if cfg.StateStoreDir == "" {
		return nil
	}
	store := newReceiverStateStore(cfg.StateStoreDir)
	// RunEpoch(e) outputs st_{u,e+1}; save under epoch=e+1 for next execution.
	return store.Save(cfg.SID, cfg.Epoch+1, states)
}
