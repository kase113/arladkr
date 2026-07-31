package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"rladkr_go/core"
	"sort"
	"strconv"
	"strings"
	"time"
)

type runStat struct {
	latencyMs                  float64
	setupMs                    float64
	completedNodes             float64
	decidedSetMean             float64
	aggRLOReadyMs              float64
	admitAggAttempts           float64
	admitAggPasses             float64
	recoverAggSuccess          float64
	disperseMs                 float64
	disperseLocalBuildMs       float64
	disperseBroadcastMs        float64
	disperseReadWaitMs         float64
	disperseTrustedReadyMs     float64
	disperseAggregatePrewarmMs float64
	lockAggMs                  float64
	lockAggReadyCandidatesMs   float64
	lockAggBuildAggregateMs    float64
	lockAggARCSharePrepareMs   float64
	lockAggARCShareAttachMs    float64
	lockAggCandidateCount      float64
	lockAggARCShareSignedCnt   float64
	lockAggShareSignMs         float64
	lockAggCertRecoverMs       float64
	lockAggLocalAdmitMs        float64
	mvbaOnlyMs                 float64
	mvbaPeerWaitMs             float64
	agreeAggMs                 float64
	recoverBarrierWaitMs       float64
	recoverServiceGraceMs      float64
	recoverMs                  float64
	recoverOnlyMs              float64
	recoverVerifyMs            float64
	recoverCollectMs           float64
	recoverVerifyOnlyMs        float64
	recoverMaterializeMs       float64
	deriveMs                   float64
	phaseSentBytes             map[string]float64
	phaseRecvBytes             map[string]float64
	totalSentBytes             float64
	totalRecvBytes             float64
	consensusHash              string
	cvComponentCount           float64
	cvARCHolderCount           float64
	cvRecoveredShardCount      float64
	cvVerifiedReceiptCount     float64
	cvLeafBuildMs              float64
	cvComponentDisperseMs      float64
	cvCommonCandidateMs        float64
	cvAggregateDisperseMs      float64
	cvAggregateAgreementMs     float64
	cvAPVSSACKCount            float64
	cvAPVSSFallbackCount       float64
	cvAPVSSProofBytes          float64
	cvAPVSSLeafWireBytes       float64
	cvAggregateGateWaitMs      float64
	cvAggregateLeafLoadMs      float64
	cvAggregateBuildMs         float64
	cvAggregateRSMs            float64
	cvAggregateHeaderTokenMs   float64
	cvAggregateOfferSendMs     float64
	cvAggregateARCWaitMs       float64
	cvAggregateCertificateMs   float64
	cvRecoverShardMs           float64
	cvReceiptMs                float64
}

type benchResultInput struct {
	n                        int
	fOld                     int
	fNew                     int
	kappa                    int
	runs                     int
	timeoutMs                int64
	apvssProvider            string
	apvssFallbackProfile     string
	apvssForcedFallbackCount int
	apvssWaitAllACKs         bool
	experimentalAPVSS        bool
	apvssOutput              string
	securityProfile          string
	deriveMode               string
	arcMode                  string
	successRuns              int
	attemptedEpochs          int
	totalAttemptLatencyMs    float64
	localNodes               []int
	requiredCompleted        int
	ablationMode             string
	commMetrics              bool
	stats                    []runStat
}

func main() {
	var (
		n                        = flag.Int("n", 4, "number of old/new committee nodes")
		f                        = flag.Int("f", 1, "common default Byzantine threshold for both committees")
		fOld                     = flag.Int("f-old", -1, "old-committee Byzantine threshold (-1 = use --f)")
		fNew                     = flag.Int("f-new", -1, "new-committee Byzantine threshold (-1 = use --f)")
		kappa                    = flag.Int("kappa", 0, "aggregate dealer count (0 = f_old+1; other values are rejected)")
		runs                     = flag.Int("runs", 3, "number of benchmark runs")
		epochs                   = flag.Int("epochs", 1, "sequential domain-separated epochs per benchmark run")
		transport                = flag.String("transport", "tcp-distributed", "agreement transport: tcp-distributed|tcp-loopback")
		bindHost                 = flag.String("bind-host", "0.0.0.0", "tcp bind host")
		basePort                 = flag.Int("base-port", 0, "deterministic base port for node listeners when >0")
		runTimeout               = flag.Duration("timeout", 90*time.Second, "timeout per epoch run")
		waitSPBCTimeout          = flag.Duration("wait-spbc-timeout", 30*time.Second, "MVBA/SPBC wait timeout")
		routeSendTimeout         = flag.Duration("route-send-timeout", 2*time.Second, "MVBA route send timeout")
		apvssFallbackProfile     = flag.String("apvss-fallback-profile", "exact-lane", "APVSS fallback proof: exact-lane|compact-batch")
		allowExperimentalAPVSS   = flag.Bool("allow-experimental-apvss", false, "allow an APVSS proof profile that has not passed production admission")
		apvssForcedFallbackCount = flag.Int("apvss-forced-fallback-count", 0, "benchmark-only forced |I| (0 = natural ACK scheduling)")
		apvssWaitAllACKs         = flag.Bool("apvss-wait-all-acks", false, "benchmark-only wait for all receiver ACKs to produce |I|=0")
		precomputeRuntime        = flag.Bool("precompute-runtime", true, "prepare deterministic runtime/key material before protocol timing")
		startAt                  = flag.Int64("start-at", 0, "unix timestamp to synchronise start across nodes (0 = start immediately)")
		prepareOnly              = flag.Bool("prepare-only", false, "prepare deterministic runtime material and exit")
		ablationMode             = flag.String("ablation-mode", "none", "security ablation mode: none|no-agclock")
		commMetrics              = flag.Bool("comm-metrics", true, "enable protocol-layer communication byte counters")
		strictNetwork            = flag.Bool("strict-network", envBoolDefault("RLADKR_STRICT_NETWORK", true), "fail if benchmark config selects local/cache protocol shortcuts")
		cvPublicKeyDir           = flag.String("cv-public-key-dir", os.Getenv("RLADKR_CV_PUBLIC_KEY_DIR"), "CV public receiver registry directory")
		cvLocalSecretDir         = flag.String("cv-local-secret-dir", os.Getenv("RLADKR_CV_LOCAL_SECRET_DIR"), "CV local receiver secret directory")
		cvLocalReceiverRaw       = flag.String("cv-local-receiver-ids", os.Getenv("RLADKR_LOCAL_RECEIVER_IDS"), "comma-separated local new-committee receiver IDs")
		cvStateChainDir          = flag.String("cv-state-chain-dir", os.Getenv("RLADKR_STATE_CHAIN_DIR"), "private directory for verified CV epoch output state")
		cvKeygenOnly             = flag.Bool("cv-keygen-only", false, "generate CV receiver and old-lock keys and exit")
	)
	flag.Parse()
	if *fOld < -1 || *fNew < -1 {
		fmt.Println("f-old and f-new must be non-negative or -1")
		return
	}
	oldFaults := *f
	newFaults := *f
	if *fOld >= 0 {
		oldFaults = *fOld
	}
	if *fNew >= 0 {
		newFaults = *fNew
	}
	effectiveKappa := core.NormalizeConfig(core.Config{
		FOld:  oldFaults,
		FNew:  newFaults,
		Kappa: *kappa,
	}).Kappa
	visited := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})
	apvssFallbackProfileName := strings.ToLower(strings.TrimSpace(*apvssFallbackProfile))

	if *runs <= 0 {
		fmt.Println("runs must be positive")
		return
	}
	if *epochs <= 0 {
		*epochs = 1
	}

	// Distributed start barrier: wait until --start-at before proceeding.
	// All peer processes launched with the same timestamp will begin
	// RunEpoch simultaneously, so every listener is already bound when
	// waitForRemoteNodeReadiness probes them.
	if *startAt > 0 {
		now := time.Now().Unix()
		if now < *startAt {
			remaining := *startAt - now
			fmt.Fprintf(os.Stderr, "WARMUP: waiting %ds for start-at unix=%d\n", remaining, *startAt)
			for time.Now().Unix() < *startAt {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}

	old := make([]int, *n)
	newC := make([]int, *n)
	for i := 0; i < *n; i++ {
		old[i] = i
		newC[i] = *n + i
	}
	runTimeoutValue := *runTimeout
	if !visited["timeout"] {
		runTimeoutValue = defaultBenchRunTimeout(*n)
	}
	waitSPBCValue := *waitSPBCTimeout
	if !visited["wait-spbc-timeout"] {
		waitSPBCValue = defaultBenchWaitSPBCTimeout(*n)
	}
	routeSendValue := *routeSendTimeout
	if !visited["route-send-timeout"] {
		routeSendValue = defaultBenchRouteSendTimeout(*n)
	}
	localNodeIDs := readLocalNodeIDsEnv(*n)
	localReceiverIDs := readLocalReceiverIDs(*cvLocalReceiverRaw, *n, localNodeIDs)
	if *cvKeygenOnly {
		if err := core.GenerateCVReceiverKeyMaterial(*cvPublicKeyDir, *cvLocalSecretDir, "rladkr-go-bench", newC); err != nil {
			fmt.Fprintf(os.Stderr, "CV_KEYGEN_ERROR err=%v\n", err)
			os.Exit(1)
		}
		if err := core.GenerateCVOldLockKeyMaterial(
			*cvPublicKeyDir, *cvLocalSecretDir, "rladkr-go-bench", old, len(old)-oldFaults,
		); err != nil {
			fmt.Fprintf(os.Stderr, "CV_KEYGEN_ERROR err=%v\n", err)
			os.Exit(1)
		}
		fmt.Printf(
			"CV_KEYGEN_OK public_dir=%s secret_dir=%s receivers=%d old_lock_threshold=%d\n",
			*cvPublicKeyDir, *cvLocalSecretDir, len(newC), len(old)-oldFaults,
		)
		return
	}
	requiredCompleted := requiredCompletedNodes(*n, oldFaults, localNodeIDs)
	epochBarrierDir := strings.TrimSpace(os.Getenv("RLADKR_EPOCH_BARRIER_DIR"))
	if (*runs)*(*epochs) > 1 && len(localNodeIDs) < *n && epochBarrierDir == "" {
		fmt.Fprintln(os.Stderr, "multi-epoch distributed benchmark requires RLADKR_EPOCH_BARRIER_DIR")
		os.Exit(1)
	}
	if (*runs)*(*epochs) > 1 && strings.TrimSpace(*cvStateChainDir) == "" {
		fmt.Fprintln(os.Stderr, "multi-epoch benchmark requires --cv-state-chain-dir or RLADKR_STATE_CHAIN_DIR")
		os.Exit(1)
	}
	if *prepareOnly {
		cfg := core.NormalizeConfig(core.Config{
			SID:                         "rladkr-go-bench",
			Epoch:                       1,
			OldCommittee:                old,
			NewCommittee:                newC,
			FOld:                        oldFaults,
			FNew:                        newFaults,
			Kappa:                       effectiveKappa,
			AgreementTransport:          *transport,
			AgreementBindHost:           *bindHost,
			AgreementBasePort:           *basePort,
			WaitSPBCTimeout:             waitSPBCValue,
			RouteSendTimeout:            routeSendValue,
			APVSSFallbackProfile:        apvssFallbackProfileName,
			AllowExperimentalAPVSS:      *allowExperimentalAPVSS,
			APVSSBenchmarkFallbackCount: *apvssForcedFallbackCount,
			APVSSBenchmarkWaitAllACKs:   *apvssWaitAllACKs,
			AblationMode:                *ablationMode,
			CommMetrics:                 *commMetrics,
			StrictNetwork:               *strictNetwork,
			LocalNodeIDs:                localNodeIDs,
			CVPublicKeyDir:              *cvPublicKeyDir,
			CVLocalSecretDir:            *cvLocalSecretDir,
			CVLocalReceiverIDs:          localReceiverIDs,
		})
		if err := core.PrepareRuntime(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "PREPARE_RUNTIME_ERROR err=%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("PREPARE_RUNTIME_OK sid=%s epoch=%d n=%d\n", cfg.SID, cfg.Epoch, len(cfg.NewCommittee))
		return
	}

	successRuns := 0
	stats := make([]runStat, 0, *runs*(*epochs))
	attemptedEpochs := 0
	totalAttemptLatencyMs := 0.0

	for i := 0; i < *runs; i++ {
		if i > 0 {
			time.Sleep(2 * time.Second)
		}
		runSuccess := true
		for epoch := 1; epoch <= *epochs; epoch++ {
			globalEpoch := i*(*epochs) + epoch
			cfg := core.NormalizeConfig(core.Config{
				SID:                         "rladkr-go-bench",
				Epoch:                       globalEpoch,
				OldCommittee:                old,
				NewCommittee:                newC,
				FOld:                        oldFaults,
				FNew:                        newFaults,
				Kappa:                       effectiveKappa,
				AgreementTransport:          *transport,
				AgreementBindHost:           *bindHost,
				AgreementBasePort:           *basePort,
				WaitSPBCTimeout:             waitSPBCValue,
				RouteSendTimeout:            routeSendValue,
				APVSSFallbackProfile:        apvssFallbackProfileName,
				AllowExperimentalAPVSS:      *allowExperimentalAPVSS,
				APVSSBenchmarkFallbackCount: *apvssForcedFallbackCount,
				APVSSBenchmarkWaitAllACKs:   *apvssWaitAllACKs,
				AblationMode:                *ablationMode,
				CommMetrics:                 *commMetrics,
				StrictNetwork:               *strictNetwork,
				LocalNodeIDs:                localNodeIDs,
				CVPublicKeyDir:              *cvPublicKeyDir,
				CVLocalSecretDir:            *cvLocalSecretDir,
				CVLocalReceiverIDs:          localReceiverIDs,
			})
			if globalEpoch > 1 {
				previous, loadErr := core.LoadCVEpochState(
					*cvStateChainDir, cfg.SID, globalEpoch-1, localReceiverIDs[0],
				)
				if loadErr != nil {
					fmt.Fprintf(os.Stderr, "EPOCH_STATE_LOAD_ERROR run=%d epoch=%d err=%v\n", i+1, globalEpoch, loadErr)
					runSuccess = false
					break
				}
				cfg.PreviousEpochStateDigest = append([]byte(nil), previous.Digest...)
			}

			totalStart := time.Now()
			attemptedEpochs++
			ctx, cancel := context.WithTimeout(context.Background(), runTimeoutValue)
			setupMs := 0.0
			if *precomputeRuntime {
				setupStart := time.Now()
				preparedCfg, prepErr := core.PrepareConfigRuntime(cfg)
				setupMs = float64(time.Since(setupStart).Microseconds()) / 1000.0
				if prepErr != nil {
					totalAttemptLatencyMs += float64(time.Since(totalStart).Microseconds()) / 1000.0
					cancel()
					fmt.Fprintf(os.Stderr, "EPOCH_SETUP_ERROR run=%d epoch=%d err=%v\n", i+1, globalEpoch, prepErr)
					runSuccess = false
					break
				}
				cfg = preparedCfg
			}
			traceBenchMain(localNodeIDs, "before_runepoch", fmt.Sprintf("run=%d epoch=%d", i+1, globalEpoch))
			res, err := core.RunEpoch(ctx, cfg)
			totalAttemptLatencyMs += float64(time.Since(totalStart).Microseconds()) / 1000.0
			cancel()
			if err != nil {
				fmt.Fprintf(os.Stderr, "EPOCH_RUN_ERROR run=%d epoch=%d err=%v\n", i+1, globalEpoch, err)
				runSuccess = false
				break
			}
			traceBenchMain(localNodeIDs, "after_runepoch", fmt.Sprintf("run=%d epoch=%d completed=%d", i+1, epoch, len(res.PerNode)))
			completed := float64(len(res.PerNode))
			if completed == 0 {
				completed = float64(*n)
			}
			if int(completed) < requiredCompleted {
				fmt.Fprintf(
					os.Stderr,
					"EPOCH_RUN_INCOMPLETE run=%d epoch=%d completed=%d required=%d\n",
					i+1,
					globalEpoch,
					int(completed),
					requiredCompleted,
				)
				runSuccess = false
				break
			}
			epochLatencyMs := float64(time.Since(totalStart).Microseconds()) / 1000.0
			resultDigest, digestErr := arlResultDigest(cfg, res)
			if (*runs)*(*epochs) > 1 {
				state, stateErr := core.PersistCVEpochState(*cvStateChainDir, cfg, res)
				if stateErr != nil {
					fmt.Fprintf(os.Stderr, "EPOCH_STATE_PERSIST_ERROR run=%d epoch=%d err=%v\n", i+1, globalEpoch, stateErr)
					runSuccess = false
					break
				}
				resultDigest = hex.EncodeToString(state.Digest)
			}
			if digestErr != nil {
				fmt.Fprintf(os.Stderr, "EPOCH_RESULT_DIGEST_ERROR run=%d epoch=%d err=%v\n", i+1, globalEpoch, digestErr)
				runSuccess = false
				break
			}
			barrierCtx, barrierCancel := context.WithTimeout(context.Background(), runTimeoutValue)
			barrierErr := waitForBenchmarkEpoch(
				barrierCtx, epochBarrierDir, cfg.SID, i+1, globalEpoch,
				old, localNodeIDs, resultDigest,
			)
			barrierCancel()
			if barrierErr != nil {
				fmt.Fprintf(os.Stderr, "EPOCH_BARRIER_ERROR run=%d epoch=%d err=%v\n", i+1, globalEpoch, barrierErr)
				runSuccess = false
				break
			}
			stats = append(stats, runStat{
				latencyMs:                  epochLatencyMs,
				setupMs:                    setupMs + float64(res.SetupLatency.Microseconds())/1000.0,
				completedNodes:             completed,
				decidedSetMean:             float64(len(res.LockedSet)),
				aggRLOReadyMs:              float64(res.AggRLOReadyLatency.Microseconds()) / 1000.0,
				admitAggAttempts:           float64(res.AdmitAggAttempts),
				admitAggPasses:             float64(res.AdmitAggPasses),
				recoverAggSuccess:          boolToFloat(res.RecoverAggSuccess),
				disperseMs:                 float64(res.DisperseLatency.Microseconds()) / 1000.0,
				disperseLocalBuildMs:       float64(res.DisperseLocalBuildLatency.Microseconds()) / 1000.0,
				disperseBroadcastMs:        float64(res.DisperseBroadcastLatency.Microseconds()) / 1000.0,
				disperseReadWaitMs:         float64(res.DisperseReadWaitLatency.Microseconds()) / 1000.0,
				disperseTrustedReadyMs:     float64(res.DisperseTrustedReadyLatency.Microseconds()) / 1000.0,
				disperseAggregatePrewarmMs: float64(res.DisperseAggregatePrewarmLatency.Microseconds()) / 1000.0,
				lockAggMs:                  float64(res.LockAggLatency.Microseconds()) / 1000.0,
				lockAggReadyCandidatesMs:   float64(res.LockAggReadyCandidatesLatency.Microseconds()) / 1000.0,
				lockAggBuildAggregateMs:    float64(res.LockAggBuildAggregateLatency.Microseconds()) / 1000.0,
				lockAggARCSharePrepareMs:   float64(res.LockAggARCSharePrepareLatency.Microseconds()) / 1000.0,
				lockAggARCShareAttachMs:    float64(res.LockAggARCShareAttachLatency.Microseconds()) / 1000.0,
				lockAggCandidateCount:      float64(res.LockAggCandidateCount),
				lockAggARCShareSignedCnt:   float64(res.LockAggARCShareSignedCount),
				lockAggShareSignMs:         float64(res.LockAggShareSignLatency.Microseconds()) / 1000.0,
				lockAggCertRecoverMs:       float64(res.LockAggCertRecoverLatency.Microseconds()) / 1000.0,
				lockAggLocalAdmitMs:        float64(res.LockAggLocalAdmitLatency.Microseconds()) / 1000.0,
				mvbaOnlyMs:                 float64(res.MVBAOnlyLatency.Microseconds()) / 1000.0,
				mvbaPeerWaitMs:             float64(res.MVBAPeerWaitLatency.Microseconds()) / 1000.0,
				agreeAggMs:                 float64(res.AgreeAggLatency.Microseconds()) / 1000.0,
				recoverBarrierWaitMs:       float64(res.RecoverBarrierWaitLatency.Microseconds()) / 1000.0,
				recoverServiceGraceMs:      float64(res.RecoverServiceGraceLatency.Microseconds()) / 1000.0,
				recoverMs:                  float64(res.RecoverLatency.Microseconds()) / 1000.0,
				recoverOnlyMs:              float64(res.RecoverOnlyLatency.Microseconds()) / 1000.0,
				recoverVerifyMs:            float64(res.RecoverVerifyLatency.Microseconds()) / 1000.0,
				recoverCollectMs:           float64(res.RecoverCollectLatency.Microseconds()) / 1000.0,
				recoverVerifyOnlyMs:        float64(res.RecoverVerifyOnlyLatency.Microseconds()) / 1000.0,
				recoverMaterializeMs:       float64(res.RecoverMaterializeLatency.Microseconds()) / 1000.0,
				deriveMs:                   float64(res.DeriveLatency.Microseconds()) / 1000.0,
				phaseSentBytes:             phaseBytesFloat(res.PhaseSentBytes),
				phaseRecvBytes:             phaseBytesFloat(res.PhaseRecvBytes),
				totalSentBytes:             float64(res.TotalSentBytes),
				totalRecvBytes:             float64(res.TotalRecvBytes),
				consensusHash:              resultDigest,
				cvComponentCount:           float64(res.CVComponentCount),
				cvARCHolderCount:           float64(res.CVARCHolderCount),
				cvRecoveredShardCount:      float64(res.CVRecoveredShardCount),
				cvVerifiedReceiptCount:     float64(res.CVVerifiedReceiptCount),
				cvLeafBuildMs:              float64(res.CVLeafBuildLatency.Microseconds()) / 1000.0,
				cvComponentDisperseMs:      float64(res.CVComponentDisperseLatency.Microseconds()) / 1000.0,
				cvCommonCandidateMs:        float64(res.CVCommonCandidateLatency.Microseconds()) / 1000.0,
				cvAggregateDisperseMs:      float64(res.CVAggregateDisperseLatency.Microseconds()) / 1000.0,
				cvAggregateAgreementMs:     float64(res.CVAggregateAgreementLatency.Microseconds()) / 1000.0,
				cvAPVSSACKCount:            float64(res.CVAPVSSACKCount),
				cvAPVSSFallbackCount:       float64(res.CVAPVSSFallbackCount),
				cvAPVSSProofBytes:          float64(res.CVAPVSSProofBytes),
				cvAPVSSLeafWireBytes:       float64(res.CVAPVSSLeafWireBytes),
				cvAggregateGateWaitMs:      float64(res.CVAggregateGateWaitLatency.Microseconds()) / 1000.0,
				cvAggregateLeafLoadMs:      float64(res.CVAggregateLeafLoadLatency.Microseconds()) / 1000.0,
				cvAggregateBuildMs:         float64(res.CVAggregateBuildLatency.Microseconds()) / 1000.0,
				cvAggregateRSMs:            float64(res.CVAggregateRSLatency.Microseconds()) / 1000.0,
				cvAggregateHeaderTokenMs:   float64(res.CVAggregateHeaderTokenLatency.Microseconds()) / 1000.0,
				cvAggregateOfferSendMs:     float64(res.CVAggregateOfferSendLatency.Microseconds()) / 1000.0,
				cvAggregateARCWaitMs:       float64(res.CVAggregateARCWaitLatency.Microseconds()) / 1000.0,
				cvAggregateCertificateMs:   float64(res.CVAggregateCertificateLatency.Microseconds()) / 1000.0,
				cvRecoverShardMs:           float64(res.CVRecoverShardLatency.Microseconds()) / 1000.0,
				cvReceiptMs:                float64(res.CVReceiptLatency.Microseconds()) / 1000.0,
			})
			traceBenchMain(localNodeIDs, "after_append_stats", fmt.Sprintf("run=%d epoch=%d", i+1, globalEpoch))
		}
		if runSuccess {
			successRuns++
		}
	}

	caps := core.CurrentAPVSSCapabilities()
	line := formatBenchResult(benchResultInput{
		n:                        *n,
		fOld:                     oldFaults,
		fNew:                     newFaults,
		kappa:                    effectiveKappa,
		runs:                     *runs,
		timeoutMs:                runTimeoutValue.Milliseconds(),
		apvssProvider:            "cv-sapvss",
		apvssFallbackProfile:     apvssFallbackProfileName,
		apvssForcedFallbackCount: *apvssForcedFallbackCount,
		apvssWaitAllACKs:         *apvssWaitAllACKs,
		experimentalAPVSS:        *allowExperimentalAPVSS,
		apvssOutput:              string(caps.OutputKind),
		securityProfile:          caps.SecurityProfile,
		deriveMode:               "scalar",
		arcMode:                  "materialized",
		successRuns:              successRuns,
		attemptedEpochs:          attemptedEpochs,
		totalAttemptLatencyMs:    totalAttemptLatencyMs,
		localNodes:               append([]int(nil), localNodeIDs...),
		requiredCompleted:        requiredCompleted,
		ablationMode:             strings.ToLower(strings.TrimSpace(*ablationMode)),
		commMetrics:              *commMetrics,
		stats:                    stats,
	})
	traceBenchMain(localNodeIDs, "before_final_print", fmt.Sprintf("success_runs=%d stats=%d", successRuns, len(stats)))
	fmt.Println(line)
	fmt.Fprintln(os.Stderr, line)
	_ = os.Stdout.Sync()
	traceBenchMain(localNodeIDs, "after_final_print", fmt.Sprintf("success_runs=%d stats=%d", successRuns, len(stats)))
	if successRuns != *runs {
		os.Exit(1)
	}
}

func defaultBenchRunTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 10 * time.Minute
	case n >= 128:
		return 5 * time.Minute
	case n >= 96:
		return 3 * time.Minute
	case n >= 64:
		return 2 * time.Minute
	default:
		return 90 * time.Second
	}
}

func defaultBenchWaitSPBCTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 3 * time.Minute
	case n >= 127:
		return 60 * time.Second
	case n >= 96:
		return 35 * time.Second
	case n >= 64:
		return 20 * time.Second
	case n >= 32:
		return 6 * time.Second
	default:
		return 2 * time.Second
	}
}

func defaultBenchRouteSendTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 20 * time.Second
	case n >= 127:
		return 12 * time.Second
	case n >= 96:
		return 8 * time.Second
	case n >= 64:
		return 5 * time.Second
	case n >= 32:
		return 1500 * time.Millisecond
	default:
		return 500 * time.Millisecond
	}
}

func traceBenchMain(localNodeIDs []int, phase string, detail string) {
	if os.Getenv("RLADKR_BENCH_DEBUG_FINALIZE") == "" {
		return
	}
	nodeLabel := intsKey(localNodeIDs)
	fmt.Fprintf(os.Stderr, "BENCH_MAIN node=%s phase=%s detail=%s\n", nodeLabel, phase, detail)
}

func readLocalNodeIDsEnv(n int) []int {
	raw := strings.TrimSpace(os.Getenv("RLADKR_LOCAL_NODE_IDS"))
	if raw == "" {
		ids := make([]int, 0, n)
		for i := 0; i < n; i++ {
			ids = append(ids, i)
		}
		return ids
	}
	valid := make(map[int]struct{}, n)
	for i := 0; i < n; i++ {
		valid[i] = struct{}{}
	}
	ids := make([]int, 0, n)
	seen := make(map[int]struct{}, n)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		if _, ok := valid[id]; !ok {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	if len(ids) == 0 {
		for i := 0; i < n; i++ {
			ids = append(ids, i)
		}
	}
	return ids
}

func readLocalReceiverIDs(raw string, n int, localOld []int) []int {
	if strings.TrimSpace(raw) == "" && len(localOld) == 1 {
		return []int{n + localOld[0]}
	}
	allowed := make(map[int]struct{}, n)
	for i := 0; i < n; i++ {
		allowed[n+i] = struct{}{}
	}
	seen := make(map[int]struct{})
	var ids []int
	for _, part := range strings.Split(raw, ",") {
		id, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		if _, ok := allowed[id]; !ok {
			continue
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

func intsKey(v []int) string {
	if len(v) == 0 {
		return "[]"
	}
	parts := make([]string, 0, len(v))
	for _, id := range v {
		parts = append(parts, strconv.Itoa(id))
	}
	return strings.Join(parts, ",")
}

func requiredCompletedNodes(n int, f int, localNodeIDs []int) int {
	if len(localNodeIDs) > 0 {
		return len(localNodeIDs)
	}
	required := n - f
	if required <= 0 {
		required = 1
	}
	return required
}

func meanOf(stats []runStat, pick func(runStat) float64) float64 {
	if len(stats) == 0 {
		return 0
	}
	sum := 0.0
	for _, s := range stats {
		sum += pick(s)
	}
	return sum / float64(len(stats))
}

func quantileOf(stats []runStat, q float64, pick func(runStat) float64) float64 {
	if len(stats) == 0 {
		return 0
	}
	values := make([]float64, 0, len(stats))
	for _, s := range stats {
		values = append(values, pick(s))
	}
	sort.Float64s(values)
	if q <= 0 {
		return values[0]
	}
	if q >= 1 {
		return values[len(values)-1]
	}
	idx := int(q * float64(len(values)-1))
	return values[idx]
}

func sumOf(stats []runStat, pick func(runStat) float64) float64 {
	sum := 0.0
	for _, s := range stats {
		sum += pick(s)
	}
	return sum
}

func admitAggPassRatio(passes, attempts float64) float64 {
	if attempts <= 0 {
		return 0
	}
	return passes / attempts
}

func boolToFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

func formatBenchResult(in benchResultInput) string {
	arcMode := strings.ToLower(strings.TrimSpace(in.arcMode))
	if arcMode == "" || arcMode == "header-only" {
		arcMode = "header-only-recovery-obligation"
	}
	successRate := float64(in.successRuns) / float64(in.runs)
	meanLatency := meanOf(in.stats, func(s runStat) float64 { return s.latencyMs })
	meanAllLatency := meanLatency
	if in.attemptedEpochs > 0 {
		meanAllLatency = in.totalAttemptLatencyMs / float64(in.attemptedEpochs)
	}
	p50Latency := quantileOf(in.stats, 0.50, func(s runStat) float64 { return s.latencyMs })
	p95Latency := quantileOf(in.stats, 0.95, func(s runStat) float64 { return s.latencyMs })
	meanSetup := meanOf(in.stats, func(s runStat) float64 { return s.setupMs })
	meanRecoverBarrierWait := meanOf(in.stats, func(s runStat) float64 { return s.recoverBarrierWaitMs })
	meanRecoverServiceGrace := meanOf(in.stats, func(s runStat) float64 { return s.recoverServiceGraceMs })
	meanOnline := meanLatency - meanSetup - meanRecoverBarrierWait
	if meanOnline < 0 {
		meanOnline = 0
	}
	meanOnlinePhaseWall := meanOnline - meanRecoverServiceGrace
	if meanOnlinePhaseWall < 0 {
		meanOnlinePhaseWall = 0
	}
	meanOnlineActiveKnown := meanOf(in.stats, func(s runStat) float64 {
		active := 0.0
		active += s.disperseLocalBuildMs
		active += s.disperseBroadcastMs
		active += s.lockAggBuildAggregateMs
		active += s.lockAggARCSharePrepareMs
		active += s.lockAggARCShareAttachMs
		active += s.lockAggShareSignMs
		active += s.lockAggCertRecoverMs
		active += s.lockAggLocalAdmitMs
		mvbaActiveKnown := s.mvbaOnlyMs - s.mvbaPeerWaitMs
		if mvbaActiveKnown > 0 {
			active += mvbaActiveKnown
		}
		active += s.recoverVerifyOnlyMs
		active += s.recoverMaterializeMs
		active += s.deriveMs
		return active
	})
	meanCompleted := meanOf(in.stats, func(s runStat) float64 { return s.completedNodes })
	meanDecidedSet := meanOf(in.stats, func(s runStat) float64 { return s.decidedSetMean })
	meanAggRLOReady := meanOf(in.stats, func(s runStat) float64 { return s.aggRLOReadyMs })
	admitAttempts := sumOf(in.stats, func(s runStat) float64 { return s.admitAggAttempts })
	admitPasses := sumOf(in.stats, func(s runStat) float64 { return s.admitAggPasses })
	recoverSuccessRatio := meanOf(in.stats, func(s runStat) float64 { return s.recoverAggSuccess })
	meanSentBytes := meanOf(in.stats, func(s runStat) float64 { return s.totalSentBytes })
	meanRecvBytes := meanOf(in.stats, func(s runStat) float64 { return s.totalRecvBytes })
	hashSummary := summarizeConsensusHash(in.stats)

	line := fmt.Sprintf(
		"E2E_BENCH_RESULT protocol=ARLADKR-GO mode=strict agreement_path=single-mvba arc_mode=%s start_phase=protocol_start end_phase=local_decide apvss_provider=%s apvss_fallback_profile=%s apvss_forced_fallback_count=%d apvss_wait_all_acks=%t experimental_apvss=%t apvss_output=%s security_profile=%s derive_mode=%s n=%d f_old=%d f_new=%d kappa=%d runs=%d timeout_ms=%d ablation_mode=%s comm_metrics=%t success_runs=%d success_rate=%.4f mean_latency_ms=%.2f mean_all_latency_ms=%.2f mean_setup_ms=%.2f mean_recover_barrier_wait_ms=%.2f mean_recover_service_grace_ms=%.2f mean_online_protocol_ms=%.2f mean_online_phase_wall_ms=%.2f mean_online_active_known_ms=%.2f p50_latency_ms=%.2f p95_latency_ms=%.2f mean_completed_nodes=%.2f mean_decided_set=%.2f mean_aggrlo_ready_ms=%.2f mean_header_obligation_ready_ms=%.2f admitagg_pass_ratio=%.4f recoveragg_success_ratio=%.4f disperse_ms=%.0f disperse_local_build_ms=%.0f disperse_broadcast_ms=%.0f disperse_read_wait_ms=%.0f disperse_trusted_ready_ms=%.0f disperse_aggregate_prewarm_ms=%.0f lockagg_ms=%.0f lockagg_ready_candidates_ms=%.0f lockagg_build_aggregate_ms=%.0f lockagg_arcshare_prepare_ms=%.0f lockagg_arcshare_attach_ms=%.0f lockagg_candidate_count=%.0f lockagg_arcshare_signed_count=%.0f lockagg_share_sign_ms=%.0f lockagg_cert_recover_ms=%.0f lockagg_local_admit_ms=%.0f mvba_only_ms=%.0f mvba_peer_wait_ms=%.0f mvba_active_known_ms=%.0f agreeagg_ms=%.0f recover_ms=%.0f recover_only_ms=%.0f recover_verify_ms=%.0f recover_collect_ms=%.0f recover_verify_only_ms=%.0f recover_materialize_ms=%.0f derive_ms=%.0f mean_total_sent_bytes=%.0f mean_total_recv_bytes=%.0f mean_agree_sent_bytes=%.0f mean_agree_recv_bytes=%.0f mean_recover_sent_bytes=%.0f mean_recover_recv_bytes=%.0f mean_recover_response_sent_bytes=%.0f mean_recover_response_recv_bytes=%.0f mean_derive_sent_bytes=%.0f mean_derive_recv_bytes=%.0f mean_agclock_prebroadcast_sent_bytes=%.0f mean_agclock_prebroadcast_recv_bytes=%.0f mean_arc_header_prebroadcast_sent_bytes=%.0f mean_arc_header_prebroadcast_recv_bytes=%.0f local_node_count=%d required_completed_nodes=%d consensus_hash=%s",
		arcMode,
		in.apvssProvider,
		in.apvssFallbackProfile,
		in.apvssForcedFallbackCount,
		in.apvssWaitAllACKs,
		in.experimentalAPVSS,
		in.apvssOutput,
		in.securityProfile,
		in.deriveMode,
		in.n,
		in.fOld,
		in.fNew,
		in.kappa,
		in.runs,
		in.timeoutMs,
		in.ablationMode,
		in.commMetrics,
		in.successRuns,
		successRate,
		meanLatency,
		meanAllLatency,
		meanSetup,
		meanRecoverBarrierWait,
		meanRecoverServiceGrace,
		meanOnline,
		meanOnlinePhaseWall,
		meanOnlineActiveKnown,
		p50Latency,
		p95Latency,
		meanCompleted,
		meanDecidedSet,
		meanAggRLOReady,
		meanAggRLOReady,
		admitAggPassRatio(admitPasses, admitAttempts),
		recoverSuccessRatio,
		meanOf(in.stats, func(s runStat) float64 { return s.disperseMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.disperseLocalBuildMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.disperseBroadcastMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.disperseReadWaitMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.disperseTrustedReadyMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.disperseAggregatePrewarmMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggReadyCandidatesMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggBuildAggregateMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggARCSharePrepareMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggARCShareAttachMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggCandidateCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggARCShareSignedCnt }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggShareSignMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggCertRecoverMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggLocalAdmitMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.mvbaOnlyMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.mvbaPeerWaitMs }),
		meanOf(in.stats, func(s runStat) float64 {
			v := s.mvbaOnlyMs - s.mvbaPeerWaitMs
			if v < 0 {
				return 0
			}
			return v
		}),
		meanOf(in.stats, func(s runStat) float64 { return s.agreeAggMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.recoverMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.recoverOnlyMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.recoverVerifyMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.recoverCollectMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.recoverVerifyOnlyMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.recoverMaterializeMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.deriveMs }),
		meanSentBytes,
		meanRecvBytes,
		meanPhaseBytes(in.stats, "agree", true),
		meanPhaseBytes(in.stats, "agree", false),
		meanPhaseBytes(in.stats, "recover", true),
		meanPhaseBytes(in.stats, "recover", false),
		meanPhaseBytes(in.stats, "recover_response", true),
		meanPhaseBytes(in.stats, "recover_response", false),
		meanPhaseBytes(in.stats, "derive", true),
		meanPhaseBytes(in.stats, "derive", false),
		meanPhaseBytes(in.stats, "agclock_prebroadcast", true),
		meanPhaseBytes(in.stats, "agclock_prebroadcast", false),
		meanPhaseBytes(in.stats, "arc_header_prebroadcast", true),
		meanPhaseBytes(in.stats, "arc_header_prebroadcast", false),
		len(in.localNodes),
		in.requiredCompleted,
		hashSummary,
	)
	return line + fmt.Sprintf(
		" mean_cv_component_count=%.0f mean_cv_arc_holder_count=%.0f mean_cv_recovered_shard_count=%.0f mean_cv_verified_receipt_count=%.0f leaf_build_ms=%.0f component_disperse_ms=%.0f common_candidate_ms=%.0f aggregate_disperse_ms=%.0f aggregate_agreement_ms=%.0f mean_apvss_ack_count=%.2f mean_apvss_fallback_count=%.2f mean_apvss_proof_bytes=%.0f mean_apvss_leaf_wire_bytes=%.0f aggregate_gate_wait_ms=%.2f aggregate_leaf_load_ms=%.2f aggregate_build_ms=%.2f aggregate_rs_ms=%.2f aggregate_header_token_ms=%.2f aggregate_offer_send_ms=%.2f aggregate_arc_wait_ms=%.2f aggregate_certificate_ms=%.2f recover_shard_ms=%.0f receipt_ms=%.0f mean_component_disperse_sent_bytes=%.0f mean_component_disperse_recv_bytes=%.0f mean_common_candidate_sent_bytes=%.0f mean_common_candidate_recv_bytes=%.0f mean_aggregate_disperse_sent_bytes=%.0f mean_aggregate_disperse_recv_bytes=%.0f mean_arc_share_sent_bytes=%.0f mean_arc_share_recv_bytes=%.0f mean_recover_shard_sent_bytes=%.0f mean_recover_shard_recv_bytes=%.0f mean_receipt_sent_bytes=%.0f mean_receipt_recv_bytes=%.0f",
		meanOf(in.stats, func(s runStat) float64 { return s.cvComponentCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvARCHolderCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvRecoveredShardCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvVerifiedReceiptCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvLeafBuildMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvComponentDisperseMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvCommonCandidateMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateDisperseMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateAgreementMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAPVSSACKCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAPVSSFallbackCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAPVSSProofBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAPVSSLeafWireBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateGateWaitMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateLeafLoadMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateBuildMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateRSMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateHeaderTokenMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateOfferSendMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateARCWaitMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateCertificateMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvRecoverShardMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvReceiptMs }),
		meanPhaseBytes(in.stats, "component_disperse", true), meanPhaseBytes(in.stats, "component_disperse", false),
		meanPhaseBytes(in.stats, "common_candidate", true), meanPhaseBytes(in.stats, "common_candidate", false),
		meanPhaseBytes(in.stats, "aggregate_disperse", true), meanPhaseBytes(in.stats, "aggregate_disperse", false),
		meanPhaseBytes(in.stats, "arc_share", true), meanPhaseBytes(in.stats, "arc_share", false),
		meanPhaseBytes(in.stats, "recover_shard", true), meanPhaseBytes(in.stats, "recover_shard", false),
		meanPhaseBytes(in.stats, "receipt", true), meanPhaseBytes(in.stats, "receipt", false),
	)
}

func consensusHash(pk []byte) string {
	if len(pk) == 0 {
		return "none"
	}
	sum := sha256.Sum256(pk)
	return hex.EncodeToString(sum[:8])
}

func summarizeConsensusHash(stats []runStat) string {
	if len(stats) == 0 {
		return "none"
	}
	h := sha256.New()
	_, _ = h.Write([]byte("ARL_ADKR_BENCH_RESULT_SEQUENCE_V1"))
	for _, s := range stats {
		if s.consensusHash == "" || s.consensusHash == "none" {
			return "none"
		}
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(s.consensusHash))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func phaseBytesFloat(src map[string]uint64) map[string]float64 {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]float64, len(src))
	for k, v := range src {
		out[k] = float64(v)
	}
	return out
}

func meanPhaseBytes(stats []runStat, name string, sent bool) float64 {
	if len(stats) == 0 {
		return 0
	}
	sum := 0.0
	count := 0
	for _, s := range stats {
		var phaseMap map[string]float64
		if sent {
			phaseMap = s.phaseSentBytes
		} else {
			phaseMap = s.phaseRecvBytes
		}
		if phaseMap == nil {
			continue
		}
		sum += phaseMap[name]
		count++
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

func envBoolDefault(name string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}
