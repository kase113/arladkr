package core

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	SID   string
	Epoch int

	OldCommittee []int
	NewCommittee []int
	F            int

	Kappa       int
	FastlaneMin int

	MVBARounds       int
	FastlaneViews    int
	WaitSPBCTimeout  time.Duration
	RouteSendTimeout time.Duration
	SendRetryMax     int
	SendRetryBackoff time.Duration

	// EnableFastlane is a legacy compatibility field. The active ARLADKR
	// protocol path ignores it and always runs LockAgg -> Dumbomvba/MVBA.
	EnableFastlane bool

	// ForceFallback is a legacy compatibility flag. The active path is always
	// Dumbomvba/MVBA, so this flag no longer changes agreement selection.
	ForceFallback bool
	// DisableFallback is retained for CLI/test compatibility only. It no
	// longer disables MVBA because fastlane has been removed from the active path.
	DisableFallback bool
	// DisableABAFallbackEstimate disables fallback ABA local tie-break estimate
	// when EST quorum evidence is incomplete.
	DisableABAFallbackEstimate bool
	// DisableCoinBitFallback disables filling missing per-node coin bits by
	// fallback bit in fallback ABA.
	DisableCoinBitFallback bool
	// AgreementKernel selects agreement runner implementation.
	// Supported: "distributed-actor", "legacy-sim", "dumbomvba-direct", "commonsubset-tcp".
	AgreementKernel string
	// AgreementTransport selects message transport for agreement kernel.
	// Supported: "tcp-loopback", "tcp-distributed".
	AgreementTransport string
	// AgreementBindHost controls TCP listener host for agreement transport.
	AgreementBindHost string
	// AgreementBasePort enables deterministic TCP port assignment when >0.
	AgreementBasePort int
	// LocalNodeIDs identifies which committee nodes are hosted by this process.
	// Empty means all old-committee nodes are local.
	LocalNodeIDs []int

	// StateStoreDir enables cross-process persisted receiver-state load/save.
	// If set, epoch>1 can load st_{u,e} from disk when InputReceiverStates is empty.
	StateStoreDir string
	// InputReceiverStates carries st_{u,e} for the current epoch.
	// It is optional for epoch 1 and required for epoch > 1.
	InputReceiverStates map[int]ReceiverState

	// APVSSProvider is fixed to the materialized CV-sAPVSS experiment path.
	APVSSProvider string
	// DeriveMode selects how post-RecoverAgg key material is derived.
	// "per-dealer" keeps the legacy compatibility path that re-processes every
	// selected dealer. "aggregate" derives directly from the single recovered
	// aggregate object, matching the ARL-ADKR experiment path. "scalar" requires
	// a provider that returns verifiable scalar threshold-key output.
	DeriveMode string
	// ArtifactCacheDir enables local multiprocess benchmarks to share
	// deterministic dealer artifacts instead of rebuilding all dealers in
	// every process.
	ArtifactCacheDir string
	// AblationMode injects protocol-level security ablations for experiments.
	// Supported: "none", "no-agclock", "leader-select".
	AblationMode string
	// AdversaryMode enables bench-only malicious proposal injection.
	// Supported: "none", "malicious-proposer-bad-agclock",
	// "malicious-proposer-leader-select-bias".
	AdversaryMode string
	// CommMetrics enables protocol-layer communication byte counters.
	CommMetrics bool
	// ARCMode selects aggregate recovery certificate semantics.
	// "header-only" keeps LockAgg lightweight. "materialized" is the Phase-1
	// CV-sAPVSS path: sign only after validating fresh aggregate shards.
	ARCMode string
	// RecoverResponseMode selects how Recover obtains aggregate fragment
	// responses after agreeing on a header-only AggRLO.
	// "network" broadcasts explicit signer/dealer responses over the
	// agreement transport; "local" keeps the process-local shortcut.
	RecoverResponseMode string
	// MaxARCCandidatesPerEpoch bounds how many LockAgg ready candidates are
	// allowed to proceed into aggregate-header preparation in one epoch.
	// This keeps ARC share fan-out near the intended constant-candidate path.
	// Default: FastlaneMin, so generic protocol/test paths remain valid.
	// Bench code can pin it lower explicitly when evaluating the 0629 variant.
	MaxARCCandidatesPerEpoch int
	// StrictNetwork makes benchmark runs fail fast if a local/cache shortcut is
	// selected for phases that should use the simulated network.
	StrictNetwork bool
	// CVPublicKeyDir contains the public receiver registry shared by all nodes.
	CVPublicKeyDir string
	// CVLocalSecretDir contains only this process's receiver secret material.
	CVLocalSecretDir string
	// CVLocalReceiverIDs identifies the new-committee receiver hosted here.
	CVLocalReceiverIDs []int

	runtime           *runtimeCrypto
	protocolTransport agreementTransport
}

func validateCVEpochConfig(cfg Config) error {
	c := NormalizeConfig(cfg)
	if c.APVSSProvider != "cv-sapvss" || c.ARCMode != "materialized" || c.DeriveMode != "scalar" {
		return errors.New("CV epoch requires cv-sapvss/materialized/scalar")
	}
	if strings.EqualFold(strings.TrimSpace(c.AgreementKernel), "dumbomvba-direct") {
		return errors.New("CV epoch requires the predicate-capable common-subset agreement kernel")
	}
	if len(sortedUnique(c.LocalNodeIDs)) != 1 {
		return errors.New("CV epoch requires exactly one local old node")
	}
	if strings.TrimSpace(c.CVPublicKeyDir) == "" {
		return errors.New("CV epoch requires a public key directory")
	}
	if strings.TrimSpace(c.CVLocalSecretDir) == "" {
		return errors.New("CV epoch requires a local secret key directory")
	}
	if err := cvRequireSeparateKeyDirsV1(c.CVPublicKeyDir, c.CVLocalSecretDir); err != nil {
		return fmt.Errorf("CV epoch requires separate key directories: %w", err)
	}
	if len(c.CVLocalReceiverIDs) != 1 {
		return errors.New("CV epoch requires exactly one local receiver")
	}
	if len(filterNodeIDs(c.CVLocalReceiverIDs, c.NewCommittee)) != 1 {
		return errors.New("CV local receiver is outside the new committee")
	}
	if strings.TrimSpace(c.ArtifactCacheDir) == "" {
		return errors.New("CV epoch requires a local artifact store")
	}
	return nil
}

func NormalizeConfig(cfg Config) Config {
	out := cfg
	if out.Epoch <= 0 {
		out.Epoch = 1
	}
	if out.Kappa == 0 {
		out.Kappa = out.F + 1
	}
	if out.Kappa == 0 {
		out.Kappa = 1
	}
	n := len(out.OldCommittee)
	if out.FastlaneMin <= 0 {
		out.FastlaneMin = n - out.F
	}
	if out.FastlaneMin <= 0 {
		out.FastlaneMin = 1
	}
	if out.MVBARounds <= 0 {
		out.MVBARounds = 3
	}
	if out.FastlaneViews <= 0 {
		out.FastlaneViews = 1
	}
	out.EnableFastlane = false
	out.ForceFallback = true
	out.DisableFallback = false
	if out.WaitSPBCTimeout <= 0 {
		out.WaitSPBCTimeout = 2 * time.Second
	}
	if out.RouteSendTimeout <= 0 {
		out.RouteSendTimeout = 300 * time.Millisecond
	}
	if out.SendRetryMax <= 0 {
		out.SendRetryMax = 10
	}
	if out.SendRetryBackoff <= 0 {
		out.SendRetryBackoff = 100 * time.Millisecond
	}
	if out.AgreementKernel == "" {
		out.AgreementKernel = "distributed-actor"
	}
	if out.AgreementTransport == "" {
		out.AgreementTransport = "tcp-distributed"
	}
	if out.AgreementBindHost == "" {
		out.AgreementBindHost = "0.0.0.0"
	}
	if len(out.LocalNodeIDs) == 0 {
		out.LocalNodeIDs = parseLocalNodeIDsEnv(out.OldCommittee)
	}
	out.LocalNodeIDs = filterNodeIDs(out.LocalNodeIDs, out.OldCommittee)
	if len(out.LocalNodeIDs) == 0 {
		out.LocalNodeIDs = sortedUnique(out.OldCommittee)
	}
	if out.APVSSProvider == "" {
		out.APVSSProvider = "cv-sapvss"
	}
	out.APVSSProvider = strings.ToLower(strings.TrimSpace(out.APVSSProvider))
	if out.DeriveMode == "" {
		out.DeriveMode = "scalar"
	}
	out.DeriveMode = strings.ToLower(strings.TrimSpace(out.DeriveMode))
	if out.ArtifactCacheDir == "" {
		out.ArtifactCacheDir = os.Getenv("RLADKR_ARTIFACT_CACHE_DIR")
	}
	if out.AblationMode == "" {
		out.AblationMode = "none"
	}
	out.AblationMode = strings.ToLower(strings.TrimSpace(out.AblationMode))
	if out.AdversaryMode == "" {
		out.AdversaryMode = "none"
	}
	out.AdversaryMode = strings.ToLower(strings.TrimSpace(out.AdversaryMode))
	if out.ARCMode == "" {
		out.ARCMode = "materialized"
	}
	out.ARCMode = strings.ToLower(strings.TrimSpace(out.ARCMode))
	if out.RecoverResponseMode == "" {
		out.RecoverResponseMode = "network"
	}
	out.RecoverResponseMode = strings.ToLower(strings.TrimSpace(out.RecoverResponseMode))
	if out.MaxARCCandidatesPerEpoch <= 0 {
		out.MaxARCCandidatesPerEpoch = out.FastlaneMin
	}
	if out.MaxARCCandidatesPerEpoch <= 0 {
		out.MaxARCCandidatesPerEpoch = 1
	}
	return out
}

func ValidateConfig(cfg Config) error {
	if cfg.SID == "" {
		return errors.New("empty SID")
	}
	oldCommittee := sortedUnique(cfg.OldCommittee)
	newCommittee := sortedUnique(cfg.NewCommittee)
	if len(oldCommittee) == 0 {
		return errors.New("empty old committee")
	}
	if len(newCommittee) == 0 {
		return errors.New("empty new committee")
	}
	if len(oldCommittee) != len(cfg.OldCommittee) {
		return errors.New("duplicate old committee member")
	}
	if len(newCommittee) != len(cfg.NewCommittee) {
		return errors.New("duplicate new committee member")
	}
	if cfg.F < 0 {
		return errors.New("invalid F")
	}
	if len(oldCommittee) < 3*cfg.F+1 {
		return errors.New("old committee does not satisfy n >= 3f+1")
	}
	if cfg.Kappa != cfg.F+1 {
		return errors.New("aggregate dealer count must equal f+1")
	}
	if cfg.FastlaneMin < cfg.F+1 {
		return errors.New("fastlane minimum below f+1")
	}
	if cfg.FastlaneMin > len(oldCommittee) {
		return errors.New("fastlane minimum exceeds old committee size")
	}
	if cfg.FastlaneViews <= 0 {
		return errors.New("invalid legacy fastlane views")
	}
	if cfg.SendRetryMax <= 0 {
		return errors.New("invalid send retry max")
	}
	if cfg.APVSSProvider != "cv-sapvss" && cfg.Epoch > 1 && len(cfg.InputReceiverStates) == 0 && cfg.StateStoreDir == "" {
		return errors.New("missing input receiver states for epoch > 1")
	}
	switch cfg.AblationMode {
	case "", "none", "no-agclock", "leader-select":
	default:
		return errors.New("invalid ablation mode")
	}
	switch cfg.AdversaryMode {
	case "", "none", "malicious-proposer-bad-agclock", "malicious-proposer-leader-select-bias":
	default:
		return errors.New("invalid adversary mode")
	}
	switch cfg.ARCMode {
	case "", "header-only", "materialized":
	default:
		return errors.New("invalid arc mode")
	}
	switch cfg.RecoverResponseMode {
	case "", "network", "local":
	default:
		return errors.New("invalid recover response mode")
	}
	switch cfg.APVSSProvider {
	case "cv-sapvss":
	default:
		return errors.New("invalid APVSS provider")
	}
	if len(newCommittee) < cfg.F+1 {
		return errors.New("CV-sAPVSS receiver count below f+1")
	}
	switch cfg.DeriveMode {
	case "per-dealer", "aggregate", "scalar":
	default:
		return errors.New("invalid derive mode")
	}
	if cfg.MaxARCCandidatesPerEpoch <= 0 {
		return errors.New("invalid max ARC candidates per epoch")
	}
	if cfg.MaxARCCandidatesPerEpoch < cfg.Kappa {
		return errors.New("max ARC candidates per epoch below kappa")
	}
	if cfg.StrictNetwork {
		if err := validateStrictNetworkConfig(cfg); err != nil {
			return err
		}
	}
	return nil
}

func validateStrictNetworkConfig(cfg Config) error {
	transport := strings.ToLower(strings.TrimSpace(cfg.AgreementTransport))
	if transport != "tcp-distributed" && transport != "tcp" {
		return errors.New("strict-network requires tcp-distributed agreement transport")
	}
	kernel := strings.ToLower(strings.TrimSpace(cfg.AgreementKernel))
	if kernel == "legacy-sim" {
		return errors.New("strict-network rejects legacy-sim agreement kernel")
	}
	recoverMode := strings.ToLower(strings.TrimSpace(cfg.RecoverResponseMode))
	if recoverMode != "" && recoverMode != "network" {
		return errors.New("strict-network requires network recover response mode")
	}
	disperseMode := strings.ToLower(strings.TrimSpace(os.Getenv("RLADKR_DISPERSE_MODE")))
	switch disperseMode {
	case "local", "cache", "file-cache", "off":
		return errors.New("strict-network rejects local/cache/off disperse mode")
	}
	if strings.TrimSpace(os.Getenv("RLADKR_NODE_ADDRS")) == "" {
		return errors.New("strict-network requires RLADKR_NODE_ADDRS")
	}
	if recoverLocalFastPathEnabled() {
		return errors.New("strict-network rejects RLADKR_RECOVER_LOCAL_FASTPATH")
	}
	if len(sortedUnique(cfg.LocalNodeIDs)) >= len(sortedUnique(cfg.OldCommittee)) {
		return errors.New("strict-network requires a proper local old-committee subset")
	}
	return nil
}

func parseLocalNodeIDsEnv(universe []int) []int {
	raw := strings.TrimSpace(os.Getenv("RLADKR_LOCAL_NODE_IDS"))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	ids := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	return filterNodeIDs(ids, universe)
}

func filterNodeIDs(ids []int, universe []int) []int {
	if len(ids) == 0 || len(universe) == 0 {
		return nil
	}
	allowed := make(map[int]struct{}, len(universe))
	for _, id := range universe {
		allowed[id] = struct{}{}
	}
	out := make([]int, 0, len(ids))
	seen := make(map[int]struct{}, len(ids))
	for _, id := range sortedUnique(ids) {
		if _, ok := allowed[id]; !ok {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}
