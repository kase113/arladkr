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
	// PreviousEpochStateDigest hash-links this epoch to the verified public
	// output state of the preceding epoch. Empty denotes the genesis state.
	PreviousEpochStateDigest []byte

	OldCommittee []int
	NewCommittee []int
	// FOld controls old-committee agreement, certificates, dealer selection,
	// and aggregate dispersal/recovery thresholds.
	FOld int
	// FNew controls the new-committee APVSS sharing degree, receiver validity,
	// and scalar-share reconstruction threshold.
	FNew int

	Kappa int

	WaitSPBCTimeout  time.Duration
	RouteSendTimeout time.Duration
	SendRetryMax     int
	SendRetryBackoff time.Duration

	// AgreementTransport selects the TCP deployment mode. Both loopback and
	// distributed modes use the same predicate-capable MVBA implementation.
	AgreementTransport string
	// AgreementBindHost controls TCP listener host for agreement transport.
	AgreementBindHost string
	// AgreementBasePort enables deterministic TCP port assignment when >0.
	AgreementBasePort int
	// LocalNodeIDs identifies which committee nodes are hosted by this process.
	// Empty means all old-committee nodes are local.
	LocalNodeIDs []int

	// APVSSFallbackProfile selects the proof carried for receivers outside the
	// ACK set. compact-batch additionally requires AllowExperimentalAPVSS.
	APVSSFallbackProfile string
	// AllowExperimentalAPVSS is an explicit benchmark-only admission switch for
	// proof profiles that have not passed the production cryptographic gate.
	AllowExperimentalAPVSS bool
	// APVSSBenchmarkFallbackCount forces an exact |I| in benchmark ACK
	// collection when positive. Zero preserves natural message scheduling.
	APVSSBenchmarkFallbackCount int
	// APVSSBenchmarkWaitAllACKs waits for every receiver to ACK, producing
	// |I|=0 on a healthy benchmark network. It is not an asynchronous protocol path.
	APVSSBenchmarkWaitAllACKs bool
	// ArtifactCacheDir enables local multiprocess benchmarks to share
	// deterministic dealer artifacts instead of rebuilding all dealers in
	// every process.
	ArtifactCacheDir string
	// AblationMode injects protocol-level security ablations for experiments.
	// Supported: "none", "no-agclock".
	AblationMode string
	// CommMetrics enables protocol-layer communication byte counters.
	CommMetrics bool
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
	if len(c.PreviousEpochStateDigest) != 0 && len(c.PreviousEpochStateDigest) != 32 {
		return errors.New("CV epoch previous-state digest must be empty or 32 bytes")
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
	if err := cvRequireSeparateKeyDirs(c.CVPublicKeyDir, c.CVLocalSecretDir); err != nil {
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
	if c.APVSSFallbackProfile == apvssFallbackCompactBatchProfile && !c.AllowExperimentalAPVSS {
		return apvssRequireProductionFallbackBackend(c.APVSSFallbackProfile)
	}
	if c.APVSSBenchmarkFallbackCount > 0 && !c.AllowExperimentalAPVSS {
		return errors.New("forced APVSS fallback count requires explicit experimental admission")
	}
	if c.APVSSBenchmarkWaitAllACKs && !c.AllowExperimentalAPVSS {
		return errors.New("waiting for all APVSS ACKs requires explicit experimental admission")
	}
	if c.APVSSBenchmarkWaitAllACKs && c.APVSSBenchmarkFallbackCount > 0 {
		return errors.New("APVSS wait-all and forced fallback modes are mutually exclusive")
	}
	return nil
}

func NormalizeConfig(cfg Config) Config {
	out := cfg
	if out.Epoch <= 0 {
		out.Epoch = 1
	}
	if out.Kappa == 0 {
		out.Kappa = out.FOld + 1
	}
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
	if out.AgreementTransport == "" {
		out.AgreementTransport = "tcp-distributed"
	}
	out.AgreementTransport = strings.ToLower(strings.TrimSpace(out.AgreementTransport))
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
	if out.APVSSFallbackProfile == "" {
		out.APVSSFallbackProfile = apvssFallbackExactLaneProfile
	}
	out.APVSSFallbackProfile = strings.ToLower(strings.TrimSpace(out.APVSSFallbackProfile))
	if out.ArtifactCacheDir == "" {
		out.ArtifactCacheDir = os.Getenv("RLADKR_ARTIFACT_CACHE_DIR")
	}
	if out.AblationMode == "" {
		out.AblationMode = "none"
	}
	out.AblationMode = strings.ToLower(strings.TrimSpace(out.AblationMode))
	return out
}

func ValidateConfig(cfg Config) error {
	cfg = NormalizeConfig(cfg)
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
	if cfg.FOld < 0 {
		return errors.New("invalid old-committee fault threshold")
	}
	if cfg.FNew < 0 {
		return errors.New("invalid new-committee fault threshold")
	}
	if len(oldCommittee) < 3*cfg.FOld+1 {
		return errors.New("old committee does not satisfy n_o >= 3f_o+1")
	}
	if len(newCommittee) < 3*cfg.FNew+1 {
		return errors.New("new committee does not satisfy n_n >= 3f_n+1")
	}
	if cfg.Kappa != cfg.FOld+1 {
		return errors.New("aggregate dealer count must equal f_o+1")
	}
	if cfg.SendRetryMax <= 0 {
		return errors.New("invalid send retry max")
	}
	if err := apvssRequireFallbackBackend(cfg.APVSSFallbackProfile); err != nil {
		return err
	}
	if cfg.APVSSBenchmarkFallbackCount < 0 || cfg.APVSSBenchmarkFallbackCount > cfg.FNew {
		return errors.New("APVSS benchmark fallback count must be in [0,f_n]")
	}
	switch cfg.AblationMode {
	case "", "none", "no-agclock":
	default:
		return errors.New("invalid ablation mode")
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
	disperseMode := strings.ToLower(strings.TrimSpace(os.Getenv("RLADKR_DISPERSE_MODE")))
	switch disperseMode {
	case "local", "cache", "file-cache", "off":
		return errors.New("strict-network rejects local/cache/off disperse mode")
	}
	if strings.TrimSpace(os.Getenv("RLADKR_NODE_ADDRS")) == "" {
		return errors.New("strict-network requires RLADKR_NODE_ADDRS")
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
