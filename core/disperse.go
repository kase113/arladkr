package core

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type dealerArtifactWire struct {
	Dealer   int    `json:"dealer"`
	Artifact []byte `json:"artifact"`
}

type dealerDescriptorWire struct {
	Dealer             int        `json:"dealer"`
	Descriptor         Descriptor `json:"descriptor"`
	ContributionDigest []byte     `json:"contribution_digest"`
}

func BuildDealerArtifacts(cfg Config) (map[int]*DealerArtifact, error) {
	artifacts, _, err := BuildDealerArtifactsDetailed(cfg)
	return artifacts, err
}

type DealerArtifactsBreakdown struct {
	LocalBuildLatency       time.Duration
	BroadcastLatency        time.Duration
	ReadWaitLatency         time.Duration
	TrustedReadyLatency     time.Duration
	AggregatePrewarmLatency time.Duration
	BuiltLocal              int
	ReusedLocal             int
	ArtifactCount           int
	CacheUsed               bool
}

func BuildDealerArtifactsDetailed(cfg Config) (map[int]*DealerArtifact, DealerArtifactsBreakdown, error) {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, DealerArtifactsBreakdown{}, err
	}
	if c.runtime == nil {
		return nil, DealerArtifactsBreakdown{}, fmt.Errorf("runtime not initialized")
	}
	if shouldUseNetworkDisperse(c) {
		return buildDealerArtifactsOverNetwork(c)
	}
	if strings.TrimSpace(c.ArtifactCacheDir) != "" {
		return buildDealerArtifactsWithCache(c)
	}
	if strings.EqualFold(c.APVSSProvider, "bls-pvss") {
		buildStart := time.Now()
		artifacts, err := buildDealerArtifactsBlsPWSS(c)
		if err != nil {
			return nil, DealerArtifactsBreakdown{}, err
		}
		readyStart := time.Now()
		populateTrustedReadyCandidates(&c, artifacts)
		return artifacts, DealerArtifactsBreakdown{
			LocalBuildLatency:   time.Since(buildStart),
			TrustedReadyLatency: time.Since(readyStart),
			ArtifactCount:       len(artifacts),
		}, nil
	}
	buildStart := time.Now()
	artifacts, err := buildDealerArtifactsOptrand(c)
	if err != nil {
		return nil, DealerArtifactsBreakdown{}, err
	}
	readyStart := time.Now()
	populateTrustedReadyCandidates(&c, artifacts)
	return artifacts, DealerArtifactsBreakdown{
		LocalBuildLatency:   time.Since(buildStart),
		TrustedReadyLatency: time.Since(readyStart),
		ArtifactCount:       len(artifacts),
	}, nil
}

func buildDealerArtifactsWithCache(cfg Config) (map[int]*DealerArtifact, DealerArtifactsBreakdown, error) {
	var breakdown DealerArtifactsBreakdown
	breakdown.CacheUsed = true
	start := time.Now()
	dir := filepath.Join(
		cfg.ArtifactCacheDir,
		safeCacheComponent(cfg.SID),
		fmt.Sprintf("epoch-%d-n-%d-f-%d-provider-%s", cfg.Epoch, len(cfg.runtime.oldOrder), cfg.F, safeCacheComponent(cfg.APVSSProvider)),
	)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, breakdown, err
	}
	local := sortedUnique(cfg.LocalNodeIDs)
	if len(local) == 0 {
		local = sortedUnique(cfg.runtime.oldOrder)
	}
	waitTimeout := artifactCacheWaitTimeout()
	traceArtifactCache(cfg, "start", "dir=%s local=%d need=%d wait=%s", dir, len(local), len(cfg.runtime.oldOrder), waitTimeout)
	buildStart := time.Now()
	built := 0
	reusedLocal := 0
	for _, dealer := range local {
		if _, ok := cfg.runtime.oldIndex[dealer]; !ok {
			continue
		}
		path := artifactCachePath(dir, dealer)
		if _, err := os.Stat(path); err == nil {
			reusedLocal++
			continue
		}
		art, err := buildSingleDealerArtifact(cfg, dealer)
		if err != nil {
			return nil, breakdown, err
		}
		if err := writeDealerArtifactCache(path, art); err != nil {
			return nil, breakdown, err
		}
		built++
	}
	breakdown.LocalBuildLatency = time.Since(buildStart)
	breakdown.BuiltLocal = built
	breakdown.ReusedLocal = reusedLocal
	traceArtifactCache(cfg, "local_ready", "built=%d reused=%d elapsed=%s", built, reusedLocal, time.Since(buildStart))
	artifacts := make(map[int]*DealerArtifact, len(cfg.runtime.oldOrder))
	readStart := time.Now()
	deadline := time.Now().Add(waitTimeout)
	lastTrace := time.Now()
	for len(artifacts) < len(cfg.runtime.oldOrder) {
		for _, dealer := range cfg.runtime.oldOrder {
			if artifacts[dealer] != nil {
				continue
			}
			art, err := readDealerArtifactCache(artifactCachePath(dir, dealer))
			if err == nil {
				artifacts[dealer] = art
			}
		}
		if len(artifacts) == len(cfg.runtime.oldOrder) {
			breakdown.ReadWaitLatency = time.Since(readStart)
			breakdown.ArtifactCount = len(artifacts)
			traceArtifactCache(cfg, "all_read", "have=%d elapsed=%s", len(artifacts), time.Since(start))
			readyStart := time.Now()
			populateTrustedReadyCandidates(&cfg, artifacts)
			breakdown.TrustedReadyLatency = time.Since(readyStart)
			breakdown.AggregatePrewarmLatency = prewarmDefaultAggregateCache(cfg, artifacts)
			traceArtifactCache(cfg, "done", "artifacts=%d elapsed=%s", len(artifacts), time.Since(start))
			return artifacts, breakdown, nil
		}
		if time.Now().After(deadline) {
			breakdown.ReadWaitLatency = time.Since(readStart)
			return nil, breakdown, fmt.Errorf("artifact cache incomplete: have=%d need=%d wait=%s dir=%s", len(artifacts), len(cfg.runtime.oldOrder), waitTimeout, dir)
		}
		if time.Since(lastTrace) >= 5*time.Second {
			traceArtifactCache(cfg, "waiting", "have=%d need=%d elapsed=%s", len(artifacts), len(cfg.runtime.oldOrder), time.Since(start))
			lastTrace = time.Now()
		}
		time.Sleep(20 * time.Millisecond)
	}
	breakdown.ReadWaitLatency = time.Since(readStart)
	breakdown.ArtifactCount = len(artifacts)
	traceArtifactCache(cfg, "all_read", "have=%d elapsed=%s", len(artifacts), time.Since(start))
	readyStart := time.Now()
	populateTrustedReadyCandidates(&cfg, artifacts)
	breakdown.TrustedReadyLatency = time.Since(readyStart)
	breakdown.AggregatePrewarmLatency = prewarmDefaultAggregateCache(cfg, artifacts)
	traceArtifactCache(cfg, "done", "artifacts=%d elapsed=%s", len(artifacts), time.Since(start))
	return artifacts, breakdown, nil
}

func shouldUseNetworkDisperse(cfg Config) bool {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("RLADKR_DISPERSE_MODE")))
	if mode == "local" || mode == "cache" || mode == "file-cache" || mode == "off" {
		return false
	}
	if mode == "network" || mode == "tcp" || mode == "full-network" {
		return true
	}
	if !strings.EqualFold(cfg.AgreementTransport, "tcp-distributed") {
		return false
	}
	if strings.TrimSpace(os.Getenv("RLADKR_NODE_ADDRS")) == "" {
		return false
	}
	local := sortedUnique(cfg.LocalNodeIDs)
	old := sortedUnique(cfg.runtime.oldOrder)
	return len(local) > 0 && !sameIntSet(local, old)
}

func buildDealerArtifactsOverNetwork(cfg Config) (map[int]*DealerArtifact, DealerArtifactsBreakdown, error) {
	var breakdown DealerArtifactsBreakdown
	start := time.Now()
	local := sortedUnique(cfg.LocalNodeIDs)
	if len(local) == 0 {
		local = sortedUnique(cfg.runtime.oldOrder)
	}
	targetDealers := networkDisperseTargetDealers(cfg)
	targetSet := make(map[int]struct{}, len(targetDealers))
	for _, dealer := range targetDealers {
		targetSet[dealer] = struct{}{}
	}
	transport := cfg.protocolTransport
	closeTransport := false
	if transport == nil {
		var err error
		transport, err = newAgreementTransport(cfg, cfg.runtime.oldOrder, len(cfg.runtime.oldOrder)*8)
		if err != nil {
			return nil, breakdown, err
		}
		closeTransport = true
	}
	if closeTransport {
		defer transport.Close()
	}

	chans := make(map[int]<-chan Message, len(local))
	for _, nodeID := range local {
		ch, chErr := transport.RecvChan(nodeID)
		if chErr != nil {
			return nil, breakdown, chErr
		}
		chans[nodeID] = ch
	}

	buildStart := time.Now()
	localArtifacts := make(map[int]*DealerArtifact, len(local))
	for _, dealer := range local {
		if _, ok := cfg.runtime.oldIndex[dealer]; !ok {
			continue
		}
		if _, ok := targetSet[dealer]; !ok {
			continue
		}
		art, buildErr := buildSingleDealerArtifact(cfg, dealer)
		if buildErr != nil {
			return nil, breakdown, buildErr
		}
		localArtifacts[dealer] = art
	}
	breakdown.LocalBuildLatency = time.Since(buildStart)
	breakdown.BuiltLocal = len(localArtifacts)

	prevPhase := cfg.runtime.commPhaseName()
	cfg.runtime.setCommPhase("disperse")
	broadcastStart := time.Now()
	for dealer, art := range localArtifacts {
		body, encErr := encodeDealerDescriptorWire(dealer, art)
		if encErr != nil {
			cfg.runtime.setCommPhase(prevPhase)
			return nil, breakdown, encErr
		}
		if err := broadcastWithRetry(cfg, transport, dealer, cfg.runtime.oldOrder, "DISPERSE_DEALER_DESCRIPTOR", body); err != nil {
			cfg.runtime.setCommPhase(prevPhase)
			return nil, breakdown, err
		}
	}
	breakdown.BroadcastLatency = time.Since(broadcastStart)
	cfg.runtime.setCommPhase(prevPhase)

	artifacts := make(map[int]*DealerArtifact, len(cfg.runtime.oldOrder))
	for dealer, art := range localArtifacts {
		if err := validateNetworkDealerArtifact(cfg, art); err != nil {
			return nil, breakdown, err
		}
		artifacts[dealer] = art
	}

	readStart := time.Now()
	deadline := time.Now().Add(artifactCacheWaitTimeout())
	if cfg.WaitSPBCTimeout > 0 {
		deadline = time.Now().Add(4 * cfg.WaitSPBCTimeout)
	}
	for !hasAllTargetArtifacts(artifacts, targetDealers) && time.Now().Before(deadline) {
		progress := false
		for _, nodeID := range local {
			msg, ok := recvMessageWithTimeout(chans[nodeID], 20*time.Millisecond)
			if !ok {
				continue
			}
			if msg.Tag != "DISPERSE_DEALER_DESCRIPTOR" {
				continue
			}
			art, decErr := decodeDealerDescriptorWire(msg.Body)
			if decErr != nil || art == nil {
				continue
			}
			if art.Dealer != msg.From {
				continue
			}
			if _, exists := artifacts[art.Dealer]; exists {
				continue
			}
			if _, ok := cfg.runtime.oldIndex[art.Dealer]; !ok {
				continue
			}
			if _, ok := targetSet[art.Dealer]; !ok {
				continue
			}
			if err := validateNetworkDealerArtifact(cfg, art); err != nil {
				continue
			}
			artifacts[art.Dealer] = art
			progress = true
		}
		if progress {
			continue
		}
	}
	breakdown.ReadWaitLatency = time.Since(readStart)
	if !hasAllTargetArtifacts(artifacts, targetDealers) {
		return nil, breakdown, fmt.Errorf("network disperse incomplete: have=%d need=%d elapsed=%s target=%v", countTargetArtifacts(artifacts, targetDealers), len(targetDealers), time.Since(start), targetDealers)
	}
	breakdown.ArtifactCount = len(artifacts)
	readyStart := time.Now()
	populateTrustedReadyCandidates(&cfg, artifacts)
	breakdown.TrustedReadyLatency = time.Since(readyStart)
	breakdown.AggregatePrewarmLatency = prewarmDefaultAggregateCache(cfg, artifacts)
	return artifacts, breakdown, nil
}

func networkDisperseTargetDealers(cfg Config) []int {
	targetSize := cfg.FastlaneMin
	if targetSize <= 0 {
		targetSize = len(cfg.runtime.oldOrder) - cfg.F
	}
	if targetSize <= 0 {
		targetSize = 1
	}
	old := append([]int(nil), cfg.runtime.oldOrder...)
	sort.Ints(old)
	if targetSize > len(old) {
		targetSize = len(old)
	}
	return append([]int(nil), old[:targetSize]...)
}

func hasAllTargetArtifacts(artifacts map[int]*DealerArtifact, target []int) bool {
	return countTargetArtifacts(artifacts, target) == len(target)
}

func countTargetArtifacts(artifacts map[int]*DealerArtifact, target []int) int {
	count := 0
	for _, dealer := range target {
		if artifacts[dealer] != nil {
			count++
		}
	}
	return count
}

func encodeDealerArtifactWire(dealer int, art *DealerArtifact) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(art); err != nil {
		return nil, err
	}
	return json.Marshal(dealerArtifactWire{Dealer: dealer, Artifact: buf.Bytes()})
}

func decodeDealerArtifactWire(body []byte) (*DealerArtifact, error) {
	var wire dealerArtifactWire
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, err
	}
	var art DealerArtifact
	if err := gob.NewDecoder(bytes.NewReader(wire.Artifact)).Decode(&art); err != nil {
		return nil, err
	}
	if art.Dealer != wire.Dealer {
		return nil, fmt.Errorf("artifact dealer mismatch: wire=%d artifact=%d", wire.Dealer, art.Dealer)
	}
	return &art, nil
}

func encodeDealerDescriptorWire(dealer int, art *DealerArtifact) ([]byte, error) {
	if art == nil {
		return nil, fmt.Errorf("nil dealer artifact")
	}
	if art.Dealer != dealer || art.Descriptor.Dealer != dealer {
		return nil, fmt.Errorf("dealer descriptor mismatch")
	}
	return json.Marshal(dealerDescriptorWire{
		Dealer:             dealer,
		Descriptor:         art.Descriptor,
		ContributionDigest: append([]byte(nil), art.ContributionDigest...),
	})
}

func decodeDealerDescriptorWire(body []byte) (*DealerArtifact, error) {
	var wire dealerDescriptorWire
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, err
	}
	if wire.Dealer != wire.Descriptor.Dealer {
		return nil, fmt.Errorf("descriptor dealer mismatch: wire=%d descriptor=%d", wire.Dealer, wire.Descriptor.Dealer)
	}
	return &DealerArtifact{
		Dealer:             wire.Dealer,
		Descriptor:         wire.Descriptor,
		ContributionDigest: append([]byte(nil), wire.ContributionDigest...),
	}, nil
}

func validateNetworkDealerArtifact(cfg Config, art *DealerArtifact) error {
	if art == nil {
		return fmt.Errorf("nil network dealer artifact")
	}
	if len(art.Payload) == 0 && len(art.Ciphertexts) == 0 {
		if art.Dealer != art.Descriptor.Dealer {
			return fmt.Errorf("dealer mismatch: artifact=%d descriptor=%d", art.Dealer, art.Descriptor.Dealer)
		}
		if len(art.ContributionDigest) == 0 {
			return fmt.Errorf("missing contribution digest for dealer=%d", art.Dealer)
		}
		if !ValidateDescriptor(cfg, art.Descriptor) {
			return fmt.Errorf("descriptor validation failed for dealer=%d", art.Dealer)
		}
		return nil
	}
	if strings.EqualFold(cfg.APVSSProvider, "optrand") {
		return OptrandShareVerify(cfg, art)
	}
	if art.Dealer != art.Descriptor.Dealer {
		return fmt.Errorf("dealer mismatch: artifact=%d descriptor=%d", art.Dealer, art.Descriptor.Dealer)
	}
	if !ValidateDescriptor(cfg, art.Descriptor) {
		return fmt.Errorf("descriptor validation failed for dealer=%d", art.Dealer)
	}
	if !bytesEq(hashBytes([]byte("rladkr-root"), art.Payload), art.Descriptor.Header.Root) {
		return fmt.Errorf("payload root mismatch for dealer=%d", art.Dealer)
	}
	if len(art.Fingerprint) == 0 {
		art.Fingerprint = fingerprintDealerArtifact(art)
	}
	if cfg.runtime != nil {
		cfg.runtime.rememberValidatedArtifact(art.Descriptor.Digest, art.Fingerprint)
	}
	return nil
}

func populateTrustedReadyCandidates(cfg *Config, artifacts map[int]*DealerArtifact) {
	if cfg == nil || cfg.runtime == nil || len(artifacts) == 0 {
		return
	}
	ready := make([]readyCandidate, 0, len(artifacts))
	for dealer, art := range artifacts {
		if art == nil || art.Dealer != dealer || art.Descriptor.Dealer != dealer {
			continue
		}
		desc := art.Descriptor
		if len(desc.Digest) == 0 || !bytesEq(desc.Digest, art.Descriptor.Digest) {
			continue
		}
		if len(desc.Fingerprint) == 0 {
			desc.Fingerprint = fingerprintDescriptor(desc)
		}
		if !bytesEq(desc.Digest, digestDescriptor(desc)) {
			continue
		}
		if len(art.Fingerprint) == 0 {
			art.Fingerprint = fingerprintDealerArtifact(art)
		}
		cfg.runtime.rememberValidatedDescriptor(desc.Digest, desc.Fingerprint)
		if len(art.Payload) > 0 || len(art.Ciphertexts) > 0 {
			cfg.runtime.rememberValidatedArtifact(desc.Digest, art.Fingerprint)
		}
		ready = append(ready, readyCandidate{
			dealer: dealer,
			digest: hex.EncodeToString(desc.Digest),
		})
	}
	sort.Slice(ready, func(i, j int) bool {
		if ready[i].digest == ready[j].digest {
			return ready[i].dealer < ready[j].dealer
		}
		return ready[i].digest < ready[j].digest
	})
	cfg.runtime.admitAggMu.Lock()
	cfg.runtime.trustedReadyCandidates = append([]readyCandidate(nil), ready...)
	cfg.runtime.admitAggMu.Unlock()
}

func prewarmDefaultAggregateCache(cfg Config, artifacts map[int]*DealerArtifact) time.Duration {
	if cfg.runtime == nil || strings.TrimSpace(cfg.ArtifactCacheDir) == "" || !strings.EqualFold(cfg.APVSSProvider, "optrand") {
		return 0
	}
	if aggregatePrewarmDisabled() {
		traceArtifactCache(cfg, "aggregate_prewarm_skip", "reason=disabled elapsed=0s")
		return 0
	}
	start := time.Now()
	candidates := trustedReadyCandidatesFromRuntime(cfg)
	if len(candidates) == 0 {
		traceArtifactCache(cfg, "aggregate_prewarm_skip", "reason=no_candidates elapsed=%s", time.Since(start))
		return time.Since(start)
	}
	dealers, err := selectDealersForLockAgg(cfg, candidates)
	if err != nil {
		traceArtifactCache(cfg, "aggregate_prewarm_skip", "reason=select_error err=%v elapsed=%s", err, time.Since(start))
		return time.Since(start)
	}
	_, _, _ = buildAggRLOForDealers(cfg, dealers, artifacts)
	traceArtifactCache(cfg, "aggregate_prewarm_done", "dealers=%d elapsed=%s", len(dealers), time.Since(start))
	return time.Since(start)
}

func aggregatePrewarmDisabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("RLADKR_AGGREGATE_PREWARM")))
	return v == "0" || v == "false" || v == "off"
}

func buildDealerArtifactsOptrand(cfg Config) (map[int]*DealerArtifact, error) {
	c := cfg
	artifacts := make(map[int]*DealerArtifact, len(c.runtime.oldOrder))
	lockThreshold := len(c.runtime.oldOrder) - c.F
	if lockThreshold <= 0 {
		lockThreshold = 1
	}
	holders := append([]int(nil), c.runtime.oldOrder...)

	for _, dealer := range c.runtime.oldOrder {
		art, err := buildEncryptedShamirDealerArtifact(c, dealer, holders, lockThreshold)
		if err != nil {
			return nil, err
		}
		artifacts[dealer] = art
	}
	return artifacts, nil
}

func buildDealerArtifactsBlsPWSS(cfg Config) (map[int]*DealerArtifact, error) {
	c := cfg
	artifacts := make(map[int]*DealerArtifact, len(c.runtime.oldOrder))
	lockThreshold := len(c.runtime.oldOrder) - c.F
	if lockThreshold <= 0 {
		lockThreshold = 1
	}
	holders := append([]int(nil), c.runtime.oldOrder...)

	for _, dealer := range c.runtime.oldOrder {
		art, err := buildSingleDealerArtifactBlsPVSS(c, dealer, holders, lockThreshold)
		if err != nil {
			return nil, err
		}
		artifacts[dealer] = art
	}
	return artifacts, nil
}

func buildSingleDealerArtifact(cfg Config, dealer int) (*DealerArtifact, error) {
	lockThreshold := len(cfg.runtime.oldOrder) - cfg.F
	if lockThreshold <= 0 {
		lockThreshold = 1
	}
	holders := append([]int(nil), cfg.runtime.oldOrder...)
	if strings.EqualFold(cfg.APVSSProvider, "bls-pvss") {
		return buildSingleDealerArtifactBlsPVSS(cfg, dealer, holders, lockThreshold)
	}
	return buildEncryptedShamirDealerArtifact(cfg, dealer, holders, lockThreshold)
}

func buildEncryptedShamirDealerArtifact(cfg Config, dealer int, holders []int, lockThreshold int) (*DealerArtifact, error) {
	payload, sharePackets, err := buildDealerTranscript(cfg, dealer)
	if err != nil {
		return nil, fmt.Errorf("dealer %d transcript build failed: %w", dealer, err)
	}
	root := hashBytes([]byte("rladkr-root"), payload)
	commitment := hashBytes([]byte("rladkr-commit"), payload)
	return buildArtifactCommon(cfg, dealer, payload, root, commitment, holders, lockThreshold,
		func() (map[int][]byte, error) {
			ciphertexts := make(map[int][]byte, len(cfg.runtime.receiverOrder))
			for _, receiver := range cfg.runtime.receiverOrder {
				packet := sharePackets[receiver]
				ct, ctErr := sealSharePacketForReceiver(cfg, dealer, receiver, root, packet)
				if ctErr != nil {
					return nil, fmt.Errorf("dealer %d seal failed for receiver=%d: %w", dealer, receiver, ctErr)
				}
				ciphertexts[receiver] = ct
			}
			return ciphertexts, nil
		})
}

func buildSingleDealerArtifactBlsPVSS(cfg Config, dealer int, holders []int, lockThreshold int) (*DealerArtifact, error) {
	tx, txErr := blsPVSSDistribute(cfg, dealer)
	if txErr != nil {
		return nil, fmt.Errorf("dealer %d bls pvss failed: %w", dealer, txErr)
	}
	payload, encodeErr := encodeBlsPVSSDealerTranscript(tx)
	if encodeErr != nil {
		return nil, fmt.Errorf("dealer %d BLS PVSS encode failed: %w", dealer, encodeErr)
	}
	root := hashBytes([]byte("rladkr-root"), payload)
	commitment := hashBytes([]byte("rladkr-commit"), payload)
	return buildArtifactCommon(cfg, dealer, payload, root, commitment, holders, lockThreshold,
		func() (map[int][]byte, error) {
			ciphertexts := make(map[int][]byte, len(cfg.runtime.receiverOrder))
			for i, receiver := range cfg.runtime.receiverOrder {
				ciphertexts[receiver] = append([]byte(nil), g2Bytes(&tx.EncryptedShares[i])...)
			}
			return ciphertexts, nil
		})
}

func artifactCachePath(dir string, dealer int) string {
	return filepath.Join(dir, fmt.Sprintf("dealer-%d.gob", dealer))
}

func writeDealerArtifactCache(path string, art *DealerArtifact) error {
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	encErr := gob.NewEncoder(f).Encode(art)
	closeErr := f.Close()
	if encErr != nil {
		_ = os.Remove(tmp)
		return encErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, path)
}

func readDealerArtifactCache(path string) (*DealerArtifact, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var art DealerArtifact
	if err := gob.NewDecoder(f).Decode(&art); err != nil {
		return nil, err
	}
	return &art, nil
}

func safeCacheComponent(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "default"
	}
	repl := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_")
	return repl.Replace(s)
}

func artifactCacheWaitTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("RLADKR_ARTIFACT_CACHE_WAIT_MS"))
	if raw == "" {
		return 30 * time.Second
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		return 30 * time.Second
	}
	return time.Duration(ms) * time.Millisecond
}

func traceArtifactCache(cfg Config, phase string, format string, args ...any) {
	if strings.TrimSpace(os.Getenv("RLADKR_ARTIFACT_CACHE_TRACE")) == "" &&
		strings.TrimSpace(os.Getenv("RLADKR_BENCH_DEBUG_FINALIZE")) == "" {
		return
	}
	nodeLabel := "all"
	local := sortedUnique(cfg.LocalNodeIDs)
	if len(local) == 1 {
		nodeLabel = fmt.Sprintf("%d", local[0])
	} else if len(local) > 1 {
		nodeLabel = fmt.Sprintf("%d_nodes", len(local))
	}
	fmt.Fprintf(
		os.Stderr,
		"RLADKR_ARTIFACT_CACHE sid=%s node=%s epoch=%d phase=%s %s\n",
		cfg.SID,
		nodeLabel,
		cfg.Epoch,
		phase,
		fmt.Sprintf(format, args...),
	)
}

func buildArtifactCommon(
	cfg Config,
	dealer int,
	payload, root, commitment []byte,
	holders []int,
	lockThreshold int,
	buildCiphertexts func() (map[int][]byte, error),
) (*DealerArtifact, error) {
	c := cfg
	meta := hashBytes(
		[]byte("rladkr-meta"),
		[]byte(c.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d", c.Epoch, dealer)),
		root,
		commitment,
	)
	header := Header{
		SID:          c.SID,
		Epoch:        c.Epoch,
		Dealer:       dealer,
		Root:         root,
		Commitment:   commitment,
		MetadataHash: meta,
	}
	lockDigest := digestHeaderForLock(header)
	shareSigs := make(map[int][]byte, len(holders))
	for _, holder := range holders {
		sig, sErr := c.runtime.lockSigner.SignShare(holder, "RL_LOCK", lockDigest)
		if sErr != nil {
			return nil, fmt.Errorf("dealer %d lock share failed from holder=%d: %w", dealer, holder, sErr)
		}
		shareSigs[holder] = sig
	}
	lockCert, certErr := c.runtime.lockSigner.Recover("RL_LOCK", lockDigest, shareSigs)
	if certErr != nil {
		return nil, fmt.Errorf("dealer %d lock cert recovery failed: %w", dealer, certErr)
	}

	desc := Descriptor{
		Dealer: dealer,
		Header: header,
		Lock: RecoverabilityLock{
			Threshold:       lockThreshold,
			Holders:         append([]int(nil), holders...),
			ShareSignatures: cloneSigMap(shareSigs),
			Certificate:     append([]byte(nil), lockCert...),
		},
	}
	desc.Digest = digestDescriptor(desc)
	desc.Fingerprint = fingerprintDescriptor(desc)

	ciphertexts, err := buildCiphertexts()
	if err != nil {
		return nil, err
	}

	art := &DealerArtifact{
		Dealer:      dealer,
		Descriptor:  desc,
		Payload:     append([]byte(nil), payload...),
		Ciphertexts: ciphertexts,
	}
	art.ContributionDigest = dealerContributionDigest(c.APVSSProvider, art)
	art.Fingerprint = fingerprintDealerArtifact(art)
	if c.runtime != nil {
		c.runtime.rememberValidatedDescriptor(desc.Digest, desc.Fingerprint)
		c.runtime.rememberValidatedArtifact(desc.Digest, art.Fingerprint)
	}
	return art, nil
}

func ValidateDescriptor(cfg Config, desc Descriptor) bool {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return false
	}
	if c.runtime == nil {
		return false
	}
	fp := desc.Fingerprint
	if len(fp) == 0 {
		fp = fingerprintDescriptor(desc)
	}
	if c.runtime.hasValidatedDescriptor(desc.Digest, fp) {
		return true
	}
	if desc.Dealer != desc.Header.Dealer {
		return false
	}
	if desc.Header.SID != c.SID || desc.Header.Epoch != c.Epoch {
		return false
	}
	if !desc.Lock.Ready() {
		return false
	}
	lockThreshold := len(c.runtime.oldOrder) - c.F
	if lockThreshold <= 0 {
		lockThreshold = 1
	}
	if desc.Lock.Threshold != lockThreshold {
		return false
	}
	holders := sortedUnique(desc.Lock.Holders)
	if len(holders) < desc.Lock.Threshold {
		return false
	}
	for _, id := range holders {
		if _, ok := c.runtime.oldIndex[id]; !ok {
			return false
		}
	}
	lockDigest := digestHeaderForLock(desc.Header)
	if len(desc.Lock.Certificate) > 0 {
		if !c.runtime.lockSigner.VerifyRecovered("RL_LOCK", lockDigest, desc.Lock.Certificate) {
			return false
		}
		passed := bytesEq(desc.Digest, digestDescriptor(desc))
		if passed {
			c.runtime.rememberValidatedDescriptor(desc.Digest, fp)
		}
		return passed
	}
	validShares := make(map[int][]byte, len(holders))
	for _, holder := range holders {
		sig, ok := desc.Lock.ShareSignatures[holder]
		if !ok || len(sig) == 0 {
			continue
		}
		if c.runtime.lockSigner.VerifyShare(holder, "RL_LOCK", lockDigest, sig) {
			validShares[holder] = sig
		}
	}
	if len(validShares) < desc.Lock.Threshold {
		return false
	}
	recovered, err := c.runtime.lockSigner.Recover("RL_LOCK", lockDigest, validShares)
	if err != nil {
		return false
	}
	if !bytesEq(recovered, desc.Lock.Certificate) {
		return false
	}
	if !c.runtime.lockSigner.VerifyRecovered("RL_LOCK", lockDigest, desc.Lock.Certificate) {
		return false
	}
	passed := bytesEq(desc.Digest, digestDescriptor(desc))
	if passed {
		c.runtime.rememberValidatedDescriptor(desc.Digest, fp)
	}
	return passed
}

func digestHeaderForLock(h Header) []byte {
	return hashBytes(
		[]byte("rladkr-lock-digest"),
		[]byte(h.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d", h.Epoch, h.Dealer)),
		h.Root,
		h.Commitment,
		h.MetadataHash,
	)
}

func digestDescriptor(desc Descriptor) []byte {
	holders := sortedUnique(desc.Lock.Holders)
	digestParts := make([][]byte, 0, 8+2*len(holders))
	digestParts = append(digestParts,
		[]byte("rladkr-desc"),
		[]byte(desc.Header.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d", desc.Header.Epoch, desc.Header.Dealer)),
		desc.Header.Root,
		desc.Header.Commitment,
		desc.Header.MetadataHash,
		encodeInts(holders),
		[]byte(fmt.Sprintf("|threshold=%d", desc.Lock.Threshold)),
		desc.Lock.Certificate,
	)
	for _, holder := range holders {
		digestParts = append(digestParts, []byte(fmt.Sprintf("|holder=%d", holder)))
		digestParts = append(digestParts, desc.Lock.ShareSignatures[holder])
	}
	return hashBytes(digestParts...)
}

func fingerprintDescriptor(desc Descriptor) []byte {
	holders := sortedUnique(desc.Lock.Holders)
	parts := make([][]byte, 0, 10+2*len(holders))
	parts = append(parts,
		[]byte("rladkr-desc-fp"),
		[]byte(desc.Header.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d|threshold=%d", desc.Header.Epoch, desc.Header.Dealer, desc.Lock.Threshold)),
		desc.Header.Root,
		desc.Header.Commitment,
		desc.Header.MetadataHash,
		desc.Lock.Certificate,
	)
	for _, holder := range holders {
		parts = append(parts, []byte(fmt.Sprintf("holder=%d", holder)))
		parts = append(parts, desc.Lock.ShareSignatures[holder])
	}
	return hashBytes(parts...)
}
