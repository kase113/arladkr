package core

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

type AgreeAggOutput struct {
	Mode             string
	AggRLO           *AggRLO
	PerNode          []NodeOutput
	PreparedFallback []byte
	LockAggLatency   time.Duration
	MVBAOnlyLatency  time.Duration
	MVBAPeerWait     time.Duration
	LockAggBreakdown LockAggBreakdown
}

type LockAggBreakdown struct {
	ReadyCandidatesLatency time.Duration
	AggBuildLatency        time.Duration
	ARCSharePrepareLatency time.Duration
	ARCShareAttachLatency  time.Duration
	CandidateCount         int
	ARCShareSignedCount    int
	AggLockSignLatency     time.Duration
	AggLockRecoverLatency  time.Duration
	LocalAdmitLatency      time.Duration
}

// AgreeAgg first prepares a header-bound AggRLO via LockAgg, then confirms its
// digest through Dumbomvba/MVBA. The previous fastlane shortcut is intentionally
// not part of the active protocol path.
func AgreeAgg(ctx context.Context, cfg Config, descriptors map[int]Descriptor, artifacts map[int]*DealerArtifact) (*AgreeAggOutput, error) {
	c := NormalizeConfig(cfg)
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	if c.runtime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}

	lockStart := time.Now()
	prepared, lockBreakdown, err := LockAgg(c, descriptors, artifacts)
	if err != nil {
		return nil, fmt.Errorf("LockAgg: %w", err)
	}
	prepared = maybeInjectBenchAdversaryAggRLO(c, prepared)
	lockLatency := time.Since(lockStart)
	mvbaStart := time.Now()
	agreedDigest, perNode, mvbaPeerWait, err := AgreeOnAggRLO(ctx, c, prepared)
	if err != nil {
		return nil, fmt.Errorf("AgreeAgg MVBA: %w", err)
	}
	mvbaLatency := time.Since(mvbaStart)
	if !bytesEq(agreedDigest, prepared.Digest) { /* CallHelp TODO */
	}
	return &AgreeAggOutput{
		Mode:             "fallback-mvba",
		AggRLO:           prepared,
		PerNode:          perNode,
		PreparedFallback: prepared.Digest,
		LockAggLatency:   lockLatency,
		MVBAOnlyLatency:  mvbaLatency,
		MVBAPeerWait:     mvbaPeerWait,
		LockAggBreakdown: lockBreakdown,
	}, nil
}

func maybeInjectBenchAdversaryAggRLO(cfg Config, rlo *AggRLO) *AggRLO {
	if rlo == nil {
		return nil
	}
	if strings.EqualFold(cfg.AdversaryMode, "malicious-proposer-leader-select-bias") {
		return rlo
	}
	if !strings.EqualFold(cfg.AdversaryMode, "malicious-proposer-bad-agclock") {
		return rlo
	}
	tampered := *rlo
	tampered.Header = rlo.Header
	tampered.Aggregate = rlo.Aggregate
	tampered.Lock = rlo.Lock
	tampered.Lock.Certificate = []byte("malicious-invalid-agclock")
	tampered.Digest = digestAggRLO(tampered)
	return &tampered
}

func LockAgg(cfg Config, descriptors map[int]Descriptor, artifacts map[int]*DealerArtifact) (*AggRLO, LockAggBreakdown, error) {
	var breakdown LockAggBreakdown
	readyStart := time.Now()
	candidates := readyCandidatesForLockAgg(cfg, descriptors, artifacts)
	breakdown.ReadyCandidatesLatency = time.Since(readyStart)
	breakdown.CandidateCount = len(candidates)
	dealers, err := selectDealersForLockAgg(cfg, candidates)
	if err != nil {
		return nil, breakdown, err
	}
	rlo, buildBreakdown, err := buildAggRLOForDealers(cfg, dealers, artifacts)
	breakdown.AggBuildLatency = buildBreakdown.AggBuildLatency
	breakdown.ARCSharePrepareLatency = buildBreakdown.ARCSharePrepareLatency
	breakdown.ARCShareAttachLatency = buildBreakdown.ARCShareAttachLatency
	breakdown.ARCShareSignedCount = buildBreakdown.ARCShareSignedCount
	breakdown.AggLockSignLatency = buildBreakdown.AggLockSignLatency
	breakdown.AggLockRecoverLatency = buildBreakdown.AggLockRecoverLatency
	breakdown.LocalAdmitLatency = buildBreakdown.LocalAdmitLatency
	return rlo, breakdown, err
}

func selectDealersForLockAgg(cfg Config, candidates []readyCandidate) ([]int, error) {
	readyMin := fastlaneReadyPoolMinimum(cfg)
	if len(candidates) < readyMin {
		return nil, fmt.Errorf("LockAgg: insufficient ready candidates: have=%d need=%d", len(candidates), readyMin)
	}
	targetSize := cfg.Kappa
	if targetSize <= 0 {
		targetSize = cfg.FOld + 1
	}
	if targetSize <= 0 {
		targetSize = 1
	}
	if len(candidates) < targetSize {
		return nil, fmt.Errorf("LockAgg: insufficient ready candidates for header-only recovery obligation: have=%d need=%d", len(candidates), targetSize)
	}
	if cfg.MaxARCCandidatesPerEpoch > 0 && len(candidates) > cfg.MaxARCCandidatesPerEpoch {
		candidates = append([]readyCandidate(nil), candidates[:cfg.MaxARCCandidatesPerEpoch]...)
	}
	if len(candidates) < targetSize {
		return nil, fmt.Errorf("LockAgg: candidate cap too small for header-only recovery obligation: capped=%d need=%d", len(candidates), targetSize)
	}
	selected := candidates
	if strings.EqualFold(cfg.AblationMode, "leader-select") {
		selected = leaderSelectedCandidates(cfg, candidates)
	}
	if strings.EqualFold(cfg.AblationMode, "leader-select") &&
		strings.EqualFold(cfg.AdversaryMode, "malicious-proposer-leader-select-bias") &&
		len(candidates) >= targetSize {
		selected = adversarialLeaderSelectedCandidates(cfg, candidates, targetSize)
	}
	dealers := make([]int, 0, targetSize)
	for i := 0; i < targetSize; i++ {
		dealers = append(dealers, selected[i].dealer)
	}
	return dealers, nil
}

func fastlaneReadyPoolMinimum(cfg Config) int {
	if cfg.FastlaneMin > 0 {
		return cfg.FastlaneMin
	}
	if readyMin := len(cfg.OldCommittee) - cfg.FOld; readyMin > 0 {
		return readyMin
	}
	return 1
}

func PrepareFallbackState(cfg Config, descriptors map[int]Descriptor, artifacts map[int]*DealerArtifact) (*AggRLO, error) {
	rlo, _, err := LockAgg(cfg, descriptors, artifacts)
	return rlo, err
}

func canUseTrustedAggregateBuild(cfg Config, dealers []int, artifacts map[int]*DealerArtifact) bool {
	if !strings.EqualFold(cfg.APVSSProvider, "optrand") || cfg.runtime == nil {
		return false
	}
	for _, dealer := range dealers {
		art, ok := artifacts[dealer]
		if !ok || art == nil {
			return false
		}
		if art.Dealer != dealer || art.Descriptor.Dealer != dealer {
			return false
		}
		if !bytesEq(art.Descriptor.Digest, digestDescriptor(art.Descriptor)) {
			return false
		}
		if len(art.ContributionDigest) == 0 {
			return false
		}
		fp := art.Descriptor.Fingerprint
		if len(fp) == 0 {
			fp = fingerprintDescriptor(art.Descriptor)
		}
		if !cfg.runtime.hasValidatedDescriptor(art.Descriptor.Digest, fp) {
			return false
		}
	}
	return true
}

func aggRLOBuildCacheKey(cfg Config, dealers []int, artifacts map[int]*DealerArtifact) string {
	provider := strings.TrimSpace(cfg.APVSSProvider)
	if provider == "" {
		provider = "optrand"
	}
	canon := sortedUnique(dealers)
	artifactParts := make([]string, 0, len(canon))
	for _, dealer := range canon {
		art := artifacts[dealer]
		if art == nil {
			artifactParts = append(artifactParts, fmt.Sprintf("%d:<missing>", dealer))
			continue
		}
		contributionDigest := art.ContributionDigest
		if len(contributionDigest) == 0 {
			contributionDigest = optrandContributionDigest(art)
		}
		artifactParts = append(
			artifactParts,
			fmt.Sprintf("%d:%x:%x", dealer, art.Descriptor.Digest, contributionDigest),
		)
	}
	return fmt.Sprintf(
		"%s|epoch=%d|provider=%s|dealers=%x|artifacts=%s",
		cfg.SID,
		cfg.Epoch,
		provider,
		encodeInts(canon),
		strings.Join(artifactParts, ","),
	)
}

func buildAggRLOForDealers(cfg Config, dealers []int, artifacts map[int]*DealerArtifact) (*AggRLO, LockAggBreakdown, error) {
	var breakdown LockAggBreakdown
	apvss := newAPVSSFromConfig(cfg)
	canon := sortedUnique(dealers)
	cacheKey := aggRLOBuildCacheKey(cfg, canon, artifacts)
	if cfg.runtime != nil {
		if cached, ok := cfg.runtime.cachedAggRLOBuild(cacheKey); ok {
			return cached, breakdown, nil
		}
	}
	var agg *APVSSAggregate
	var err error
	aggStart := time.Now()
	if cfg.runtime != nil {
		if cached, ok := cfg.runtime.cachedAggregateBuild(cacheKey); ok {
			agg = cached
		}
	}
	if agg == nil {
		if canUseTrustedAggregateBuild(cfg, canon, artifacts) {
			var txErr error
			agg, txErr = buildOrLoadTrustedAggregateCache(cfg, cacheKey, func() (*APVSSAggregate, error) {
				tx, err := BuildTrustedOptrandAggregatedTranscript(cfg, canon, artifacts)
				if err != nil {
					return nil, err
				}
				return &APVSSAggregate{
					Provider:        "optrand",
					Dealers:         append([]int(nil), tx.Dealers...),
					AggregateDigest: append([]byte(nil), tx.AggregateDigest...),
					ListTranscript:  tx,
				}, nil
			})
			if txErr != nil {
				return nil, breakdown, txErr
			}
		} else {
			agg, err = apvss.Agg(cfg, canon, artifacts)
			if err != nil {
				return nil, breakdown, err
			}
		}
		if cfg.runtime != nil {
			cfg.runtime.rememberAggregateBuild(cacheKey, agg)
		}
	}
	breakdown.AggBuildLatency = time.Since(aggStart)
	rlo, buildBreakdown, err := BuildAggRLO(cfg, canon, agg)
	if err != nil {
		return nil, breakdown, err
	}
	breakdown.ARCSharePrepareLatency = buildBreakdown.ARCSharePrepareLatency
	breakdown.ARCShareAttachLatency = buildBreakdown.ARCShareAttachLatency
	breakdown.AggLockSignLatency = buildBreakdown.AggLockSignLatency
	breakdown.AggLockRecoverLatency = buildBreakdown.AggLockRecoverLatency
	admitStart := time.Now()
	if err := AdmitLocallyConstructedAgg(cfg, rlo); err != nil {
		return nil, breakdown, err
	}
	breakdown.LocalAdmitLatency = time.Since(admitStart)
	if cfg.runtime != nil {
		cfg.runtime.rememberAggRLOBuild(cacheKey, rlo)
	}
	return rlo, breakdown, nil
}

func trustedReadyCandidates(descriptors map[int]Descriptor, artifacts map[int]*DealerArtifact) []readyCandidate {
	if len(artifacts) > 0 {
		for _, art := range artifacts {
			if art == nil {
				continue
			}
			// use runtime-populated cache when available
			break
		}
	}
	ready := make([]readyCandidate, 0, len(descriptors))
	for dealer, desc := range descriptors {
		art, ok := artifacts[dealer]
		if !ok || art == nil || art.Dealer != dealer || art.Descriptor.Dealer != dealer {
			continue
		}
		if len(desc.Digest) == 0 || !bytesEq(desc.Digest, art.Descriptor.Digest) {
			continue
		}
		if !bytesEq(desc.Digest, digestDescriptor(desc)) {
			continue
		}
		ready = append(ready, readyCandidate{
			dealer: dealer,
			digest: fmt.Sprintf("%x", desc.Digest),
		})
	}
	sort.Slice(ready, func(i, j int) bool {
		if ready[i].digest == ready[j].digest {
			return ready[i].dealer < ready[j].dealer
		}
		return ready[i].digest < ready[j].digest
	})
	return ready
}

func trustedReadyCandidatesFromRuntime(cfg Config) []readyCandidate {
	if cfg.runtime == nil {
		return nil
	}
	cfg.runtime.admitAggMu.Lock()
	defer cfg.runtime.admitAggMu.Unlock()
	if len(cfg.runtime.trustedReadyCandidates) == 0 {
		return nil
	}
	return append([]readyCandidate(nil), cfg.runtime.trustedReadyCandidates...)
}

func readyCandidatesForLockAgg(
	cfg Config,
	descriptors map[int]Descriptor,
	artifacts map[int]*DealerArtifact,
) []readyCandidate {
	if cached := trustedReadyCandidatesFromRuntime(cfg); len(cached) > 0 {
		return cached
	}
	if !cfg.EnableFastlane && cfg.ArtifactCacheDir != "" {
		return trustedReadyCandidates(descriptors, artifacts)
	}
	return canonicalReadyCandidates(cfg, descriptors, artifacts)
}

func fallbackSeedDealers(cfg Config, descriptors map[int]Descriptor, artifacts map[int]*DealerArtifact) []int {
	candidates := readyCandidatesForLockAgg(cfg, descriptors, artifacts)
	if len(candidates) < fastlaneReadyPoolMinimum(cfg) {
		return nil
	}
	targetSize := cfg.Kappa
	required := cfg.FOld + 1
	if required <= 0 {
		required = 1
	}
	if targetSize < required {
		targetSize = required
	}
	if targetSize > len(cfg.OldCommittee) {
		targetSize = len(cfg.OldCommittee)
	}
	ready := make([]int, 0, len(candidates))
	for _, cand := range candidates {
		ready = append(ready, cand.dealer)
	}
	if len(ready) < targetSize && len(ready) >= required {
		targetSize = len(ready)
	}
	p := takeFirst(ready, targetSize)
	if len(p) < required {
		p = stableFirst(cfg.OldCommittee, required)
	}
	return normalizeCandidate(p, targetSize, cfg.OldCommittee)
}

func leaderSelectedCandidates(cfg Config, candidates []readyCandidate) []readyCandidate {
	if len(candidates) <= 1 || len(cfg.OldCommittee) == 0 {
		return candidates
	}
	leader := leaderForRound(cfg.SID, sortedUnique(cfg.OldCommittee), cfg.Epoch)
	if leader < 0 {
		return candidates
	}
	rotated := make([]readyCandidate, 0, len(candidates))
	for _, cand := range candidates {
		if cand.dealer >= leader {
			rotated = append(rotated, cand)
		}
	}
	for _, cand := range candidates {
		if cand.dealer < leader {
			rotated = append(rotated, cand)
		}
	}
	if len(rotated) != len(candidates) {
		return candidates
	}
	return rotated
}

func adversarialLeaderSelectedCandidates(cfg Config, candidates []readyCandidate, targetSize int) []readyCandidate {
	if targetSize <= 0 || len(candidates) < targetSize {
		return candidates
	}
	preferred := make([]int, 0, targetSize)
	for _, id := range sortedCopy(cfg.OldCommittee) {
		if id%3 == 0 {
			preferred = append(preferred, id)
		}
	}
	for _, id := range sortedCopy(cfg.OldCommittee) {
		if id%3 != 0 {
			preferred = append(preferred, id)
		}
	}
	preferred = normalizeCandidate(preferred, targetSize, cfg.OldCommittee)
	byDealer := make(map[int]readyCandidate, len(candidates))
	for _, cand := range candidates {
		byDealer[cand.dealer] = cand
	}
	out := make([]readyCandidate, 0, len(candidates))
	used := make(map[int]struct{}, len(candidates))
	for _, dealer := range preferred {
		if cand, ok := byDealer[dealer]; ok {
			out = append(out, cand)
			used[dealer] = struct{}{}
			if len(out) >= targetSize {
				break
			}
		}
	}
	if len(out) < targetSize {
		for _, cand := range candidates {
			if _, ok := used[cand.dealer]; ok {
				continue
			}
			out = append(out, cand)
			used[cand.dealer] = struct{}{}
			if len(out) >= targetSize {
				break
			}
		}
	}
	for _, cand := range candidates {
		if _, ok := used[cand.dealer]; ok {
			continue
		}
		out = append(out, cand)
	}
	if len(out) != len(candidates) {
		return candidates
	}
	return out
}
