package core

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

type aggLockShareWire struct {
	Holder          int    `json:"holder"`
	Epoch           int    `json:"epoch"`
	AggHeaderDigest []byte `json:"agg_header_digest"`
	ObligationKind  string `json:"obligation_kind"`
	Sig             []byte `json:"sig"`
}

type AggRLOBuildBreakdown struct {
	ARCSharePrepareLatency time.Duration
	ARCShareAttachLatency  time.Duration
	ARCShareSignedCount    int
	AggLockSignLatency     time.Duration
	AggLockRecoverLatency  time.Duration
}

type aggRLOMaterializedBinding struct {
	payloadDigest  []byte
	freshShardRoot []byte
	beforeSign     func(int) error
}

// BuildAggRLO constructs a header-bound aggregate recovery-lock object.
// In the current header-only ARC mode, LockAgg certifies only AggHeader and
// the obligation to recover the aggregate later; fragment materialization and
// deep aggregate verification remain in Recover.
func BuildAggRLO(cfg Config, dealers []int, agg *APVSSAggregate) (*AggRLO, AggRLOBuildBreakdown, error) {
	return buildAggRLO(cfg, dealers, agg, nil)
}

func buildAggRLO(
	cfg Config,
	dealers []int,
	agg *APVSSAggregate,
	binding *aggRLOMaterializedBinding,
) (*AggRLO, AggRLOBuildBreakdown, error) {
	c := cfg
	var breakdown AggRLOBuildBreakdown
	if err := ensureRuntime(&c); err != nil {
		return nil, breakdown, err
	}
	if c.runtime == nil {
		return nil, breakdown, fmt.Errorf("runtime not initialized")
	}
	if agg == nil {
		return nil, breakdown, fmt.Errorf("nil APVSS aggregate")
	}
	canonDealers, err := validateFinalDealerSet(c, dealers)
	if err != nil {
		return nil, breakdown, fmt.Errorf("AggRLO dealer set: %w", err)
	}
	if len(canonDealers) != len(agg.Dealers) {
		return nil, breakdown, fmt.Errorf("dealer count mismatch between AggRLO and aggregate")
	}
	for i := range canonDealers {
		if canonDealers[i] != agg.Dealers[i] {
			return nil, breakdown, fmt.Errorf("dealer ordering mismatch at index=%d", i)
		}
	}

	header := AggHeader{
		SID:             c.SID,
		Epoch:           c.Epoch,
		Dealers:         append([]int(nil), canonDealers...),
		AggregateDigest: append([]byte(nil), agg.AggregateDigest...),
	}
	if binding != nil {
		header.PayloadDigest = append([]byte(nil), binding.payloadDigest...)
		header.FreshShardRoot = append([]byte(nil), binding.freshShardRoot...)
	}
	header.MetadataHash = hashBytes(
		[]byte("aggrlo-meta"),
		[]byte(c.SID),
		[]byte(fmt.Sprintf("|epoch=%d", c.Epoch)),
		encodeInts(canonDealers),
		agg.AggregateDigest,
		header.PayloadDigest,
		header.FreshShardRoot,
	)
	lockThreshold := len(c.runtime.oldOrder) - c.FOld
	if lockThreshold <= 0 {
		lockThreshold = 1
	}
	holders := takeFirst(c.runtime.oldOrder, lockThreshold)
	lockDigest := digestAggHeaderForLock(header)
	signStart := time.Now()
	var beforeSign func(int) error
	if binding != nil {
		beforeSign = binding.beforeSign
	}
	shareSigs, attachLatency, signedCount, err := collectAggLockShares(c, holders, lockDigest, beforeSign)
	if err != nil {
		return nil, breakdown, err
	}
	signLatency := time.Since(signStart)
	if signLatency < attachLatency {
		attachLatency = signLatency
	}
	breakdown.ARCShareAttachLatency = attachLatency
	breakdown.ARCSharePrepareLatency = signLatency - attachLatency
	breakdown.ARCShareSignedCount = signedCount
	breakdown.AggLockSignLatency = signLatency
	recoverStart := time.Now()
	cert, err := c.runtime.lockSigner.Recover("RL_AGG_LOCK", lockDigest, shareSigs)
	if err != nil {
		return nil, breakdown, fmt.Errorf("aggregate recovery-obligation cert recovery failed: %w", err)
	}
	breakdown.AggLockRecoverLatency = time.Since(recoverStart)

	rlo := &AggRLO{
		Header: header,
		Lock: AggLock{
			Threshold:       lockThreshold,
			Holders:         holders,
			ShareSignatures: cloneSigMap(shareSigs),
			Certificate:     append([]byte(nil), cert...),
		},
		Aggregate: APVSSAggregate{
			Provider:        agg.Provider,
			Dealers:         append([]int(nil), agg.Dealers...),
			AggregateDigest: append([]byte(nil), agg.AggregateDigest...),
		},
	}
	if agg.ListTranscript != nil {
		if agg.ListTranscript.Trusted {
			rlo.Aggregate.ListTranscript = agg.ListTranscript
		} else {
			rlo.Aggregate.ListTranscript = &ListBackedAggregateTranscript{
				Dealers:             append([]int(nil), agg.ListTranscript.Dealers...),
				ContributionDigests: make(map[int][]byte, len(agg.ListTranscript.ContributionDigests)),
				AggregateDigest:     append([]byte(nil), agg.ListTranscript.AggregateDigest...),
				Trusted:             agg.ListTranscript.Trusted,
			}
			for dealer, dig := range agg.ListTranscript.ContributionDigests {
				rlo.Aggregate.ListTranscript.ContributionDigests[dealer] = append([]byte(nil), dig...)
			}
		}
	}
	if agg.BlsPVSSTranscript != nil {
		rlo.Aggregate.BlsPVSSTranscript = cloneBlsPVSSAggregateTranscript(agg.BlsPVSSTranscript)
	}
	rlo.Digest = digestAggRLO(*rlo)
	return rlo, breakdown, nil
}

func collectAggLockShares(
	cfg Config,
	holders []int,
	lockDigest []byte,
	beforeSign func(int) error,
) (map[int][]byte, time.Duration, int, error) {
	shareSigs := make(map[int][]byte, len(holders))
	var attachLatency time.Duration
	signedCount := 0
	for _, holder := range holders {
		if beforeSign != nil {
			if err := beforeSign(holder); err != nil {
				return nil, 0, signedCount, fmt.Errorf("aggregate materialization check failed for holder=%d: %w", holder, err)
			}
		}
		if cached, ok := cfg.runtime.preparedARCShare(holder, cfg.Epoch, lockDigest); ok && len(cached.Signature) > 0 {
			shareSigs[holder] = append([]byte(nil), cached.Signature...)
			continue
		}
		sig, err := cfg.runtime.lockSigner.SignShare(holder, "RL_AGG_LOCK", lockDigest)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("aggregate lock share failed for holder=%d: %w", holder, err)
		}
		shareSigs[holder] = sig
		signedCount++
		cfg.runtime.cachePreparedARCShare(ARCHeaderShare{
			Holder:          holder,
			Epoch:           cfg.Epoch,
			AggHeaderDigest: append([]byte(nil), lockDigest...),
			ObligationKind:  "header-only-recovery-obligation",
			Signature:       append([]byte(nil), sig...),
		})
	}
	if !cfg.CommMetrics {
		return shareSigs, 0, signedCount, nil
	}

	prevPhase := cfg.runtime.commPhaseName()
	cfg.runtime.setCommPhase("arc_header_prebroadcast")
	defer cfg.runtime.setCommPhase(prevPhase)
	localSet := nodeSet(sortedUnique(cfg.LocalNodeIDs))
	attachStart := time.Now()
	for _, holder := range holders {
		body, mErr := json.Marshal(aggLockShareWire{
			Holder:          holder,
			Epoch:           cfg.Epoch,
			AggHeaderDigest: append([]byte(nil), lockDigest...),
			ObligationKind:  "header-only-recovery-obligation",
			Sig:             shareSigs[holder],
		})
		if mErr != nil {
			return nil, 0, 0, mErr
		}
		for _, to := range cfg.runtime.oldOrder {
			if to == holder {
				continue
			}
			wireBytes := jsonWireMessageBytes(Message{
				From: holder,
				To:   to,
				Tag:  "ARC_HEADER_SHARE",
				Body: body,
			})
			if wireBytes <= 0 {
				continue
			}
			if _, ok := localSet[holder]; ok {
				cfg.runtime.recordSentBytes(wireBytes)
			}
			if _, ok := localSet[to]; ok {
				cfg.runtime.recordRecvBytes(wireBytes)
			}
		}
	}
	attachLatency = time.Since(attachStart)
	return shareSigs, attachLatency, signedCount, nil
}

func buildARCHeaderShares(epoch int, lockDigest []byte, shareSigs map[int][]byte) []ARCHeaderShare {
	if len(shareSigs) == 0 {
		return nil
	}
	holders := make([]int, 0, len(shareSigs))
	for holder := range shareSigs {
		holders = append(holders, holder)
	}
	sort.Ints(holders)
	out := make([]ARCHeaderShare, 0, len(holders))
	for _, holder := range holders {
		out = append(out, ARCHeaderShare{
			Holder:          holder,
			Epoch:           epoch,
			AggHeaderDigest: append([]byte(nil), lockDigest...),
			ObligationKind:  "header-only-recovery-obligation",
			Signature:       append([]byte(nil), shareSigs[holder]...),
		})
	}
	return out
}

func cacheARCHeaderShares(cfg Config, shares []ARCHeaderShare) {
	if cfg.runtime == nil || len(shares) == 0 {
		return
	}
	for _, share := range shares {
		cfg.runtime.cachePreparedARCShare(share)
	}
}

func AdmitAgg(
	cfg Config,
	rlo *AggRLO,
	apvss APVSS,
	artifacts map[int]*DealerArtifact,
) error {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return err
	}
	if c.runtime == nil {
		return fmt.Errorf("runtime not initialized")
	}
	passed := false
	defer func() {
		c.runtime.recordAdmitAgg(passed)
	}()
	if apvss == nil {
		return fmt.Errorf("nil APVSS provider")
	}
	if _, err := validateAggRLOShape(c, rlo); err != nil {
		return err
	}
	if err := apvss.AVer(c, &rlo.Aggregate, artifacts); err != nil {
		return fmt.Errorf("AggRLO APVSS aggregate verify failed: %w", err)
	}
	if err := validateAggRLOLock(c, rlo, true); err != nil {
		return err
	}
	if err := validateAggRLODigest(rlo); err != nil {
		return err
	}
	passed = true
	c.runtime.rememberValidatedAggRLO(rlo.Digest, fingerprintAggRLO(rlo))
	return nil
}

func AdmitLocallyConstructedAgg(cfg Config, rlo *AggRLO) error {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return err
	}
	if c.runtime == nil {
		return fmt.Errorf("runtime not initialized")
	}
	passed := false
	defer func() {
		c.runtime.recordAdmitAgg(passed)
	}()
	if _, err := validateAggRLOShape(c, rlo); err != nil {
		return err
	}
	if c.runtime.hasValidatedAggRLO(rlo.Digest, fingerprintAggRLO(rlo)) {
		passed = true
		return nil
	}
	if err := validateAggRLOLock(c, rlo, false); err != nil {
		return err
	}
	if err := validateAggRLODigest(rlo); err != nil {
		return err
	}
	passed = true
	c.runtime.rememberValidatedAggRLO(rlo.Digest, fingerprintAggRLO(rlo))
	return nil
}

func validateAggRLOShape(cfg Config, rlo *AggRLO) ([]int, error) {
	if rlo == nil {
		return nil, fmt.Errorf("nil AggRLO")
	}
	if rlo.Header.SID != cfg.SID || rlo.Header.Epoch != cfg.Epoch {
		return nil, fmt.Errorf("AggRLO sid/epoch mismatch")
	}
	dealers, err := validateFinalDealerSet(cfg, rlo.Header.Dealers)
	if err != nil {
		return nil, fmt.Errorf("AggRLO dealer set: %w", err)
	}
	if len(rlo.Aggregate.Dealers) != len(dealers) {
		return nil, fmt.Errorf("AggRLO aggregate dealer count mismatch")
	}
	for i := range dealers {
		if dealers[i] != rlo.Aggregate.Dealers[i] {
			return nil, fmt.Errorf("AggRLO aggregate dealers mismatch at index=%d", i)
		}
	}
	if !bytesEq(rlo.Header.AggregateDigest, rlo.Aggregate.AggregateDigest) {
		return nil, fmt.Errorf("AggRLO aggregate digest mismatch")
	}
	if rlo.Aggregate.Provider == "cv-sapvss" &&
		(len(rlo.Header.PayloadDigest) != 32 || len(rlo.Header.FreshShardRoot) != 32) {
		return nil, fmt.Errorf("CV-sAPVSS AggRLO missing materialized payload binding")
	}
	return dealers, nil
}

func validateFinalDealerSet(cfg Config, dealers []int) ([]int, error) {
	if cfg.Kappa != cfg.FOld+1 {
		return nil, fmt.Errorf("aggregate dealer count must equal f_o+1")
	}
	canonical := sortedUnique(dealers)
	if len(canonical) != len(dealers) {
		return nil, fmt.Errorf("dealers must be unique")
	}
	if len(canonical) != cfg.Kappa {
		return nil, fmt.Errorf("dealer count mismatch: have=%d need=%d", len(canonical), cfg.Kappa)
	}
	oldCommittee := nodeSet(cfg.OldCommittee)
	for _, dealer := range canonical {
		if _, ok := oldCommittee[dealer]; !ok {
			return nil, fmt.Errorf("dealer outside old committee: %d", dealer)
		}
	}
	return canonical, nil
}

func validateAggRLOLock(cfg Config, rlo *AggRLO, strictShares bool) error {
	lockThreshold := len(cfg.runtime.oldOrder) - cfg.FOld
	if lockThreshold <= 0 {
		lockThreshold = 1
	}
	if strings.EqualFold(cfg.AblationMode, "no-agclock") {
		return nil
	}
	if rlo.Lock.Threshold != lockThreshold {
		return fmt.Errorf("AggLock threshold mismatch")
	}
	holders := sortedUnique(rlo.Lock.Holders)
	if len(holders) < rlo.Lock.Threshold {
		return fmt.Errorf("AggLock holders below threshold")
	}
	for _, id := range holders {
		if _, ok := cfg.runtime.oldIndex[id]; !ok {
			return fmt.Errorf("AggLock holder outside old committee: %d", id)
		}
	}
	lockDigest := digestAggHeaderForLock(rlo.Header)
	if strictShares {
		validShares := make(map[int][]byte, len(holders))
		for _, holder := range holders {
			sig, ok := rlo.Lock.ShareSignatures[holder]
			if !ok || len(sig) == 0 {
				continue
			}
			if cfg.runtime.lockSigner.VerifyShare(holder, "RL_AGG_LOCK", lockDigest, sig) {
				validShares[holder] = sig
			}
		}
		if len(validShares) < rlo.Lock.Threshold {
			return fmt.Errorf("AggLock valid shares below threshold")
		}
		recovered, err := cfg.runtime.lockSigner.Recover("RL_AGG_LOCK", lockDigest, validShares)
		if err != nil {
			return fmt.Errorf("AggLock cert recover failed: %w", err)
		}
		if !bytesEq(recovered, rlo.Lock.Certificate) {
			return fmt.Errorf("AggLock certificate mismatch")
		}
	}
	if !cfg.runtime.lockSigner.VerifyRecovered("RL_AGG_LOCK", lockDigest, rlo.Lock.Certificate) {
		return fmt.Errorf("AggLock recovered header-only obligation signature invalid")
	}
	return nil
}

func validateAggRLODigest(rlo *AggRLO) error {
	if !bytesEq(rlo.Digest, digestAggRLO(*rlo)) {
		return fmt.Errorf("AggRLO digest mismatch")
	}
	return nil
}

func digestAggHeaderForLock(h AggHeader) []byte {
	return hashBytes(
		[]byte("aggrlo-lock-digest"),
		[]byte(h.SID),
		[]byte(fmt.Sprintf("|epoch=%d", h.Epoch)),
		encodeInts(h.Dealers),
		h.AggregateDigest,
		h.PayloadDigest,
		h.FreshShardRoot,
		h.MetadataHash,
	)
}

func digestAggRLO(r AggRLO) []byte {
	holders := sortedUnique(r.Lock.Holders)
	digestParts := make([][]byte, 0, 9+2*len(holders))
	digestParts = append(digestParts,
		[]byte("aggrlo"),
		[]byte(r.Header.SID),
		[]byte(fmt.Sprintf("|epoch=%d", r.Header.Epoch)),
		encodeInts(r.Header.Dealers),
		r.Header.AggregateDigest,
		r.Header.PayloadDigest,
		r.Header.FreshShardRoot,
		r.Header.MetadataHash,
		[]byte(r.Aggregate.Provider),
		encodeInts(r.Aggregate.Dealers),
		r.Aggregate.AggregateDigest,
	)
	digestParts = append(digestParts,
		encodeInts(holders),
		[]byte(fmt.Sprintf("|threshold=%d", r.Lock.Threshold)),
		r.Lock.Certificate,
	)
	for _, holder := range holders {
		digestParts = append(digestParts, []byte(fmt.Sprintf("|holder=%d", holder)))
		digestParts = append(digestParts, r.Lock.ShareSignatures[holder])
	}
	return hashBytes(digestParts...)
}

func fingerprintAggRLO(r *AggRLO) []byte {
	if r == nil {
		return nil
	}
	holders := sortedUnique(r.Lock.Holders)
	parts := make([][]byte, 0, 16+2*len(holders))
	parts = append(parts,
		[]byte("aggrlo-fingerprint"),
		[]byte(r.Header.SID),
		[]byte(fmt.Sprintf("|epoch=%d", r.Header.Epoch)),
		encodeInts(r.Header.Dealers),
		r.Header.AggregateDigest,
		r.Header.PayloadDigest,
		r.Header.FreshShardRoot,
		r.Header.MetadataHash,
		[]byte(r.Aggregate.Provider),
		encodeInts(r.Aggregate.Dealers),
		r.Aggregate.AggregateDigest,
		[]byte(fmt.Sprintf("|lock-threshold=%d", r.Lock.Threshold)),
		encodeInts(holders),
		r.Lock.Certificate,
		r.Digest,
	)
	for _, holder := range holders {
		parts = append(parts, []byte(fmt.Sprintf("|holder=%d", holder)))
		parts = append(parts, r.Lock.ShareSignatures[holder])
	}
	if tx := r.Aggregate.ListTranscript; tx != nil {
		dealers := sortedUnique(tx.Dealers)
		parts = append(parts,
			[]byte("list-backed"),
			encodeInts(dealers),
			tx.AggregateDigest,
		)
		for _, dealer := range dealers {
			parts = append(parts, []byte(fmt.Sprintf("|list-dealer=%d", dealer)))
			parts = append(parts, tx.ContributionDigests[dealer])
		}
	}
	if tx := r.Aggregate.BlsPVSSTranscript; tx != nil {
		dealers := sortedUnique(tx.Dealers)
		parts = append(parts,
			[]byte("bls-pvss"),
			encodeInts(dealers),
			g1Bytes(&tx.AggregatedZeta),
		)
		for _, c := range tx.AggregatedCommitments {
			cc := c
			parts = append(parts, g1Bytes(&cc))
		}
		for _, e := range tx.AggregatedEncryptedShares {
			ee := e
			parts = append(parts, g2Bytes(&ee))
		}
		for _, dealer := range dealers {
			if per, ok := tx.PerDealer[dealer]; ok && per != nil {
				parts = append(parts, []byte(fmt.Sprintf("|bls-dealer=%d", dealer)))
				parts = append(parts, marshalBlsPVSSDealerTranscript(per))
			}
		}
	}
	return hashBytes(parts...)
}
