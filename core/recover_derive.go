package core

import (
	"fmt"
	"runtime"
	"sort"
	"sync"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

func RecoverAndDerive(
	cfg Config,
	lockedSet []int,
	artifacts map[int]*DealerArtifact,
) ([]int, map[int][]byte, map[int][]byte, []byte, error) {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, nil, nil, nil, err
	}
	if c.runtime == nil {
		return nil, nil, nil, nil, fmt.Errorf("runtime not initialized")
	}
	if len(lockedSet) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("empty locked set")
	}
	sortedLocked := stableFirst(lockedSet, len(lockedSet))
	// ARL-ADKR: process ALL locked dealers, not a κ-sample.
	// The AggRLO carries a header-only recoverability obligation via AggLock;
	// Recover has already bound that obligation to a verified aggregate object.
	// Safety then follows from the combinatorial fact that |S|=n-f contains
	// f+1 honest dealers — no statistical sampling needed.
	dealers := sortedLocked
	sort.Ints(dealers)

	suite := edwards25519.NewBlakeSHA256Ed25519()
	receiverShares := make(map[int]kyber.Scalar, len(c.runtime.receiverOrder))
	for _, receiver := range c.runtime.receiverOrder {
		receiverShares[receiver] = suite.Scalar().Zero()
	}
	aggCommit := suite.Point().Null()

	recovered := make(map[int][]byte, len(dealers))
	minOpeners := c.F + 1
	if minOpeners <= 0 {
		minOpeners = 1
	}
	if minOpeners > len(c.runtime.receiverOrder) {
		minOpeners = len(c.runtime.receiverOrder)
	}

	// Process dealers in parallel.
	numWorkers := runtime.GOMAXPROCS(0)
	if numWorkers < 1 {
		numWorkers = 4
	}
	if numWorkers > len(dealers) {
		numWorkers = len(dealers)
	}

	dealerCh := make(chan int, len(dealers))
	resultCh := make(chan dealerResult, len(dealers))
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for dealer := range dealerCh {
				res := processDealer(c, dealer, artifacts[dealer], minOpeners)
				resultCh <- res
			}
		}()
	}

	for _, d := range dealers {
		dealerCh <- d
	}
	close(dealerCh)
	wg.Wait()
	close(resultCh)

	var mu sync.Mutex
	for res := range resultCh {
		if res.err != nil {
			return nil, nil, nil, nil, res.err
		}
		mu.Lock()
		recovered[res.dealer] = res.recovered
		aggCommit = aggCommit.Add(aggCommit, res.commit)
		for receiver, share := range res.shares {
			receiverShares[receiver].Add(receiverShares[receiver], share)
		}
		mu.Unlock()
	}

	newShares := make(map[int][]byte, len(c.runtime.receiverOrder))
	for _, receiver := range c.runtime.receiverOrder {
		raw, err := receiverShares[receiver].MarshalBinary()
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("marshal receiver share failed: receiver=%d", receiver)
		}
		newShares[receiver] = raw
	}
	newPublicKey, err := aggCommit.MarshalBinary()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("marshal new public key failed: %w", err)
	}
	return dealers, recovered, newShares, newPublicKey, nil
}

func RecoverAndDeriveFromAggRLO(
	cfg Config,
	recoverOut *RecoverAggOutput,
	artifacts map[int]*DealerArtifact,
) ([]int, map[int][]byte, map[int][]byte, []byte, error) {
	c := NormalizeConfig(cfg)
	apvss := newAPVSSFromConfig(c)
	if err := validateAPVSSDeriveMode(c, apvss); err != nil {
		return nil, nil, nil, nil, err
	}
	if recoverOut == nil || recoverOut.AggRLO == nil {
		return nil, nil, nil, nil, fmt.Errorf("nil recover aggregate output")
	}
	if recoverOut.Recovered == nil {
		return nil, nil, nil, nil, fmt.Errorf("nil recovered aggregate material")
	}
	if c.DeriveMode == "scalar" {
		return recoverAndDeriveScalar(c, recoverOut, artifacts)
	}
	if c.DeriveMode == "aggregate" {
		return RecoverAndDeriveAggregate(c, recoverOut, artifacts)
	}
	dealers := sortedUnique(recoverOut.AggRLO.Header.Dealers)
	agg, err := apvss.Agg(c, dealers, artifacts)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if !bytesEq(agg.AggregateDigest, recoverOut.AggRLO.Header.AggregateDigest) {
		return nil, nil, nil, nil, fmt.Errorf("aggregate digest binding mismatch")
	}
	rec, err := apvss.Rec(c, agg, artifacts)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if !bytesEq(rec.RecoveredMaterial, recoverOut.Recovered.RecoveredMaterial) {
		return nil, nil, nil, nil, fmt.Errorf("recovered aggregate material binding mismatch")
	}
	return RecoverAndDerive(c, recoverOut.AggRLO.Header.Dealers, artifacts)
}

func recoverAndDeriveScalar(
	cfg Config,
	recoverOut *RecoverAggOutput,
	artifacts map[int]*DealerArtifact,
) ([]int, map[int][]byte, map[int][]byte, []byte, error) {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, nil, nil, nil, err
	}
	if c.APVSSProvider != "scalar-shamir" {
		return nil, nil, nil, nil, fmt.Errorf("direct scalar derivation requires scalar-shamir provider")
	}
	dealers, err := validateAggRLOShape(c, recoverOut.AggRLO)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err := validateAggRLOLock(c, recoverOut.AggRLO, true); err != nil {
		return nil, nil, nil, nil, err
	}
	if err := validateAggRLODigest(recoverOut.AggRLO); err != nil {
		return nil, nil, nil, nil, err
	}
	if err := NewScalarShamirAPVSS().AVer(c, &recoverOut.AggRLO.Aggregate, artifacts); err != nil {
		return nil, nil, nil, nil, err
	}

	recovered := recoverOut.Recovered
	if recovered.OutputKind != APVSSOutputScalar {
		return nil, nil, nil, nil, fmt.Errorf("scalar recovered output kind mismatch: %s", recovered.OutputKind)
	}
	if !bytesEq(recovered.AggregateDigest, recoverOut.AggRLO.Header.AggregateDigest) {
		return nil, nil, nil, nil, fmt.Errorf("scalar recovered aggregate digest mismatch")
	}
	expectedThreshold := dealerShareThreshold(c, len(c.runtime.receiverOrder))
	if expectedThreshold == 0 || recovered.ScalarThreshold != expectedThreshold {
		return nil, nil, nil, nil, fmt.Errorf(
			"scalar recovered threshold mismatch: have=%d need=%d",
			recovered.ScalarThreshold,
			expectedThreshold,
		)
	}
	list := recoverOut.AggRLO.Aggregate.ListTranscript
	if list == nil {
		return nil, nil, nil, nil, fmt.Errorf("missing scalar list-backed aggregate transcript")
	}
	if len(recovered.ContributionDigests) != len(list.ContributionDigests) {
		return nil, nil, nil, nil, fmt.Errorf("scalar recovered contribution count mismatch")
	}
	for _, dealer := range dealers {
		if !bytesEq(recovered.ContributionDigests[dealer], list.ContributionDigests[dealer]) {
			return nil, nil, nil, nil, fmt.Errorf("scalar recovered contribution mismatch for dealer=%d", dealer)
		}
	}

	if len(recovered.ScalarShares) != len(c.runtime.receiverOrder) {
		return nil, nil, nil, nil, fmt.Errorf(
			"scalar recovered receiver count mismatch: have=%d need=%d",
			len(recovered.ScalarShares),
			len(c.runtime.receiverOrder),
		)
	}
	suite := edwards25519.NewBlakeSHA256Ed25519()
	for _, receiver := range c.runtime.receiverOrder {
		raw, ok := recovered.ScalarShares[receiver]
		if !ok || len(raw) == 0 {
			return nil, nil, nil, nil, fmt.Errorf("missing scalar recovered share for receiver=%d", receiver)
		}
		scalar := suite.Scalar()
		if err := scalar.UnmarshalBinary(raw); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("invalid scalar recovered share for receiver=%d: %w", receiver, err)
		}
		canonical, err := scalar.MarshalBinary()
		if err != nil || !bytesEq(raw, canonical) {
			return nil, nil, nil, nil, fmt.Errorf("non-canonical scalar recovered share for receiver=%d", receiver)
		}
	}

	publicKey := suite.Point()
	if err := publicKey.UnmarshalBinary(recovered.ThresholdPublicKey); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("invalid scalar threshold public key: %w", err)
	}
	canonicalPublicKey, err := publicKey.MarshalBinary()
	if err != nil || !bytesEq(recovered.ThresholdPublicKey, canonicalPublicKey) {
		return nil, nil, nil, nil, fmt.Errorf("non-canonical scalar threshold public key")
	}
	if publicKey.Equal(suite.Point().Null()) {
		return nil, nil, nil, nil, fmt.Errorf("scalar threshold public key is identity")
	}
	eight := suite.Scalar().SetInt64(8)
	inverseEight := suite.Scalar().Inv(eight)
	projected := suite.Point().Mul(inverseEight, suite.Point().Mul(eight, publicKey))
	if !projected.Equal(publicKey) {
		return nil, nil, nil, nil, fmt.Errorf("scalar threshold public key is outside prime-order subgroup")
	}

	expectedMaterial := scalarShamirRecoveredMaterialHash(
		recovered.AggregateDigest,
		recovered.ScalarThreshold,
		dealers,
		recovered.ContributionDigests,
		c.runtime.receiverOrder,
		recovered.ScalarShares,
		recovered.ThresholdPublicKey,
	)
	if !bytesEq(recovered.RecoveredMaterial, expectedMaterial) {
		return nil, nil, nil, nil, fmt.Errorf("scalar recovered material digest mismatch")
	}

	return append([]int(nil), dealers...),
		map[int][]byte{-1: append([]byte(nil), recovered.RecoveredMaterial...)},
		cloneBytesMap(recovered.ScalarShares),
		append([]byte(nil), recovered.ThresholdPublicKey...),
		nil
}

func RecoverAndDeriveAggregate(
	cfg Config,
	recoverOut *RecoverAggOutput,
	artifacts map[int]*DealerArtifact,
) ([]int, map[int][]byte, map[int][]byte, []byte, error) {
	if recoverOut == nil || recoverOut.AggRLO == nil {
		return nil, nil, nil, nil, fmt.Errorf("nil recover aggregate output")
	}
	if recoverOut.Recovered == nil || len(recoverOut.Recovered.RecoveredMaterial) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("nil recovered aggregate material")
	}
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, nil, nil, nil, err
	}
	if c.runtime == nil {
		return nil, nil, nil, nil, fmt.Errorf("runtime not initialized")
	}
	dealers := sortedUnique(recoverOut.AggRLO.Header.Dealers)
	if !bytesEq(recoverOut.Recovered.AggregateDigest, recoverOut.AggRLO.Header.AggregateDigest) {
		return nil, nil, nil, nil, fmt.Errorf("recovered aggregate digest mismatch")
	}

	newShares := make(map[int][]byte, len(c.runtime.receiverOrder))
	recovered := map[int][]byte{
		-1: append([]byte(nil), recoverOut.Recovered.RecoveredMaterial...),
	}
	for _, receiver := range c.runtime.receiverOrder {
		newShares[receiver] = hashBytes(
			[]byte("arladkr-aggregate-share"),
			[]byte(c.SID),
			[]byte(fmt.Sprintf("|epoch=%d|receiver=%d", c.Epoch, receiver)),
			recoverOut.AggRLO.Digest,
			recoverOut.Recovered.RecoveredMaterial,
		)
	}
	newPublicKey := hashBytes(
		[]byte("arladkr-aggregate-public-key"),
		[]byte(c.SID),
		[]byte(fmt.Sprintf("|epoch=%d", c.Epoch)),
		recoverOut.AggRLO.Digest,
		recoverOut.Recovered.RecoveredMaterial,
	)
	return dealers, recovered, newShares, newPublicKey, nil
}

type dealerResult struct {
	dealer       int
	recovered    []byte
	commit       kyber.Point
	shares       map[int]kyber.Scalar
	validOpeners int
	err          error
}

func processDealer(
	cfg Config,
	dealer int,
	art *DealerArtifact,
	minOpeners int,
) dealerResult {
	res := dealerResult{dealer: dealer, shares: make(map[int]kyber.Scalar)}
	if art == nil {
		res.err = fmt.Errorf("dealer %d: missing artifact", dealer)
		return res
	}
	if !bytesEq(hashBytes([]byte("rladkr-root"), art.Payload), art.Descriptor.Header.Root) {
		res.err = fmt.Errorf("dealer %d: payload root mismatch", dealer)
		return res
	}
	transcript, err := decodeDealerTranscript(art.Payload)
	if err != nil {
		res.err = fmt.Errorf("dealer %d: transcript decode: %w", dealer, err)
		return res
	}
	if transcript.Dealer != dealer {
		res.err = fmt.Errorf("dealer %d: transcript mismatch", dealer)
		return res
	}
	suite := edwards25519.NewBlakeSHA256Ed25519()
	recvOrder := cfg.runtime.receiverOrder
	threshold := dealerShareThreshold(cfg, len(recvOrder))
	if threshold == 0 {
		res.err = fmt.Errorf("dealer %d: invalid share threshold", dealer)
		return res
	}
	if transcript.Threshold != threshold {
		res.err = fmt.Errorf("dealer %d: threshold mismatch", dealer)
		return res
	}

	transcriptDigest := hashBytes([]byte("rladkr-transcript-digest"), transcript.Raw)
	for _, receiver := range recvOrder {
		ct, ok := art.Ciphertexts[receiver]
		if !ok || len(ct) == 0 {
			continue
		}
		plain, decErr := openSharePacketForReceiver(cfg, dealer, receiver, art.Descriptor.Header.Root, ct)
		if decErr != nil {
			continue
		}
		sharePacket, parseErr := decodeDealerSharePacket(plain)
		zeroBytes(plain)
		if parseErr != nil {
			continue
		}
		expectedProvider, expectedVersion := expectedDealerShareSchema(cfg)
		if sharePacket.Provider != expectedProvider || sharePacket.Version != expectedVersion {
			continue
		}
		if sharePacket.Dealer != dealer || sharePacket.Receiver != receiver {
			continue
		}
		expectedIndex, ok := cfg.runtime.receiverIndex[receiver]
		if !ok || sharePacket.ShareIndex != expectedIndex {
			continue
		}
		if !bytesEq(sharePacket.TranscriptDigest, transcriptDigest) {
			continue
		}
		if !containsInt(transcript.ReceiverIDs, receiver) {
			continue
		}
		if !transcript.PubPoly.Check(&share.PriShare{I: sharePacket.ShareIndex, V: sharePacket.ShareValue}) {
			continue
		}
		res.shares[receiver] = suite.Scalar().Set(sharePacket.ShareValue)
		res.validOpeners++
	}
	if res.validOpeners < minOpeners {
		res.err = fmt.Errorf("dealer %d: recoverability threshold not met (have=%d need=%d)", dealer, res.validOpeners, minOpeners)
		return res
	}
	res.recovered = append([]byte(nil), transcript.Raw...)
	res.commit = transcript.PubPoly.Commit()
	return res
}

func containsInt(v []int, target int) bool {
	for _, n := range v {
		if n == target {
			return true
		}
	}
	return false
}
