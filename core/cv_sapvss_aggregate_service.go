package core

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

const (
	cvNetworkAggHeaderDomain   = "ARL-CV-sAPVSS/network-aggregate-header"
	cvFreshShardArtifactDomain = "ARL-CV-sAPVSS/fresh-shard-artifact"
	cvAggregateOfferDomain     = "ARL-CV-sAPVSS/aggregate-manifest-offer"
	cvARCShareDomain           = "ARL-CV-sAPVSS/arc-share"
	cvARCCertificateDomain     = "ARL-CV-sAPVSS/arc-certificate"
	cvRecoverGetDomain         = "ARL-CV-sAPVSS/recover-get"
	cvMaxAggregateShards       = 1 << 16
)

type cvFreshShardArtifact struct {
	headerDigest  []byte
	nonce         []byte
	dataShards    int
	totalShards   int
	payloadDigest []byte
	root          []byte
	shard         cvAggregateShard
}

// cvAggregateManifestOffer carries only the aggregate header and compact
// component references. The receiver reconstructs the aggregate and its own
// deterministic RS shard from its verified leaf cache.
type cvAggregateManifestOffer struct {
	header      AggHeader
	descriptors []*cvComponentDescriptor
	readyRoot   []byte
	root        []byte
}

func cvComponentManifestRoot(descriptors []*cvComponentDescriptor) ([]byte, error) {
	if len(descriptors) == 0 {
		return nil, fmt.Errorf("empty CV-sAPVSS component manifest")
	}
	parts := make([][]byte, 0, 1+2*len(descriptors))
	parts = append(parts, []byte("ARL-CV-sAPVSS/component-manifest-root"))
	last := -1
	for _, descriptor := range descriptors {
		if descriptor == nil || descriptor.dealer <= last || len(descriptor.leafDigest) != 32 {
			return nil, fmt.Errorf("invalid CV-sAPVSS component manifest entry")
		}
		last = descriptor.dealer
		parts = append(parts, []byte(fmt.Sprintf("|dealer=%d", descriptor.dealer)), descriptor.leafDigest)
	}
	return hashBytes(parts...), nil
}

func cvAggregateManifestOfferCanonicalBytes(offer *cvAggregateManifestOffer) ([]byte, error) {
	if offer == nil || len(offer.readyRoot) != 32 || len(offer.root) != 32 || (len(offer.descriptors) > 0 && len(offer.descriptors) != len(offer.header.Dealers)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate manifest offer")
	}
	headerWire, err := cvNetworkAggHeaderCanonicalBytes(offer.header)
	if err != nil {
		return nil, err
	}
	if len(offer.descriptors) > 0 {
		wantRoot, rootErr := cvComponentManifestRoot(offer.descriptors)
		if rootErr != nil || !bytes.Equal(wantRoot, offer.root) {
			return nil, fmt.Errorf("CV-sAPVSS aggregate manifest root mismatch")
		}
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAggregateOfferDomain))
	_ = cvWriteBytes(&wire, headerWire)
	_ = cvWriteBytes(&wire, offer.readyRoot)
	_ = cvWriteBytes(&wire, offer.root)
	return wire.Bytes(), nil
}

func cvDecodeAggregateManifestOffer(wire []byte, cfg Config) (*cvAggregateManifestOffer, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregateOfferDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateOfferDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate manifest offer domain")
	}
	headerWire, err := r.bytes(1 << 20)
	if err != nil {
		return nil, err
	}
	header, err := cvDecodeNetworkAggHeader(headerWire, cfg)
	if err != nil {
		return nil, err
	}
	readyRoot, err := r.bytes(32)
	if err != nil || len(readyRoot) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate ReadyCert root")
	}
	root, err := r.bytes(32)
	if err != nil || len(root) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate manifest root")
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate manifest framing")
	}
	offer := &cvAggregateManifestOffer{header: header, readyRoot: append([]byte(nil), readyRoot...), root: append([]byte(nil), root...)}
	canonical, err := cvAggregateManifestOfferCanonicalBytes(offer)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS aggregate manifest offer")
	}
	return offer, nil
}

type cvARCShare struct {
	holder       int
	headerDigest []byte
	signature    []byte
}

func cvARCCertificateCanonicalBytes(headerDigest, certificate []byte) ([]byte, error) {
	if len(headerDigest) != 32 || len(certificate) == 0 || len(certificate) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS ARC certificate")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvARCCertificateDomain))
	_ = cvWriteBytes(&wire, headerDigest)
	_ = cvWriteBytes(&wire, certificate)
	return wire.Bytes(), nil
}

func cvDecodeARCCertificate(wire []byte) ([]byte, []byte, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvARCCertificateDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvARCCertificateDomain)) {
		return nil, nil, fmt.Errorf("invalid CV-sAPVSS ARC certificate domain")
	}
	headerDigest, err := r.bytes(32)
	if err != nil || len(headerDigest) != 32 {
		return nil, nil, fmt.Errorf("invalid CV-sAPVSS ARC certificate digest")
	}
	certificate, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(certificate) == 0 || r.reader.Len() != 0 {
		return nil, nil, fmt.Errorf("invalid CV-sAPVSS ARC certificate")
	}
	canonical, err := cvARCCertificateCanonicalBytes(headerDigest, certificate)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, nil, fmt.Errorf("non-canonical CV-sAPVSS ARC certificate")
	}
	return headerDigest, certificate, nil
}

func cvBuildNetworkAggHeader(cfg Config, agg *cvAggregateTranscript, dispersal *cvAggregateDispersal) (AggHeader, error) {
	if err := cvValidateAggregateErasureDimensions(cfg, dispersal); err != nil {
		return AggHeader{}, err
	}
	if err := cvVerifyAggregateDispersal(agg, dispersal); err != nil {
		return AggHeader{}, err
	}
	dealers, err := cvDealerIDsToInts(agg.dealerIDs)
	if err != nil {
		return AggHeader{}, err
	}
	if _, err := validateFinalDealerSet(cfg, dealers); err != nil {
		return AggHeader{}, err
	}
	header := AggHeader{
		SID:             cfg.SID,
		Epoch:           cfg.Epoch,
		Dealers:         append([]int(nil), dealers...),
		AggregateDigest: append([]byte(nil), agg.digest...),
		PayloadDigest:   append([]byte(nil), dispersal.payloadDigest...),
		FreshShardRoot:  append([]byte(nil), dispersal.root...),
	}
	header.MetadataHash = hashBytes(
		[]byte("aggrlo-meta"), []byte(cfg.SID),
		[]byte(fmt.Sprintf("|epoch=%d", cfg.Epoch)), encodeInts(dealers),
		header.AggregateDigest, header.PayloadDigest, header.FreshShardRoot,
	)
	return header, nil
}

func cvNetworkAggHeaderCanonicalBytes(header AggHeader) ([]byte, error) {
	if header.SID == "" || header.Epoch < 0 || len(header.Dealers) == 0 ||
		len(header.AggregateDigest) != 32 || len(header.PayloadDigest) != 32 ||
		len(header.FreshShardRoot) != 32 || len(header.MetadataHash) != 32 ||
		!sort.IntsAreSorted(header.Dealers) {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate header")
	}
	for i, dealer := range header.Dealers {
		if dealer < 0 || (i > 0 && dealer == header.Dealers[i-1]) {
			return nil, fmt.Errorf("invalid CV-sAPVSS aggregate dealer order")
		}
	}
	wantMetadata := hashBytes(
		[]byte("aggrlo-meta"), []byte(header.SID),
		[]byte(fmt.Sprintf("|epoch=%d", header.Epoch)), encodeInts(header.Dealers),
		header.AggregateDigest, header.PayloadDigest, header.FreshShardRoot,
	)
	if !bytes.Equal(wantMetadata, header.MetadataHash) {
		return nil, fmt.Errorf("CV-sAPVSS aggregate header metadata mismatch")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvNetworkAggHeaderDomain))
	_ = cvWriteBytes(&wire, []byte(header.SID))
	cvWriteUint64(&wire, uint64(header.Epoch))
	_ = cvWriteUint32(&wire, len(header.Dealers))
	for _, dealer := range header.Dealers {
		cvWriteUint64(&wire, uint64(dealer))
	}
	for _, field := range [][]byte{header.AggregateDigest, header.PayloadDigest, header.FreshShardRoot, header.MetadataHash} {
		_ = cvWriteBytes(&wire, field)
	}
	return wire.Bytes(), nil
}

func cvDecodeNetworkAggHeader(wire []byte, cfg Config) (AggHeader, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvNetworkAggHeaderDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvNetworkAggHeaderDomain)) {
		return AggHeader{}, fmt.Errorf("invalid CV-sAPVSS aggregate header domain")
	}
	sid, err := r.bytes(cvMaxNetworkEnvelopeSIDBytes)
	if err != nil || string(sid) != cfg.SID {
		return AggHeader{}, fmt.Errorf("CV-sAPVSS aggregate header SID mismatch")
	}
	epoch, err := r.uint64()
	if err != nil || epoch != uint64(cfg.Epoch) {
		return AggHeader{}, fmt.Errorf("CV-sAPVSS aggregate header epoch mismatch")
	}
	dealerCount, err := r.uint32()
	if err != nil || dealerCount != cfg.FOld+1 || dealerCount > len(cfg.OldCommittee) {
		return AggHeader{}, fmt.Errorf("invalid CV-sAPVSS aggregate dealer count")
	}
	oldSet := nodeSet(cfg.OldCommittee)
	dealers := make([]int, dealerCount)
	for i := range dealers {
		dealer, readErr := r.uint64()
		if readErr != nil || dealer > uint64(^uint(0)>>1) {
			return AggHeader{}, fmt.Errorf("invalid CV-sAPVSS aggregate dealer")
		}
		dealers[i] = int(dealer)
		if _, ok := oldSet[dealers[i]]; !ok || (i > 0 && dealers[i] <= dealers[i-1]) {
			return AggHeader{}, fmt.Errorf("invalid CV-sAPVSS aggregate dealer order")
		}
	}
	fields := make([][]byte, 4)
	for i := range fields {
		fields[i], err = r.bytes(32)
		if err != nil || len(fields[i]) != 32 {
			return AggHeader{}, fmt.Errorf("invalid CV-sAPVSS aggregate header digest")
		}
	}
	if r.reader.Len() != 0 {
		return AggHeader{}, fmt.Errorf("trailing CV-sAPVSS aggregate header bytes")
	}
	header := AggHeader{SID: string(sid), Epoch: int(epoch), Dealers: dealers,
		AggregateDigest: fields[0], PayloadDigest: fields[1], FreshShardRoot: fields[2], MetadataHash: fields[3]}
	canonical, err := cvNetworkAggHeaderCanonicalBytes(header)
	if err != nil || !bytes.Equal(canonical, wire) {
		return AggHeader{}, fmt.Errorf("non-canonical CV-sAPVSS aggregate header")
	}
	return header, nil
}

func cvFreshShardArtifactCanonicalBytes(artifact *cvFreshShardArtifact) ([]byte, error) {
	if artifact == nil || len(artifact.headerDigest) != 32 || len(artifact.nonce) != 32 ||
		artifact.dataShards <= 0 || artifact.totalShards < artifact.dataShards ||
		artifact.totalShards > cvMaxAggregateShards || len(artifact.payloadDigest) != 32 ||
		len(artifact.root) != 32 || artifact.shard.index < 0 ||
		artifact.shard.index >= artifact.totalShards || len(artifact.shard.payload) == 0 ||
		len(artifact.shard.payload) > cvMaxNetworkPayloadBytes {
		return nil, fmt.Errorf("invalid CV-sAPVSS fresh shard artifact")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvFreshShardArtifactDomain))
	for _, field := range [][]byte{artifact.headerDigest, artifact.nonce, artifact.payloadDigest, artifact.root} {
		_ = cvWriteBytes(&wire, field)
	}
	_ = cvWriteUint32(&wire, artifact.dataShards)
	_ = cvWriteUint32(&wire, artifact.totalShards)
	_ = cvWriteUint32(&wire, artifact.shard.index)
	_ = cvWriteBytes(&wire, artifact.shard.payload)
	_ = cvWriteUint32(&wire, len(artifact.shard.siblings))
	for _, sibling := range artifact.shard.siblings {
		if len(sibling) != 32 {
			return nil, fmt.Errorf("invalid CV-sAPVSS fresh shard branch")
		}
		_ = cvWriteBytes(&wire, sibling)
	}
	return wire.Bytes(), nil
}

func cvDecodeFreshShardArtifact(wire []byte, cfg Config, header AggHeader) (*cvFreshShardArtifact, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvFreshShardArtifactDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvFreshShardArtifactDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS fresh shard artifact domain")
	}
	fields := make([][]byte, 4)
	for i := range fields {
		fields[i], err = r.bytes(32)
		if err != nil || len(fields[i]) != 32 {
			return nil, fmt.Errorf("invalid CV-sAPVSS fresh shard artifact digest")
		}
	}
	dataShards, err := r.uint32()
	if err != nil {
		return nil, err
	}
	totalShards, err := r.uint32()
	if err != nil {
		return nil, err
	}
	index, err := r.uint32()
	if err != nil {
		return nil, err
	}
	payload, err := r.bytes(cvMaxNetworkPayloadBytes)
	if err != nil || len(payload) == 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS fresh shard payload")
	}
	siblingCount, err := r.uint32()
	if err != nil || siblingCount > 64 {
		return nil, fmt.Errorf("invalid CV-sAPVSS fresh shard branch count")
	}
	siblings := make([][]byte, siblingCount)
	for i := range siblings {
		siblings[i], err = r.bytes(32)
		if err != nil || len(siblings[i]) != 32 {
			return nil, fmt.Errorf("invalid CV-sAPVSS fresh shard branch")
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV-sAPVSS fresh shard artifact bytes")
	}
	artifact := &cvFreshShardArtifact{headerDigest: fields[0], nonce: fields[1],
		payloadDigest: fields[2], root: fields[3], dataShards: dataShards,
		totalShards: totalShards, shard: cvAggregateShard{index: index, payload: payload, siblings: siblings}}
	if err := cvVerifyFreshShardArtifact(cfg, header, artifact); err != nil {
		return nil, err
	}
	canonical, err := cvFreshShardArtifactCanonicalBytes(artifact)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS fresh shard artifact")
	}
	return artifact, nil
}

func cvVerifyFreshShardArtifact(cfg Config, header AggHeader, artifact *cvFreshShardArtifact) error {
	n := len(sortedUnique(cfg.OldCommittee))
	if artifact == nil || artifact.totalShards != n || artifact.dataShards != n-2*cfg.FOld ||
		!bytes.Equal(artifact.headerDigest, digestAggHeaderForLock(header)) ||
		!bytes.Equal(artifact.payloadDigest, header.PayloadDigest) ||
		!bytes.Equal(artifact.root, header.FreshShardRoot) {
		return fmt.Errorf("CV-sAPVSS fresh shard does not match aggregate header")
	}
	dispersal := &cvAggregateDispersal{nonce: artifact.nonce, dataShards: artifact.dataShards,
		payloadDigest: artifact.payloadDigest, root: artifact.root, shards: make([]cvAggregateShard, n)}
	dispersal.shards[artifact.shard.index] = artifact.shard
	return cvVerifyAggregateShard(dispersal, &artifact.shard)
}

type cvMaterializeAttempt struct {
	value *cvMaterializedAggregate
	err   error
}

// MaterializeFirstCertified tracks canonical-prefix reselections and returns
// the first aggregate that obtains a recovered ARC certificate. A slow first
// candidate must not prevent a later converged ReadyCert root from driving the
// epoch into MVBA.
func (s *cvComponentService) MaterializeFirstCertified(
	ctx context.Context,
	initial []*cvComponentDescriptor,
) (*cvMaterializedAggregate, error) {
	if ctx == nil || len(initial) != len(s.cfg.OldCommittee)-s.cfg.FOld {
		return nil, fmt.Errorf("invalid CV-sAPVSS initial materialization candidate")
	}
	candidateCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
	}()
	results := make(chan cvMaterializeAttempt, len(s.cfg.OldCommittee)+2)
	seen := make(map[string]struct{}, len(s.cfg.OldCommittee)+1)
	launch := func(descriptors []*cvComponentDescriptor) {
		certificate, err := cvBuildComponentReadyCertificate(s.localNode, descriptors)
		if err != nil {
			return
		}
		key := fmt.Sprintf("%x", certificate.root)
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		candidate := append([]*cvComponentDescriptor(nil), descriptors...)
		workers.Add(1)
		go func() {
			defer workers.Done()
			value, materializeErr := s.MaterializeAndCollectARC(candidateCtx, candidate)
			select {
			case results <- cvMaterializeAttempt{value: value, err: materializeErr}:
			case <-candidateCtx.Done():
			}
		}()
	}
	launch(initial)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case result := <-results:
			if result.err == nil && result.value != nil {
				return result.value, nil
			}
		case descriptors := <-s.readyCandidates:
			// Coalesce roots already queued before spending another aggregate
			// verification on an intermediate canonical prefix.
		drain:
			for {
				select {
				case newer := <-s.readyCandidates:
					descriptors = newer
				default:
					break drain
				}
			}
			launch(descriptors)
		}
	}
}

func (s *cvComponentService) MaterializeAndCollectARC(ctx context.Context, descriptors []*cvComponentDescriptor) (*cvMaterializedAggregate, error) {
	metrics := cvAggregateMaterializeMetrics{}
	want := s.cfg.FOld + 1
	ready := len(s.cfg.OldCommittee) - s.cfg.FOld
	if ctx == nil || len(descriptors) != ready {
		return nil, fmt.Errorf("CV-sAPVSS network materializer requires one n_o-f_o ReadyCert pool")
	}
	readyCertificate, err := cvBuildComponentReadyCertificate(s.localNode, descriptors)
	if err != nil {
		return nil, err
	}
	readyKey := fmt.Sprintf("%x", readyCertificate.root)
	s.mu.Lock()
	_, readyAccepted := s.acceptedReadyRoots[readyKey]
	s.mu.Unlock()
	if !readyAccepted {
		return nil, fmt.Errorf("CV-sAPVSS materializer pool is not backed by an accepted ReadyCert")
	}
	phaseStart := time.Now()
	s.aggregateBuildMu.Lock()
	metrics.gateWait = time.Since(phaseStart)
	aggregateBuildLocked := true
	defer func() {
		if aggregateBuildLocked {
			s.aggregateBuildMu.Unlock()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !s.isCanonicalReadyPool(descriptors) {
		return nil, fmt.Errorf("stale CV-sAPVSS canonical ReadyCert pool")
	}
	selectedDescriptors := make([]*cvComponentDescriptor, 0, want)
	leaves := make([]*cvVerifiedLeaf, 0, want)
	phaseStart = time.Now()
	lastDealer := -1
	for _, descriptor := range descriptors {
		if descriptor == nil || descriptor.dealer <= lastDealer || cvValidateNetworkComponentDescriptor(s.cfg, descriptor) != nil {
			return nil, fmt.Errorf("invalid CV-sAPVSS materializer descriptor set")
		}
		lastDealer = descriptor.dealer
	}
	// A remote offer can finish verification for this exact FirstKValid
	// manifest while the local materializer is waiting for the aggregate build
	// gate. Reuse that verified aggregate instead of serializing and combining
	// the same large leaves again.
	firstDescriptors := descriptors[:want]
	firstRoot, firstRootErr := cvComponentManifestRoot(firstDescriptors)
	var cachedAggregate *cvAggregateTranscript
	if firstRootErr == nil {
		s.mu.Lock()
		cachedAggregate = s.verifiedAggregatesByRoot[fmt.Sprintf("%x", firstRoot)]
		s.mu.Unlock()
		if !cvAggregateMatchesDescriptors(cachedAggregate, firstDescriptors) {
			cachedAggregate = nil
		}
	}
	type loadResult struct {
		index int
		leaf  *cvVerifiedLeaf
	}
	for cursor := 0; cachedAggregate == nil && len(leaves) < want && cursor < len(descriptors); {
		batchSize := want - len(leaves)
		end := cursor + batchSize
		if end > len(descriptors) {
			end = len(descriptors)
		}
		results := make(chan loadResult, end-cursor)
		jobs := make(chan int)
		workers := cvComponentLoadWorkers(end - cursor)
		for worker := 0; worker < workers; worker++ {
			go func() {
				for index := range jobs {
					leaf, _ := s.loadOrRetrieveComponent(ctx, descriptors[index])
					results <- loadResult{index: index, leaf: leaf}
				}
			}()
		}
		for index := cursor; index < end; index++ {
			jobs <- index
		}
		close(jobs)
		loaded := make([]*cvVerifiedLeaf, end-cursor)
		for range loaded {
			result := <-results
			loaded[result.index-cursor] = result.leaf
		}
		for offset, leaf := range loaded {
			if leaf == nil {
				continue
			}
			selectedDescriptors = append(selectedDescriptors, descriptors[cursor+offset])
			leaves = append(leaves, leaf)
		}
		cursor = end
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !s.isCanonicalReadyPool(descriptors) {
			return nil, fmt.Errorf("stale CV-sAPVSS canonical ReadyCert pool")
		}
	}
	if cachedAggregate != nil {
		selectedDescriptors = append(selectedDescriptors, firstDescriptors...)
	} else if len(leaves) != want {
		return nil, fmt.Errorf("CV-sAPVSS materializer found %d valid leaves, need %d", len(leaves), want)
	}
	metrics.leafLoad = time.Since(phaseStart)
	phaseStart = time.Now()
	agg := cachedAggregate
	if agg == nil {
		agg, err = cvAggServiceVerified(s.leafCtx, leaves)
		if err != nil {
			return nil, err
		}
	}
	metrics.aggregate = time.Since(phaseStart)
	manifestRoot, err := cvComponentManifestRoot(selectedDescriptors)
	if err != nil {
		return nil, err
	}
	manifestKey := fmt.Sprintf("%x", manifestRoot)
	s.mu.Lock()
	if existing := s.verifiedAggregatesByRoot[manifestKey]; existing != nil && !bytes.Equal(existing.digest, agg.digest) {
		s.mu.Unlock()
		return nil, fmt.Errorf("conflicting verified CV-sAPVSS manifest aggregate cache entry")
	}
	s.verifiedAggregatesByRoot[manifestKey] = agg
	s.mu.Unlock()
	n := len(s.cfg.OldCommittee)
	phaseStart = time.Now()
	dispersalKey := fmt.Sprintf("%x", agg.digest)
	s.mu.Lock()
	dispersal := s.verifiedDispersals[dispersalKey]
	s.mu.Unlock()
	if dispersal == nil {
		dispersal, err = cvDisperseAggregate(agg, n, n-2*s.cfg.FOld)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.verifiedDispersals[dispersalKey] = dispersal
		s.mu.Unlock()
	}
	metrics.rsDisperse = time.Since(phaseStart)
	phaseStart = time.Now()
	header, err := cvBuildNetworkAggHeader(s.cfg, agg, dispersal)
	if err != nil {
		return nil, err
	}
	headerDigest := digestAggHeaderForLock(header)
	key := fmt.Sprintf("%x", headerDigest)
	s.mu.Lock()
	if existing := s.verifiedAggregates[key]; existing != nil {
		if !bytes.Equal(existing.digest, agg.digest) {
			s.mu.Unlock()
			return nil, fmt.Errorf("conflicting verified CV-sAPVSS aggregate cache entry")
		}
	} else {
		s.verifiedAggregates[key] = agg
	}
	s.mu.Unlock()
	metrics.headerToken = time.Since(phaseStart)
	s.aggregateBuildMu.Unlock()
	aggregateBuildLocked = false
	pending := &cvPendingARCShare{values: make(chan cvARCShare, n), certificates: make(chan []byte, 1)}
	s.mu.Lock()
	if _, exists := s.pendingARCs[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV-sAPVSS ARC collection already active")
	}
	s.pendingARCs[key] = pending
	// Read the certificate cache while publishing the pending collector. This
	// closes the race where a valid certificate arrived between a cache lookup
	// and pending registration and would otherwise leave the collector asleep.
	existingCertificate := append([]byte(nil), s.aggregateCertificates[key]...)
	s.mu.Unlock()
	if len(existingCertificate) > 0 {
		pending.certificates <- existingCertificate
	}
	defer func() {
		s.mu.Lock()
		if s.pendingARCs[key] == pending {
			delete(s.pendingARCs, key)
		}
		s.mu.Unlock()
	}()
	oldOrder := sortedUnique(s.cfg.OldCommittee)
	offerWire, err := cvAggregateManifestOfferCanonicalBytes(&cvAggregateManifestOffer{
		header: header, descriptors: selectedDescriptors, readyRoot: readyCertificate.root, root: manifestRoot,
	})
	if err != nil {
		return nil, err
	}
	s.cfg.runtime.setCommPhase("aggregate_disperse")
	phaseStart = time.Now()
	sent := 0
	offerTargets := make([]int, 0, len(oldOrder)-1)
	for _, holder := range oldOrder {
		if holder == s.localNode {
			// The collector materializes its own shard below.
			sent++
			continue
		}
		offerTargets = append(offerTargets, holder)
	}
	sent += s.sendMany(offerTargets, cvTagAggregateManifest, offerWire)
	// The collector is itself an old-committee holder. Some transports do not
	// loop a self-directed offer through the router, so record its verified
	// shard/share locally instead of waiting for a self-message.
	if selfIndex := sort.SearchInts(oldOrder, s.localNode); selfIndex < len(oldOrder) && oldOrder[selfIndex] == s.localNode {
		selfArtifact := cvFreshShardArtifact{headerDigest: append([]byte(nil), headerDigest...),
			nonce: append([]byte(nil), dispersal.nonce...), dataShards: dispersal.dataShards,
			totalShards: len(dispersal.shards), payloadDigest: append([]byte(nil), dispersal.payloadDigest...),
			root: append([]byte(nil), dispersal.root...), shard: dispersal.shards[selfIndex]}
		selfWire, selfErr := cvFreshShardArtifactCanonicalBytes(&selfArtifact)
		if selfErr != nil {
			return nil, selfErr
		}
		if selfErr = s.persistFreshArtifact(headerDigest, selfWire); selfErr != nil {
			return nil, fmt.Errorf("persist local CV-sAPVSS fresh artifact before ARC: %w", selfErr)
		}
		selfSig, selfErr := s.localARCShare(headerDigest)
		if selfErr != nil {
			return nil, selfErr
		}
		pending.values <- cvARCShare{holder: s.localNode, headerDigest: append([]byte(nil), headerDigest...), signature: selfSig}
	}
	threshold := n - s.cfg.FOld
	if sent < threshold {
		return nil, fmt.Errorf("CV-sAPVSS aggregate dispersal reached %d holders, need %d", sent, threshold)
	}
	metrics.offerSend = time.Since(phaseStart)
	s.cfg.runtime.setCommPhase("arc_share")
	phaseStart = time.Now()
	shares := make(map[int][]byte, threshold)
	var certificate []byte
	for len(shares) < threshold && len(certificate) == 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case share := <-pending.values:
			if _, duplicate := shares[share.holder]; !duplicate {
				shares[share.holder] = append([]byte(nil), share.signature...)
			}
		case recovered := <-pending.certificates:
			certificate = append([]byte(nil), recovered...)
		}
	}
	metrics.arcWait = time.Since(phaseStart)
	phaseStart = time.Now()
	if len(certificate) == 0 {
		certificate, err = s.cfg.runtime.lockSigner.Recover("RL_AGG_LOCK", headerDigest, shares)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		if s.aggregateCertificates[key] == nil {
			s.aggregateCertificates[key] = append([]byte(nil), certificate...)
		}
		s.mu.Unlock()
		if certificateWire, certErr := cvARCCertificateCanonicalBytes(headerDigest, certificate); certErr == nil {
			s.sendMany(oldOrder, cvTagARCCertificate, certificateWire)
		}
	}
	rlo := &AggRLO{Header: header, Lock: AggLock{Threshold: threshold, Certificate: certificate}, Aggregate: APVSSAggregate{
		Provider: "cv-sapvss", Dealers: append([]int(nil), header.Dealers...),
		AggregateDigest: append([]byte(nil), header.AggregateDigest...),
	}}
	rlo.Digest = digestAggRLO(*rlo)
	if _, err := validateAggRLOShape(s.cfg, rlo); err != nil {
		return nil, err
	}
	if err := validateAggRLOLock(s.cfg, rlo); err != nil {
		return nil, err
	}
	metrics.certificate = time.Since(phaseStart)
	return &cvMaterializedAggregate{
		rlo: rlo, aggregate: agg, dispersal: dispersal, metrics: metrics,
	}, nil
}

func (s *cvComponentService) handleAggregateOffer(msg Message) {
	if cvPerfCountersEnabled {
		cvPerfCounters.aggregateOffers.Add(1)
	}
	s.backgroundWG.Add(1)
	go func() {
		defer s.backgroundWG.Done()
		manifest, err := cvDecodeAggregateManifestOffer(msg.Body, s.cfg)
		if err != nil {
			return
		}
		readyKey := fmt.Sprintf("%x", manifest.readyRoot)
		s.mu.Lock()
		_, accepted := s.acceptedReadyRoots[readyKey]
		if !accepted {
			// Keep at most one not-yet-resolved offer per authenticated sender.
			// Otherwise arbitrary unknown roots would provide an unbounded memory
			// amplification path before their ReadyCert messages arrive.
			for key, pending := range s.pendingReadyOffers {
				kept := pending[:0]
				for _, candidate := range pending {
					if candidate.From != msg.From {
						kept = append(kept, candidate)
					}
				}
				if len(kept) == 0 {
					delete(s.pendingReadyOffers, key)
				} else {
					s.pendingReadyOffers[key] = kept
				}
			}
			pending := s.pendingReadyOffers[readyKey]
			s.pendingReadyOffers[readyKey] = append(pending, msg)
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		s.handleAggregateManifestOffer(msg, manifest)
	}()
}

func (s *cvComponentService) handleAggregateManifestOffer(msg Message, offer *cvAggregateManifestOffer) {
	if offer == nil {
		return
	}
	key := fmt.Sprintf("%x", digestAggHeaderForLock(offer.header))
	processingKey := fmt.Sprintf("%s/%d", key, msg.From)
	s.mu.Lock()
	if _, exists := s.processingOffers[processingKey]; exists {
		s.mu.Unlock()
		return
	}
	s.processingOffers[processingKey] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.processingOffers, processingKey)
		s.mu.Unlock()
	}()
	oldOrder := sortedUnique(s.cfg.OldCommittee)
	index := sort.SearchInts(oldOrder, s.localNode)
	if index >= len(oldOrder) || oldOrder[index] != s.localNode {
		return
	}
	agg, dispersal, err := s.verifyNetworkAggregateManifestForARC(offer)
	if err != nil {
		return
	}
	headerDigest := digestAggHeaderForLock(offer.header)
	artifact := cvFreshShardArtifact{headerDigest: headerDigest,
		nonce: append([]byte(nil), dispersal.nonce...), dataShards: dispersal.dataShards,
		totalShards: len(dispersal.shards), payloadDigest: append([]byte(nil), dispersal.payloadDigest...),
		root: append([]byte(nil), dispersal.root...), shard: dispersal.shards[index]}
	shardWire, err := cvFreshShardArtifactCanonicalBytes(&artifact)
	if err != nil || s.persistFreshArtifact(artifact.headerDigest, shardWire) != nil {
		return
	}
	_ = agg // aggregate verification is included in verifyAggregateManifestForARC.
	sig, err := s.localARCShare(artifact.headerDigest)
	if err != nil {
		return
	}
	shareWire, err := cvARCShareCanonicalBytes(&cvARCShare{holder: s.localNode, headerDigest: artifact.headerDigest, signature: sig})
	if err == nil {
		_ = s.send(msg.From, cvTagARCShare, shareWire)
	}
}

func (s *cvComponentService) resolveAggregateManifestDescriptors(offer *cvAggregateManifestOffer) error {
	if offer == nil || len(offer.header.Dealers) != s.cfg.FOld+1 || len(offer.readyRoot) != 32 || len(offer.root) != 32 {
		return fmt.Errorf("invalid CV-sAPVSS aggregate manifest reference")
	}
	readyKey := fmt.Sprintf("%x", offer.readyRoot)
	resolvedKey := fmt.Sprintf("%s/%x", readyKey, offer.root)
	s.mu.Lock()
	resolved := append([]*cvComponentDescriptor(nil), s.resolvedAggregateManifests[resolvedKey]...)
	readyPool := append([]*cvComponentDescriptor(nil), s.readyDescriptorsByRoot[readyKey]...)
	s.mu.Unlock()
	if len(resolved) == s.cfg.FOld+1 {
		if !cvDescriptorsMatchDealers(resolved, offer.header.Dealers) {
			return fmt.Errorf("cached aggregate manifest dealers do not match header")
		}
		offer.descriptors = resolved
		return nil
	}
	if len(readyPool) != len(s.cfg.OldCommittee)-s.cfg.FOld {
		return fmt.Errorf("missing accepted CV-sAPVSS ReadyCert pool")
	}
	descriptors := make([]*cvComponentDescriptor, 0, s.cfg.FOld+1)
	for _, descriptor := range readyPool {
		if _, err := s.loadOrRetrieveComponent(s.ctx, descriptor); err != nil {
			continue
		}
		descriptors = append(descriptors, descriptor)
		if len(descriptors) == s.cfg.FOld+1 {
			break
		}
	}
	if len(descriptors) != s.cfg.FOld+1 {
		return fmt.Errorf("ReadyCert pool has insufficient valid CV-sAPVSS components")
	}
	if !cvDescriptorsMatchDealers(descriptors, offer.header.Dealers) {
		return fmt.Errorf("aggregate offer is not ReadyCert FirstKValid")
	}
	root, err := cvComponentManifestRoot(descriptors)
	if err != nil || !bytes.Equal(root, offer.root) {
		return fmt.Errorf("CV-sAPVSS aggregate manifest root does not match local cache")
	}
	s.mu.Lock()
	s.resolvedAggregateManifests[resolvedKey] = append([]*cvComponentDescriptor(nil), descriptors...)
	s.mu.Unlock()
	offer.descriptors = descriptors
	return nil
}

func cvDescriptorsMatchDealers(descriptors []*cvComponentDescriptor, dealers []int) bool {
	if len(descriptors) != len(dealers) {
		return false
	}
	for i, descriptor := range descriptors {
		if descriptor == nil || descriptor.dealer != dealers[i] {
			return false
		}
	}
	return true
}

func cvAggregateMatchesDescriptors(agg *cvAggregateTranscript, descriptors []*cvComponentDescriptor) bool {
	if agg == nil || len(agg.dealerIDs) != len(descriptors) || len(agg.leafDigests) != len(descriptors) {
		return false
	}
	for i, descriptor := range descriptors {
		if descriptor == nil || agg.dealerIDs[i] != uint64(descriptor.dealer) ||
			!bytes.Equal(agg.leafDigests[i], descriptor.leafDigest) {
			return false
		}
	}
	return true
}

func (s *cvComponentService) verifyNetworkAggregateManifestForARC(
	offer *cvAggregateManifestOffer,
) (*cvAggregateTranscript, *cvAggregateDispersal, error) {
	s.aggregateBuildMu.Lock()
	defer s.aggregateBuildMu.Unlock()
	if err := s.resolveAggregateManifestDescriptors(offer); err != nil {
		return nil, nil, err
	}
	return s.verifyAggregateManifestForARCLocked(offer)
}

func (s *cvComponentService) verifyAggregateManifestForARC(offer *cvAggregateManifestOffer) (*cvAggregateTranscript, *cvAggregateDispersal, error) {
	s.aggregateBuildMu.Lock()
	defer s.aggregateBuildMu.Unlock()
	return s.verifyAggregateManifestForARCLocked(offer)
}

func (s *cvComponentService) verifyAggregateManifestForARCLocked(offer *cvAggregateManifestOffer) (*cvAggregateTranscript, *cvAggregateDispersal, error) {
	if offer == nil {
		return nil, nil, fmt.Errorf("nil CV-sAPVSS aggregate manifest offer")
	}
	wantRoot, err := cvComponentManifestRoot(offer.descriptors)
	if err != nil || !bytes.Equal(offer.root, wantRoot) {
		return nil, nil, fmt.Errorf("invalid CV-sAPVSS aggregate manifest references")
	}
	key := fmt.Sprintf("%x", digestAggHeaderForLock(offer.header))
	manifestKey := fmt.Sprintf("%x", wantRoot)
	s.mu.Lock()
	agg := s.verifiedAggregates[key]
	if agg == nil {
		agg = s.verifiedAggregatesByRoot[manifestKey]
	}
	s.mu.Unlock()
	if agg == nil {
		leaves := make([]*cvVerifiedLeaf, len(offer.descriptors))
		for i, descriptor := range offer.descriptors {
			leaf, loadErr := s.loadOrRetrieveComponent(s.ctx, descriptor)
			if loadErr != nil {
				return nil, nil, loadErr
			}
			leaves[i] = leaf
		}
		var buildErr error
		agg, buildErr = cvAggServiceVerified(s.leafCtx, leaves)
		if buildErr != nil {
			return nil, nil, buildErr
		}
	}
	if !cvAggregateMatchesDescriptors(agg, offer.descriptors) || !bytes.Equal(agg.digest, offer.header.AggregateDigest) {
		return nil, nil, fmt.Errorf("aggregate manifest digest mismatch")
	}
	dispersalKey := fmt.Sprintf("%x", agg.digest)
	s.mu.Lock()
	dispersal := s.verifiedDispersals[dispersalKey]
	s.mu.Unlock()
	// The manifest contains no remote aggregate object. Rebuilding the
	// canonical aggregate once is therefore both AVer and local materialization.
	if dispersal == nil {
		dispersal, err = cvDisperseAggregate(agg, len(s.cfg.OldCommittee), len(s.cfg.OldCommittee)-2*s.cfg.FOld)
		if err != nil {
			return nil, nil, err
		}
		s.mu.Lock()
		s.verifiedDispersals[dispersalKey] = dispersal
		s.mu.Unlock()
	}
	if !bytes.Equal(dispersal.root, offer.header.FreshShardRoot) || !bytes.Equal(dispersal.payloadDigest, offer.header.PayloadDigest) {
		return nil, nil, fmt.Errorf("aggregate manifest RS binding mismatch")
	}
	s.mu.Lock()
	if existing := s.verifiedAggregates[key]; existing != nil && !bytes.Equal(existing.digest, agg.digest) {
		s.mu.Unlock()
		return nil, nil, fmt.Errorf("conflicting verified CV-sAPVSS aggregate cache entry")
	}
	s.verifiedAggregates[key] = agg
	s.verifiedAggregatesByRoot[manifestKey] = agg
	s.mu.Unlock()
	return agg, dispersal, nil
}

func (s *cvComponentService) handleARCShare(msg Message) {
	share, err := cvDecodeARCShare(msg.Body)
	if err != nil || share.holder != msg.From || !s.cfg.runtime.lockSigner.VerifyShare(
		share.holder, "RL_AGG_LOCK", share.headerDigest, share.signature,
	) {
		return
	}
	key := fmt.Sprintf("%x", share.headerDigest)
	s.mu.Lock()
	pending := s.pendingARCs[key]
	s.mu.Unlock()
	if pending != nil {
		select {
		case pending.values <- *share:
		default:
		}
	}
}

func (s *cvComponentService) handleARCCertificate(msg Message) {
	headerDigest, certificate, err := cvDecodeARCCertificate(msg.Body)
	if err != nil || !s.cfg.runtime.lockSigner.VerifyRecovered("RL_AGG_LOCK", headerDigest, certificate) {
		return
	}
	key := fmt.Sprintf("%x", headerDigest)
	s.mu.Lock()
	if existing := s.aggregateCertificates[key]; existing == nil {
		s.aggregateCertificates[key] = append([]byte(nil), certificate...)
	}
	pending := s.pendingARCs[key]
	s.mu.Unlock()
	if pending != nil {
		select {
		case pending.certificates <- append([]byte(nil), certificate...):
		default:
		}
	}
}

func (s *cvComponentService) loadOrRetrieveComponent(ctx context.Context, descriptor *cvComponentDescriptor) (*cvVerifiedLeaf, error) {
	return s.getVerifiedComponent(ctx, descriptor)
}

func (s *cvComponentService) getVerifiedComponent(ctx context.Context, descriptor *cvComponentDescriptor) (*cvVerifiedLeaf, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil CV-sAPVSS verified component context")
	}
	if err := cvValidateNetworkComponentDescriptor(s.cfg, descriptor); err != nil {
		return nil, err
	}
	key := cvComponentKey(descriptor.dealer, descriptor.leafDigest)
	s.mu.Lock()
	cached := s.verifiedLeaves[key]
	if cached != nil {
		s.mu.Unlock()
		if cvPerfCountersEnabled {
			cvPerfCounters.verifiedLeafCacheHits.Add(1)
		}
		return cached, nil
	}
	call := s.componentRetrievals[key]
	if call == nil {
		if cvPerfCountersEnabled {
			cvPerfCounters.componentRetrievalStarts.Add(1)
		}
		call = &cvComponentRetrievalCall{done: make(chan struct{})}
		s.componentRetrievals[key] = call
		s.backgroundWG.Add(1)
		go func() {
			defer s.backgroundWG.Done()
			accepted, retrieveErr := s.loadOrRetrieveComponentOnce(descriptor)
			s.mu.Lock()
			call.accepted = accepted
			call.err = retrieveErr
			delete(s.componentRetrievals, key)
			close(call.done)
			s.mu.Unlock()
		}()
	} else if cvPerfCountersEnabled {
		cvPerfCounters.componentRetrievalJoins.Add(1)
	}
	s.mu.Unlock()
	if cvPerfCountersEnabled {
		cvPerfCounters.verifiedLeafCacheMiss.Add(1)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case <-call.done:
		return call.accepted, call.err
	}
}

func (s *cvComponentService) loadOrRetrieveComponentOnce(descriptor *cvComponentDescriptor) (*cvVerifiedLeaf, error) {
	wire, err := s.store.Read(s.cfg.SID, s.cfg.Epoch, descriptor.dealer, s.localNode, descriptor.leafDigest)
	if err == nil {
		accepted, decodeErr := s.cacheVerifiedWire(descriptor.dealer, descriptor.leafDigest, wire)
		if decodeErr != nil {
			return nil, fmt.Errorf("stored CV-sAPVSS component leaf is invalid")
		}
		return accepted, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	accepted, err := s.retrieveComponentNetwork(s.ctx, descriptor)
	if err != nil {
		return nil, err
	}
	if accepted == nil {
		return nil, fmt.Errorf("retrieved CV-sAPVSS component was not verified")
	}
	return accepted, nil
}

func (s *cvComponentService) RecoverAggregate(ctx context.Context, rlo *AggRLO) (*cvAggregateTranscript, error) {
	if ctx == nil || rlo == nil {
		return nil, fmt.Errorf("invalid CV-sAPVSS network recovery input")
	}
	if _, err := validateAggRLOShape(s.cfg, rlo); err != nil {
		return nil, err
	}
	if err := validateAggRLOLock(s.cfg, rlo); err != nil {
		return nil, err
	}
	if err := validateAggRLODigest(rlo); err != nil {
		return nil, err
	}
	headerDigest := digestAggHeaderForLock(rlo.Header)
	key := fmt.Sprintf("%x", headerDigest)
	requestTargets := sortedUnique(s.cfg.OldCommittee)
	pending := &cvPendingRecovery{rlo: cloneAggRLO(rlo), allowed: nodeSet(requestTargets),
		values: make(chan cvFreshShardArtifact, len(requestTargets))}
	s.mu.Lock()
	if _, exists := s.pendingRecoveries[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV-sAPVSS aggregate recovery already active")
	}
	s.pendingRecoveries[key] = pending
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pendingRecoveries, key)
		s.mu.Unlock()
	}()
	requestWire, _ := cvRecoverGetCanonicalBytes(headerDigest)
	s.sendMany(requestTargets, cvTagRecoverGet, requestWire)
	need := len(s.cfg.OldCommittee) - 2*s.cfg.FOld
	artifacts := make(map[int]cvFreshShardArtifact, need)
	for len(artifacts) < need {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case artifact := <-pending.values:
			artifacts[artifact.shard.index] = artifact
		}
	}
	n := len(s.cfg.OldCommittee)
	dispersal := &cvAggregateDispersal{dataShards: need, shards: make([]cvAggregateShard, n)}
	available := make([]int, 0, len(artifacts))
	for index, artifact := range artifacts {
		if dispersal.nonce == nil {
			dispersal.nonce = append([]byte(nil), artifact.nonce...)
			dispersal.payloadDigest = append([]byte(nil), artifact.payloadDigest...)
			dispersal.root = append([]byte(nil), artifact.root...)
		} else if !bytes.Equal(dispersal.nonce, artifact.nonce) || !bytes.Equal(dispersal.root, artifact.root) {
			return nil, fmt.Errorf("inconsistent CV-sAPVSS recovery shards")
		}
		dispersal.shards[index] = artifact.shard
		available = append(available, index)
	}
	wire, err := cvRecoverAggregateWire(dispersal, available)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(hashBytes([]byte(cvAggregatePayloadDomain), wire), rlo.Header.PayloadDigest) ||
		!bytes.Equal(hashBytes([]byte(cvAggregateDomain), wire), rlo.Header.AggregateDigest) {
		return nil, fmt.Errorf("recovered CV-sAPVSS aggregate digest mismatch")
	}
	agg, err := cvDecodeAggregate(wire)
	if err != nil {
		return nil, err
	}
	if string(agg.context.sessionID) != s.cfg.SID || int(agg.context.epoch) != s.cfg.Epoch || len(agg.dealerIDs) != len(rlo.Header.Dealers) {
		return nil, fmt.Errorf("recovered CV-sAPVSS aggregate context mismatch")
	}
	for i, dealer := range agg.dealerIDs {
		if int(dealer) != rlo.Header.Dealers[i] {
			return nil, fmt.Errorf("recovered CV-sAPVSS aggregate dealer mismatch")
		}
	}
	return agg, nil
}

func (s *cvComponentService) handleRecoverGet(msg Message) {
	headerDigest, err := cvDecodeRecoverGet(msg.Body)
	if err != nil {
		return
	}
	shardWire, err := s.freshStore.Read(s.cfg.SID, s.cfg.Epoch, headerDigest, s.localNode)
	if err == nil {
		_ = s.send(msg.From, cvTagRecoverShard, shardWire)
	}
}

func (s *cvComponentService) handleRecoverShard(msg Message) {
	headerDigest, err := cvFreshShardArtifactHeaderDigest(msg.Body)
	if err != nil {
		return
	}
	key := fmt.Sprintf("%x", headerDigest)
	s.mu.Lock()
	pending := s.pendingRecoveries[key]
	s.mu.Unlock()
	if pending == nil {
		return
	}
	if _, ok := pending.allowed[msg.From]; !ok {
		return
	}
	artifact, err := cvDecodeFreshShardArtifact(msg.Body, s.cfg, pending.rlo.Header)
	if err != nil {
		return
	}
	oldOrder := sortedUnique(s.cfg.OldCommittee)
	index := sort.SearchInts(oldOrder, msg.From)
	if index >= len(oldOrder) || oldOrder[index] != msg.From || artifact.shard.index != index {
		return
	}
	select {
	case pending.values <- *artifact:
	default:
	}
}

func cvARCShareCanonicalBytes(share *cvARCShare) ([]byte, error) {
	if share == nil || share.holder < 0 || len(share.headerDigest) != 32 || len(share.signature) == 0 ||
		len(share.signature) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV-sAPVSS ARC share")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvARCShareDomain))
	cvWriteUint64(&wire, uint64(share.holder))
	_ = cvWriteBytes(&wire, share.headerDigest)
	_ = cvWriteBytes(&wire, share.signature)
	return wire.Bytes(), nil
}

func cvDecodeARCShare(wire []byte) (*cvARCShare, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvARCShareDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvARCShareDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS ARC share domain")
	}
	holder, err := r.uint64()
	if err != nil || holder > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV-sAPVSS ARC holder")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS ARC digest")
	}
	sig, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(sig) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS ARC signature")
	}
	share := &cvARCShare{holder: int(holder), headerDigest: digest, signature: sig}
	canonical, err := cvARCShareCanonicalBytes(share)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS ARC share")
	}
	return share, nil
}

func cvRecoverGetCanonicalBytes(headerDigest []byte) ([]byte, error) {
	if len(headerDigest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS recovery request")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvRecoverGetDomain))
	_ = cvWriteBytes(&wire, headerDigest)
	return wire.Bytes(), nil
}

func cvDecodeRecoverGet(wire []byte) ([]byte, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvRecoverGetDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvRecoverGetDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS recovery request domain")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS recovery request digest")
	}
	canonical, _ := cvRecoverGetCanonicalBytes(digest)
	if !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS recovery request")
	}
	return digest, nil
}

func cvFreshShardArtifactHeaderDigest(wire []byte) ([]byte, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvFreshShardArtifactDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvFreshShardArtifactDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS fresh shard artifact domain")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS fresh shard header digest")
	}
	return digest, nil
}
