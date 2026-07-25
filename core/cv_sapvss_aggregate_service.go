package core

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"time"
)

const (
	cvNetworkAggHeaderDomainV1   = "ARL-CV-sAPVSS-v1/network-aggregate-header"
	cvFreshShardArtifactDomainV1 = "ARL-CV-sAPVSS-v1/fresh-shard-artifact"
	cvAggregateOfferDomainV1     = "ARL-CV-sAPVSS-v1/aggregate-offer"
	cvARCShareDomainV1           = "ARL-CV-sAPVSS-v1/arc-share"
	cvRecoverGetDomainV1         = "ARL-CV-sAPVSS-v1/recover-get"
)

type cvFreshShardArtifactV1 struct {
	headerDigest  []byte
	nonce         []byte
	dataShards    int
	totalShards   int
	payloadDigest []byte
	root          []byte
	shard         cvAggregateShardV1
}

type cvAggregateOfferV1 struct {
	header      AggHeader
	descriptors []*cvComponentDescriptorV1
	aggregate   *cvAggregateV1
	shard       cvFreshShardArtifactV1
}

type cvARCShareV1 struct {
	holder       int
	headerDigest []byte
	signature    []byte
}

type cvVerifiedAggregateOfferTokenV1 struct {
	headerWire      []byte
	descriptorWires [][]byte
	aggregateWire   []byte
}

func cvBuildVerifiedAggregateOfferTokenV1(
	header AggHeader,
	descriptors []*cvComponentDescriptorV1,
	aggregate *cvAggregateV1,
) (*cvVerifiedAggregateOfferTokenV1, error) {
	if aggregate == nil || len(descriptors) == 0 || len(descriptors) != len(header.Dealers) ||
		len(descriptors) != len(aggregate.dealerIDs) || len(descriptors) != len(aggregate.leafDigests) ||
		!bytes.Equal(header.AggregateDigest, aggregate.digest) {
		return nil, fmt.Errorf("invalid verified CV-sAPVSS aggregate offer")
	}
	headerWire, err := cvNetworkAggHeaderV1CanonicalBytes(header)
	if err != nil {
		return nil, err
	}
	aggregateWire, err := cvAggregateV1CanonicalBytes(aggregate)
	if err != nil || !bytes.Equal(aggregateWire, aggregate.digestWire) ||
		!bytes.Equal(aggregate.digest, hashBytes([]byte(cvAggregateV1Domain), aggregateWire)) {
		return nil, fmt.Errorf("invalid verified CV-sAPVSS aggregate wire")
	}
	token := &cvVerifiedAggregateOfferTokenV1{
		headerWire: append([]byte(nil), headerWire...), aggregateWire: append([]byte(nil), aggregateWire...),
		descriptorWires: make([][]byte, len(descriptors)),
	}
	for i, descriptor := range descriptors {
		if descriptor == nil || descriptor.dealer != header.Dealers[i] ||
			uint64(descriptor.dealer) != aggregate.dealerIDs[i] ||
			!bytes.Equal(descriptor.leafDigest, aggregate.leafDigests[i]) {
			return nil, fmt.Errorf("verified CV-sAPVSS aggregate manifest mismatch")
		}
		descriptorWire, encodeErr := cvComponentDescriptorV1CanonicalBytes(descriptor)
		if encodeErr != nil {
			return nil, encodeErr
		}
		token.descriptorWires[i] = append([]byte(nil), descriptorWire...)
	}
	return token, nil
}

func (token *cvVerifiedAggregateOfferTokenV1) matches(offer *cvAggregateOfferV1) error {
	if token == nil || offer == nil {
		return fmt.Errorf("missing verified CV-sAPVSS aggregate offer token")
	}
	candidate, err := cvBuildVerifiedAggregateOfferTokenV1(offer.header, offer.descriptors, offer.aggregate)
	if err != nil || !bytes.Equal(token.headerWire, candidate.headerWire) ||
		!bytes.Equal(token.aggregateWire, candidate.aggregateWire) ||
		len(token.descriptorWires) != len(candidate.descriptorWires) {
		return fmt.Errorf("CV-sAPVSS aggregate offer does not match verified token")
	}
	for i := range token.descriptorWires {
		if !bytes.Equal(token.descriptorWires[i], candidate.descriptorWires[i]) {
			return fmt.Errorf("CV-sAPVSS aggregate descriptor does not match verified token")
		}
	}
	return nil
}

func cvBuildNetworkAggHeaderV1(cfg Config, agg *cvAggregateV1, dispersal *cvAggregateDispersalV1) (AggHeader, error) {
	if err := cvValidateAggregateErasureDimensionsV1(cfg, dispersal); err != nil {
		return AggHeader{}, err
	}
	if err := cvVerifyAggregateDispersalV1(agg, dispersal); err != nil {
		return AggHeader{}, err
	}
	dealers, err := cvDealerIDsToIntsV1(agg.dealerIDs)
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

func cvNetworkAggHeaderV1CanonicalBytes(header AggHeader) ([]byte, error) {
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
	_ = cvWriteBytes(&wire, []byte(cvNetworkAggHeaderDomainV1))
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

func cvDecodeNetworkAggHeaderV1(wire []byte, cfg Config) (AggHeader, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvNetworkAggHeaderDomainV1))
	if err != nil || !bytes.Equal(domain, []byte(cvNetworkAggHeaderDomainV1)) {
		return AggHeader{}, fmt.Errorf("invalid CV-sAPVSS aggregate header domain")
	}
	sid, err := r.bytes(cvMaxNetworkEnvelopeSIDBytesV1)
	if err != nil || string(sid) != cfg.SID {
		return AggHeader{}, fmt.Errorf("CV-sAPVSS aggregate header SID mismatch")
	}
	epoch, err := r.uint64()
	if err != nil || epoch != uint64(cfg.Epoch) {
		return AggHeader{}, fmt.Errorf("CV-sAPVSS aggregate header epoch mismatch")
	}
	dealerCount, err := r.uint32()
	if err != nil || dealerCount != cfg.F+1 || dealerCount > len(cfg.OldCommittee) {
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
	canonical, err := cvNetworkAggHeaderV1CanonicalBytes(header)
	if err != nil || !bytes.Equal(canonical, wire) {
		return AggHeader{}, fmt.Errorf("non-canonical CV-sAPVSS aggregate header")
	}
	return header, nil
}

func cvFreshShardArtifactV1CanonicalBytes(artifact *cvFreshShardArtifactV1) ([]byte, error) {
	if artifact == nil || len(artifact.headerDigest) != 32 || len(artifact.nonce) != 32 ||
		artifact.dataShards <= 0 || artifact.totalShards < artifact.dataShards ||
		artifact.totalShards > cvMaxComponentHoldersV1 || len(artifact.payloadDigest) != 32 ||
		len(artifact.root) != 32 || artifact.shard.index < 0 ||
		artifact.shard.index >= artifact.totalShards || len(artifact.shard.payload) == 0 ||
		len(artifact.shard.payload) > cvMaxNetworkPayloadBytesV1 {
		return nil, fmt.Errorf("invalid CV-sAPVSS fresh shard artifact")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvFreshShardArtifactDomainV1))
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

func cvDecodeFreshShardArtifactV1(wire []byte, cfg Config, header AggHeader) (*cvFreshShardArtifactV1, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvFreshShardArtifactDomainV1))
	if err != nil || !bytes.Equal(domain, []byte(cvFreshShardArtifactDomainV1)) {
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
	payload, err := r.bytes(cvMaxNetworkPayloadBytesV1)
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
	artifact := &cvFreshShardArtifactV1{headerDigest: fields[0], nonce: fields[1],
		payloadDigest: fields[2], root: fields[3], dataShards: dataShards,
		totalShards: totalShards, shard: cvAggregateShardV1{index: index, payload: payload, siblings: siblings}}
	if err := cvVerifyFreshShardArtifactV1(cfg, header, artifact); err != nil {
		return nil, err
	}
	canonical, err := cvFreshShardArtifactV1CanonicalBytes(artifact)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS fresh shard artifact")
	}
	return artifact, nil
}

func cvVerifyFreshShardArtifactV1(cfg Config, header AggHeader, artifact *cvFreshShardArtifactV1) error {
	n := len(sortedUnique(cfg.OldCommittee))
	if artifact == nil || artifact.totalShards != n || artifact.dataShards != n-2*cfg.F ||
		!bytes.Equal(artifact.headerDigest, digestAggHeaderForLock(header)) ||
		!bytes.Equal(artifact.payloadDigest, header.PayloadDigest) ||
		!bytes.Equal(artifact.root, header.FreshShardRoot) {
		return fmt.Errorf("CV-sAPVSS fresh shard does not match aggregate header")
	}
	dispersal := &cvAggregateDispersalV1{nonce: artifact.nonce, dataShards: artifact.dataShards,
		payloadDigest: artifact.payloadDigest, root: artifact.root, shards: make([]cvAggregateShardV1, n)}
	dispersal.shards[artifact.shard.index] = artifact.shard
	return cvVerifyAggregateShardV1(dispersal, &artifact.shard)
}

func cvAggregateOfferV1CanonicalBytes(offer *cvAggregateOfferV1) ([]byte, error) {
	if offer == nil || offer.aggregate == nil || len(offer.descriptors) == 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate offer")
	}
	headerWire, err := cvNetworkAggHeaderV1CanonicalBytes(offer.header)
	if err != nil {
		return nil, err
	}
	aggregateWire, err := cvAggregateV1CanonicalBytes(offer.aggregate)
	if err != nil {
		return nil, err
	}
	shardWire, err := cvFreshShardArtifactV1CanonicalBytes(&offer.shard)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAggregateOfferDomainV1))
	_ = cvWriteBytes(&wire, headerWire)
	_ = cvWriteUint32(&wire, len(offer.descriptors))
	for _, descriptor := range offer.descriptors {
		descriptorWire, encodeErr := cvComponentDescriptorV1CanonicalBytes(descriptor)
		if encodeErr != nil {
			return nil, encodeErr
		}
		_ = cvWriteBytes(&wire, descriptorWire)
	}
	_ = cvWriteBytes(&wire, aggregateWire)
	_ = cvWriteBytes(&wire, shardWire)
	return wire.Bytes(), nil
}

func cvDecodeAggregateOfferV1(wire []byte, cfg Config) (*cvAggregateOfferV1, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregateOfferDomainV1))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateOfferDomainV1)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate offer domain")
	}
	headerWire, err := r.bytes(1 << 20)
	if err != nil {
		return nil, err
	}
	header, err := cvDecodeNetworkAggHeaderV1(headerWire, cfg)
	if err != nil {
		return nil, err
	}
	count, err := r.uint32()
	if err != nil || count != cfg.F+1 {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate offer descriptor count")
	}
	descriptors := make([]*cvComponentDescriptorV1, count)
	for i := range descriptors {
		descriptorWire, readErr := r.bytes(cvMaxCanonicalFieldBytes)
		if readErr != nil {
			return nil, readErr
		}
		descriptors[i], readErr = cvDecodeAndValidateComponentDescriptorV1(cfg, descriptorWire)
		if readErr != nil || descriptors[i].dealer != header.Dealers[i] {
			return nil, fmt.Errorf("CV-sAPVSS aggregate offer descriptor mismatch")
		}
	}
	aggregateWire, err := r.bytes(cvMaxCanonicalFieldBytes)
	if err != nil {
		return nil, err
	}
	aggregate, err := cvDecodeAggregateV1(aggregateWire)
	if err != nil || !bytes.Equal(aggregate.digest, header.AggregateDigest) {
		return nil, fmt.Errorf("CV-sAPVSS aggregate offer payload mismatch")
	}
	shardWire, err := r.bytes(cvMaxNetworkPayloadBytesV1)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate offer framing")
	}
	shard, err := cvDecodeFreshShardArtifactV1(shardWire, cfg, header)
	if err != nil {
		return nil, err
	}
	offer := &cvAggregateOfferV1{header: header, descriptors: descriptors, aggregate: aggregate, shard: *shard}
	canonical, err := cvAggregateOfferV1CanonicalBytes(offer)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS aggregate offer")
	}
	return offer, nil
}

func (s *cvComponentServiceV1) MaterializeAndCollectARC(ctx context.Context, descriptors []*cvComponentDescriptorV1) (*cvMaterializedAggregateV1, error) {
	metrics := cvAggregateMaterializeMetricsV1{}
	want := s.cfg.F + 1
	ready := len(s.cfg.OldCommittee) - s.cfg.F
	if ctx == nil || len(descriptors) < want || len(descriptors) > ready {
		return nil, fmt.Errorf("CV-sAPVSS network materializer requires K through n-f descriptors")
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
	selectedDescriptors := make([]*cvComponentDescriptorV1, 0, want)
	leaves := make([]*cvVerifiedLeafV1, 0, want)
	phaseStart = time.Now()
	lastDealer := -1
	for _, descriptor := range descriptors {
		if descriptor == nil || descriptor.dealer <= lastDealer || cvValidateComponentDescriptorV1(s.cfg, descriptor) != nil {
			return nil, fmt.Errorf("invalid CV-sAPVSS materializer descriptor set")
		}
		lastDealer = descriptor.dealer
	}
	type loadResult struct {
		index int
		leaf  *cvVerifiedLeafV1
	}
	for cursor := 0; len(leaves) < want && cursor < len(descriptors); {
		batchSize := want - len(leaves)
		end := cursor + batchSize
		if end > len(descriptors) {
			end = len(descriptors)
		}
		results := make(chan loadResult, end-cursor)
		for index := cursor; index < end; index++ {
			descriptor := descriptors[index]
			go func(index int) {
				leaf, _ := s.loadOrRetrieveComponent(ctx, descriptor)
				results <- loadResult{index: index, leaf: leaf}
			}(index)
		}
		loaded := make([]*cvVerifiedLeafV1, end-cursor)
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
	}
	if len(leaves) != want {
		return nil, fmt.Errorf("CV-sAPVSS materializer found %d valid leaves, need %d", len(leaves), want)
	}
	metrics.leafLoad = time.Since(phaseStart)
	phaseStart = time.Now()
	agg, err := cvAggVerifiedV1(s.leafCtx, leaves)
	if err != nil {
		return nil, err
	}
	metrics.aggregate = time.Since(phaseStart)
	n := len(s.cfg.OldCommittee)
	phaseStart = time.Now()
	dispersal, err := cvDisperseAggregateV1(agg, n, n-2*s.cfg.F)
	if err != nil {
		return nil, err
	}
	metrics.rsDisperse = time.Since(phaseStart)
	phaseStart = time.Now()
	header, err := cvBuildNetworkAggHeaderV1(s.cfg, agg, dispersal)
	if err != nil {
		return nil, err
	}
	headerDigest := digestAggHeaderForLock(header)
	key := fmt.Sprintf("%x", headerDigest)
	token, err := cvBuildVerifiedAggregateOfferTokenV1(header, selectedDescriptors, agg)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if existing := s.verifiedAggregateOffers[key]; existing != nil {
		if matchErr := existing.matches(&cvAggregateOfferV1{
			header: header, descriptors: selectedDescriptors, aggregate: agg,
		}); matchErr != nil {
			s.mu.Unlock()
			return nil, fmt.Errorf("conflicting verified CV-sAPVSS aggregate offer")
		}
	} else {
		if len(s.verifiedAggregateOffers) >= ready {
			s.mu.Unlock()
			return nil, fmt.Errorf("verified CV-sAPVSS aggregate offer cache is full")
		}
		s.verifiedAggregateOffers[key] = token
	}
	s.mu.Unlock()
	metrics.headerToken = time.Since(phaseStart)
	s.aggregateBuildMu.Unlock()
	aggregateBuildLocked = false
	pending := &cvPendingARCShareV1{values: make(chan cvARCShareV1, n)}
	s.mu.Lock()
	if _, exists := s.pendingARCs[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV-sAPVSS ARC collection already active")
	}
	s.pendingARCs[key] = pending
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pendingARCs, key)
		s.mu.Unlock()
	}()
	oldOrder := sortedUnique(s.cfg.OldCommittee)
	s.cfg.runtime.setCommPhase("aggregate_disperse")
	phaseStart = time.Now()
	sent := 0
	for index, holder := range oldOrder {
		artifact := cvFreshShardArtifactV1{headerDigest: append([]byte(nil), headerDigest...),
			nonce: append([]byte(nil), dispersal.nonce...), dataShards: dispersal.dataShards,
			totalShards: len(dispersal.shards), payloadDigest: append([]byte(nil), dispersal.payloadDigest...),
			root: append([]byte(nil), dispersal.root...), shard: dispersal.shards[index]}
		offerWire, encodeErr := cvAggregateOfferV1CanonicalBytes(&cvAggregateOfferV1{
			header: header, descriptors: selectedDescriptors, aggregate: agg, shard: artifact,
		})
		if encodeErr != nil {
			return nil, encodeErr
		}
		if s.send(holder, cvTagAggregateShardV1, offerWire) == nil {
			sent++
		}
	}
	threshold := n - s.cfg.F
	if sent < threshold {
		return nil, fmt.Errorf("CV-sAPVSS aggregate dispersal reached %d holders, need %d", sent, threshold)
	}
	metrics.offerSend = time.Since(phaseStart)
	s.cfg.runtime.setCommPhase("arc_share")
	phaseStart = time.Now()
	shares := make(map[int][]byte, threshold)
	for len(shares) < threshold {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case share := <-pending.values:
			if _, duplicate := shares[share.holder]; !duplicate {
				shares[share.holder] = append([]byte(nil), share.signature...)
			}
		}
	}
	metrics.arcWait = time.Since(phaseStart)
	phaseStart = time.Now()
	holders := make([]int, 0, len(shares))
	for holder := range shares {
		holders = append(holders, holder)
	}
	sort.Ints(holders)
	certificate, err := s.cfg.runtime.lockSigner.Recover("RL_AGG_LOCK", headerDigest, shares)
	if err != nil {
		return nil, err
	}
	rlo := &AggRLO{Header: header, Lock: AggLock{Threshold: threshold, Holders: holders,
		ShareSignatures: shares, Certificate: certificate}, Aggregate: APVSSAggregate{
		Provider: "cv-sapvss", Dealers: append([]int(nil), header.Dealers...),
		AggregateDigest: append([]byte(nil), header.AggregateDigest...),
	}}
	rlo.Digest = digestAggRLO(*rlo)
	if _, err := validateAggRLOShape(s.cfg, rlo); err != nil {
		return nil, err
	}
	if err := validateAggRLOLock(s.cfg, rlo, true); err != nil {
		return nil, err
	}
	metrics.certificate = time.Since(phaseStart)
	return &cvMaterializedAggregateV1{
		rlo: rlo, aggregate: agg, dispersal: dispersal, metrics: metrics,
	}, nil
}

func (s *cvComponentServiceV1) handleAggregateOffer(msg Message) {
	if cvPerfCountersEnabled {
		cvPerfCounters.aggregateOffers.Add(1)
	}
	go func() {
		offer, err := cvDecodeAggregateOfferV1(msg.Body, s.cfg)
		if err != nil {
			return
		}
		key := fmt.Sprintf("%x", offer.shard.headerDigest)
		s.mu.Lock()
		if prior, exists := s.candidateByMaterializer[msg.From]; exists && prior != key {
			s.mu.Unlock()
			return
		}
		s.candidateByMaterializer[msg.From] = key
		if _, exists := s.processingOffers[key]; exists {
			s.mu.Unlock()
			return
		}
		s.processingOffers[key] = struct{}{}
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			delete(s.processingOffers, key)
			s.mu.Unlock()
		}()
		oldOrder := sortedUnique(s.cfg.OldCommittee)
		index := sort.SearchInts(oldOrder, s.localNode)
		if index >= len(oldOrder) || oldOrder[index] != s.localNode || offer.shard.shard.index != index {
			return
		}
		if err := s.verifyAggregateOfferForARC(offer); err != nil {
			return
		}
		shardWire, err := cvFreshShardArtifactV1CanonicalBytes(&offer.shard)
		if err != nil || s.freshStore.Put(s.cfg.SID, s.cfg.Epoch, offer.shard.headerDigest, s.localNode, shardWire) != nil {
			return
		}
		sig, err := s.cfg.runtime.lockSigner.SignShare(s.localNode, "RL_AGG_LOCK", offer.shard.headerDigest)
		if err != nil {
			return
		}
		shareWire, err := cvARCShareV1CanonicalBytes(&cvARCShareV1{
			holder: s.localNode, headerDigest: offer.shard.headerDigest, signature: sig,
		})
		if err == nil {
			// Multiple materializers produce the same deterministic header. Every
			// local collector must observe the holder's share, not only the sender
			// of the first offer that reached this holder.
			for _, node := range sortedUnique(s.cfg.OldCommittee) {
				_ = s.send(node, cvTagARCShareV1, shareWire)
			}
		}
	}()
}

func (s *cvComponentServiceV1) verifyAggregateOfferForARC(offer *cvAggregateOfferV1) error {
	if offer == nil {
		return fmt.Errorf("nil CV-sAPVSS aggregate offer")
	}
	s.aggregateBuildMu.Lock()
	defer s.aggregateBuildMu.Unlock()
	key := fmt.Sprintf("%x", digestAggHeaderForLock(offer.header))
	s.mu.Lock()
	cached := s.verifiedAggregateOffers[key]
	s.mu.Unlock()
	if cached != nil {
		if err := cached.matches(offer); err != nil {
			return err
		}
		if cvPerfCountersEnabled {
			cvPerfCounters.verifiedAggregateOfferCacheHits.Add(1)
		}
		return nil
	}
	if cvPerfCountersEnabled {
		cvPerfCounters.verifiedAggregateOfferCacheMiss.Add(1)
	}
	leaves := make([]*cvVerifiedLeafV1, len(offer.descriptors))
	for i, descriptor := range offer.descriptors {
		leaf, err := s.loadOrRetrieveComponent(s.ctx, descriptor)
		if err != nil {
			return err
		}
		leaves[i] = leaf
	}
	if cvPerfCountersEnabled {
		cvPerfCounters.aggregateOfferAVers.Add(1)
	}
	if err := cvAVerVerifiedV1(s.leafCtx, offer.aggregate, leaves); err != nil {
		return err
	}
	token, err := cvBuildVerifiedAggregateOfferTokenV1(offer.header, offer.descriptors, offer.aggregate)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.verifiedAggregateOffers) >= len(s.cfg.OldCommittee)-s.cfg.F {
		return fmt.Errorf("verified CV-sAPVSS aggregate offer cache is full")
	}
	s.verifiedAggregateOffers[key] = token
	return nil
}

func (s *cvComponentServiceV1) handleARCShare(msg Message) {
	share, err := cvDecodeARCShareV1(msg.Body)
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

func (s *cvComponentServiceV1) loadOrRetrieveComponent(ctx context.Context, descriptor *cvComponentDescriptorV1) (*cvVerifiedLeafV1, error) {
	key := cvComponentKeyV1(descriptor.dealer, descriptor.leafDigest)
	s.mu.Lock()
	cached := s.verifiedLeaves[key]
	s.mu.Unlock()
	if cached != nil {
		if err := cvValidateAcceptedLeafV1(s.leafCtx, cached); err != nil {
			return nil, err
		}
		if cvPerfCountersEnabled {
			cvPerfCounters.verifiedLeafCacheHits.Add(1)
		}
		return cached, nil
	}
	if cvPerfCountersEnabled {
		cvPerfCounters.verifiedLeafCacheMiss.Add(1)
	}
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
	leaf, err := s.Retrieve(ctx, descriptor)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	accepted := s.verifiedLeaves[key]
	s.mu.Unlock()
	if accepted == nil || accepted.leaf != leaf {
		return nil, fmt.Errorf("retrieved CV-sAPVSS component was not verified")
	}
	return accepted, nil
}

func (s *cvComponentServiceV1) RecoverAggregate(ctx context.Context, rlo *AggRLO) (*cvAggregateV1, error) {
	if ctx == nil || rlo == nil {
		return nil, fmt.Errorf("invalid CV-sAPVSS network recovery input")
	}
	if _, err := validateAggRLOShape(s.cfg, rlo); err != nil {
		return nil, err
	}
	if err := validateAggRLOLock(s.cfg, rlo, true); err != nil {
		return nil, err
	}
	if err := validateAggRLODigest(rlo); err != nil {
		return nil, err
	}
	headerDigest := digestAggHeaderForLock(rlo.Header)
	key := fmt.Sprintf("%x", headerDigest)
	pending := &cvPendingRecoveryV1{rlo: cloneAggRLO(rlo), allowed: nodeSet(rlo.Lock.Holders),
		values: make(chan cvFreshShardArtifactV1, len(rlo.Lock.Holders))}
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
	requestWire, _ := cvRecoverGetV1CanonicalBytes(headerDigest)
	for _, holder := range rlo.Lock.Holders {
		_ = s.send(holder, cvTagRecoverGetV1, requestWire)
	}
	need := len(s.cfg.OldCommittee) - 2*s.cfg.F
	artifacts := make(map[int]cvFreshShardArtifactV1, need)
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
	dispersal := &cvAggregateDispersalV1{dataShards: need, shards: make([]cvAggregateShardV1, n)}
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
	wire, err := cvRecoverAggregateWireV1(dispersal, available)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(hashBytes([]byte(cvAggregatePayloadDomain), wire), rlo.Header.PayloadDigest) ||
		!bytes.Equal(hashBytes([]byte(cvAggregateV1Domain), wire), rlo.Header.AggregateDigest) {
		return nil, fmt.Errorf("recovered CV-sAPVSS aggregate digest mismatch")
	}
	agg, err := cvDecodeAggregateV1(wire)
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

func (s *cvComponentServiceV1) handleRecoverGet(msg Message) {
	headerDigest, err := cvDecodeRecoverGetV1(msg.Body)
	if err != nil {
		return
	}
	shardWire, err := s.freshStore.Read(s.cfg.SID, s.cfg.Epoch, headerDigest, s.localNode)
	if err == nil {
		_ = s.send(msg.From, cvTagRecoverShardV1, shardWire)
	}
}

func (s *cvComponentServiceV1) handleRecoverShard(msg Message) {
	headerDigest, err := cvFreshShardArtifactHeaderDigestV1(msg.Body)
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
	artifact, err := cvDecodeFreshShardArtifactV1(msg.Body, s.cfg, pending.rlo.Header)
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

func cvARCShareV1CanonicalBytes(share *cvARCShareV1) ([]byte, error) {
	if share == nil || share.holder < 0 || len(share.headerDigest) != 32 || len(share.signature) == 0 ||
		len(share.signature) > cvMaxComponentSignatureBytesV1 {
		return nil, fmt.Errorf("invalid CV-sAPVSS ARC share")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvARCShareDomainV1))
	cvWriteUint64(&wire, uint64(share.holder))
	_ = cvWriteBytes(&wire, share.headerDigest)
	_ = cvWriteBytes(&wire, share.signature)
	return wire.Bytes(), nil
}

func cvDecodeARCShareV1(wire []byte) (*cvARCShareV1, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvARCShareDomainV1))
	if err != nil || !bytes.Equal(domain, []byte(cvARCShareDomainV1)) {
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
	sig, err := r.bytes(cvMaxComponentSignatureBytesV1)
	if err != nil || len(sig) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS ARC signature")
	}
	share := &cvARCShareV1{holder: int(holder), headerDigest: digest, signature: sig}
	canonical, err := cvARCShareV1CanonicalBytes(share)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS ARC share")
	}
	return share, nil
}

func cvRecoverGetV1CanonicalBytes(headerDigest []byte) ([]byte, error) {
	if len(headerDigest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS recovery request")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvRecoverGetDomainV1))
	_ = cvWriteBytes(&wire, headerDigest)
	return wire.Bytes(), nil
}

func cvDecodeRecoverGetV1(wire []byte) ([]byte, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvRecoverGetDomainV1))
	if err != nil || !bytes.Equal(domain, []byte(cvRecoverGetDomainV1)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS recovery request domain")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS recovery request digest")
	}
	canonical, _ := cvRecoverGetV1CanonicalBytes(digest)
	if !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS recovery request")
	}
	return digest, nil
}

func cvFreshShardArtifactHeaderDigestV1(wire []byte) ([]byte, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvFreshShardArtifactDomainV1))
	if err != nil || !bytes.Equal(domain, []byte(cvFreshShardArtifactDomainV1)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS fresh shard artifact domain")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS fresh shard header digest")
	}
	return digest, nil
}
