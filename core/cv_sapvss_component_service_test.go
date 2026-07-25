package core

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"
)

func TestCVComponentServiceDispersesCertifiesAndRetrievesOverNetwork(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 128)
	router, err := newCVSAPVSSRouterV1(
		context.Background(), transport, cfg.SID, cfg.Epoch, nodes, nodes, 64,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })

	services := make([]*cvComponentServiceV1, len(nodes))
	for i, node := range nodes {
		store, storeErr := newCVComponentLeafStoreV1(t.TempDir())
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		services[i], err = newCVComponentServiceV1(
			context.Background(), cfg, &leafContext, node, transport, router, store,
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	descriptor, err := services[0].Disperse(ctx, leaves[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := transport.sentCount(cvTagComponentInitV1); got != len(nodes)-1 {
		t.Fatalf("component dispersal sent %d INIT messages, want %d without self-INIT", got, len(nodes)-1)
	}
	if len(descriptor.holders) != len(nodes)-cfg.FOld ||
		len(descriptor.shareSignatures) != len(descriptor.holders) {
		t.Fatalf("component certificate does not preserve n-f holder shares: %+v", descriptor)
	}
	if err := cvValidateComponentDescriptorV1(cfg, descriptor); err != nil {
		t.Fatalf("network-produced descriptor rejected: %v", err)
	}
	for _, service := range services {
		service.mu.Lock()
		cached := len(service.verifiedLeaves)
		service.mu.Unlock()
		if cached != 0 {
			t.Fatalf("availability lock populated node %d verified-leaf cache", service.localNode)
		}
	}

	getBefore := transport.sentCount(cvTagComponentGetV1)
	leafBefore := transport.sentCount(cvTagComponentLeafV1)
	retrieved, err := services[len(services)-1].Retrieve(ctx, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retrieved.digest, leaves[0].digest) ||
		transport.sentCount(cvTagComponentGetV1) <= getBefore ||
		transport.sentCount(cvTagComponentLeafV1) <= leafBefore {
		t.Fatal("component retrieval did not use authenticated GET/LEAF network messages")
	}

	_, err = services[1].Disperse(ctx, leaves[1])
	if err != nil {
		t.Fatal(err)
	}
	insufficientCtx, insufficientCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	if _, collectErr := services[0].CollectComponentCandidates(insufficientCtx); collectErr == nil {
		insufficientCancel()
		t.Fatal("component candidate collection succeeded below n-f certified descriptors")
	}
	insufficientCancel()
	thirdLeaf, err := cvRandomDealerLeafV1(leafContext, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := services[2].Disperse(ctx, thirdLeaf); err != nil {
		t.Fatal(err)
	}
	candidateSets := make(map[int][]*cvComponentDescriptorV1, len(services))
	for _, service := range services {
		candidates, collectErr := service.CollectComponentCandidates(ctx)
		if collectErr != nil {
			t.Fatal(collectErr)
		}
		if len(candidates) != len(nodes)-cfg.FOld ||
			candidates[0].dealer != 0 || candidates[1].dealer != 1 || candidates[2].dealer != 2 {
			t.Fatalf("node %d collected unexpected component candidates: %+v", service.localNode, candidates)
		}
		candidateSets[service.localNode] = candidates
	}
	type materializeResult struct {
		value *cvMaterializedAggregateV1
		err   error
	}
	materializedResults := make(chan materializeResult, len(services))
	for _, service := range services {
		service := service
		go func() {
			value, materializeErr := service.MaterializeAndCollectARC(
				ctx, candidateSets[service.localNode],
			)
			materializedResults <- materializeResult{value: value, err: materializeErr}
		}()
	}
	var materialized *cvMaterializedAggregateV1
	for range services {
		result := <-materializedResults
		if result.err != nil {
			t.Fatal(result.err)
		}
		if materialized == nil {
			materialized = result.value
			continue
		}
		if !bytes.Equal(
			digestAggHeaderForLock(result.value.rlo.Header),
			digestAggHeaderForLock(materialized.rlo.Header),
		) || !bytes.Equal(result.value.aggregate.digest, materialized.aggregate.digest) {
			t.Fatal("concurrent materializers produced different aggregate headers")
		}
	}
	if len(materialized.rlo.Lock.Holders) != len(nodes)-cfg.FOld ||
		len(materialized.rlo.Lock.ShareSignatures) != len(materialized.rlo.Lock.Holders) {
		t.Fatal("network ARC did not preserve n-f individual holder shares")
	}
	for _, service := range services {
		service.mu.Lock()
		cachedOffers := len(service.verifiedAggregateOffers)
		service.mu.Unlock()
		if cachedOffers != 1 {
			t.Fatalf("node %d cached %d verified aggregate offers, want one", service.localNode, cachedOffers)
		}
	}
	stoppedHolder := -1
	for _, holder := range materialized.rlo.Lock.Holders {
		if holder != services[len(services)-1].localNode {
			stoppedHolder = holder
			break
		}
	}
	if stoppedHolder < 0 {
		t.Fatal("test could not select an ARC holder to stop")
	}
	if err := services[stoppedHolder].Close(); err != nil {
		t.Fatal(err)
	}
	recoverGetBefore := transport.sentCount(cvTagRecoverGetV1)
	recoverShardBefore := transport.sentCount(cvTagRecoverShardV1)
	recovered, err := services[len(services)-1].RecoverAggregate(ctx, materialized.rlo)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered.digest, materialized.aggregate.digest) ||
		transport.sentCount(cvTagRecoverGetV1) <= recoverGetBefore ||
		transport.sentCount(cvTagRecoverShardV1)-recoverShardBefore < len(nodes)-2*cfg.FOld {
		t.Fatal("aggregate recovery did not collect n-2f ARC-holder shards over the network")
	}
}

func TestCVVerifiedAggregateOfferTokenRejectsMutation(t *testing.T) {
	cfg, context, _, leaves := cvM4Fixture(t)
	accepted := make([]*cvVerifiedLeafV1, cfg.FOld+1)
	descriptors := make([]*cvComponentDescriptorV1, cfg.FOld+1)
	for i := range accepted {
		wire, err := cvLeafV1CanonicalBytes(leaves[i])
		if err != nil {
			t.Fatal(err)
		}
		accepted[i], err = cvAcceptedLeafV1(&context, leaves[i], wire)
		if err != nil {
			t.Fatal(err)
		}
		descriptors[i] = &cvComponentDescriptorV1{
			dealer: int(leaves[i].dealerID), leafDigest: accepted[i].leafDigest,
			holders: []int{0, 1, 2}, shareSignatures: map[int][]byte{
				0: {1}, 1: {2}, 2: {3},
			}, certificate: []byte{4},
		}
	}
	aggregate, err := cvAggVerifiedV1(&context, accepted)
	if err != nil {
		t.Fatal(err)
	}
	dispersal, err := cvDisperseAggregateV1(aggregate, len(cfg.OldCommittee), len(cfg.OldCommittee)-2*cfg.FOld)
	if err != nil {
		t.Fatal(err)
	}
	header, err := cvBuildNetworkAggHeaderV1(cfg, aggregate, dispersal)
	if err != nil {
		t.Fatal(err)
	}
	token, err := cvBuildVerifiedAggregateOfferTokenV1(header, descriptors, aggregate)
	if err != nil {
		t.Fatal(err)
	}
	valid := &cvAggregateOfferV1{header: header, descriptors: descriptors, aggregate: aggregate}
	if err := token.matches(valid); err != nil {
		t.Fatalf("verified token rejected its source offer: %v", err)
	}

	t.Run("descriptor digest", func(t *testing.T) {
		badDescriptors := append([]*cvComponentDescriptorV1(nil), descriptors...)
		copyDescriptor := *descriptors[0]
		copyDescriptor.leafDigest = append([]byte(nil), descriptors[0].leafDigest...)
		copyDescriptor.leafDigest[0] ^= 1
		badDescriptors[0] = &copyDescriptor
		if err := token.matches(&cvAggregateOfferV1{
			header: header, descriptors: badDescriptors, aggregate: aggregate,
		}); err == nil {
			t.Fatal("verified aggregate token accepted a mutated descriptor digest")
		}
	})
	t.Run("aggregate ciphertext", func(t *testing.T) {
		badAggregate := cvCloneAggregateV1ForTest(aggregate)
		badAggregate.receivers[0].scalarChunks[0].c.Add(
			&badAggregate.receivers[0].scalarChunks[0].c, &genG1,
		)
		if err := token.matches(&cvAggregateOfferV1{
			header: header, descriptors: descriptors, aggregate: badAggregate,
		}); err == nil {
			t.Fatal("verified aggregate token accepted mutated aggregate bytes")
		}
	})
	t.Run("fresh root", func(t *testing.T) {
		badHeader := header
		badHeader.FreshShardRoot = append([]byte(nil), header.FreshShardRoot...)
		badHeader.FreshShardRoot[0] ^= 1
		badHeader.MetadataHash = hashBytes(
			[]byte("aggrlo-meta"), []byte(badHeader.SID),
			[]byte(fmt.Sprintf("|epoch=%d", badHeader.Epoch)), encodeInts(badHeader.Dealers),
			badHeader.AggregateDigest, badHeader.PayloadDigest, badHeader.FreshShardRoot,
		)
		if err := token.matches(&cvAggregateOfferV1{
			header: badHeader, descriptors: descriptors, aggregate: aggregate,
		}); err == nil {
			t.Fatal("verified aggregate token accepted a mutated fresh root")
		}
	})
}

func TestCVComponentServiceCandidateCollectionRequiresReadyCertifiedDescriptors(t *testing.T) {
	cfg, leafContext, _, _ := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 32)
	router, err := newCVSAPVSSRouterV1(
		context.Background(), transport, cfg.SID, cfg.Epoch, nodes, []int{0}, 16,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	store, err := newCVComponentLeafStoreV1(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := newCVComponentServiceV1(
		context.Background(), cfg, &leafContext, 0, transport, router, store,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := service.CollectComponentCandidates(ctx); err == nil {
		t.Fatal("component candidate collection succeeded below n-f certified descriptors")
	}
}

func TestCVComponentMaterializerSkipsInvalidAvailableLeaf(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 128)
	router, err := newCVSAPVSSRouterV1(
		context.Background(), transport, cfg.SID, cfg.Epoch, nodes, nodes, 64,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })

	services := make([]*cvComponentServiceV1, len(nodes))
	for i, node := range nodes {
		store, storeErr := newCVComponentLeafStoreV1(t.TempDir())
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		services[i], err = newCVComponentServiceV1(
			context.Background(), cfg, &leafContext, node, transport, router, store,
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})

	bad := cvCloneLeafV1ForTest(leaves[0])
	bad.receivers[0].receiverPublicKey = leafContext.receiverPublicKeys[1]
	bad.digest = cvLeafV1Digest(bad)
	if err := cvVerifyLeafV1(&leafContext, bad); err == nil {
		t.Fatal("test fixture did not produce an invalid APVSS leaf")
	}
	third, err := cvRandomDealerLeafV1(leafContext, 2)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	for dealer, leaf := range []*cvLeafV1{bad, leaves[1], third} {
		if _, err := services[dealer].Disperse(ctx, leaf); err != nil {
			t.Fatalf("availability-lock dealer %d: %v", dealer, err)
		}
	}
	candidates, err := services[3].CollectComponentCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := services[3].MaterializeAndCollectARC(ctx, candidates)
	if err != nil {
		t.Fatal(err)
	}
	if got := materialized.aggregate.dealerIDs; len(got) != cfg.FOld+1 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("materializer selected dealers %v, want [1 2]", got)
	}
	badKey := cvComponentKeyV1(0, bad.digest)
	for _, service := range services {
		service.mu.Lock()
		_, cached := service.verifiedLeaves[badKey]
		service.mu.Unlock()
		if cached {
			t.Fatalf("node %d cached an invalid leaf as verified", service.localNode)
		}
	}
}

func TestCVComponentServiceRejectsForgedDealerInit(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 32)
	router, err := newCVSAPVSSRouterV1(
		context.Background(), transport, cfg.SID, cfg.Epoch, nodes, []int{2}, 16,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	store, err := newCVComponentLeafStoreV1(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := newCVComponentServiceV1(
		context.Background(), cfg, &leafContext, 2, transport, router, store,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	leafWire, err := cvLeafV1CanonicalBytes(leaves[0])
	if err != nil {
		t.Fatal(err)
	}
	artifactWire, err := cvComponentLeafArtifactV1CanonicalBytes(&cvComponentLeafArtifactV1{
		dealer: 0, leafDigest: leaves[0].digest, leafWire: leafWire,
	})
	if err != nil {
		t.Fatal(err)
	}
	statement, err := cvComponentStatementDigestV1(0, leaves[0].digest)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := cfg.runtime.lockSigner.SignShare(
		1, cvComponentDealerSignatureDomainV1, statement,
	)
	if err != nil {
		t.Fatal(err)
	}
	initWire, err := cvComponentInitV1CanonicalBytes(&cvComponentInitV1{
		artifactWire: artifactWire,
		dealerSig:    forged,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cvEncodeNetworkEnvelopeV1(cfg.SID, cfg.Epoch, initWire)
	if err != nil {
		t.Fatal(err)
	}
	acksBefore := transport.sentCount(cvTagComponentAckV1)
	if err := transport.Send(Message{From: 0, To: 2, Tag: cvTagComponentInitV1, Body: envelope}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := transport.sentCount(cvTagComponentAckV1); got != acksBefore {
		t.Fatalf("forged dealer INIT produced ACK: before=%d after=%d", acksBefore, got)
	}
}
