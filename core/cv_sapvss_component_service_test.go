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
	router, err := newCVSAPVSSRouter(
		context.Background(), transport, cfg.SID, cfg.Epoch, nodes, nodes, 64,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })

	services := make([]*cvComponentService, len(nodes))
	for i, node := range nodes {
		store, storeErr := newCVComponentLeafStore(t.TempDir())
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		services[i], err = newCVComponentService(
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
	if got := transport.sentCount(cvTagComponentInit); got != len(nodes)-1 {
		t.Fatalf("component dispersal sent %d INIT messages, want %d without self-INIT", got, len(nodes)-1)
	}
	if len(descriptor.certificate) == 0 {
		t.Fatalf("component certificate is empty: %+v", descriptor)
	}
	if err := cvValidateComponentDescriptor(cfg, descriptor); err != nil {
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

	getBefore := transport.sentCount(cvTagComponentGet)
	leafBefore := transport.sentCount(cvTagComponentLeaf)
	retrieved, err := services[len(services)-1].Retrieve(ctx, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retrieved.digest, leaves[0].digest) ||
		transport.sentCount(cvTagComponentGet) <= getBefore ||
		transport.sentCount(cvTagComponentLeaf) <= leafBefore {
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
	thirdLeaf, err := cvRandomDealerLeaf(leafContext, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := services[2].Disperse(ctx, thirdLeaf); err != nil {
		t.Fatal(err)
	}
	candidateSets := make(map[int][]*cvComponentDescriptor, len(services))
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
	if got, wantAtLeast := transport.sentCount(cvTagComponentReady), len(nodes)*(len(nodes)-1); got < wantAtLeast {
		t.Fatalf("ReadyCert dissemination sent %d messages, want at least %d", got, wantAtLeast)
	}
	for _, service := range services {
		service.mu.Lock()
		published := len(service.publishedReadyRoots)
		accepted := len(service.acceptedReadyRoots)
		service.mu.Unlock()
		if published == 0 || accepted == 0 {
			t.Fatalf("node %d did not publish/accept a ReadyCert", service.localNode)
		}
	}
	type materializeResult struct {
		value *cvMaterializedAggregate
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
	var materialized *cvMaterializedAggregate
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
	if materialized.rlo.Lock.Threshold != len(nodes)-cfg.FOld || len(materialized.rlo.Lock.Certificate) == 0 {
		t.Fatal("network ARC did not produce a compact recovered certificate")
	}
	for _, service := range services {
		service.mu.Lock()
		cachedOffers := len(service.verifiedAggregates)
		service.mu.Unlock()
		if cachedOffers != 1 {
			t.Fatalf("node %d cached %d verified aggregate offers, want one", service.localNode, cachedOffers)
		}
	}
	stoppedHolder := services[0].localNode
	if err := services[stoppedHolder].Close(); err != nil {
		t.Fatal(err)
	}
	recoverGetBefore := transport.sentCount(cvTagRecoverGet)
	recoverShardBefore := transport.sentCount(cvTagRecoverShard)
	recovered, err := services[len(services)-1].RecoverAggregate(ctx, materialized.rlo)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered.digest, materialized.aggregate.digest) ||
		transport.sentCount(cvTagRecoverGet) <= recoverGetBefore ||
		transport.sentCount(cvTagRecoverShard)-recoverShardBefore < len(nodes)-2*cfg.FOld {
		t.Fatal("aggregate recovery did not collect n-2f ARC-holder shards over the network")
	}
}

func TestCVAggregateManifestOfferRejectsMutation(t *testing.T) {
	cfg, context, _, leaves := cvM4Fixture(t)
	accepted := make([]*cvVerifiedLeaf, cfg.FOld+1)
	descriptors := make([]*cvComponentDescriptor, cfg.FOld+1)
	for i := range accepted {
		wire, err := cvLeafCanonicalBytes(leaves[i])
		if err != nil {
			t.Fatal(err)
		}
		accepted[i], err = cvAcceptedLeaf(&context, leaves[i], wire)
		if err != nil {
			t.Fatal(err)
		}
		descriptors[i] = &cvComponentDescriptor{dealer: int(leaves[i].dealerID), leafDigest: accepted[i].leafDigest, certificate: []byte{4}}
	}
	aggregate, err := cvAggVerified(&context, accepted)
	if err != nil {
		t.Fatal(err)
	}
	dispersal, err := cvDisperseAggregate(aggregate, len(cfg.OldCommittee), len(cfg.OldCommittee)-2*cfg.FOld)
	if err != nil {
		t.Fatal(err)
	}
	header, err := cvBuildNetworkAggHeader(cfg, aggregate, dispersal)
	if err != nil {
		t.Fatal(err)
	}
	root, err := cvComponentManifestRoot(descriptors)
	if err != nil {
		t.Fatal(err)
	}
	readyRoot := bytes.Repeat([]byte{0x52}, 32)
	wire, err := cvAggregateManifestOfferCanonicalBytes(&cvAggregateManifestOffer{
		header: header, descriptors: descriptors, readyRoot: readyRoot, root: root,
	})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAggregateManifestOffer(wire, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.readyRoot, readyRoot) || !bytes.Equal(decoded.root, root) || len(decoded.descriptors) != 0 {
		t.Fatal("manifest offer did not preserve its compact reference")
	}

	t.Run("manifest root mismatch", func(t *testing.T) {
		badDescriptors := append([]*cvComponentDescriptor(nil), descriptors...)
		copyDescriptor := *descriptors[0]
		copyDescriptor.leafDigest = append([]byte(nil), descriptors[0].leafDigest...)
		copyDescriptor.leafDigest[0] ^= 1
		badDescriptors[0] = &copyDescriptor
		if _, err := cvAggregateManifestOfferCanonicalBytes(&cvAggregateManifestOffer{
			header: header, descriptors: badDescriptors, readyRoot: readyRoot, root: root,
		}); err == nil {
			t.Fatal("encoded an aggregate manifest with a mismatched root")
		}
	})
	t.Run("trailing bytes", func(t *testing.T) {
		if _, err := cvDecodeAggregateManifestOffer(append(wire, 0), cfg); err == nil {
			t.Fatal("accepted an aggregate manifest with trailing bytes")
		}
	})
	t.Run("unknown ReadyCert root is deferred", func(t *testing.T) {
		service := &cvComponentService{
			cfg:                    cfg,
			acceptedReadyRoots:     make(map[string]struct{}),
			pendingReadyOffers:     make(map[string][]Message),
			processingOffers:       make(map[string]struct{}),
			readyDescriptorsByRoot: make(map[string][]*cvComponentDescriptor),
		}
		service.handleAggregateOffer(Message{From: 1, Body: wire})
		key := fmt.Sprintf("%x", readyRoot)
		deadline := time.Now().Add(time.Second)
		for {
			service.mu.Lock()
			pending := len(service.pendingReadyOffers[key])
			service.mu.Unlock()
			if pending == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("aggregate offer with an unknown ReadyCert root was not deferred")
			}
			time.Sleep(time.Millisecond)
		}
		newReadyRoot := bytes.Repeat([]byte{0x53}, 32)
		newWire, err := cvAggregateManifestOfferCanonicalBytes(&cvAggregateManifestOffer{
			header: header, descriptors: descriptors, readyRoot: newReadyRoot, root: root,
		})
		if err != nil {
			t.Fatal(err)
		}
		service.handleAggregateOffer(Message{From: 1, Body: newWire})
		newKey := fmt.Sprintf("%x", newReadyRoot)
		deadline = time.Now().Add(time.Second)
		for {
			service.mu.Lock()
			oldPending := len(service.pendingReadyOffers[key])
			newPending := len(service.pendingReadyOffers[newKey])
			service.mu.Unlock()
			if oldPending == 0 && newPending == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("unknown-root pending offers were not bounded to one per sender")
			}
			time.Sleep(time.Millisecond)
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
	router, err := newCVSAPVSSRouter(
		context.Background(), transport, cfg.SID, cfg.Epoch, nodes, []int{0}, 16,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	store, err := newCVComponentLeafStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := newCVComponentService(
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

func TestCVComponentReadyCertificateReselectsAfterLowerDealerArrives(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 256)
	router, err := newCVSAPVSSRouter(context.Background(), transport, cfg.SID, cfg.Epoch, nodes, nodes, 128)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	services := make([]*cvComponentService, len(nodes))
	for i, node := range nodes {
		store, storeErr := newCVComponentLeafStore(t.TempDir())
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		services[i], err = newCVComponentService(context.Background(), cfg, &leafContext, node, transport, router, store)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})
	dealerLeaves := make([]*cvLeaf, len(nodes))
	dealerLeaves[0], dealerLeaves[1] = leaves[0], leaves[1]
	for dealer := 2; dealer < len(nodes); dealer++ {
		dealerLeaves[dealer], err = cvRandomDealerLeaf(leafContext, dealer)
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	for _, dealer := range []int{1, 2, 3} {
		if _, err := services[dealer].Disperse(ctx, dealerLeaves[dealer]); err != nil {
			t.Fatal(err)
		}
	}
	var first []*cvComponentDescriptor
	select {
	case first = <-services[0].readyCandidates:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if len(first) != 3 || first[0].dealer != 1 || first[1].dealer != 2 || first[2].dealer != 3 {
		t.Fatalf("unexpected first ReadyCert pool: %+v", first)
	}
	if _, err := services[0].Disperse(ctx, dealerLeaves[0]); err != nil {
		t.Fatal(err)
	}
	var second []*cvComponentDescriptor
	select {
	case second = <-services[0].readyCandidates:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if len(second) != 3 || second[0].dealer != 0 || second[1].dealer != 1 || second[2].dealer != 2 {
		t.Fatalf("ReadyCert did not reselect canonical lower pool: %+v", second)
	}
}

func TestCVComponentMaterializerSkipsInvalidAvailableLeaf(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 128)
	router, err := newCVSAPVSSRouter(
		context.Background(), transport, cfg.SID, cfg.Epoch, nodes, nodes, 64,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })

	services := make([]*cvComponentService, len(nodes))
	for i, node := range nodes {
		store, storeErr := newCVComponentLeafStore(t.TempDir())
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		services[i], err = newCVComponentService(
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

	bad := cvCloneLeafForTest(leaves[0])
	bad.receivers[0].receiverPublicKey = leafContext.receiverPublicKeys[1]
	bad.digest = cvLeafDigest(bad)
	if err := cvVerifyLeaf(&leafContext, bad); err == nil {
		t.Fatal("test fixture did not produce an invalid APVSS leaf")
	}
	third, err := cvRandomDealerLeaf(leafContext, 2)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	for dealer, leaf := range []*cvLeaf{bad, leaves[1], third} {
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
	wrongSelected := candidates[:cfg.FOld+1]
	wrongRoot, err := cvComponentManifestRoot(wrongSelected)
	if err != nil {
		t.Fatal(err)
	}
	wrongHeader := materialized.rlo.Header
	wrongHeader.Dealers = []int{0, 1}
	wrongOffer := &cvAggregateManifestOffer{
		header: wrongHeader, readyRoot: cvMustReadyRootForTest(t, services[3], candidates), root: wrongRoot,
	}
	if err := services[3].resolveAggregateManifestDescriptors(wrongOffer); err == nil {
		t.Fatal("accepted aggregate offer that was not ReadyCert FirstKValid")
	}
	badKey := cvComponentKey(0, bad.digest)
	for _, service := range services {
		service.mu.Lock()
		_, cached := service.verifiedLeaves[badKey]
		service.mu.Unlock()
		if cached {
			t.Fatalf("node %d cached an invalid leaf as verified", service.localNode)
		}
	}
}

func cvMustReadyRootForTest(t testing.TB, service *cvComponentService, descriptors []*cvComponentDescriptor) []byte {
	t.Helper()
	certificate, err := cvBuildComponentReadyCertificate(service.localNode, descriptors)
	if err != nil {
		t.Fatal(err)
	}
	return certificate.root
}

func TestCVComponentServiceRejectsForgedDealerInit(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 32)
	router, err := newCVSAPVSSRouter(
		context.Background(), transport, cfg.SID, cfg.Epoch, nodes, []int{2}, 16,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	store, err := newCVComponentLeafStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := newCVComponentService(
		context.Background(), cfg, &leafContext, 2, transport, router, store,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()

	leafWire, err := cvLeafCanonicalBytes(leaves[0])
	if err != nil {
		t.Fatal(err)
	}
	dispersal, shards, err := cvDisperseComponent(leafWire, len(cfg.OldCommittee), len(cfg.OldCommittee)-2*cfg.FOld)
	if err != nil {
		t.Fatal(err)
	}
	artifactWire, err := cvComponentShardArtifactCanonicalBytes(&cvComponentShardArtifact{
		dealer: 0, leafDigest: leaves[0].digest, dispersal: *dispersal, shard: shards[1],
	})
	if err != nil {
		t.Fatal(err)
	}
	statement, err := cvComponentStatementDigest(0, leaves[0].digest, dispersal)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := cfg.runtime.lockSigner.SignShare(
		1, cvComponentDealerSignatureDomain, statement,
	)
	if err != nil {
		t.Fatal(err)
	}
	initWire, err := cvComponentInitCanonicalBytes(&cvComponentInit{
		artifactWire: artifactWire,
		dealerSig:    forged,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cvEncodeNetworkEnvelope(cfg.SID, cfg.Epoch, initWire)
	if err != nil {
		t.Fatal(err)
	}
	acksBefore := transport.sentCount(cvTagComponentAck)
	if err := transport.Send(Message{From: 0, To: 2, Tag: cvTagComponentInit, Body: envelope}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := transport.sentCount(cvTagComponentAck); got != acksBefore {
		t.Fatalf("forged dealer INIT produced ACK: before=%d after=%d", acksBefore, got)
	}
}
