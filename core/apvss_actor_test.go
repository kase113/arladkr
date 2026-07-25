package core

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestAPVSSReceiverActorsCollectACKsV1(t *testing.T) {
	fixture := apvssFixtureV1(t, 4, 1)
	fixture.leaf.dealerID = 0
	fixture.leaf.digest = cvLeafV1Digest(fixture.leaf)
	oldNodes := []int{0, 1, 2, 3}
	receiverOrder := []int{10, 11, 12, 13}
	allNodes := sortedUnique(append(append([]int(nil), oldNodes...), receiverOrder...))
	cfg := NormalizeConfig(Config{
		SID: string(fixture.context.sessionID), Epoch: int(fixture.context.epoch),
		OldCommittee: oldNodes, NewCommittee: receiverOrder, FOld: 1, FNew: 1, Kappa: 2,
		APVSSProvider: "cv-sapvss", ARCMode: "materialized",
		APVSSFallbackProfile:   apvssFallbackCompactBatchProfileV1,
		AllowExperimentalAPVSS: true, APVSSBenchmarkFallbackCount: 1,
		LocalNodeIDs: oldNodes, ArtifactCacheDir: t.TempDir(),
	})
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	transport := newCVRouterTestTransport(allNodes, 128)
	router, err := newCVSAPVSSRouterWithReceiversV1(
		context.Background(), transport, cfg.SID, cfg.Epoch,
		oldNodes, receiverOrder, allNodes, 64,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	secrets := make(map[int]fr.Element, len(receiverOrder))
	for i, receiverID := range receiverOrder {
		secrets[receiverID] = fixture.receiverSecrets[i]
	}
	store, err := newCVComponentLeafStoreV1(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := newCVComponentServiceWithReceiversV1(
		context.Background(), cfg, &fixture.context, 0, transport, router, store,
		receiverOrder, secrets,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	prototype, err := service.CollectAPVSSLaneACKs(ctx, fixture.leaf, &fixture.witness)
	if err != nil {
		t.Fatal(err)
	}
	fallbackCount := apvssPrototypeFallbackCountV1(prototype)
	if len(prototype.acks) != len(receiverOrder)-1 || fallbackCount != 1 {
		t.Fatalf("actor ACK/fallback counts = %d/%d", len(prototype.acks), fallbackCount)
	}
	if prototype.fallbackProfile != apvssFallbackCompactBatchProfileV1 || prototype.compactFallback == nil {
		t.Fatal("actor did not assemble the experimental compact fallback profile")
	}
	if err := apvssVerifyPrototypeV1(&fixture.context, prototype); err != nil {
		t.Fatalf("actor-produced APVSS leaf rejected: %v", err)
	}
	if transport.sentCount(apvssTagLaneOfferV1) != len(receiverOrder) ||
		transport.sentCount(apvssTagLaneACKV1) < len(receiverOrder)-fixture.context.sharingDegree {
		t.Fatal("receiver actors did not exchange the expected offer/ACK messages")
	}
}

func TestAPVSSReceiverActorsFeedAvailabilityAndVerifiedCacheV1(t *testing.T) {
	fixture := apvssFixtureV1(t, 4, 1)
	fixture.leaf.dealerID = 0
	fixture.leaf.digest = cvLeafV1Digest(fixture.leaf)
	oldNodes := []int{0, 1, 2, 3}
	receiverOrder := []int{10, 11, 12, 13}
	allNodes := sortedUnique(append(append([]int(nil), oldNodes...), receiverOrder...))
	cfg := NormalizeConfig(Config{
		SID: string(fixture.context.sessionID), Epoch: int(fixture.context.epoch),
		OldCommittee: oldNodes, NewCommittee: receiverOrder, FOld: 1, FNew: 1, Kappa: 2,
		APVSSProvider: "cv-sapvss", ARCMode: "materialized",
		LocalNodeIDs: oldNodes, ArtifactCacheDir: t.TempDir(),
	})
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	transport := newCVRouterTestTransport(allNodes, 256)
	router, err := newCVSAPVSSRouterWithReceiversV1(
		context.Background(), transport, cfg.SID, cfg.Epoch,
		oldNodes, receiverOrder, allNodes, 128,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	services := make([]*cvComponentServiceV1, len(oldNodes))
	for i, node := range oldNodes {
		store, storeErr := newCVComponentLeafStoreV1(t.TempDir())
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		services[i], err = newCVComponentServiceWithReceiversV1(
			context.Background(), cfg, &fixture.context, node, transport, router, store,
			receiverOrder, map[int]fr.Element{receiverOrder[i]: fixture.receiverSecrets[i]},
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	prototype, err := services[0].CollectAPVSSLaneACKs(ctx, fixture.leaf, &fixture.witness)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := services[0].DisperseAPVSS(ctx, prototype)
	if err != nil {
		t.Fatalf(
			"disperse APVSS: %v (init=%d component_ack=%d)",
			err,
			transport.sentCount(cvTagComponentInitV1),
			transport.sentCount(cvTagComponentAckV1),
		)
	}
	if !bytes.Equal(descriptor.leafDigest, prototype.digest) {
		t.Fatal("availability descriptor did not bind the APVSS leaf digest")
	}
	for _, service := range services {
		service.mu.Lock()
		cachedBefore := len(service.verifiedLeaves)
		service.mu.Unlock()
		if cachedBefore != 0 {
			t.Fatal("availability lock performed APVSS proof verification")
		}
		accepted, err := service.loadOrRetrieveComponent(ctx, descriptor)
		if err != nil {
			t.Fatal(err)
		}
		if accepted.apvss == nil || !bytes.Equal(accepted.leafDigest, prototype.digest) {
			t.Fatal("materializer did not cache an APVSS-verified leaf token")
		}
		if err := cvValidateAcceptedLeafV1(&fixture.context, accepted); err != nil {
			t.Fatalf("cached APVSS token rejected: %v", err)
		}
	}
}
