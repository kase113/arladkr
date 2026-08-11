package core

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestCVAPDBNetworkServiceV2LockAndRecoverOverAuthenticatedRouter(t *testing.T) {
	auth, _, _, cfg := cvNetworkAuthV2Fixture(t)
	_, public := cvAgreementObjectV2Fixture(t)
	contextDigest := public.ContextDigest
	poolDigest := hashBytes([]byte("network APDB pool"))
	selectionDigest := hashBytes([]byte("network APDB selection"))
	proposer := cfg.OldCommittee[0]
	instance, err := cvAggregateInstanceDigestV2(contextDigest, proposer, poolDigest, selectionDigest)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("authenticated APDB network payload")
	encoded, err := cvAPDBEncodeV2(instance, payload, public.Params.recoveryThreshold, len(cfg.OldCommittee), 2048)
	if err != nil {
		t.Fatal(err)
	}

	localNodes := append([]int(nil), cfg.OldCommittee...)
	localReceiver := cfg.NewCommittee[0]
	localNodes = sortedUnique(append(localNodes, localReceiver))
	allNodes := sortedUnique(append(append([]int(nil), cfg.OldCommittee...), cfg.NewCommittee...))
	transport := newCVRouterTestTransport(allNodes, 256)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, localNodes, 128, auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	holderStore, err := newCVAPDBHolderStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	serviceCfg := cvAPDBNetworkServiceConfigV2{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee,
		ExpectedContext: contextDigest, TotalShards: len(cfg.OldCommittee),
		DataShards: public.Params.recoveryThreshold, ShardBytes: encoded.shardBytes, MaximumPayload: 2048,
	}
	services := make(map[int]*cvAPDBNetworkServiceV2, len(localNodes))
	for _, node := range localNodes {
		nodeCfg := serviceCfg
		nodeCfg.LocalNode = node
		localStore := holderStore
		if !cvMemberInRosterV2(node, cfg.OldCommittee) {
			localStore = nil
		}
		services[node], err = newCVAPDBNetworkServiceV2(context.Background(), nodeCfg, transport, router, auth,
			localStore, public.APDBSigner, public.ControlSigner)
		if err != nil {
			t.Fatalf("start node %d APDB network service: %v", node, err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	lock, err := services[proposer].Lock(ctx, encoded)
	if err != nil {
		t.Fatalf("network LockPD: %v", err)
	}
	if cvVerifyAPDBLockV2(lock, public.APDBSigner) != nil {
		t.Fatal("network LockPD produced an invalid compact lock")
	}
	if got := transport.sentCount(cvTagAPDBStoreV2); got != len(cfg.OldCommittee) {
		t.Fatalf("LockPD sent %d stores, want all %d holders", got, len(cfg.OldCommittee))
	}

	componentRecovered, err := services[cfg.OldCommittee[1]].RecoverComponent(ctx, lock, nil)
	if err != nil || !bytes.Equal(componentRecovered, payload) {
		t.Fatalf("network component recovery: %v", err)
	}
	if got := transport.sentCount(cvTagAPDBRecoverGetV2); got != len(cfg.OldCommittee) {
		t.Fatalf("component recovery sent %d requests, want all %d holders", got, len(cfg.OldCommittee))
	}

	header := cvAggregateHeaderV2{
		ContextDigest: contextDigest, ProposerID: proposer, PoolDigest: poolDigest, SelectionDigest: selectionDigest,
		AggregateDigest: hashBytes([]byte("network aggregate")), PayloadDigest: hashBytes(payload),
		APDBInstance: instance, APDBRoot: encoded.root,
	}
	decisionStatement, err := cvDecisionStatementV2(contextDigest, &header, lock)
	if err != nil {
		t.Fatal(err)
	}
	handoff := cvHandoffV2{
		ContextDigest: contextDigest, Header: header, ARC: *lock,
		DecCert: cvRecoverThresholdCertificateV2ForTest(t, public.ControlSigner, public.OldCommittee,
			cvDecisionCertificateV2Domain, decisionStatement),
	}
	request, err := cvAggregateRecoveryRequestV2CanonicalBytes(&cvAggregateRecoveryRequestV2{Handoff: handoff})
	if err != nil {
		t.Fatal(err)
	}
	aggregateRecovered, err := services[localReceiver].RecoverAggregate(ctx, request, nil)
	if err != nil || !bytes.Equal(aggregateRecovered, payload) {
		t.Fatalf("network aggregate recovery: %v", err)
	}
	if got := transport.sentCount(cvTagAggregateRecoverGetV2); got != len(cfg.OldCommittee) {
		t.Fatalf("aggregate recovery sent %d requests, want all %d holders", got, len(cfg.OldCommittee))
	}
}

func TestCVAPDBNetworkServiceV2RejectsMissingAuthentication(t *testing.T) {
	auth, _, _, cfg := cvNetworkAuthV2Fixture(t)
	_, public := cvAgreementObjectV2Fixture(t)
	nodes := sortedUnique(append(append([]int(nil), cfg.OldCommittee...), cfg.NewCommittee...))
	transport := newCVRouterTestTransport(nodes, 16)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, []int{cfg.OldCommittee[0]}, 8, auth)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	serviceCfg := cvAPDBNetworkServiceConfigV2{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), LocalNode: cfg.OldCommittee[0],
		OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee, ExpectedContext: public.ContextDigest,
		TotalShards: len(cfg.OldCommittee), DataShards: public.Params.recoveryThreshold,
		ShardBytes: 32, MaximumPayload: 1024,
	}
	holderStore, err := newCVAPDBHolderStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newCVAPDBNetworkServiceV2(context.Background(), serviceCfg, transport, router, nil,
		holderStore, public.APDBSigner, public.ControlSigner); err == nil {
		t.Fatal("started V2 APDB network service without an authenticator")
	}
}
