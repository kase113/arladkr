package core

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestCVCertifiedCandidateV2AcceptsRelaysAndSuppressesDuplicates(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	_, _, receivers, cfg := cvNetworkAuthV2Fixture(t)
	auth, err := newCVNetworkAuthenticatorV2(public.ValidatorKeys, receivers)
	if err != nil {
		t.Fatal(err)
	}
	transport := newCVRouterTestTransport(cfg.OldCommittee, 256)
	router, err := newCVSAPVSSRouterWithReceivers(
		context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, cfg.OldCommittee, 128, auth,
	)
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
		ExpectedContext: public.ContextDigest, TotalShards: len(cfg.OldCommittee),
		DataShards: public.Params.recoveryThreshold, ShardBytes: 32, MaximumPayload: 2048,
		Params: public.Params, EligibilityCoin: public.EligibilityCoin,
	}
	services := make(map[int]*cvAPDBNetworkServiceV2, len(cfg.OldCommittee))
	for _, member := range cfg.OldCommittee {
		memberCfg := serviceCfg
		memberCfg.LocalNode = member
		services[member], err = newCVAPDBNetworkServiceV2(
			context.Background(), memberCfg, transport, router, auth, holderStore,
			public.APDBSigner, public.ControlSigner, public.CoinSigner,
		)
		if err != nil {
			t.Fatal(err)
		}
		// The agreement fixture uses a synthetic context digest, so attach only
		// the public validator registry needed by the candidate predicate.
		services[member].cfg.Validators = public.ValidatorKeys
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})

	relay := cfg.OldCommittee[0]
	if relay == object.Header.ProposerID {
		relay = cfg.OldCommittee[1]
	}
	receiver := cfg.OldCommittee[len(cfg.OldCommittee)-1]
	if receiver == relay {
		receiver = cfg.OldCommittee[len(cfg.OldCommittee)-2]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	published := make(chan error, 1)
	go func() { published <- services[relay].PublishCertifiedCandidateV2(ctx, object) }()
	got, err := services[receiver].AwaitFirstCertifiedCandidateV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Header.ProposerID != object.Header.ProposerID || relay == object.Header.ProposerID {
		t.Fatalf("candidate relay=%d embedded proposer=%d", relay, got.Header.ProposerID)
	}

	_, validators, err := cvAgreementEligibilitySamplesV2(public)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvAgreementObjectV2CanonicalBytes(object, public.Params, validators)
	if err != nil {
		t.Fatal(err)
	}
	if _, accepted, err := services[receiver].acceptCertifiedCandidateV2(wire); err != nil || accepted {
		t.Fatalf("duplicate candidate accepted=%v err=%v", accepted, err)
	}
	mutated := append([]byte(nil), wire...)
	mutated[len(mutated)-1] ^= 1
	if _, _, err := services[receiver].acceptCertifiedCandidateV2(mutated); err == nil {
		t.Fatal("accepted mutated certified candidate")
	}
	select {
	case duplicate := <-services[receiver].certifiedCandidateChV2:
		t.Fatalf("duplicate candidate reached first-candidate queue: proposer=%d", duplicate.Header.ProposerID)
	case <-time.After(20 * time.Millisecond):
	}

	deadline := time.Now().Add(time.Second)
	for !cvCandidateRelaySentForTest(transport, receiver, relay) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !cvCandidateRelaySentForTest(transport, receiver, relay) {
		t.Fatalf("node %d accepted but did not relay candidate received from %d", receiver, relay)
	}
	cancel()
	if err := <-published; err != context.Canceled {
		t.Fatalf("candidate publisher shutdown error=%v", err)
	}
	if !bytes.Equal(got.Header.AggregateDigest, object.Header.AggregateDigest) {
		t.Fatal("relayed candidate changed aggregate digest")
	}
}

func cvCandidateRelaySentForTest(transport *cvRouterTestTransport, from, excluded int) bool {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	for _, message := range transport.sent {
		if message.Tag == cvTagCertifiedCandidateV2 && message.From == from && message.To != excluded {
			return true
		}
	}
	return false
}
