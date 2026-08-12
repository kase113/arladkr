package core

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestCVLaneNetworkV2BuildsAllACKLeafWithActorLocalSecrets(t *testing.T) {
	cfg := cvV2ParamsTestConfig()
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		t.Fatal(err)
	}
	receiverPublic := filepath.Join(t.TempDir(), "receiver-public")
	receiverSecret := filepath.Join(t.TempDir(), "receiver-secret")
	if err := cvGenerateReceiverRegistryV2(receiverPublic, receiverSecret, cfg.SID, uint64(cfg.Epoch), cfg.NewCommittee); err != nil {
		t.Fatal(err)
	}
	validatorPublic := filepath.Join(t.TempDir(), "validator-public")
	validatorSecret := filepath.Join(t.TempDir(), "validator-secret")
	if err := cvGenerateValidatorRegistryV2(validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee); err != nil {
		t.Fatal(err)
	}
	thresholdPublic := filepath.Join(t.TempDir(), "threshold-public")
	thresholdSecret := filepath.Join(t.TempDir(), "threshold-secret")
	if err := cvGenerateOldCommitteeKeyBundleV2(thresholdPublic, thresholdSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params); err != nil {
		t.Fatal(err)
	}
	receivers, err := cvLoadReceiverRegistryV2(receiverPublic, receiverSecret, cfg.SID, uint64(cfg.Epoch), cfg.NewCommittee, cfg.NewCommittee)
	if err != nil {
		t.Fatal(err)
	}
	validators, err := cvLoadValidatorRegistryV2(validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleV2(thresholdPublic, thresholdSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params)
	if err != nil {
		t.Fatal(err)
	}
	apdbSigner, _ := newTBLSThresholdSignerFromV2Material(bundle.apdb)
	controlSigner, _ := newTBLSThresholdSignerFromV2Material(bundle.control)
	coinSigner, _ := newTBLSThresholdSignerFromV2Material(bundle.coin)
	auth, err := newCVNetworkAuthenticatorV2(validators, receivers)
	if err != nil {
		t.Fatal(err)
	}
	leafContext := &cvLeafContextV2{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee,
		ReceiverRegistryDigest: receivers.registryDigest, SharingDegree: params.newShareDegree,
		Profile: cvChunkProfile{chunkBits: 8, maxComponents: params.componentCount},
	}
	contextDigest, err := cvLeafContextDigestV2(leafContext)
	if err != nil {
		t.Fatal(err)
	}
	dealer := cfg.OldCommittee[0]
	localNodes := sortedUnique(append([]int{dealer}, cfg.NewCommittee...))
	transport := newCVRouterTestTransport(localNodes, 512)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, localNodes, 256, auth)
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
		ExpectedContext: contextDigest, TotalShards: len(cfg.OldCommittee), DataShards: params.recoveryThreshold,
		ShardBytes: 0, MaximumPayload: cvMaxLeafWireBytes, Params: params,
		LeafContext: leafContext, Receivers: receivers, Validators: validators,
	}
	services := make(map[int]*cvAPDBNetworkServiceV2, len(localNodes))
	for _, node := range localNodes {
		nodeCfg := serviceCfg
		nodeCfg.LocalNode = node
		localStore := holderStore
		if cvMemberInRosterV2(node, cfg.NewCommittee) {
			localStore = nil
			nodeCfg.Receivers, err = cvLoadReceiverRegistryV2(
				receiverPublic, receiverSecret, cfg.SID, uint64(cfg.Epoch), cfg.NewCommittee, []int{node},
			)
			if err != nil {
				t.Fatal(err)
			}
			nodeCfg.Validators, err = cvLoadValidatorRegistryV2(
				validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, nil,
			)
		} else {
			nodeCfg.Receivers, err = cvLoadReceiverRegistryV2(
				receiverPublic, receiverSecret, cfg.SID, uint64(cfg.Epoch), cfg.NewCommittee, nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			nodeCfg.Validators, err = cvLoadValidatorRegistryV2(
				validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, []int{node},
			)
		}
		if err != nil {
			t.Fatal(err)
		}
		services[node], err = newCVAPDBNetworkServiceV2(context.Background(), nodeCfg, transport, router, auth,
			localStore, apdbSigner, controlSigner, coinSigner)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	leaf, err := services[dealer].BuildAllACKLeafV2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyAPVSSV2(leaf, leafContext, receivers, validators); err != nil {
		t.Fatal(err)
	}
	if len(services[dealer].cfg.Receivers.localEncryptionSecrets) != 0 ||
		len(services[dealer].cfg.Receivers.localIdentitySecrets) != 0 ||
		len(services[dealer].cfg.Validators.localSecrets) != 1 {
		t.Fatal("network V2 dealer actor received non-local secrets")
	}
	for _, receiver := range cfg.NewCommittee {
		if len(services[receiver].cfg.Receivers.localEncryptionSecrets) != 1 ||
			len(services[receiver].cfg.Receivers.localIdentitySecrets) != 1 ||
			len(services[receiver].cfg.Validators.localSecrets) != 0 {
			t.Fatalf("network V2 receiver %d received non-local secrets", receiver)
		}
	}
	if len(leaf.Partition.ACKReceiverIndices) != len(cfg.NewCommittee) || len(leaf.Partition.FallbackReceiverIndices) != 0 {
		t.Fatal("network V2 leaf did not contain all receiver ACKs")
	}
	if got := transport.sentCount(cvTagLaneOfferV2); got != len(cfg.NewCommittee) {
		t.Fatalf("network V2 dealer sent %d offers", got)
	}
	if got := transport.sentCount(cvTagLaneACKV2); got != len(cfg.NewCommittee) {
		t.Fatalf("network V2 receivers sent %d ACKs", got)
	}
}

func TestCVLaneACKMessageV2StrictCodecAndBinding(t *testing.T) {
	leaf, context, receivers, _ := cvAllACKLeafV2Fixture(t)
	offer := &leaf.Receivers[0].Offer
	offerWire, err := cvReceiverLaneOfferV2CanonicalBytes(context, leaf.DealerID, offer, &receivers.encryptionPublicKeys[0])
	if err != nil {
		t.Fatal(err)
	}
	message := &cvLaneACKMessageV2{
		DealerID: leaf.DealerID, ReceiverID: offer.ReceiverID, ReceiverIndex: offer.ReceiverIndex,
		OfferDigest: cvLaneOfferDigestV2(offerWire), Evidence: *leaf.Receivers[0].ACK,
	}
	wire, err := cvLaneACKMessageV2CanonicalBytes(message, context)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeLaneACKMessageV2(wire, context)
	if err != nil || decoded.DealerID != message.DealerID || decoded.ReceiverID != message.ReceiverID {
		t.Fatalf("round-trip CV V2 lane ACK message: %v", err)
	}
	if _, err := cvDecodeLaneACKMessageV2(append(append([]byte(nil), wire...), 0), context); err == nil {
		t.Fatal("accepted trailing CV V2 lane ACK message bytes")
	}
	mutated := append([]byte(nil), wire...)
	mutated[len(mutated)-1] ^= 1
	decoded, err = cvDecodeLaneACKMessageV2(mutated, context)
	if err == nil && cvVerifyACKV2(context, message.DealerID, offer, &receivers.encryptionPublicKeys[0],
		receivers.identityPublicKeys[0], &decoded.Evidence) == nil {
		t.Fatal("accepted mutated CV V2 lane ACK evidence")
	}
}

func TestCVComponentNetworkV2PublicationBarrier(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real V2 component publication barrier in short mode")
	}
	_, leafContext, receivers, validators := cvAllACKLeafV2Fixture(t)
	cfg := cvV2ParamsTestConfig()
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		t.Fatal(err)
	}
	thresholdPublic := filepath.Join(t.TempDir(), "threshold-public")
	thresholdSecret := filepath.Join(t.TempDir(), "threshold-secret")
	if err := cvGenerateOldCommitteeKeyBundleV2(thresholdPublic, thresholdSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params); err != nil {
		t.Fatal(err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleV2(thresholdPublic, thresholdSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params)
	if err != nil {
		t.Fatal(err)
	}
	apdbSigner, _ := newTBLSThresholdSignerFromV2Material(bundle.apdb)
	controlSigner, _ := newTBLSThresholdSignerFromV2Material(bundle.control)
	coinSigner, _ := newTBLSThresholdSignerFromV2Material(bundle.coin)
	auth, err := newCVNetworkAuthenticatorV2(validators, receivers)
	if err != nil {
		t.Fatal(err)
	}
	contextDigest, err := cvLeafContextDigestV2(leafContext)
	if err != nil {
		t.Fatal(err)
	}
	allNodes := sortedUnique(append(append([]int(nil), cfg.OldCommittee...), cfg.NewCommittee...))
	transport := newCVRouterTestTransport(allNodes, 8192)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, allNodes, 4096, auth)
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
		ExpectedContext: contextDigest, TotalShards: len(cfg.OldCommittee), DataShards: params.recoveryThreshold,
		MaximumPayload: cvMaxLeafWireBytes, Params: params, LeafContext: leafContext,
		Receivers: receivers, Validators: validators,
	}
	services := make(map[int]*cvAPDBNetworkServiceV2, len(allNodes))
	for _, node := range allNodes {
		nodeCfg := serviceCfg
		nodeCfg.LocalNode = node
		localStore := holderStore
		if cvMemberInRosterV2(node, cfg.NewCommittee) {
			localStore = nil
		}
		services[node], err = newCVAPDBNetworkServiceV2(context.Background(), nodeCfg, transport, router, auth,
			localStore, apdbSigner, controlSigner, coinSigner)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	published := make(chan error, len(cfg.OldCommittee))
	for _, dealer := range cfg.OldCommittee {
		go func(node int) {
			leaf, buildErr := services[node].BuildAllACKLeafV2(ctx)
			if buildErr == nil {
				_, buildErr = services[node].PublishComponentV2(ctx, leaf)
			}
			published <- buildErr
		}(dealer)
	}
	for range cfg.OldCommittee {
		if err := <-published; err != nil {
			t.Fatal(err)
		}
	}
	var frozen []cvComponentRefV2
	for _, member := range cfg.OldCommittee {
		refs, err := services[member].AwaitComponentRefsV2(ctx)
		if err != nil || len(refs) != params.poolSize {
			t.Fatalf("old member %d component barrier: refs=%d err=%v", member, len(refs), err)
		}
		if frozen == nil {
			frozen = refs
			continue
		}
		for i := range refs {
			if refs[i].Header.DealerID != frozen[i].Header.DealerID || !bytes.Equal(refs[i].Lock.Root, frozen[i].Lock.Root) {
				t.Fatal("old actors froze different V2 component catalogs")
			}
		}
	}
}
