package core

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func TestCVSendRecoveryRequestsWithRetryV2RetriesOnlyMissingHolders(t *testing.T) {
	recipients := []int{0, 1, 2, 3}
	attempts := make(map[int]int, len(recipients))
	successes := make(map[int]int, len(recipients))
	ready, err := cvSendRecoveryRequestsWithRetryV2(
		context.Background(), context.Background(), nil, recipients, 3, 2,
		func(int) time.Duration { return 0 },
		func(current []int) []cvFanoutSendResultV2 {
			results := make([]cvFanoutSendResultV2, 0, len(current))
			for _, recipient := range current {
				attempts[recipient]++
				result := cvFanoutSendResultV2{recipient: recipient, wireBytes: 100 + recipient}
				if recipient >= 2 && attempts[recipient] == 1 {
					result.err = errors.New("transient send failure")
				}
				if recipient == 3 {
					result.err = errors.New("holder unavailable")
				}
				results = append(results, result)
			}
			return results
		},
		func(result cvFanoutSendResultV2) { successes[result.recipient]++ },
	)
	if err != nil || ready {
		t.Fatalf("recovery request retry: ready=%v err=%v", ready, err)
	}
	if attempts[0] != 1 || attempts[1] != 1 || attempts[2] != 2 || attempts[3] != 2 {
		t.Fatalf("unexpected per-holder attempts: %v", attempts)
	}
	if successes[0] != 1 || successes[1] != 1 || successes[2] != 1 || successes[3] != 0 {
		t.Fatalf("unexpected successful-send accounting: %v", successes)
	}
}

func TestCVSendRecoveryRequestsWithRetryV2ReportsExhaustedThreshold(t *testing.T) {
	attempts := 0
	_, err := cvSendRecoveryRequestsWithRetryV2(
		context.Background(), context.Background(), nil, []int{0, 1, 2, 3}, 3, 2,
		func(int) time.Duration { return 0 },
		func(current []int) []cvFanoutSendResultV2 {
			attempts++
			results := make([]cvFanoutSendResultV2, 0, len(current))
			for _, recipient := range current {
				result := cvFanoutSendResultV2{recipient: recipient, wireBytes: 100}
				if recipient >= 2 {
					result.err = errors.New("holder unavailable")
				}
				results = append(results, result)
			}
			return results
		}, nil,
	)
	if err == nil || err.Error() != "CV V2 APDB recovery reached 2 holders, need 3" {
		t.Fatalf("unexpected exhausted-retry error: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("recovery request attempts=%d, want 3", attempts)
	}
}

func TestCVSendRecoveryRequestsWithRetryV2StopsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	_, err := cvSendRecoveryRequestsWithRetryV2(
		ctx, context.Background(), nil, []int{0, 1, 2}, 2, 4,
		func(int) time.Duration { return time.Hour },
		func(current []int) []cvFanoutSendResultV2 {
			attempts++
			cancel()
			results := make([]cvFanoutSendResultV2, 0, len(current))
			for _, recipient := range current {
				results = append(results, cvFanoutSendResultV2{recipient: recipient, err: errors.New("send failed")})
			}
			return results
		}, nil,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("recovery request cancellation error: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("recovery retried after cancellation: attempts=%d", attempts)
	}
}

func TestCVAPDBNetworkServiceV2BuildsVCertAfterRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real APVSS aggregate validation network test in short mode")
	}
	first, leafContext, receivers, validators := cvAllACKLeafV2Fixture(t)
	cfg := cvV2ParamsTestConfig()
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		t.Fatal(err)
	}
	leaves := []*cvLeafV2{first}
	for i := 1; i < params.poolSize; i++ {
		leaves = append(leaves, cvBuildAllACKLeafForDealerV2(t, cfg.OldCommittee[i], leafContext, receivers, validators))
	}
	publicDir := filepath.Join(t.TempDir(), "threshold-public")
	secretDir := filepath.Join(t.TempDir(), "threshold-secret")
	if err := cvGenerateOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params); err != nil {
		t.Fatal(err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params)
	if err != nil {
		t.Fatal(err)
	}
	apdbSigner, err := newTBLSThresholdSignerFromV2Material(bundle.apdb)
	if err != nil {
		t.Fatal(err)
	}
	controlSigner, err := newTBLSThresholdSignerFromV2Material(bundle.control)
	if err != nil {
		t.Fatal(err)
	}
	coinSigner, err := newTBLSThresholdSignerFromV2Material(bundle.coin)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := cvRunReferenceEpochV2(cvReferenceEpochInputV2{
		Context: leafContext, Params: params, Leaves: leaves, Receivers: receivers, Validators: validators,
		APDBSigner: apdbSigner, ControlSigner: controlSigner, CoinSigner: coinSigner,
	})
	if err != nil {
		t.Fatal(err)
	}
	contextDigest, err := cvLeafContextDigestV2(leafContext)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := newCVNetworkAuthenticatorV2(validators, receivers)
	if err != nil {
		t.Fatal(err)
	}
	transport := newCVRouterTestTransport(cfg.OldCommittee, 4096)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, cfg.OldCommittee, 2048, auth)
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
		ShardBytes: reference.Components[0].encoded.shardBytes, MaximumPayload: cvMaxLeafWireBytes,
		Params: params, EligibilityCoin: &reference.EligibilityCoin,
		LeafContext: leafContext, Receivers: receivers, Validators: validators,
	}
	services := make(map[int]*cvAPDBNetworkServiceV2, len(cfg.OldCommittee))
	for _, member := range cfg.OldCommittee {
		memberCfg := serviceCfg
		memberCfg.LocalNode = member
		services[member], err = newCVAPDBNetworkServiceV2(context.Background(), memberCfg, transport, router, auth,
			holderStore, apdbSigner, controlSigner, coinSigner)
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
	proposer := reference.Header.ProposerID
	for i := range reference.Components {
		lock, lockErr := services[proposer].Lock(ctx, reference.Components[i].encoded)
		if lockErr != nil {
			t.Fatal(lockErr)
		}
		reference.Pool.Components[i].Lock = *lock
	}
	aggregateEncoded, err := cvAPDBEncodeSizedV2(reference.Header.APDBInstance, reference.AggregatePayload,
		params.recoveryThreshold, len(cfg.OldCommittee), serviceCfg.ShardBytes, cvMaxLeafWireBytes)
	if err != nil {
		t.Fatal(err)
	}
	header := reference.Header
	header.APDBRoot = append([]byte(nil), aggregateEncoded.root...)
	arc, err := services[proposer].Lock(ctx, aggregateEncoded)
	if err != nil {
		t.Fatal(err)
	}
	request := &cvValidationRequestV2{
		Header: header, Pool: reference.Pool, PoolCert: reference.PoolCert,
		ContributorCoin: reference.ContributorCoin, SelectedIndices: reference.SelectedIndices, ARC: *arc,
	}
	resultCh := make(chan error, len(cfg.OldCommittee)-1)
	for _, member := range cfg.OldCommittee {
		if member == proposer {
			continue
		}
		go func(node int) {
			certificate, waitErr := services[node].AwaitValidationResult(ctx, request)
			if waitErr == nil {
				waitErr = cvVerifyValidationCertificateV2(certificate, &request.Header,
					services[node].validatorSample, params.validatorThreshold, validators)
			}
			resultCh <- waitErr
		}(member)
	}
	certificate, err := services[proposer].CertifyAggregate(ctx, request)
	if err != nil {
		t.Fatalf("network VCert: %v", err)
	}
	if err := cvVerifyValidationCertificateV2(certificate, &request.Header,
		services[proposer].validatorSample, params.validatorThreshold, validators); err != nil {
		t.Fatal(err)
	}
	for range len(cfg.OldCommittee) - 1 {
		if err := <-resultCh; err != nil {
			t.Fatal(err)
		}
	}
	for _, member := range cfg.OldCommittee {
		if cvContainsID(services[proposer].validatorSample, member) {
			continue
		}
		if got := transport.sentCountFromTo(cvTagValidationRequestV2, proposer, member); got != 1 {
			t.Fatalf("non-validator %d received %d validation requests, want one initial delivery", member, got)
		}
	}
}

func TestCVAPDBNetworkServiceV2ReceiversPersistBeforeExchangingScalarShares(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real V2 receiver recovery network test in short mode")
	}
	first, leafContext, receivers, validators := cvAllACKLeafV2Fixture(t)
	cfg := cvV2ParamsTestConfig()
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		t.Fatal(err)
	}
	leaves := []*cvLeafV2{first}
	for i := 1; i < params.poolSize; i++ {
		leaves = append(leaves, cvBuildAllACKLeafForDealerV2(t, cfg.OldCommittee[i], leafContext, receivers, validators))
	}
	publicDir := filepath.Join(t.TempDir(), "threshold-public")
	secretDir := filepath.Join(t.TempDir(), "threshold-secret")
	if err := cvGenerateOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params); err != nil {
		t.Fatal(err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params)
	if err != nil {
		t.Fatal(err)
	}
	apdbSigner, _ := newTBLSThresholdSignerFromV2Material(bundle.apdb)
	controlSigner, _ := newTBLSThresholdSignerFromV2Material(bundle.control)
	coinSigner, _ := newTBLSThresholdSignerFromV2Material(bundle.coin)
	reference, err := cvRunReferenceEpochV2(cvReferenceEpochInputV2{
		Context: leafContext, Params: params, Leaves: leaves, Receivers: receivers, Validators: validators,
		APDBSigner: apdbSigner, ControlSigner: controlSigner, CoinSigner: coinSigner,
	})
	if err != nil {
		t.Fatal(err)
	}
	contextDigest, err := cvLeafContextDigestV2(leafContext)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := newCVNetworkAuthenticatorV2(validators, receivers)
	if err != nil {
		t.Fatal(err)
	}
	allNodes := sortedUnique(append(append([]int(nil), cfg.OldCommittee...), cfg.NewCommittee...))
	transport := newCVRouterTestTransport(allNodes, 4096)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, allNodes, 2048, auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	holderStore, err := newCVAPDBHolderStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	aggregateEncoded, err := cvAPDBEncodeV2(reference.Header.APDBInstance, reference.AggregatePayload,
		params.recoveryThreshold, len(cfg.OldCommittee), cvMaxLeafWireBytes)
	if err != nil {
		t.Fatal(err)
	}
	serviceCfg := cvAPDBNetworkServiceConfigV2{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee,
		ExpectedContext: contextDigest, TotalShards: len(cfg.OldCommittee), DataShards: params.recoveryThreshold,
		ShardBytes: aggregateEncoded.shardBytes, MaximumPayload: cvMaxLeafWireBytes, Params: params,
		EligibilityCoin: &reference.EligibilityCoin, LeafContext: leafContext, Receivers: receivers, Validators: validators,
	}
	services := make(map[int]*cvAPDBNetworkServiceV2, len(allNodes))
	failingReceiver := cfg.NewCommittee[0]
	for _, node := range allNodes {
		nodeCfg := serviceCfg
		nodeCfg.LocalNode = node
		localStore := holderStore
		if cvMemberInRosterV2(node, cfg.NewCommittee) {
			localStore = nil
			nodeCfg.ScalarStore, err = newCVScalarStoreV2(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if node == failingReceiver {
				blocker := filepath.Dir(filepath.Dir(nodeCfg.ScalarStore.path(cfg.SID, uint64(cfg.Epoch), node)))
				if err := os.WriteFile(blocker, []byte("block scalar state directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
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
	proposer := reference.Header.ProposerID
	arc, err := services[proposer].Lock(ctx, aggregateEncoded)
	if err != nil {
		t.Fatal(err)
	}
	header := reference.Header
	header.APDBRoot = append([]byte(nil), arc.Root...)
	statement, err := cvDecisionStatementV2(contextDigest, &header, arc)
	if err != nil {
		t.Fatal(err)
	}
	handoff := &cvHandoffV2{ContextDigest: contextDigest, Header: header, ARC: *arc,
		DecCert: cvRecoverThresholdCertificateV2ForTest(t, controlSigner, cfg.OldCommittee, cvDecisionCertificateV2Domain, statement)}
	type receiverResult struct {
		node   int
		public bls12381.G1Affine
		err    error
	}
	results := make(chan receiverResult, len(cfg.NewCommittee))
	for _, receiver := range cfg.NewCommittee {
		go func(node int) {
			_, _, _, publicKey, recoverErr := services[node].RecoverAndExchangeScalarShare(ctx, handoff)
			results <- receiverResult{node: node, public: publicKey, err: recoverErr}
		}(receiver)
	}
	var publicKey bls12381.G1Affine
	havePublicKey := false
	for i := 0; i < len(cfg.NewCommittee); i++ {
		result := <-results
		if result.node == failingReceiver {
			if result.err == nil {
				t.Fatal("receiver released a scalar share after persistence failure")
			}
			continue
		}
		if result.err != nil {
			t.Fatal(result.err)
		}
		if !havePublicKey {
			publicKey = result.public
			havePublicKey = true
		} else if !publicKey.Equal(&result.public) {
			t.Fatal("CV V2 receivers recovered different public keys")
		}
	}
	if !havePublicKey || !publicKey.Equal(&reference.PublicKey) {
		t.Fatal("network receiver public key differs from reference recovery")
	}
	if cvContainsID(transport.sentFromByTag(cvTagAggregateShareV2), failingReceiver) {
		t.Fatal("receiver broadcast a public scalar output after persistence failure")
	}
	services[failingReceiver].mu.Lock()
	localOutputCount := len(services[failingReceiver].localScalarOutputs)
	services[failingReceiver].mu.Unlock()
	if localOutputCount != 0 {
		t.Fatal("receiver registered a public scalar output after persistence failure")
	}
}

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
		Params: public.Params, EligibilityCoin: public.EligibilityCoin,
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
			localStore, public.APDBSigner, public.ControlSigner, public.CoinSigner)
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
	invocation, err := cvEligibilityCoinInvocationV2(cfg.SID, uint64(cfg.Epoch))
	if err != nil {
		t.Fatal(err)
	}
	type coinResult struct {
		output *cvCoinOutputV2
		err    error
	}
	coinResults := make(chan coinResult, len(cfg.OldCommittee))
	for _, member := range cfg.OldCommittee {
		go func(node int) {
			output, coinErr := services[node].EligibilityCoin(ctx)
			coinResults <- coinResult{output: output, err: coinErr}
		}(member)
	}
	var coinValue []byte
	for range cfg.OldCommittee {
		result := <-coinResults
		if result.err != nil {
			t.Fatalf("network eligibility coin: %v", result.err)
		}
		if err := cvVerifyCoinOutputV2(result.output, invocation, public.CoinSigner); err != nil {
			t.Fatal(err)
		}
		if coinValue == nil {
			coinValue = append([]byte(nil), result.output.Value...)
		} else if !bytes.Equal(coinValue, result.output.Value) {
			t.Fatal("network coin nodes derived different outputs")
		}
	}
	minimumCoinShares := len(cfg.OldCommittee) * (len(cfg.OldCommittee) - 1)
	if got := transport.sentCount(cvTagCoinShareV2); got < minimumCoinShares {
		t.Fatalf("network coin sent only %d shares, need at least %d", got, minimumCoinShares)
	}

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
		Params: public.Params, EligibilityCoin: public.EligibilityCoin,
	}
	holderStore, err := newCVAPDBHolderStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newCVAPDBNetworkServiceV2(context.Background(), serviceCfg, transport, router, nil,
		holderStore, public.APDBSigner, public.ControlSigner, public.CoinSigner); err == nil {
		t.Fatal("started V2 APDB network service without an authenticator")
	}
}

func TestCVAPDBNetworkServiceV2CertifiesEligiblePool(t *testing.T) {
	auth, _, _, cfg := cvNetworkAuthV2Fixture(t)
	object, public := cvAgreementObjectV2Fixture(t)
	transport := newCVRouterTestTransport(cfg.OldCommittee, 256)
	router, err := newCVSAPVSSRouterWithReceivers(context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, cfg.OldCommittee, 128, auth)
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
		services[member], err = newCVAPDBNetworkServiceV2(context.Background(), memberCfg, transport, router, auth,
			holderStore, public.APDBSigner, public.ControlSigner, public.CoinSigner)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type certifiedResult struct {
		pool *cvPoolV2
		cert *cvPoolCertificateV2
		err  error
	}
	results := make(chan certifiedResult, len(cfg.OldCommittee)-1)
	for _, member := range cfg.OldCommittee {
		if member == object.Pool.ProposerID {
			continue
		}
		go func(node int) {
			pool, cert, waitErr := services[node].AwaitCertifiedPool(ctx, object.Pool.ProposerID)
			results <- certifiedResult{pool: pool, cert: cert, err: waitErr}
		}(member)
	}
	certificate, err := services[object.Pool.ProposerID].CertifyPool(ctx, &object.Pool)
	if err != nil {
		t.Fatalf("certify V2 pool: %v", err)
	}
	if err := cvVerifyPoolCertificateV2(&object.Pool, certificate, public.ControlSigner); err != nil {
		t.Fatal(err)
	}
	for range len(cfg.OldCommittee) - 1 {
		result := <-results
		if result.err != nil || !bytes.Equal(result.pool.Digest, object.Pool.Digest) ||
			cvVerifyPoolCertificateV2(result.pool, result.cert, public.ControlSigner) != nil {
			t.Fatalf("await certified V2 pool: %v", result.err)
		}
	}
	if got := transport.sentCount(cvTagPoolOfferV2); got < len(cfg.OldCommittee)-1 {
		t.Fatalf("pool proposer sent %d offers", got)
	}
	if got := transport.sentCount(cvTagPoolCertShareV2); got < public.ControlSigner.Threshold()-1 {
		t.Fatalf("pool certification returned %d shares", got)
	}
	if got := transport.sentCount(cvTagPoolCertV2); got != len(cfg.OldCommittee)-1 {
		t.Fatalf("pool proposer sent %d certificates", got)
	}
	offersAfterCertification := transport.sentCount(cvTagPoolOfferV2)
	certificatesAfterCertification := transport.sentCount(cvTagPoolCertV2)
	time.Sleep(2 * cvControlRetryIntervalV2)
	if got := transport.sentCount(cvTagPoolOfferV2); got != offersAfterCertification {
		t.Fatalf("pool offers continued after certification: before=%d after=%d", offersAfterCertification, got)
	}
	if got := transport.sentCount(cvTagPoolCertV2); got != certificatesAfterCertification {
		t.Fatalf("pool certificates continued after certification: before=%d after=%d", certificatesAfterCertification, got)
	}

	badCertificate := *certificate
	badCertificate.Certificate = append([]byte(nil), certificate.Certificate...)
	badCertificate.Certificate[0] ^= 1
	if _, err := services[cfg.OldCommittee[0]].ContributorCoin(ctx, &object.Pool, &badCertificate); err == nil {
		t.Fatal("released contributor coin share without a valid PoolCert")
	}
	type contributorResult struct {
		output *cvCoinOutputV2
		err    error
	}
	contributorResults := make(chan contributorResult, len(cfg.OldCommittee))
	for _, member := range cfg.OldCommittee {
		go func(node int) {
			output, coinErr := services[node].ContributorCoin(ctx, &object.Pool, certificate)
			contributorResults <- contributorResult{output: output, err: coinErr}
		}(member)
	}
	contributorInvocation, err := cvContributorCoinInvocationV2(public.ContextDigest, object.Pool.ProposerID, object.Pool.Digest)
	if err != nil {
		t.Fatal(err)
	}
	var contributorValue []byte
	for range cfg.OldCommittee {
		result := <-contributorResults
		if result.err != nil || cvVerifyCoinOutputV2(result.output, contributorInvocation, public.CoinSigner) != nil {
			t.Fatalf("network contributor coin: %v", result.err)
		}
		if contributorValue == nil {
			contributorValue = append([]byte(nil), result.output.Value...)
		} else if !bytes.Equal(contributorValue, result.output.Value) {
			t.Fatal("network contributor coin outputs differ")
		}
	}

	proposers, _, err := cvDeriveEligibilitySamplesV2(cfg.OldCommittee, public.EligibilityCoin.Value,
		public.Params.proposerSampleSize, public.Params.validatorSampleSize)
	if err != nil {
		t.Fatal(err)
	}
	eligible := nodeSet(proposers)
	nonEligible := -1
	for _, member := range cfg.OldCommittee {
		if _, ok := eligible[member]; !ok {
			nonEligible = member
			break
		}
	}
	if nonEligible >= 0 {
		nonEligiblePool, err := cvBuildPoolV2(public.ContextDigest, nonEligible, object.Pool.Components, public.Params)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := services[nonEligible].CertifyPool(ctx, nonEligiblePool); err == nil {
			t.Fatal("certified a pool from a non-eligible proposer")
		}
	}
}

func TestCVAPDBNetworkServiceV2FinalizesDecisionAndRelaysHandoff(t *testing.T) {
	auth, _, _, cfg := cvNetworkAuthV2Fixture(t)
	object, public := cvAgreementObjectV2Fixture(t)
	receiver := cfg.NewCommittee[0]
	localNodes := sortedUnique(append(append([]int(nil), cfg.OldCommittee...), receiver))
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
	decisionRoot := t.TempDir()
	serviceCfg := cvAPDBNetworkServiceConfigV2{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch), OldRoster: cfg.OldCommittee, NewRoster: cfg.NewCommittee,
		ExpectedContext: public.ContextDigest, TotalShards: len(cfg.OldCommittee),
		DataShards: public.Params.recoveryThreshold, ShardBytes: 32, MaximumPayload: 2048,
		Params: public.Params, EligibilityCoin: public.EligibilityCoin,
	}
	services := make(map[int]*cvAPDBNetworkServiceV2, len(localNodes))
	for _, node := range localNodes {
		nodeCfg := serviceCfg
		nodeCfg.LocalNode = node
		localStore := holderStore
		if node == receiver {
			localStore = nil
		} else {
			nodeCfg.DecisionStore, err = newCVDecisionSignStoreV2(decisionRoot)
			if err != nil {
				t.Fatal(err)
			}
		}
		services[node], err = newCVAPDBNetworkServiceV2(context.Background(), nodeCfg, transport, router, auth,
			localStore, public.APDBSigner, public.ControlSigner, public.CoinSigner)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	handoffResult := make(chan error, 1)
	go func() {
		handoff, waitErr := services[receiver].AwaitHandoff(ctx)
		if waitErr == nil {
			waitErr = cvVerifyHandoffV2(handoff, public.ContextDigest, public.APDBSigner, public.ControlSigner)
		}
		handoffResult <- waitErr
	}()
	finalized := make(chan error, len(cfg.OldCommittee))
	finalize := func(member int) {
		go func(node int) {
			handoff, finalizeErr := services[node].FinalizeDecision(ctx, object)
			if finalizeErr == nil {
				finalizeErr = cvVerifyHandoffV2(handoff, public.ContextDigest, public.APDBSigner, public.ControlSigner)
			}
			finalized <- finalizeErr
		}(member)
	}
	threshold := public.ControlSigner.Threshold()
	for _, member := range cfg.OldCommittee[:threshold] {
		finalize(member)
	}
	for range threshold {
		if err := <-finalized; err != nil {
			t.Fatal(err)
		}
	}
	// The remaining old node enters finalization only after a recovered
	// certificate has already been relayed and cached.
	for _, member := range cfg.OldCommittee[threshold:] {
		finalize(member)
	}
	for range len(cfg.OldCommittee) - threshold {
		if err := <-finalized; err != nil {
			t.Fatal(err)
		}
	}
	if err := <-handoffResult; err != nil {
		t.Fatal(err)
	}
	if got := transport.sentCount(cvTagDecisionShareV2); got < len(cfg.OldCommittee)*(public.ControlSigner.Threshold()-1) {
		t.Fatalf("decision phase sent only %d shares", got)
	}
	minimumHandoffs := len(cfg.OldCommittee) + len(cfg.NewCommittee) - 1
	if got := transport.sentCount(cvTagHandoffV2); got < minimumHandoffs {
		t.Fatalf("decision phase sent only %d handoffs", got)
	}
}
