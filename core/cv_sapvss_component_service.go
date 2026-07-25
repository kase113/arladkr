package core

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvComponentInitDomainV1            = "ARL-CV-sAPVSS-v1/component-init"
	cvComponentAckDomainV1             = "ARL-CV-sAPVSS-v1/component-ack"
	cvComponentGetDomainV1             = "ARL-CV-sAPVSS-v1/component-get"
	cvComponentDealerSignatureDomainV1 = "RL_CV_COMPONENT_DEALER"
)

type cvComponentInitV1 struct {
	artifactWire []byte
	dealerSig    []byte
}

type cvComponentAckV1 struct {
	dealer     int
	holder     int
	leafDigest []byte
	signature  []byte
}

type cvComponentGetV1 struct {
	dealer     int
	leafDigest []byte
}

type cvPendingComponentLeafV1 struct {
	allowed map[int]struct{}
	values  chan *cvLeafV1
}

type cvPendingARCShareV1 struct {
	values chan cvARCShareV1
}

type cvPendingRecoveryV1 struct {
	rlo     *AggRLO
	allowed map[int]struct{}
	values  chan cvFreshShardArtifactV1
}

type cvReceivedReceiptV1 struct {
	receiverID int
	wire       []byte
}

type cvPendingReceiptExchangeV1 struct {
	agg           *cvAggregateV1
	receiverOrder []int
	values        chan cvReceivedReceiptV1
}

type apvssPendingLaneACKsV1 struct {
	leaf   *cvLeafV1
	values chan apvssLaneACKV1
}

type cvComponentServiceV1 struct {
	ctx                  context.Context
	cancel               context.CancelFunc
	cfg                  Config
	leafCtx              *cvLeafContextV1
	localNode            int
	transport            agreementTransport
	store                *cvComponentLeafStoreV1
	freshStore           *cvFreshShardStoreV1
	inbox                <-chan Message
	receiverOrder        []int
	receiverIndex        map[int]int
	localReceiverSecrets map[int]fr.Element

	mu                         sync.Mutex
	aggregateBuildMu           sync.Mutex
	pendingACKs                map[string]chan cvComponentAckV1
	pendingLeaves              map[string]*cvPendingComponentLeafV1
	pendingARCs                map[string]*cvPendingARCShareV1
	pendingRecoveries          map[string]*cvPendingRecoveryV1
	pendingReceipts            *cvPendingReceiptExchangeV1
	pendingLaneACKs            map[string]*apvssPendingLaneACKsV1
	processingOffers           map[string]struct{}
	candidateByMaterializer    map[int]string
	verifiedLeaves             map[string]*cvVerifiedLeafV1
	verifiedAggregateOffers    map[string]*cvVerifiedAggregateOfferTokenV1
	componentDescriptors       map[int]*cvComponentDescriptorV1
	componentCandidatesChanged chan struct{}
	done                       chan struct{}
}

func newCVComponentServiceV1(
	ctx context.Context,
	cfg Config,
	leafContext *cvLeafContextV1,
	localNode int,
	transport agreementTransport,
	router *cvSAPVSSRouterV1,
	store *cvComponentLeafStoreV1,
) (*cvComponentServiceV1, error) {
	return newCVComponentServiceWithReceiversV1(
		ctx, cfg, leafContext, localNode, transport, router, store, nil, nil,
	)
}

func newCVComponentServiceWithReceiversV1(
	ctx context.Context,
	cfg Config,
	leafContext *cvLeafContextV1,
	localNode int,
	transport agreementTransport,
	router *cvSAPVSSRouterV1,
	store *cvComponentLeafStoreV1,
	receiverOrder []int,
	localReceiverSecrets map[int]fr.Element,
) (*cvComponentServiceV1, error) {
	c := NormalizeConfig(cfg)
	if ctx == nil || leafContext == nil || transport == nil || router == nil || store == nil {
		return nil, fmt.Errorf("invalid CV-sAPVSS component service configuration")
	}
	if err := ValidateConfig(c); err != nil {
		return nil, err
	}
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	if _, ok := nodeSet(c.OldCommittee)[localNode]; !ok ||
		string(leafContext.sessionID) != c.SID || int(leafContext.epoch) != c.Epoch {
		return nil, fmt.Errorf("CV-sAPVSS component service context mismatch")
	}
	if err := cvValidateLeafContextV1(leafContext); err != nil {
		return nil, err
	}
	freshStore, err := newCVFreshShardStoreV1(c.ArtifactCacheDir)
	if err != nil {
		return nil, err
	}
	receiverIndex := make(map[int]int, len(receiverOrder))
	if len(receiverOrder) > 0 {
		expectedOrder := sortedUnique(c.NewCommittee)
		if len(receiverOrder) != len(expectedOrder) {
			return nil, fmt.Errorf("APVSS receiver roster length mismatch")
		}
		for i := range receiverOrder {
			if receiverOrder[i] != expectedOrder[i] {
				return nil, fmt.Errorf("APVSS receiver roster order mismatch")
			}
			receiverIndex[receiverOrder[i]] = i + 1
		}
	}
	actorIDs := []int{localNode}
	localSecrets := make(map[int]fr.Element, len(localReceiverSecrets))
	for receiverID, secret := range localReceiverSecrets {
		if _, ok := receiverIndex[receiverID]; !ok || secret.IsZero() {
			return nil, fmt.Errorf("invalid local APVSS receiver %d", receiverID)
		}
		localSecrets[receiverID] = secret
		actorIDs = append(actorIDs, receiverID)
	}
	actorIDs = sortedUnique(actorIDs)
	serviceCtx, cancel := context.WithCancel(ctx)
	mergedInbox := make(chan Message, len(actorIDs)*64)
	service := &cvComponentServiceV1{
		ctx:                        serviceCtx,
		cancel:                     cancel,
		cfg:                        c,
		leafCtx:                    leafContext,
		localNode:                  localNode,
		transport:                  transport,
		store:                      store,
		freshStore:                 freshStore,
		inbox:                      mergedInbox,
		receiverOrder:              append([]int(nil), receiverOrder...),
		receiverIndex:              receiverIndex,
		localReceiverSecrets:       localSecrets,
		pendingACKs:                make(map[string]chan cvComponentAckV1),
		pendingLeaves:              make(map[string]*cvPendingComponentLeafV1),
		pendingARCs:                make(map[string]*cvPendingARCShareV1),
		pendingRecoveries:          make(map[string]*cvPendingRecoveryV1),
		pendingLaneACKs:            make(map[string]*apvssPendingLaneACKsV1),
		processingOffers:           make(map[string]struct{}),
		candidateByMaterializer:    make(map[int]string),
		verifiedLeaves:             make(map[string]*cvVerifiedLeafV1),
		verifiedAggregateOffers:    make(map[string]*cvVerifiedAggregateOfferTokenV1),
		componentDescriptors:       make(map[int]*cvComponentDescriptorV1),
		componentCandidatesChanged: make(chan struct{}, 1),
		done:                       make(chan struct{}),
	}
	for _, actorID := range actorIDs {
		source, receiveErr := router.Receive(actorID)
		if receiveErr != nil {
			cancel()
			return nil, receiveErr
		}
		go func(inbox <-chan Message) {
			for {
				select {
				case <-serviceCtx.Done():
					return
				case msg, ok := <-inbox:
					if !ok {
						return
					}
					select {
					case mergedInbox <- msg:
					case <-serviceCtx.Done():
						return
					}
				}
			}
		}(source)
	}
	go service.run()
	return service, nil
}

func (s *cvComponentServiceV1) Close() error {
	if s == nil {
		return nil
	}
	s.cancel()
	<-s.done
	return nil
}

func (s *cvComponentServiceV1) CollectAPVSSLaneACKs(
	ctx context.Context,
	leaf *cvLeafV1,
	witness *apvssDealerWitnessV1,
) (*apvssLeafPrototypeV1, error) {
	if ctx == nil || leaf == nil || witness == nil || leaf.dealerID != uint64(s.localNode) ||
		len(s.receiverOrder) != len(leaf.receivers) {
		return nil, fmt.Errorf("invalid APVSS lane ACK collection input")
	}
	if err := apvssValidateStructuralLeafV1(s.leafCtx, leaf); err != nil {
		return nil, err
	}
	leafWire, err := cvLeafV1CanonicalBytes(leaf)
	if err != nil {
		return nil, err
	}
	key := cvComponentKeyV1(s.localNode, leaf.digest)
	pending := &apvssPendingLaneACKsV1{
		leaf: leaf, values: make(chan apvssLaneACKV1, len(s.receiverOrder)),
	}
	s.mu.Lock()
	if _, exists := s.pendingLaneACKs[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("APVSS lane ACK collection already active")
	}
	s.pendingLaneACKs[key] = pending
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pendingLaneACKs, key)
		s.mu.Unlock()
	}()

	sent := 0
	for _, receiverID := range s.receiverOrder {
		if s.sendFrom(s.localNode, receiverID, apvssTagLaneOfferV1, leafWire) == nil {
			sent++
		}
	}
	threshold := len(s.receiverOrder) - s.leafCtx.sharingDegree
	if sent < threshold {
		return nil, fmt.Errorf("APVSS lane offer reached %d receivers, need %d", sent, threshold)
	}
	requiredACKs := threshold
	if s.cfg.APVSSBenchmarkWaitAllACKs {
		requiredACKs = len(s.receiverOrder)
	} else if s.cfg.APVSSBenchmarkFallbackCount > 0 {
		requiredACKs = len(s.receiverOrder) - s.cfg.APVSSBenchmarkFallbackCount
	}
	acks := make(map[int]apvssLaneACKV1, len(s.receiverOrder))
	for len(acks) < requiredACKs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case ack := <-pending.values:
			acks[ack.receiverIndex] = ack
		}
	}
	assemble := func() (*apvssLeafPrototypeV1, error) {
		ordered := make([]apvssLaneACKV1, 0, len(acks))
		for receiverIndex := 1; receiverIndex <= len(s.receiverOrder); receiverIndex++ {
			if ack, ok := acks[receiverIndex]; ok {
				ordered = append(ordered, ack)
			}
		}
		return apvssAssembleVerifiedPrototypeWithFallbackProfileV1(
			s.leafCtx, leaf, witness, ordered, s.cfg.APVSSFallbackProfile,
		)
	}
	if s.cfg.APVSSBenchmarkWaitAllACKs || s.cfg.APVSSBenchmarkFallbackCount > 0 {
		return assemble()
	}
	// Include replies already delivered with the threshold response without
	// adding a synchrony assumption or an extra protocol timeout.
	for {
		select {
		case ack := <-pending.values:
			acks[ack.receiverIndex] = ack
		default:
			return assemble()
		}
	}
}

func (s *cvComponentServiceV1) Disperse(ctx context.Context, leaf *cvLeafV1) (*cvComponentDescriptorV1, error) {
	if ctx == nil || leaf == nil || leaf.dealerID != uint64(s.localNode) {
		return nil, fmt.Errorf("CV-sAPVSS component dealer does not match local node")
	}
	leafWire, err := cvLeafV1CanonicalBytes(leaf)
	if err != nil {
		return nil, err
	}
	return s.disperseComponentWire(ctx, int(leaf.dealerID), leaf.digest, leafWire)
}

func (s *cvComponentServiceV1) DisperseAPVSS(
	ctx context.Context,
	prototype *apvssLeafPrototypeV1,
) (*cvComponentDescriptorV1, error) {
	if ctx == nil || prototype == nil || prototype.leaf == nil ||
		prototype.leaf.dealerID != uint64(s.localNode) {
		return nil, fmt.Errorf("APVSS component dealer does not match local node")
	}
	leafWire, err := apvssLeafPrototypeV1CanonicalBytes(prototype)
	if err != nil {
		return nil, err
	}
	digest := hashBytes([]byte(apvssLeafDigestDomain), leafWire)
	if len(prototype.digest) > 0 && !bytes.Equal(prototype.digest, digest) {
		return nil, fmt.Errorf("APVSS component leaf digest mismatch")
	}
	prototype.digest = append([]byte(nil), digest...)
	return s.disperseComponentWire(ctx, int(prototype.leaf.dealerID), digest, leafWire)
}

func (s *cvComponentServiceV1) disperseComponentWire(
	ctx context.Context,
	dealer int,
	leafDigest, leafWire []byte,
) (*cvComponentDescriptorV1, error) {
	if ctx == nil || dealer != s.localNode || len(leafDigest) != 32 || len(leafWire) == 0 ||
		!bytes.Equal(leafDigest, cvComponentLeafPayloadDigestV1(leafWire)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component payload")
	}
	artifactWire, err := cvComponentLeafArtifactV1CanonicalBytes(&cvComponentLeafArtifactV1{
		dealer: dealer, leafDigest: leafDigest, leafWire: leafWire,
	})
	if err != nil {
		return nil, err
	}
	if err := s.store.Put(s.cfg.SID, s.cfg.Epoch, dealer, s.localNode, leafDigest, leafWire); err != nil {
		return nil, err
	}
	statement, err := cvComponentStatementDigestV1(dealer, leafDigest)
	if err != nil {
		return nil, err
	}
	localHolderSig, err := s.cfg.runtime.lockSigner.SignShare(
		s.localNode, cvComponentLockSignatureDomainV1, statement,
	)
	if err != nil {
		return nil, err
	}
	dealerSig, err := s.cfg.runtime.lockSigner.SignShare(
		s.localNode, cvComponentDealerSignatureDomainV1, statement,
	)
	if err != nil {
		return nil, err
	}
	initWire, err := cvComponentInitV1CanonicalBytes(&cvComponentInitV1{
		artifactWire: artifactWire,
		dealerSig:    dealerSig,
	})
	if err != nil {
		return nil, err
	}

	key := cvComponentKeyV1(dealer, leafDigest)
	acks := make(chan cvComponentAckV1, len(s.cfg.OldCommittee))
	s.mu.Lock()
	if _, exists := s.pendingACKs[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV-sAPVSS component dispersal already active")
	}
	s.pendingACKs[key] = acks
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pendingACKs, key)
		s.mu.Unlock()
	}()

	sent := 0
	for _, holder := range sortedUnique(s.cfg.OldCommittee) {
		if holder == s.localNode {
			continue
		}
		if s.send(holder, cvTagComponentInitV1, initWire) == nil {
			sent++
		}
	}
	threshold := len(s.cfg.OldCommittee) - s.cfg.FOld
	if sent+1 < threshold {
		return nil, fmt.Errorf("CV-sAPVSS component INIT reached %d holders, need %d", sent+1, threshold)
	}
	shares := map[int][]byte{s.localNode: append([]byte(nil), localHolderSig...)}
	for len(shares) < threshold {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case ack := <-acks:
			if _, duplicate := shares[ack.holder]; !duplicate {
				shares[ack.holder] = append([]byte(nil), ack.signature...)
			}
		}
	}
	holders := make([]int, 0, len(shares))
	for holder := range shares {
		holders = append(holders, holder)
	}
	sort.Ints(holders)
	certificate, err := s.cfg.runtime.lockSigner.Recover(
		cvComponentLockSignatureDomainV1, statement, shares,
	)
	if err != nil {
		return nil, err
	}
	descriptor := &cvComponentDescriptorV1{
		dealer:          dealer,
		leafDigest:      append([]byte(nil), leafDigest...),
		holders:         holders,
		shareSignatures: shares,
		certificate:     certificate,
	}
	if err := cvValidateComponentDescriptorV1(s.cfg, descriptor); err != nil {
		return nil, err
	}
	descriptorWire, err := cvComponentDescriptorV1CanonicalBytes(descriptor)
	if err != nil {
		return nil, err
	}
	if err := s.acceptComponentDescriptorWire(descriptorWire); err != nil {
		return nil, err
	}
	for _, node := range sortedUnique(s.cfg.OldCommittee) {
		_ = s.send(node, cvTagComponentCertV1, descriptorWire)
	}
	return descriptor, nil
}

func (s *cvComponentServiceV1) CollectComponentCandidates(
	ctx context.Context,
) ([]*cvComponentDescriptorV1, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil CV-sAPVSS component candidate context")
	}
	want := s.cfg.FOld + 1
	ready := len(s.cfg.OldCommittee) - s.cfg.FOld
	if s.cfg.Kappa != want || ready < want {
		return nil, fmt.Errorf("CV-sAPVSS component candidate selection requires K=f_o+1")
	}
	batchWindow := durationEnvMs("RLADKR_CV_CANDIDATE_BATCH_MS", 50*time.Millisecond)
	var batchTimer *time.Timer
	var batchDone <-chan time.Time
	defer func() {
		if batchTimer != nil {
			batchTimer.Stop()
		}
	}()
	for {
		s.mu.Lock()
		dealers := make([]int, 0, len(s.componentDescriptors))
		for dealer := range s.componentDescriptors {
			dealers = append(dealers, dealer)
		}
		sort.Ints(dealers)
		if len(dealers) >= ready && batchTimer == nil {
			batchTimer = time.NewTimer(batchWindow)
			batchDone = batchTimer.C
		}
		if len(dealers) == len(s.cfg.OldCommittee) {
			selected := make([]*cvComponentDescriptorV1, 0, ready)
			for _, dealer := range dealers[:ready] {
				selected = append(selected, s.componentDescriptors[dealer])
			}
			s.mu.Unlock()
			return selected, nil
		}
		s.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-batchDone:
			s.mu.Lock()
			dealers := make([]int, 0, len(s.componentDescriptors))
			for dealer := range s.componentDescriptors {
				dealers = append(dealers, dealer)
			}
			sort.Ints(dealers)
			if len(dealers) < ready {
				s.mu.Unlock()
				return nil, fmt.Errorf("CV-sAPVSS candidate batch fell below availability threshold")
			}
			selected := make([]*cvComponentDescriptorV1, 0, ready)
			for _, dealer := range dealers[:ready] {
				selected = append(selected, s.componentDescriptors[dealer])
			}
			s.mu.Unlock()
			return selected, nil
		case <-s.componentCandidatesChanged:
		}
	}
}

func (s *cvComponentServiceV1) acceptComponentDescriptorWire(wire []byte) error {
	descriptor, err := cvDecodeAndValidateComponentDescriptorV1(s.cfg, wire)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if _, exists := s.componentDescriptors[descriptor.dealer]; !exists {
		s.componentDescriptors[descriptor.dealer] = descriptor
	}
	s.mu.Unlock()
	select {
	case s.componentCandidatesChanged <- struct{}{}:
	default:
	}
	return nil
}

func (s *cvComponentServiceV1) Retrieve(
	ctx context.Context,
	descriptor *cvComponentDescriptorV1,
) (*cvLeafV1, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil CV-sAPVSS component retrieval context")
	}
	if err := cvValidateComponentDescriptorV1(s.cfg, descriptor); err != nil {
		return nil, err
	}
	key := cvComponentKeyV1(descriptor.dealer, descriptor.leafDigest)
	pending := &cvPendingComponentLeafV1{
		allowed: nodeSet(descriptor.holders),
		values:  make(chan *cvLeafV1, len(descriptor.holders)),
	}
	s.mu.Lock()
	if _, exists := s.pendingLeaves[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV-sAPVSS component retrieval already active")
	}
	s.pendingLeaves[key] = pending
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pendingLeaves, key)
		s.mu.Unlock()
	}()
	requestWire, err := cvComponentGetV1CanonicalBytes(&cvComponentGetV1{
		dealer: descriptor.dealer, leafDigest: descriptor.leafDigest,
	})
	if err != nil {
		return nil, err
	}
	sent := 0
	for _, holder := range descriptor.holders {
		if s.send(holder, cvTagComponentGetV1, requestWire) == nil {
			sent++
		}
	}
	if sent == 0 {
		return nil, fmt.Errorf("CV-sAPVSS component retrieval reached no certificate holder")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case leaf := <-pending.values:
		return leaf, nil
	}
}

func (s *cvComponentServiceV1) run() {
	defer close(s.done)
	for {
		select {
		case <-s.ctx.Done():
			return
		case msg, ok := <-s.inbox:
			if !ok {
				return
			}
			s.handle(msg)
		}
	}
}

func (s *cvComponentServiceV1) handle(msg Message) {
	switch msg.Tag {
	case cvTagComponentInitV1:
		s.handleInit(msg)
	case cvTagComponentAckV1:
		s.handleACK(msg)
	case cvTagComponentCertV1:
		_ = s.acceptComponentDescriptorWire(msg.Body)
	case cvTagComponentGetV1:
		s.handleGet(msg)
	case cvTagComponentLeafV1:
		s.handleLeaf(msg)
	case cvTagAggregateShardV1:
		s.handleAggregateOffer(msg)
	case cvTagARCShareV1:
		s.handleARCShare(msg)
	case cvTagRecoverGetV1:
		s.handleRecoverGet(msg)
	case cvTagRecoverShardV1:
		s.handleRecoverShard(msg)
	case cvTagReceiptV1:
		s.handleReceipt(msg)
	case apvssTagLaneOfferV1:
		s.handleAPVSSLaneOffer(msg)
	case apvssTagLaneACKV1:
		s.handleAPVSSLaneACK(msg)
	}
}

func (s *cvComponentServiceV1) handleAPVSSLaneOffer(msg Message) {
	secret, local := s.localReceiverSecrets[msg.To]
	receiverIndex, registered := s.receiverIndex[msg.To]
	if !local || !registered {
		return
	}
	leaf, err := cvDecodeLeafV1(msg.Body, s.leafCtx)
	if err != nil || leaf.dealerID != uint64(msg.From) {
		return
	}
	ack, err := apvssIssueVerifiedLaneACKV1(s.leafCtx, leaf, receiverIndex, secret)
	if err != nil {
		return
	}
	wire, err := apvssLaneACKMessageV1CanonicalBytes(&apvssLaneACKMessageV1{
		dealerID: leaf.dealerID, leafDigest: leaf.digest, ack: ack,
	})
	if err == nil {
		_ = s.sendFrom(msg.To, msg.From, apvssTagLaneACKV1, wire)
	}
}

func (s *cvComponentServiceV1) handleAPVSSLaneACK(msg Message) {
	s.mu.Lock()
	pending := make([]*apvssPendingLaneACKsV1, 0, len(s.pendingLaneACKs))
	for _, value := range s.pendingLaneACKs {
		pending = append(pending, value)
	}
	s.mu.Unlock()
	for _, collection := range pending {
		message, err := apvssDecodeLaneACKMessageV1(msg.Body, collection.leaf)
		if err != nil || message.dealerID != uint64(s.localNode) ||
			message.ack.receiverIndex <= 0 || message.ack.receiverIndex > len(s.receiverOrder) ||
			s.receiverOrder[message.ack.receiverIndex-1] != msg.From {
			continue
		}
		select {
		case collection.values <- message.ack:
		default:
		}
		return
	}
}

func (s *cvComponentServiceV1) ExchangeReceipts(
	ctx context.Context,
	agg *cvAggregateV1,
	receiverOrder []int,
	localSecrets map[int]fr.Element,
) (map[int][]byte, map[int][]byte, []byte, error) {
	if ctx == nil || len(localSecrets) == 0 {
		return nil, nil, nil, fmt.Errorf("invalid CV-sAPVSS receipt exchange input")
	}
	shares, localReceipts, err := cvCreateLocalDecryptionOutputsV1(s.leafCtx, agg, receiverOrder, localSecrets)
	if err != nil {
		return nil, nil, nil, err
	}
	pending := &cvPendingReceiptExchangeV1{
		agg: agg, receiverOrder: append([]int(nil), receiverOrder...),
		values: make(chan cvReceivedReceiptV1, len(receiverOrder)*2),
	}
	s.mu.Lock()
	if s.pendingReceipts != nil {
		s.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("CV-sAPVSS receipt exchange already active")
	}
	s.pendingReceipts = pending
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingReceipts == pending {
			s.pendingReceipts = nil
		}
		s.mu.Unlock()
	}()

	verified := make(map[int][]byte, len(receiverOrder))
	for receiverID, wire := range localReceipts {
		verified[receiverID] = append([]byte(nil), wire...)
	}
	broadcast := func() {
		for _, wire := range localReceipts {
			for _, node := range sortedUnique(s.cfg.OldCommittee) {
				_ = s.send(node, cvTagReceiptV1, wire)
			}
		}
	}
	broadcast()
	threshold := s.leafCtx.sharingDegree + 1
	if len(verified) >= threshold {
		key, keyErr := cvThresholdPublicKeyFromReceiptsV1(s.leafCtx, agg, receiverOrder, verified)
		return shares, verified, key, keyErr
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for len(verified) < threshold {
		select {
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, nil, nil, s.ctx.Err()
		case <-ticker.C:
			broadcast()
		case receipt := <-pending.values:
			if _, duplicate := verified[receipt.receiverID]; !duplicate {
				verified[receipt.receiverID] = append([]byte(nil), receipt.wire...)
			}
		}
	}
	key, err := cvThresholdPublicKeyFromReceiptsV1(s.leafCtx, agg, receiverOrder, verified)
	return shares, verified, key, err
}

func (s *cvComponentServiceV1) handleReceipt(msg Message) {
	s.mu.Lock()
	pending := s.pendingReceipts
	s.mu.Unlock()
	if pending == nil {
		return
	}
	r := newCVWireReader(msg.Body)
	domain, err := r.bytes(len(cvReceiptV1Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvReceiptV1Domain)) {
		return
	}
	aggregateDigest, err := r.bytes(32)
	if err != nil || !bytes.Equal(aggregateDigest, pending.agg.digest) {
		return
	}
	receiverIndex, err := r.uint32()
	if err != nil || receiverIndex <= 0 || receiverIndex > len(pending.receiverOrder) {
		return
	}
	if _, err := cvDecodeReceiptV1(msg.Body, s.leafCtx, pending.agg, receiverIndex); err != nil {
		return
	}
	received := cvReceivedReceiptV1{
		receiverID: pending.receiverOrder[receiverIndex-1],
		wire:       append([]byte(nil), msg.Body...),
	}
	select {
	case pending.values <- received:
	default:
	}
}

func (s *cvComponentServiceV1) handleInit(msg Message) {
	init, err := cvDecodeComponentInitV1(msg.Body)
	if err != nil {
		return
	}
	dealer, digest, err := cvComponentLeafArtifactIdentityV1(init.artifactWire)
	if err != nil || dealer != msg.From {
		return
	}
	statement, err := cvComponentStatementDigestV1(dealer, digest)
	if err != nil || !s.cfg.runtime.lockSigner.VerifyShare(
		dealer, cvComponentDealerSignatureDomainV1, statement, init.dealerSig,
	) {
		return
	}
	artifact, err := cvDecodeAvailableComponentLeafArtifactV1(init.artifactWire, dealer)
	if err != nil || !bytes.Equal(artifact.leafDigest, digest) {
		return
	}
	if err := s.store.Put(
		s.cfg.SID, s.cfg.Epoch, dealer, s.localNode, digest, artifact.leafWire,
	); err != nil {
		return
	}
	sig, err := s.cfg.runtime.lockSigner.SignShare(
		s.localNode, cvComponentLockSignatureDomainV1, statement,
	)
	if err != nil {
		return
	}
	ackWire, err := cvComponentAckV1CanonicalBytes(&cvComponentAckV1{
		dealer: dealer, holder: s.localNode, leafDigest: digest, signature: sig,
	})
	if err == nil {
		_ = s.send(dealer, cvTagComponentAckV1, ackWire)
	}
}

func (s *cvComponentServiceV1) handleACK(msg Message) {
	ack, err := cvDecodeComponentAckV1(msg.Body)
	if err != nil || ack.holder != msg.From || ack.dealer != s.localNode {
		return
	}
	statement, err := cvComponentStatementDigestV1(ack.dealer, ack.leafDigest)
	if err != nil || !s.cfg.runtime.lockSigner.VerifyShare(
		ack.holder, cvComponentLockSignatureDomainV1, statement, ack.signature,
	) {
		return
	}
	key := cvComponentKeyV1(ack.dealer, ack.leafDigest)
	s.mu.Lock()
	ch := s.pendingACKs[key]
	s.mu.Unlock()
	if ch != nil {
		select {
		case ch <- *ack:
		default:
		}
	}
}

func (s *cvComponentServiceV1) handleGet(msg Message) {
	request, err := cvDecodeComponentGetV1(msg.Body)
	if err != nil {
		return
	}
	leafWire, err := s.store.Read(
		s.cfg.SID, s.cfg.Epoch, request.dealer, s.localNode, request.leafDigest,
	)
	if err != nil {
		return
	}
	artifactWire, err := cvComponentLeafArtifactV1CanonicalBytes(&cvComponentLeafArtifactV1{
		dealer: request.dealer, leafDigest: request.leafDigest, leafWire: leafWire,
	})
	if err == nil {
		_ = s.send(msg.From, cvTagComponentLeafV1, artifactWire)
	}
}

func (s *cvComponentServiceV1) handleLeaf(msg Message) {
	dealer, digest, err := cvComponentLeafArtifactIdentityV1(msg.Body)
	if err != nil {
		return
	}
	key := cvComponentKeyV1(dealer, digest)
	s.mu.Lock()
	pending := s.pendingLeaves[key]
	s.mu.Unlock()
	if pending == nil {
		return
	}
	if _, ok := pending.allowed[msg.From]; !ok {
		return
	}
	artifact, err := cvDecodeAvailableComponentLeafArtifactV1(msg.Body, dealer)
	if err != nil {
		return
	}
	if err := s.store.Put(
		s.cfg.SID, s.cfg.Epoch, dealer, s.localNode, digest, artifact.leafWire,
	); err != nil {
		return
	}
	accepted, err := s.cacheVerifiedWire(dealer, digest, artifact.leafWire)
	if err != nil {
		return
	}
	select {
	case pending.values <- accepted.leaf:
	default:
	}
}

func (s *cvComponentServiceV1) send(to int, tag string, payload []byte) error {
	return s.sendFrom(s.localNode, to, tag, payload)
}

func (s *cvComponentServiceV1) sendFrom(from, to int, tag string, payload []byte) error {
	envelope, err := cvEncodeNetworkEnvelopeV1(s.cfg.SID, s.cfg.Epoch, payload)
	if err != nil {
		return err
	}
	return s.transport.Send(Message{From: from, To: to, Tag: tag, Body: envelope})
}

func (s *cvComponentServiceV1) cacheVerifiedLeaf(
	dealer int,
	digest []byte,
	leaf *cvLeafV1,
	canonicalWire []byte,
) error {
	accepted, err := cvAcceptedLeafV1(s.leafCtx, leaf, canonicalWire)
	if err != nil || !bytes.Equal(accepted.leafDigest, digest) {
		return fmt.Errorf("invalid verified CV-sAPVSS component cache entry")
	}
	return s.cacheAcceptedLeaf(dealer, digest, accepted)
}

func (s *cvComponentServiceV1) cacheVerifiedWire(
	dealer int,
	digest, canonicalWire []byte,
) (*cvVerifiedLeafV1, error) {
	if dealer < 0 || len(digest) != 32 || len(canonicalWire) == 0 ||
		!bytes.Equal(digest, cvComponentLeafPayloadDigestV1(canonicalWire)) {
		return nil, fmt.Errorf("invalid verified component wire")
	}
	var accepted *cvVerifiedLeafV1
	var err error
	if apvssHasLeafWireDomainV1(canonicalWire) {
		prototype, decodeErr := apvssDecodeLeafPrototypeV1(canonicalWire, s.leafCtx)
		if decodeErr != nil || prototype.leaf.dealerID != uint64(dealer) ||
			!bytes.Equal(prototype.digest, digest) {
			return nil, fmt.Errorf("invalid APVSS component leaf")
		}
		accepted, err = cvAcceptedDecodedAPVSSLeafV1(s.leafCtx, prototype, canonicalWire)
	} else {
		leaf, decodeErr := cvDecodeLeafV1(canonicalWire, s.leafCtx)
		if decodeErr != nil || leaf.dealerID != uint64(dealer) || !bytes.Equal(leaf.digest, digest) {
			return nil, fmt.Errorf("invalid CV-sAPVSS component leaf")
		}
		accepted, err = cvAcceptedLeafV1(s.leafCtx, leaf, canonicalWire)
	}
	if err != nil {
		return nil, err
	}
	if err := s.cacheAcceptedLeaf(dealer, digest, accepted); err != nil {
		return nil, err
	}
	key := cvComponentKeyV1(dealer, digest)
	s.mu.Lock()
	cached := s.verifiedLeaves[key]
	s.mu.Unlock()
	return cached, nil
}

func (s *cvComponentServiceV1) cacheAcceptedLeaf(
	dealer int,
	digest []byte,
	accepted *cvVerifiedLeafV1,
) error {
	if accepted == nil || !bytes.Equal(accepted.leafDigest, digest) {
		return fmt.Errorf("invalid accepted CV-sAPVSS component cache entry")
	}
	key := cvComponentKeyV1(dealer, digest)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.verifiedLeaves[key]; existing != nil {
		if !bytes.Equal(existing.canonicalWire, accepted.canonicalWire) {
			return fmt.Errorf("conflicting verified CV-sAPVSS component cache entry")
		}
		return nil
	}
	if len(s.verifiedLeaves) >= len(s.cfg.OldCommittee) {
		return fmt.Errorf("verified CV-sAPVSS component cache is full")
	}
	s.verifiedLeaves[key] = accepted
	return nil
}

func cvComponentKeyV1(dealer int, digest []byte) string {
	return fmt.Sprintf("%d:%x", dealer, digest)
}

func cvDecodeAndValidateComponentDescriptorV1(cfg Config, wire []byte) (*cvComponentDescriptorV1, error) {
	descriptor, err := cvDecodeComponentDescriptorV1(
		wire, sortedUnique(cfg.OldCommittee), len(cfg.OldCommittee)-cfg.FOld,
	)
	if err != nil {
		return nil, err
	}
	if err := cvValidateComponentDescriptorV1(cfg, descriptor); err != nil {
		return nil, err
	}
	return descriptor, nil
}

func cvComponentInitV1CanonicalBytes(init *cvComponentInitV1) ([]byte, error) {
	if init == nil || len(init.artifactWire) == 0 ||
		len(init.artifactWire) > cvMaxNetworkPayloadBytesV1 || len(init.dealerSig) == 0 ||
		len(init.dealerSig) > cvMaxComponentSignatureBytesV1 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component INIT")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentInitDomainV1))
	_ = cvWriteBytes(&wire, init.artifactWire)
	_ = cvWriteBytes(&wire, init.dealerSig)
	return wire.Bytes(), nil
}

func cvDecodeComponentInitV1(wire []byte) (*cvComponentInitV1, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentInitDomainV1))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentInitDomainV1)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component INIT domain")
	}
	artifact, err := r.bytes(cvMaxNetworkPayloadBytesV1)
	if err != nil || len(artifact) == 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component INIT artifact")
	}
	sig, err := r.bytes(cvMaxComponentSignatureBytesV1)
	if err != nil || len(sig) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component INIT signature")
	}
	init := &cvComponentInitV1{artifactWire: artifact, dealerSig: sig}
	canonical, err := cvComponentInitV1CanonicalBytes(init)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS component INIT")
	}
	return init, nil
}

func cvComponentAckV1CanonicalBytes(ack *cvComponentAckV1) ([]byte, error) {
	if ack == nil || ack.dealer < 0 || ack.holder < 0 || len(ack.leafDigest) != 32 ||
		len(ack.signature) == 0 || len(ack.signature) > cvMaxComponentSignatureBytesV1 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component ACK")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentAckDomainV1))
	cvWriteUint64(&wire, uint64(ack.dealer))
	cvWriteUint64(&wire, uint64(ack.holder))
	_ = cvWriteBytes(&wire, ack.leafDigest)
	_ = cvWriteBytes(&wire, ack.signature)
	return wire.Bytes(), nil
}

func cvDecodeComponentAckV1(wire []byte) (*cvComponentAckV1, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentAckDomainV1))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentAckDomainV1)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component ACK domain")
	}
	dealer, err := r.uint64()
	if err != nil || dealer > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component ACK dealer")
	}
	holder, err := r.uint64()
	if err != nil || holder > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component ACK holder")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component ACK digest")
	}
	sig, err := r.bytes(cvMaxComponentSignatureBytesV1)
	if err != nil || len(sig) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component ACK signature")
	}
	ack := &cvComponentAckV1{dealer: int(dealer), holder: int(holder), leafDigest: digest, signature: sig}
	canonical, err := cvComponentAckV1CanonicalBytes(ack)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS component ACK")
	}
	return ack, nil
}

func cvComponentGetV1CanonicalBytes(request *cvComponentGetV1) ([]byte, error) {
	if request == nil || request.dealer < 0 || len(request.leafDigest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component GET")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentGetDomainV1))
	cvWriteUint64(&wire, uint64(request.dealer))
	_ = cvWriteBytes(&wire, request.leafDigest)
	return wire.Bytes(), nil
}

func cvDecodeComponentGetV1(wire []byte) (*cvComponentGetV1, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentGetDomainV1))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentGetDomainV1)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component GET domain")
	}
	dealer, err := r.uint64()
	if err != nil || dealer > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component GET dealer")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component GET digest")
	}
	request := &cvComponentGetV1{dealer: int(dealer), leafDigest: digest}
	canonical, err := cvComponentGetV1CanonicalBytes(request)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS component GET")
	}
	return request, nil
}

func cvComponentLeafArtifactIdentityV1(wire []byte) (int, []byte, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentLeafArtifactDomainV1))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentLeafArtifactDomainV1)) {
		return 0, nil, fmt.Errorf("invalid CV-sAPVSS component leaf artifact domain")
	}
	dealer, err := r.uint64()
	if err != nil || dealer > uint64(^uint(0)>>1) {
		return 0, nil, fmt.Errorf("invalid CV-sAPVSS component leaf artifact dealer")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return 0, nil, fmt.Errorf("invalid CV-sAPVSS component leaf artifact digest")
	}
	leafWire, err := r.bytes(cvMaxLeafWireBytesV1)
	if err != nil || len(leafWire) == 0 || r.reader.Len() != 0 {
		return 0, nil, fmt.Errorf("invalid CV-sAPVSS component leaf artifact framing")
	}
	leafDigest := cvComponentLeafPayloadDigestV1(leafWire)
	if !bytes.Equal(digest, leafDigest) {
		return 0, nil, fmt.Errorf("invalid CV-sAPVSS component leaf artifact framing")
	}
	return int(dealer), append([]byte(nil), digest...), nil
}
