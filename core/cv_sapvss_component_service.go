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
	cvComponentInitDomain            = "ARL-CV-sAPVSS/component-init"
	cvComponentAckDomain             = "ARL-CV-sAPVSS/component-ack"
	cvComponentGetDomain             = "ARL-CV-sAPVSS/component-get"
	cvComponentDealerSignatureDomain = "RL_CV_COMPONENT_DEALER"
)

type cvComponentInit struct {
	artifactWire []byte
	dealerSig    []byte
}

type cvComponentAck struct {
	dealer     int
	holder     int
	leafDigest []byte
	signature  []byte
}

type cvComponentGet struct {
	dealer     int
	leafDigest []byte
}

type cvPendingComponentLeaf struct {
	allowed map[int]struct{}
	values  chan *cvLeaf
}

type cvPendingARCShare struct {
	values chan cvARCShare
}

type cvPendingRecovery struct {
	rlo     *AggRLO
	allowed map[int]struct{}
	values  chan cvFreshShardArtifact
}

type cvReceivedReceipt struct {
	receiverID int
	wire       []byte
}

type cvPendingReceiptExchange struct {
	agg           *cvAggregateTranscript
	receiverOrder []int
	values        chan cvReceivedReceipt
}

type apvssPendingLaneACKs struct {
	leaf   *cvLeaf
	values chan apvssLaneACK
}

type cvComponentService struct {
	ctx                  context.Context
	cancel               context.CancelFunc
	cfg                  Config
	leafCtx              *cvLeafContext
	localNode            int
	transport            agreementTransport
	store                *cvComponentLeafStore
	freshStore           *cvFreshShardStore
	inbox                <-chan Message
	receiverOrder        []int
	receiverIndex        map[int]int
	localReceiverSecrets map[int]fr.Element

	mu                         sync.Mutex
	aggregateBuildMu           sync.Mutex
	pendingACKs                map[string]chan cvComponentAck
	pendingLeaves              map[string]*cvPendingComponentLeaf
	pendingARCs                map[string]*cvPendingARCShare
	pendingRecoveries          map[string]*cvPendingRecovery
	pendingReceipts            *cvPendingReceiptExchange
	pendingLaneACKs            map[string]*apvssPendingLaneACKs
	processingOffers           map[string]struct{}
	candidateByMaterializer    map[int]string
	verifiedLeaves             map[string]*cvVerifiedLeaf
	aggregateCertificates      map[string][]byte
	verifiedAggregates         map[string]*cvAggregateTranscript
	componentDescriptors       map[int]*cvComponentDescriptor
	componentCandidatesChanged chan struct{}
	done                       chan struct{}
}

func newCVComponentService(
	ctx context.Context,
	cfg Config,
	leafContext *cvLeafContext,
	localNode int,
	transport agreementTransport,
	router *cvSAPVSSRouter,
	store *cvComponentLeafStore,
) (*cvComponentService, error) {
	return newCVComponentServiceWithReceivers(
		ctx, cfg, leafContext, localNode, transport, router, store, nil, nil,
	)
}

func newCVComponentServiceWithReceivers(
	ctx context.Context,
	cfg Config,
	leafContext *cvLeafContext,
	localNode int,
	transport agreementTransport,
	router *cvSAPVSSRouter,
	store *cvComponentLeafStore,
	receiverOrder []int,
	localReceiverSecrets map[int]fr.Element,
) (*cvComponentService, error) {
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
	if err := cvValidateLeafContext(leafContext); err != nil {
		return nil, err
	}
	freshStore, err := newCVFreshShardStore(c.ArtifactCacheDir)
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
	service := &cvComponentService{
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
		pendingACKs:                make(map[string]chan cvComponentAck),
		pendingLeaves:              make(map[string]*cvPendingComponentLeaf),
		pendingARCs:                make(map[string]*cvPendingARCShare),
		pendingRecoveries:          make(map[string]*cvPendingRecovery),
		pendingLaneACKs:            make(map[string]*apvssPendingLaneACKs),
		processingOffers:           make(map[string]struct{}),
		candidateByMaterializer:    make(map[int]string),
		verifiedLeaves:             make(map[string]*cvVerifiedLeaf),
		aggregateCertificates:      make(map[string][]byte),
		verifiedAggregates:         make(map[string]*cvAggregateTranscript),
		componentDescriptors:       make(map[int]*cvComponentDescriptor),
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

func (s *cvComponentService) Close() error {
	if s == nil {
		return nil
	}
	s.cancel()
	<-s.done
	return nil
}

func (s *cvComponentService) CollectAPVSSLaneACKs(
	ctx context.Context,
	leaf *cvLeaf,
	witness *apvssDealerWitness,
) (*apvssLeafPrototype, error) {
	if ctx == nil || leaf == nil || witness == nil || leaf.dealerID != uint64(s.localNode) ||
		len(s.receiverOrder) != len(leaf.receivers) {
		return nil, fmt.Errorf("invalid APVSS lane ACK collection input")
	}
	if err := apvssValidateStructuralLeaf(s.leafCtx, leaf); err != nil {
		return nil, err
	}
	leafWire, err := cvLeafCanonicalBytes(leaf)
	if err != nil {
		return nil, err
	}
	key := cvComponentKey(s.localNode, leaf.digest)
	pending := &apvssPendingLaneACKs{
		leaf: leaf, values: make(chan apvssLaneACK, len(s.receiverOrder)),
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
		if s.sendFrom(s.localNode, receiverID, apvssTagLaneOffer, leafWire) == nil {
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
	acks := make(map[int]apvssLaneACK, len(s.receiverOrder))
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
	assemble := func() (*apvssLeafPrototype, error) {
		ordered := make([]apvssLaneACK, 0, len(acks))
		for receiverIndex := 1; receiverIndex <= len(s.receiverOrder); receiverIndex++ {
			if ack, ok := acks[receiverIndex]; ok {
				ordered = append(ordered, ack)
			}
		}
		return apvssAssembleVerifiedPrototypeWithFallbackProfile(
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

func (s *cvComponentService) Disperse(ctx context.Context, leaf *cvLeaf) (*cvComponentDescriptor, error) {
	if ctx == nil || leaf == nil || leaf.dealerID != uint64(s.localNode) {
		return nil, fmt.Errorf("CV-sAPVSS component dealer does not match local node")
	}
	leafWire, err := cvLeafCanonicalBytes(leaf)
	if err != nil {
		return nil, err
	}
	return s.disperseComponentWire(ctx, int(leaf.dealerID), leaf.digest, leafWire)
}

func (s *cvComponentService) DisperseAPVSS(
	ctx context.Context,
	prototype *apvssLeafPrototype,
) (*cvComponentDescriptor, error) {
	if ctx == nil || prototype == nil || prototype.leaf == nil ||
		prototype.leaf.dealerID != uint64(s.localNode) {
		return nil, fmt.Errorf("APVSS component dealer does not match local node")
	}
	leafWire, err := apvssLeafPrototypeCanonicalBytes(prototype)
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

func (s *cvComponentService) disperseComponentWire(
	ctx context.Context,
	dealer int,
	leafDigest, leafWire []byte,
) (*cvComponentDescriptor, error) {
	if ctx == nil || dealer != s.localNode || len(leafDigest) != 32 || len(leafWire) == 0 ||
		!bytes.Equal(leafDigest, cvComponentLeafPayloadDigest(leafWire)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component payload")
	}
	artifactWire, err := cvComponentLeafArtifactCanonicalBytes(&cvComponentLeafArtifact{
		dealer: dealer, leafDigest: leafDigest, leafWire: leafWire,
	})
	if err != nil {
		return nil, err
	}
	if err := s.store.Put(s.cfg.SID, s.cfg.Epoch, dealer, s.localNode, leafDigest, leafWire); err != nil {
		return nil, err
	}
	statement, err := cvComponentStatementDigest(dealer, leafDigest)
	if err != nil {
		return nil, err
	}
	localHolderSig, err := s.cfg.runtime.lockSigner.SignShare(
		s.localNode, cvComponentLockSignatureDomain, statement,
	)
	if err != nil {
		return nil, err
	}
	dealerSig, err := s.cfg.runtime.lockSigner.SignShare(
		s.localNode, cvComponentDealerSignatureDomain, statement,
	)
	if err != nil {
		return nil, err
	}
	initWire, err := cvComponentInitCanonicalBytes(&cvComponentInit{
		artifactWire: artifactWire,
		dealerSig:    dealerSig,
	})
	if err != nil {
		return nil, err
	}

	key := cvComponentKey(dealer, leafDigest)
	acks := make(chan cvComponentAck, len(s.cfg.OldCommittee))
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
		if s.send(holder, cvTagComponentInit, initWire) == nil {
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
		cvComponentLockSignatureDomain, statement, shares,
	)
	if err != nil {
		return nil, err
	}
	descriptor := &cvComponentDescriptor{
		dealer:          dealer,
		leafDigest:      append([]byte(nil), leafDigest...),
		holders:         holders,
		shareSignatures: shares,
		certificate:     certificate,
	}
	if err := cvValidateComponentDescriptor(s.cfg, descriptor); err != nil {
		return nil, err
	}
	descriptorWire, err := cvComponentDescriptorCanonicalBytes(descriptor)
	if err != nil {
		return nil, err
	}
	if err := s.acceptComponentDescriptorWire(descriptorWire); err != nil {
		return nil, err
	}
	for _, node := range sortedUnique(s.cfg.OldCommittee) {
		_ = s.send(node, cvTagComponentCert, descriptorWire)
	}
	return descriptor, nil
}

func (s *cvComponentService) CollectComponentCandidates(
	ctx context.Context,
) ([]*cvComponentDescriptor, error) {
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
			selected := make([]*cvComponentDescriptor, 0, ready)
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
			selected := make([]*cvComponentDescriptor, 0, ready)
			for _, dealer := range dealers[:ready] {
				selected = append(selected, s.componentDescriptors[dealer])
			}
			s.mu.Unlock()
			return selected, nil
		case <-s.componentCandidatesChanged:
		}
	}
}

func (s *cvComponentService) acceptComponentDescriptorWire(wire []byte) error {
	descriptor, err := cvDecodeAndValidateComponentDescriptor(s.cfg, wire)
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

func (s *cvComponentService) Retrieve(
	ctx context.Context,
	descriptor *cvComponentDescriptor,
) (*cvLeaf, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil CV-sAPVSS component retrieval context")
	}
	if err := cvValidateNetworkComponentDescriptor(s.cfg, descriptor); err != nil {
		return nil, err
	}
	key := cvComponentKey(descriptor.dealer, descriptor.leafDigest)
	oldOrder := sortedUnique(s.cfg.OldCommittee)
	pending := &cvPendingComponentLeaf{
		// Compact descriptors intentionally omit holder identities. Requests are
		// sent to the complete old roster and authenticated leaf responses are
		// accepted only after digest/dealer checks.
		allowed: nodeSet(oldOrder),
		values:  make(chan *cvLeaf, len(oldOrder)),
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
	requestWire, err := cvComponentGetCanonicalBytes(&cvComponentGet{
		dealer: descriptor.dealer, leafDigest: descriptor.leafDigest,
	})
	if err != nil {
		return nil, err
	}
	sent := 0
	for _, holder := range oldOrder {
		if s.send(holder, cvTagComponentGet, requestWire) == nil {
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

func (s *cvComponentService) run() {
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

func (s *cvComponentService) handle(msg Message) {
	switch msg.Tag {
	case cvTagComponentInit:
		s.handleInit(msg)
	case cvTagComponentAck:
		s.handleACK(msg)
	case cvTagComponentCert:
		_ = s.acceptComponentDescriptorWire(msg.Body)
	case cvTagComponentGet:
		s.handleGet(msg)
	case cvTagComponentLeaf:
		s.handleLeaf(msg)
	case cvTagAggregateManifest:
		s.handleAggregateOffer(msg)
	case cvTagARCShare:
		s.handleARCShare(msg)
	case cvTagARCCertificate:
		s.handleARCCertificate(msg)
	case cvTagRecoverGet:
		s.handleRecoverGet(msg)
	case cvTagRecoverShard:
		s.handleRecoverShard(msg)
	case cvTagReceipt:
		s.handleReceipt(msg)
	case apvssTagLaneOffer:
		s.handleAPVSSLaneOffer(msg)
	case apvssTagLaneACK:
		s.handleAPVSSLaneACK(msg)
	}
}

func (s *cvComponentService) handleAPVSSLaneOffer(msg Message) {
	secret, local := s.localReceiverSecrets[msg.To]
	receiverIndex, registered := s.receiverIndex[msg.To]
	if !local || !registered {
		return
	}
	leaf, err := cvDecodeLeaf(msg.Body, s.leafCtx)
	if err != nil || leaf.dealerID != uint64(msg.From) {
		return
	}
	ack, err := apvssIssueVerifiedLaneACK(s.leafCtx, leaf, receiverIndex, secret)
	if err != nil {
		return
	}
	wire, err := apvssLaneACKMessageCanonicalBytes(&apvssLaneACKMessage{
		dealerID: leaf.dealerID, leafDigest: leaf.digest, ack: ack,
	})
	if err == nil {
		_ = s.sendFrom(msg.To, msg.From, apvssTagLaneACK, wire)
	}
}

func (s *cvComponentService) handleAPVSSLaneACK(msg Message) {
	s.mu.Lock()
	pending := make([]*apvssPendingLaneACKs, 0, len(s.pendingLaneACKs))
	for _, value := range s.pendingLaneACKs {
		pending = append(pending, value)
	}
	s.mu.Unlock()
	for _, collection := range pending {
		message, err := apvssDecodeLaneACKMessage(msg.Body, collection.leaf)
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

func (s *cvComponentService) ExchangeReceipts(
	ctx context.Context,
	agg *cvAggregateTranscript,
	receiverOrder []int,
	localSecrets map[int]fr.Element,
) (map[int][]byte, map[int][]byte, []byte, error) {
	if ctx == nil || len(localSecrets) == 0 {
		return nil, nil, nil, fmt.Errorf("invalid CV-sAPVSS receipt exchange input")
	}
	shares, localReceipts, err := cvCreateLocalDecryptionOutputs(s.leafCtx, agg, receiverOrder, localSecrets)
	if err != nil {
		return nil, nil, nil, err
	}
	pending := &cvPendingReceiptExchange{
		agg: agg, receiverOrder: append([]int(nil), receiverOrder...),
		values: make(chan cvReceivedReceipt, len(receiverOrder)*2),
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
				_ = s.send(node, cvTagReceipt, wire)
			}
		}
	}
	broadcast()
	threshold := s.leafCtx.sharingDegree + 1
	if len(verified) >= threshold {
		key, keyErr := cvThresholdPublicKeyFromReceipts(s.leafCtx, agg, receiverOrder, verified)
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
	key, err := cvThresholdPublicKeyFromReceipts(s.leafCtx, agg, receiverOrder, verified)
	return shares, verified, key, err
}

func (s *cvComponentService) handleReceipt(msg Message) {
	s.mu.Lock()
	pending := s.pendingReceipts
	s.mu.Unlock()
	if pending == nil {
		return
	}
	r := newCVWireReader(msg.Body)
	domain, err := r.bytes(len(cvReceiptDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvReceiptDomain)) {
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
	if _, err := cvDecodeReceipt(msg.Body, s.leafCtx, pending.agg, receiverIndex); err != nil {
		return
	}
	received := cvReceivedReceipt{
		receiverID: pending.receiverOrder[receiverIndex-1],
		wire:       append([]byte(nil), msg.Body...),
	}
	select {
	case pending.values <- received:
	default:
	}
}

func (s *cvComponentService) handleInit(msg Message) {
	init, err := cvDecodeComponentInit(msg.Body)
	if err != nil {
		return
	}
	dealer, digest, err := cvComponentLeafArtifactIdentity(init.artifactWire)
	if err != nil || dealer != msg.From {
		return
	}
	statement, err := cvComponentStatementDigest(dealer, digest)
	if err != nil || !s.cfg.runtime.lockSigner.VerifyShare(
		dealer, cvComponentDealerSignatureDomain, statement, init.dealerSig,
	) {
		return
	}
	artifact, err := cvDecodeAvailableComponentLeafArtifact(init.artifactWire, dealer)
	if err != nil || !bytes.Equal(artifact.leafDigest, digest) {
		return
	}
	if err := s.store.Put(
		s.cfg.SID, s.cfg.Epoch, dealer, s.localNode, digest, artifact.leafWire,
	); err != nil {
		return
	}
	sig, err := s.cfg.runtime.lockSigner.SignShare(
		s.localNode, cvComponentLockSignatureDomain, statement,
	)
	if err != nil {
		return
	}
	ackWire, err := cvComponentAckCanonicalBytes(&cvComponentAck{
		dealer: dealer, holder: s.localNode, leafDigest: digest, signature: sig,
	})
	if err == nil {
		_ = s.send(dealer, cvTagComponentAck, ackWire)
	}
}

func (s *cvComponentService) handleACK(msg Message) {
	ack, err := cvDecodeComponentAck(msg.Body)
	if err != nil || ack.holder != msg.From || ack.dealer != s.localNode {
		return
	}
	statement, err := cvComponentStatementDigest(ack.dealer, ack.leafDigest)
	if err != nil || !s.cfg.runtime.lockSigner.VerifyShare(
		ack.holder, cvComponentLockSignatureDomain, statement, ack.signature,
	) {
		return
	}
	key := cvComponentKey(ack.dealer, ack.leafDigest)
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

func (s *cvComponentService) handleGet(msg Message) {
	request, err := cvDecodeComponentGet(msg.Body)
	if err != nil {
		return
	}
	leafWire, err := s.store.Read(
		s.cfg.SID, s.cfg.Epoch, request.dealer, s.localNode, request.leafDigest,
	)
	if err != nil {
		return
	}
	artifactWire, err := cvComponentLeafArtifactCanonicalBytes(&cvComponentLeafArtifact{
		dealer: request.dealer, leafDigest: request.leafDigest, leafWire: leafWire,
	})
	if err == nil {
		_ = s.send(msg.From, cvTagComponentLeaf, artifactWire)
	}
}

func (s *cvComponentService) handleLeaf(msg Message) {
	dealer, digest, err := cvComponentLeafArtifactIdentity(msg.Body)
	if err != nil {
		return
	}
	key := cvComponentKey(dealer, digest)
	s.mu.Lock()
	pending := s.pendingLeaves[key]
	s.mu.Unlock()
	if pending == nil {
		return
	}
	if _, ok := pending.allowed[msg.From]; !ok {
		return
	}
	artifact, err := cvDecodeAvailableComponentLeafArtifact(msg.Body, dealer)
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

func (s *cvComponentService) send(to int, tag string, payload []byte) error {
	return s.sendFrom(s.localNode, to, tag, payload)
}

func (s *cvComponentService) sendFrom(from, to int, tag string, payload []byte) error {
	envelope, err := cvEncodeNetworkEnvelope(s.cfg.SID, s.cfg.Epoch, payload)
	if err != nil {
		return err
	}
	return s.transport.Send(Message{From: from, To: to, Tag: tag, Body: envelope})
}

func (s *cvComponentService) cacheVerifiedLeaf(
	dealer int,
	digest []byte,
	leaf *cvLeaf,
	canonicalWire []byte,
) error {
	accepted, err := cvAcceptedLeaf(s.leafCtx, leaf, canonicalWire)
	if err != nil || !bytes.Equal(accepted.leafDigest, digest) {
		return fmt.Errorf("invalid verified CV-sAPVSS component cache entry")
	}
	return s.cacheAcceptedLeaf(dealer, digest, accepted)
}

func (s *cvComponentService) cacheVerifiedWire(
	dealer int,
	digest, canonicalWire []byte,
) (*cvVerifiedLeaf, error) {
	if dealer < 0 || len(digest) != 32 || len(canonicalWire) == 0 ||
		!bytes.Equal(digest, cvComponentLeafPayloadDigest(canonicalWire)) {
		return nil, fmt.Errorf("invalid verified component wire")
	}
	var accepted *cvVerifiedLeaf
	var err error
	if apvssHasLeafWireDomain(canonicalWire) {
		prototype, decodeErr := apvssDecodeLeafPrototype(canonicalWire, s.leafCtx)
		if decodeErr != nil || prototype.leaf.dealerID != uint64(dealer) ||
			!bytes.Equal(prototype.digest, digest) {
			return nil, fmt.Errorf("invalid APVSS component leaf")
		}
		accepted, err = cvAcceptedDecodedAPVSSLeaf(s.leafCtx, prototype, canonicalWire)
	} else {
		leaf, decodeErr := cvDecodeLeaf(canonicalWire, s.leafCtx)
		if decodeErr != nil || leaf.dealerID != uint64(dealer) || !bytes.Equal(leaf.digest, digest) {
			return nil, fmt.Errorf("invalid CV-sAPVSS component leaf")
		}
		accepted, err = cvAcceptedLeaf(s.leafCtx, leaf, canonicalWire)
	}
	if err != nil {
		return nil, err
	}
	if err := s.cacheAcceptedLeaf(dealer, digest, accepted); err != nil {
		return nil, err
	}
	key := cvComponentKey(dealer, digest)
	s.mu.Lock()
	cached := s.verifiedLeaves[key]
	s.mu.Unlock()
	return cached, nil
}

func (s *cvComponentService) cacheAcceptedLeaf(
	dealer int,
	digest []byte,
	accepted *cvVerifiedLeaf,
) error {
	if accepted == nil || !bytes.Equal(accepted.leafDigest, digest) {
		return fmt.Errorf("invalid accepted CV-sAPVSS component cache entry")
	}
	key := cvComponentKey(dealer, digest)
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

func cvComponentKey(dealer int, digest []byte) string {
	return fmt.Sprintf("%d:%x", dealer, digest)
}

func cvDecodeAndValidateComponentDescriptor(cfg Config, wire []byte) (*cvComponentDescriptor, error) {
	descriptor, err := cvDecodeComponentDescriptor(wire, sortedUnique(cfg.OldCommittee))
	if err != nil {
		return nil, err
	}
	if err := cvValidateNetworkComponentDescriptor(cfg, descriptor); err != nil {
		return nil, err
	}
	return descriptor, nil
}

func cvComponentInitCanonicalBytes(init *cvComponentInit) ([]byte, error) {
	if init == nil || len(init.artifactWire) == 0 ||
		len(init.artifactWire) > cvMaxNetworkPayloadBytes || len(init.dealerSig) == 0 ||
		len(init.dealerSig) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV-sAPVSS component INIT")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentInitDomain))
	_ = cvWriteBytes(&wire, init.artifactWire)
	_ = cvWriteBytes(&wire, init.dealerSig)
	return wire.Bytes(), nil
}

func cvDecodeComponentInit(wire []byte) (*cvComponentInit, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentInitDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentInitDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component INIT domain")
	}
	artifact, err := r.bytes(cvMaxNetworkPayloadBytes)
	if err != nil || len(artifact) == 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component INIT artifact")
	}
	sig, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(sig) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component INIT signature")
	}
	init := &cvComponentInit{artifactWire: artifact, dealerSig: sig}
	canonical, err := cvComponentInitCanonicalBytes(init)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS component INIT")
	}
	return init, nil
}

func cvComponentAckCanonicalBytes(ack *cvComponentAck) ([]byte, error) {
	if ack == nil || ack.dealer < 0 || ack.holder < 0 || len(ack.leafDigest) != 32 ||
		len(ack.signature) == 0 || len(ack.signature) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV-sAPVSS component ACK")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentAckDomain))
	cvWriteUint64(&wire, uint64(ack.dealer))
	cvWriteUint64(&wire, uint64(ack.holder))
	_ = cvWriteBytes(&wire, ack.leafDigest)
	_ = cvWriteBytes(&wire, ack.signature)
	return wire.Bytes(), nil
}

func cvDecodeComponentAck(wire []byte) (*cvComponentAck, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentAckDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentAckDomain)) {
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
	sig, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(sig) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component ACK signature")
	}
	ack := &cvComponentAck{dealer: int(dealer), holder: int(holder), leafDigest: digest, signature: sig}
	canonical, err := cvComponentAckCanonicalBytes(ack)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS component ACK")
	}
	return ack, nil
}

func cvComponentGetCanonicalBytes(request *cvComponentGet) ([]byte, error) {
	if request == nil || request.dealer < 0 || len(request.leafDigest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component GET")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentGetDomain))
	cvWriteUint64(&wire, uint64(request.dealer))
	_ = cvWriteBytes(&wire, request.leafDigest)
	return wire.Bytes(), nil
}

func cvDecodeComponentGet(wire []byte) (*cvComponentGet, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentGetDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentGetDomain)) {
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
	request := &cvComponentGet{dealer: int(dealer), leafDigest: digest}
	canonical, err := cvComponentGetCanonicalBytes(request)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS component GET")
	}
	return request, nil
}

func cvComponentLeafArtifactIdentity(wire []byte) (int, []byte, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentLeafArtifactDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentLeafArtifactDomain)) {
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
	leafWire, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil || len(leafWire) == 0 || r.reader.Len() != 0 {
		return 0, nil, fmt.Errorf("invalid CV-sAPVSS component leaf artifact framing")
	}
	leafDigest := cvComponentLeafPayloadDigest(leafWire)
	if !bytes.Equal(digest, leafDigest) {
		return 0, nil, fmt.Errorf("invalid CV-sAPVSS component leaf artifact framing")
	}
	return int(dealer), append([]byte(nil), digest...), nil
}
