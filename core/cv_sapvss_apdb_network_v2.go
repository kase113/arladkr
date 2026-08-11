package core

import (
	"context"
	"fmt"
	"sync"
)

type cvNetworkEnvelopeSealer interface {
	seal(from, to int, tag string, envelope []byte) ([]byte, error)
}

type cvAPDBNetworkServiceConfigV2 struct {
	SID             string
	Epoch           uint64
	LocalNode       int
	OldRoster       []int
	NewRoster       []int
	ExpectedContext []byte
	TotalShards     int
	DataShards      int
	ShardBytes      int
	MaximumPayload  int
}

type cvAPDBPendingLockV2 struct {
	collector *cvAPDBLockCollectorV2
	ready     chan struct{}
}

type cvAPDBPendingRecoveryV2 struct {
	collector *cvAPDBRecoveryCollectorV2
	ready     chan struct{}
}

type cvAPDBNetworkServiceV2 struct {
	ctx           context.Context
	cancel        context.CancelFunc
	cfg           cvAPDBNetworkServiceConfigV2
	transport     agreementTransport
	auth          cvNetworkEnvelopeSealer
	holderStore   *cvAPDBHolderStoreV2
	apdbSigner    *tblsThresholdSigner
	controlSigner *tblsThresholdSigner
	inbox         <-chan Message

	mu                sync.Mutex
	pendingLocks      map[string]*cvAPDBPendingLockV2
	pendingComponents map[string]*cvAPDBPendingRecoveryV2
	pendingAggregates map[string]*cvAPDBPendingRecoveryV2
	done              chan struct{}
}

func newCVAPDBNetworkServiceV2(
	ctx context.Context, cfg cvAPDBNetworkServiceConfigV2, transport agreementTransport, router *cvSAPVSSRouter,
	auth cvNetworkEnvelopeSealer, holderStore *cvAPDBHolderStoreV2,
	apdbSigner, controlSigner *tblsThresholdSigner,
) (*cvAPDBNetworkServiceV2, error) {
	if ctx == nil || cfg.SID == "" || cfg.Epoch == 0 || cfg.Epoch > uint64(^uint(0)>>1) || cfg.LocalNode < 0 ||
		transport == nil || router == nil || auth == nil || len(cfg.ExpectedContext) != 32 ||
		cfg.TotalShards != len(cfg.OldRoster) || cfg.DataShards <= 0 || cfg.DataShards > cfg.TotalShards ||
		cfg.ShardBytes <= 0 || cfg.MaximumPayload <= 0 ||
		!equalInts(cfg.OldRoster, sortedUnique(cfg.OldRoster)) ||
		!equalInts(cfg.NewRoster, sortedUnique(cfg.NewRoster)) ||
		!cvV2SignerHasRole(apdbSigner, cvV2RoleAPDB) ||
		!cvV2SignerHasRole(controlSigner, cvV2RoleControl) ||
		!equalInts(apdbSigner.memberOrder, cfg.OldRoster) ||
		!equalInts(controlSigner.memberOrder, cfg.OldRoster) {
		return nil, fmt.Errorf("invalid CV V2 APDB network service configuration")
	}
	isOld := cvMemberInRosterV2(cfg.LocalNode, cfg.OldRoster)
	isNew := cvMemberInRosterV2(cfg.LocalNode, cfg.NewRoster)
	if (!isOld && !isNew) || (isOld && holderStore == nil) {
		return nil, fmt.Errorf("invalid CV V2 APDB network service local role")
	}
	inbox, err := router.Receive(cfg.LocalNode)
	if err != nil {
		return nil, err
	}
	serviceContext, cancel := context.WithCancel(ctx)
	service := &cvAPDBNetworkServiceV2{
		ctx: serviceContext, cancel: cancel, cfg: cfg, transport: transport, auth: auth,
		holderStore: holderStore, apdbSigner: apdbSigner, controlSigner: controlSigner, inbox: inbox,
		pendingLocks:      make(map[string]*cvAPDBPendingLockV2),
		pendingComponents: make(map[string]*cvAPDBPendingRecoveryV2),
		pendingAggregates: make(map[string]*cvAPDBPendingRecoveryV2),
		done:              make(chan struct{}),
	}
	service.cfg.OldRoster = append([]int(nil), cfg.OldRoster...)
	service.cfg.NewRoster = append([]int(nil), cfg.NewRoster...)
	service.cfg.ExpectedContext = append([]byte(nil), cfg.ExpectedContext...)
	go service.run()
	return service, nil
}

func (s *cvAPDBNetworkServiceV2) Close() error {
	if s == nil {
		return nil
	}
	s.cancel()
	<-s.done
	return nil
}

func (s *cvAPDBNetworkServiceV2) Lock(ctx context.Context, encoded *cvAPDBEncodedV2) (*cvAPDBLockV2, error) {
	if s == nil || ctx == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) || encoded == nil ||
		encoded.totalShards != s.cfg.TotalShards || encoded.dataShards != s.cfg.DataShards ||
		encoded.shardBytes != s.cfg.ShardBytes {
		return nil, fmt.Errorf("invalid CV V2 network LockPD input")
	}
	collector, err := newCVAPDBLockCollectorV2(encoded, s.cfg.OldRoster, s.apdbSigner)
	if err != nil {
		return nil, err
	}
	key := string(encoded.instanceDigest)
	pending := &cvAPDBPendingLockV2{collector: collector, ready: make(chan struct{}, 1)}
	if err := s.registerLock(key, pending); err != nil {
		return nil, err
	}
	defer s.unregisterLock(key, pending)

	sent := 0
	for _, holder := range collector.StoreRecipients() {
		offer, offerErr := collector.StoreOffer(holder)
		if offerErr == nil && s.send(holder, cvTagAPDBStoreV2, offer) == nil {
			sent++
		}
	}
	if sent < s.apdbSigner.Threshold() {
		return nil, fmt.Errorf("CV V2 LockPD reached %d holders, need %d", sent, s.apdbSigner.Threshold())
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case <-pending.ready:
		return collector.RecoverLock()
	}
}

func (s *cvAPDBNetworkServiceV2) RecoverComponent(
	ctx context.Context, lock *cvAPDBLockV2, bindingCheck func([]byte) error,
) ([]byte, error) {
	if s == nil || ctx == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) {
		return nil, fmt.Errorf("invalid CV V2 component recovery caller")
	}
	request, err := cvAPDBLockV2CanonicalBytes(lock)
	if err != nil {
		return nil, err
	}
	collector, err := newCVAPDBRecoveryCollectorV2(lock, s.cfg.OldRoster, s.cfg.DataShards, s.cfg.ShardBytes,
		s.cfg.MaximumPayload, s.apdbSigner, bindingCheck)
	if err != nil {
		return nil, err
	}
	return s.runRecovery(ctx, cvTagAPDBRecoverGetV2, request, string(lock.InstanceDigest), collector, false)
}

func (s *cvAPDBNetworkServiceV2) RecoverAggregate(
	ctx context.Context, requestWire []byte, bindingCheck func([]byte) error,
) ([]byte, error) {
	if s == nil || ctx == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 aggregate recovery caller")
	}
	collector, err := newCVAggregateRecoveryCollectorV2(requestWire, s.cfg.ExpectedContext, s.cfg.OldRoster,
		s.cfg.DataShards, s.cfg.ShardBytes, s.cfg.MaximumPayload, s.apdbSigner, s.controlSigner, bindingCheck)
	if err != nil {
		return nil, err
	}
	return s.runRecovery(ctx, cvTagAggregateRecoverGetV2, requestWire,
		string(collector.lock.InstanceDigest), collector, true)
}

func (s *cvAPDBNetworkServiceV2) runRecovery(
	ctx context.Context, requestTag string, request []byte, key string,
	collector *cvAPDBRecoveryCollectorV2, aggregate bool,
) ([]byte, error) {
	pending := &cvAPDBPendingRecoveryV2{collector: collector, ready: make(chan struct{}, 1)}
	if err := s.registerRecovery(key, pending, aggregate); err != nil {
		return nil, err
	}
	defer s.unregisterRecovery(key, pending, aggregate)
	sent := 0
	for _, holder := range collector.RequestRecipients() {
		if s.send(holder, requestTag, request) == nil {
			sent++
		}
	}
	if sent < collector.dataShards {
		return nil, fmt.Errorf("CV V2 APDB recovery reached %d holders, need %d", sent, collector.dataShards)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case <-pending.ready:
		return collector.Recover()
	}
}

func (s *cvAPDBNetworkServiceV2) run() {
	defer close(s.done)
	defer s.cancel()
	for {
		select {
		case <-s.ctx.Done():
			return
		case msg, ok := <-s.inbox:
			if !ok {
				return
			}
			s.dispatch(msg)
		}
	}
}

func (s *cvAPDBNetworkServiceV2) dispatch(msg Message) {
	switch msg.Tag {
	case cvTagAPDBStoreV2:
		if s.holderStore == nil {
			return
		}
		response, err := cvHandleAPDBStoreOfferV2(s.cfg.SID, s.cfg.Epoch, msg.From, s.cfg.LocalNode,
			s.cfg.OldRoster, msg.Body, s.cfg.TotalShards, s.cfg.ShardBytes, s.holderStore, s.apdbSigner)
		if err == nil {
			_ = s.send(msg.From, cvTagAPDBStoredShareV2, response)
		}
	case cvTagAPDBStoredShareV2:
		response, err := cvDecodeAPDBStoredShareV2(msg.Body)
		if err != nil {
			return
		}
		pending := s.lookupLock(string(response.InstanceDigest))
		if pending != nil {
			if complete, addErr := pending.collector.AddStoredShare(msg.From, msg.Body); addErr == nil && complete {
				cvNotifyAPDBV2(pending.ready)
			}
		}
	case cvTagAPDBRecoverGetV2:
		if s.holderStore == nil {
			return
		}
		response, err := cvHandleAPDBRecoveryRequestV2(s.cfg.SID, s.cfg.Epoch, msg.From, s.cfg.LocalNode,
			s.cfg.OldRoster, msg.Body, s.cfg.TotalShards, s.cfg.ShardBytes, s.holderStore, s.apdbSigner)
		if err == nil {
			_ = s.send(msg.From, cvTagAPDBRecoverStoreV2, response)
		}
	case cvTagAggregateRecoverGetV2:
		if s.holderStore == nil {
			return
		}
		response, err := cvHandleAggregateRecoveryRequestV2(s.cfg.SID, s.cfg.Epoch, msg.From, s.cfg.LocalNode,
			s.cfg.OldRoster, s.cfg.NewRoster, msg.Body, s.cfg.ExpectedContext, s.cfg.TotalShards,
			s.cfg.ShardBytes, s.holderStore, s.apdbSigner, s.controlSigner)
		if err == nil {
			_ = s.send(msg.From, cvTagAggregateRecoverStoreV2, response)
		}
	case cvTagAPDBRecoverStoreV2, cvTagAggregateRecoverStoreV2:
		store, err := cvDecodeAPDBStoreV2(msg.Body, s.cfg.TotalShards, s.cfg.ShardBytes)
		if err != nil {
			return
		}
		aggregate := msg.Tag == cvTagAggregateRecoverStoreV2
		pending := s.lookupRecovery(string(store.InstanceDigest), aggregate)
		if pending != nil {
			if complete, addErr := pending.collector.AddStore(msg.From, msg.Body); addErr == nil && complete {
				cvNotifyAPDBV2(pending.ready)
			}
		}
	}
}

func (s *cvAPDBNetworkServiceV2) send(to int, tag string, payload []byte) error {
	envelope, err := cvEncodeNetworkEnvelope(s.cfg.SID, int(s.cfg.Epoch), payload)
	if err != nil {
		return err
	}
	wire, err := s.auth.seal(s.cfg.LocalNode, to, tag, envelope)
	if err != nil {
		return err
	}
	return s.transport.Send(Message{From: s.cfg.LocalNode, To: to, Tag: tag, Body: wire})
}

func (s *cvAPDBNetworkServiceV2) registerLock(key string, pending *cvAPDBPendingLockV2) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.pendingLocks[key]; exists {
		return fmt.Errorf("CV V2 LockPD already active for instance")
	}
	s.pendingLocks[key] = pending
	return nil
}

func (s *cvAPDBNetworkServiceV2) unregisterLock(key string, pending *cvAPDBPendingLockV2) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingLocks[key] == pending {
		delete(s.pendingLocks, key)
	}
}

func (s *cvAPDBNetworkServiceV2) lookupLock(key string) *cvAPDBPendingLockV2 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingLocks[key]
}

func (s *cvAPDBNetworkServiceV2) registerRecovery(key string, pending *cvAPDBPendingRecoveryV2, aggregate bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	target := s.pendingComponents
	if aggregate {
		target = s.pendingAggregates
	}
	if _, exists := target[key]; exists {
		return fmt.Errorf("CV V2 APDB recovery already active for instance")
	}
	target[key] = pending
	return nil
}

func (s *cvAPDBNetworkServiceV2) unregisterRecovery(key string, pending *cvAPDBPendingRecoveryV2, aggregate bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	target := s.pendingComponents
	if aggregate {
		target = s.pendingAggregates
	}
	if target[key] == pending {
		delete(target, key)
	}
}

func (s *cvAPDBNetworkServiceV2) lookupRecovery(key string, aggregate bool) *cvAPDBPendingRecoveryV2 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if aggregate {
		return s.pendingAggregates[key]
	}
	return s.pendingComponents[key]
}

func cvNotifyAPDBV2(ready chan struct{}) {
	select {
	case ready <- struct{}{}:
	default:
	}
}
