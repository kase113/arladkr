package core

import (
	"bytes"
	"context"
	"fmt"
	"sort"
)

func (s *cvAPDBNetworkServiceV2) PublishComponentV2(ctx context.Context, leaf *cvLeafV2) (*cvComponentRefV2, error) {
	if s == nil || ctx == nil || leaf == nil || s.cfg.LeafContext == nil ||
		!cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) || leaf.DealerID != s.cfg.LocalNode {
		return nil, fmt.Errorf("invalid CV V2 component publication input")
	}
	payload, err := cvLeafV2CanonicalBytes(leaf, s.cfg.Receivers, s.cfg.Validators)
	if err != nil {
		return nil, err
	}
	instance, err := cvComponentInstanceDigestV2(s.cfg.ExpectedContext, s.cfg.LocalNode)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	shardBytes := s.cfg.ShardBytes
	s.mu.Unlock()
	encoded, err := cvAPDBEncodeSizedV2(
		instance, payload, s.cfg.DataShards, s.cfg.TotalShards, shardBytes, s.cfg.MaximumPayload,
	)
	if err != nil {
		return nil, err
	}
	lock, err := s.Lock(ctx, encoded)
	if err != nil {
		return nil, err
	}
	header := cvComponentHeaderV2{
		ContextDigest: append([]byte(nil), s.cfg.ExpectedContext...), DealerID: s.cfg.LocalNode,
		PayloadDigest: cvComponentPayloadDigestV2(payload), Instance: append([]byte(nil), instance...), Root: append([]byte(nil), lock.Root...),
	}
	ref := &cvComponentRefV2{Header: header, Lock: *lock}
	if err := cvValidateComponentRefV2(*ref, s.apdbSigner); err != nil {
		return nil, err
	}
	wire, err := cvComponentRefV2CanonicalBytes(*ref)
	if err != nil {
		return nil, err
	}
	s.storeComponentRefV2(*ref)
	s.mu.Lock()
	s.localComponentRefV2 = append([]byte(nil), wire...)
	s.mu.Unlock()
	for _, member := range s.cfg.OldRoster {
		if member != s.cfg.LocalNode {
			_ = s.send(member, cvTagComponentRefV2, wire)
		}
	}
	return ref, nil
}

func (s *cvAPDBNetworkServiceV2) AwaitComponentRefsV2(ctx context.Context) ([]cvComponentRefV2, error) {
	if s == nil || ctx == nil {
		return nil, fmt.Errorf("invalid CV V2 component reference wait")
	}
	s.mu.Lock()
	if len(s.frozenComponentRefsV2) == s.cfg.Params.poolSize {
		s.mu.Unlock()
		return s.frozenComponentRefs(), nil
	}
	ready := s.componentRefsReadyV2
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case <-ready:
	}
	return s.frozenComponentRefs(), nil
}

func (s *cvAPDBNetworkServiceV2) storeComponentRefV2(ref cvComponentRefV2) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.componentRefsV2[ref.Header.DealerID]; exists {
		return
	}
	s.componentRefsV2[ref.Header.DealerID] = ref
	if len(s.frozenComponentRefsV2) == 0 && len(s.componentRefsV2) >= s.cfg.Params.poolSize {
		refs := make([]cvComponentRefV2, 0, len(s.componentRefsV2))
		for _, candidate := range s.componentRefsV2 {
			refs = append(refs, candidate)
		}
		sort.Slice(refs, func(i, j int) bool { return refs[i].Header.DealerID < refs[j].Header.DealerID })
		s.frozenComponentRefsV2 = append([]cvComponentRefV2(nil), refs[:s.cfg.Params.poolSize]...)
		cvNotifyAPDBV2(s.componentRefsReadyV2)
	}
}

func (s *cvAPDBNetworkServiceV2) frozenComponentRefs() []cvComponentRefV2 {
	s.mu.Lock()
	refs := append([]cvComponentRefV2(nil), s.frozenComponentRefsV2...)
	s.mu.Unlock()
	return refs
}

func (s *cvAPDBNetworkServiceV2) handleComponentRefV2(msg Message) {
	ref, err := cvDecodeComponentRefV2(msg.Body)
	if err != nil || ref.Header.DealerID != msg.From || !bytes.Equal(ref.Header.ContextDigest, s.cfg.ExpectedContext) {
		return
	}
	if err := cvValidateComponentRefV2(ref, s.apdbSigner); err != nil {
		return
	}
	s.storeComponentRefV2(ref)
	s.mu.Lock()
	localWire := append([]byte(nil), s.localComponentRefV2...)
	s.mu.Unlock()
	if len(localWire) != 0 && msg.From != s.cfg.LocalNode {
		_ = s.send(msg.From, cvTagComponentRefV2, localWire)
	}
}
