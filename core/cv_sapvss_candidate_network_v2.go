package core

import (
	"context"
	"fmt"
	"time"
)

const cvCertifiedCandidateDigestV2Domain = "ARL-CV-sAPVSS/v2-scalar-group/certified-candidate-digest"

func (s *cvAPDBNetworkServiceV2) agreementPublicContextV2() (cvAgreementPublicContextV2, error) {
	if s == nil {
		return cvAgreementPublicContextV2{}, fmt.Errorf("nil CV V2 candidate service")
	}
	s.mu.Lock()
	coin := s.eligibilityCoin
	s.mu.Unlock()
	if coin == nil {
		return cvAgreementPublicContextV2{}, fmt.Errorf("CV V2 eligibility coin is not available")
	}
	coinWire, err := cvCoinOutputV2CanonicalBytes(coin)
	if err != nil {
		return cvAgreementPublicContextV2{}, err
	}
	coin, err = cvDecodeCoinOutputV2(coinWire)
	if err != nil {
		return cvAgreementPublicContextV2{}, err
	}
	public := cvAgreementPublicContextV2{
		SID: s.cfg.SID, Epoch: s.cfg.Epoch, ContextDigest: append([]byte(nil), s.cfg.ExpectedContext...),
		OldCommittee: append([]int(nil), s.cfg.OldRoster...), EligibilityCoin: coin, Params: s.cfg.Params,
		APDBSigner: s.apdbSigner, ControlSigner: s.controlSigner, CoinSigner: s.coinSigner,
		ValidatorKeys: s.cfg.Validators,
	}
	if _, _, err := cvAgreementEligibilitySamplesV2(public); err != nil {
		return cvAgreementPublicContextV2{}, err
	}
	return public, nil
}

func (s *cvAPDBNetworkServiceV2) acceptCertifiedCandidateV2(wire []byte) (*cvAgreementObjectV2, bool, error) {
	public, err := s.agreementPublicContextV2()
	if err != nil {
		return nil, false, err
	}
	_, validators, err := cvAgreementEligibilitySamplesV2(public)
	if err != nil {
		return nil, false, err
	}
	object, err := cvDecodeAgreementObjectV2(wire, s.cfg.Params, validators)
	if err != nil || cvVerifyAgreementObjectV2(object, public) != nil {
		return nil, false, fmt.Errorf("invalid CV V2 certified candidate")
	}
	canonical, err := cvAgreementObjectV2CanonicalBytes(object, s.cfg.Params, validators)
	if err != nil {
		return nil, false, err
	}
	digest := string(hashBytes([]byte(cvCertifiedCandidateDigestV2Domain), canonical))
	s.mu.Lock()
	if _, duplicate := s.certifiedCandidatesV2[digest]; duplicate {
		s.mu.Unlock()
		return object, false, nil
	}
	s.certifiedCandidatesV2[digest] = append([]byte(nil), canonical...)
	s.mu.Unlock()
	select {
	case s.certifiedCandidateChV2 <- object:
	case <-s.ctx.Done():
		return nil, false, s.ctx.Err()
	}
	return object, true, nil
}

func (s *cvAPDBNetworkServiceV2) PublishCertifiedCandidateV2(
	ctx context.Context, candidate *cvAgreementObjectV2,
) error {
	if s == nil || ctx == nil || candidate == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) {
		return fmt.Errorf("invalid CV V2 certified candidate publisher")
	}
	public, err := s.agreementPublicContextV2()
	if err != nil {
		return err
	}
	_, validators, err := cvAgreementEligibilitySamplesV2(public)
	if err != nil {
		return err
	}
	wire, err := cvAgreementObjectV2CanonicalBytes(candidate, s.cfg.Params, validators)
	if err != nil || cvVerifyAgreementObjectV2(candidate, public) != nil {
		return fmt.Errorf("invalid local CV V2 certified candidate")
	}
	if _, _, err := s.acceptCertifiedCandidateV2(wire); err != nil {
		return err
	}
	sendCandidate := func() {
		for _, member := range s.cfg.OldRoster {
			if member != s.cfg.LocalNode {
				_ = s.send(member, cvTagCertifiedCandidateV2, wire)
			}
		}
	}
	sendCandidate()
	retry := time.NewTicker(100 * time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-retry.C:
			sendCandidate()
		}
	}
}

func (s *cvAPDBNetworkServiceV2) AwaitFirstCertifiedCandidateV2(
	ctx context.Context,
) (*cvAgreementObjectV2, error) {
	if s == nil || ctx == nil {
		return nil, fmt.Errorf("invalid CV V2 certified candidate wait")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case candidate := <-s.certifiedCandidateChV2:
		return candidate, nil
	}
}

func (s *cvAPDBNetworkServiceV2) CertifiedCandidateCountV2() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.certifiedCandidatesV2)
}

func (s *cvAPDBNetworkServiceV2) handleCertifiedCandidateV2(msg Message) {
	_, accepted, err := s.acceptCertifiedCandidateV2(msg.Body)
	if err != nil || !accepted {
		return
	}
	for _, member := range s.cfg.OldRoster {
		if member != s.cfg.LocalNode && member != msg.From {
			_ = s.send(member, cvTagCertifiedCandidateV2, msg.Body)
		}
	}
}
