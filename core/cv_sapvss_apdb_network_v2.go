package core

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
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
	Params          cvV2Params
	EligibilityCoin *cvCoinOutputV2
	LeafContext     *cvLeafContextV2
	Receivers       *cvReceiverKeyMaterialV2
	Validators      *cvValidatorKeyMaterialV2
	DecisionStore   *cvDecisionSignStoreV2
	ScalarStore     *cvScalarStoreV2
}

type cvAPDBPendingLockV2 struct {
	collector *cvAPDBLockCollectorV2
	ready     chan struct{}
}

type cvAPDBPendingRecoveryV2 struct {
	collector *cvAPDBRecoveryCollectorV2
	ready     chan struct{}
}

type cvPendingCoinV2 struct {
	invocation []byte
	shares     map[int][]byte
	ready      chan struct{}
}

type cvNetworkPoolSlotV2 struct {
	state       cvPoolSlotStateV2
	poolWire    []byte
	certWire    []byte
	localShare  []byte
	shares      map[int][]byte
	sharesReady chan struct{}
	certReady   chan struct{}
	certifying  bool
}

type cvPendingValidationV2 struct {
	requestWire []byte
	request     *cvValidationRequestV2
	statement   []byte
	signatures  map[int][]byte
	ready       chan struct{}
}

type cvValidationRecordV2 struct {
	requestWire []byte
	resultWire  []byte
	resultReady chan struct{}
}

type cvCertifiedValidationV2 struct {
	request     *cvValidationRequestV2
	certificate *cvValidationCertificateV2
}

type cvPendingDecisionV2 struct {
	statement []byte
	shares    map[int][]byte
	ready     chan struct{}
}

type cvPendingScalarSharesV2 struct {
	aggregate *cvAggregateV2
	outputs   map[int]*cvScalarShareOutputV2
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
	coinSigner    *tblsThresholdSigner
	inbox         <-chan Message

	mu                    sync.Mutex
	pendingLocks          map[string]*cvAPDBPendingLockV2
	pendingComponents     map[string]*cvAPDBPendingRecoveryV2
	pendingAggregates     map[string]*cvAPDBPendingRecoveryV2
	pendingCoins          map[string]*cvPendingCoinV2
	localCoinShares       map[string][]byte
	coinShareReplies      map[string]map[int]struct{}
	poolSlots             map[int]*cvNetworkPoolSlotV2
	eligibleProposers     map[int]struct{}
	eligibilityValue      []byte
	validatorSample       []int
	pendingValidation     map[string]*cvPendingValidationV2
	validationRecords     map[string]*cvValidationRecordV2
	validationInFlight    map[string]struct{}
	signedValidation      map[int][]byte
	validationLocalShares map[string][]byte
	certifiedValidation   map[int]*cvCertifiedValidationV2
	certifiedReady        map[int]chan struct{}
	pendingDecisions      map[string]*cvPendingDecisionV2
	decisionLocalShares   map[string][]byte
	acceptedHandoff       []byte
	handoffReady          chan struct{}
	localScalarOutputs    map[string][]byte
	pendingScalarShares   map[string]*cvPendingScalarSharesV2
	pendingLaneACKsV2     *cvPendingLaneACKsV2
	componentRefsV2       map[int]cvComponentRefV2
	frozenComponentRefsV2 []cvComponentRefV2
	localComponentRefV2   []byte
	componentRefsReadyV2  chan struct{}
	done                  chan struct{}
}

func newCVAPDBNetworkServiceV2(
	ctx context.Context, cfg cvAPDBNetworkServiceConfigV2, transport agreementTransport, router *cvSAPVSSRouter,
	auth cvNetworkEnvelopeSealer, holderStore *cvAPDBHolderStoreV2,
	apdbSigner, controlSigner, coinSigner *tblsThresholdSigner,
) (*cvAPDBNetworkServiceV2, error) {
	if ctx == nil || cfg.SID == "" || cfg.Epoch == 0 || cfg.Epoch > uint64(^uint(0)>>1) || cfg.LocalNode < 0 ||
		transport == nil || router == nil || auth == nil || len(cfg.ExpectedContext) != 32 ||
		cfg.TotalShards != len(cfg.OldRoster) || cfg.DataShards <= 0 || cfg.DataShards > cfg.TotalShards ||
		cfg.ShardBytes < 0 || cfg.MaximumPayload <= 0 ||
		!equalInts(cfg.OldRoster, sortedUnique(cfg.OldRoster)) ||
		!equalInts(cfg.NewRoster, sortedUnique(cfg.NewRoster)) ||
		!cvV2SignerHasRole(apdbSigner, cvV2RoleAPDB) ||
		!cvV2SignerHasRole(controlSigner, cvV2RoleControl) ||
		!cvV2SignerHasRole(coinSigner, cvV2RoleCoin) ||
		!equalInts(apdbSigner.memberOrder, cfg.OldRoster) ||
		!equalInts(controlSigner.memberOrder, cfg.OldRoster) ||
		!equalInts(coinSigner.memberOrder, cfg.OldRoster) ||
		cfg.Params.apdbLockThreshold != apdbSigner.Threshold() ||
		cfg.Params.decisionThreshold != controlSigner.Threshold() ||
		cfg.Params.componentCount != coinSigner.Threshold() ||
		cfg.Params.recoveryThreshold != cfg.DataShards ||
		cfg.Params.poolSize <= 0 || cfg.Params.poolSize > len(cfg.OldRoster) {
		return nil, fmt.Errorf("invalid CV V2 APDB network service configuration")
	}
	validationParts := 0
	if cfg.LeafContext != nil {
		validationParts++
	}
	if cfg.Receivers != nil {
		validationParts++
	}
	if cfg.Validators != nil {
		validationParts++
	}
	if validationParts != 0 && validationParts != 3 {
		return nil, fmt.Errorf("incomplete CV V2 network validation material")
	}
	if validationParts == 3 {
		contextWire, contextErr := cvLeafContextV2CanonicalBytes(cfg.LeafContext)
		contextDigest, digestErr := cvLeafContextDigestV2(cfg.LeafContext)
		if contextErr != nil || len(contextWire) == 0 || cfg.LeafContext.SID != cfg.SID || cfg.LeafContext.Epoch != cfg.Epoch ||
			digestErr != nil || !bytes.Equal(contextDigest, cfg.ExpectedContext) ||
			cvValidateReceiverMaterialForLeafV2(cfg.LeafContext, cfg.Receivers) != nil ||
			cvValidateValidatorMaterialForLeafV2(cfg.LeafContext, cfg.Validators) != nil {
			return nil, fmt.Errorf("invalid CV V2 network validation material")
		}
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
		holderStore: holderStore, apdbSigner: apdbSigner, controlSigner: controlSigner, coinSigner: coinSigner, inbox: inbox,
		pendingLocks:          make(map[string]*cvAPDBPendingLockV2),
		pendingComponents:     make(map[string]*cvAPDBPendingRecoveryV2),
		pendingAggregates:     make(map[string]*cvAPDBPendingRecoveryV2),
		pendingCoins:          make(map[string]*cvPendingCoinV2),
		localCoinShares:       make(map[string][]byte, 2),
		coinShareReplies:      make(map[string]map[int]struct{}, 2),
		poolSlots:             make(map[int]*cvNetworkPoolSlotV2, cfg.Params.proposerSampleSize),
		eligibleProposers:     make(map[int]struct{}, cfg.Params.proposerSampleSize),
		pendingValidation:     make(map[string]*cvPendingValidationV2),
		validationRecords:     make(map[string]*cvValidationRecordV2),
		validationInFlight:    make(map[string]struct{}),
		signedValidation:      make(map[int][]byte),
		validationLocalShares: make(map[string][]byte),
		certifiedValidation:   make(map[int]*cvCertifiedValidationV2),
		certifiedReady:        make(map[int]chan struct{}),
		pendingDecisions:      make(map[string]*cvPendingDecisionV2),
		decisionLocalShares:   make(map[string][]byte),
		handoffReady:          make(chan struct{}, 1),
		localScalarOutputs:    make(map[string][]byte),
		pendingScalarShares:   make(map[string]*cvPendingScalarSharesV2),
		componentRefsV2:       make(map[int]cvComponentRefV2, cfg.Params.poolSize),
		componentRefsReadyV2:  make(chan struct{}, 1),
		done:                  make(chan struct{}),
	}
	service.cfg.OldRoster = append([]int(nil), cfg.OldRoster...)
	service.cfg.NewRoster = append([]int(nil), cfg.NewRoster...)
	service.cfg.ExpectedContext = append([]byte(nil), cfg.ExpectedContext...)
	if cfg.EligibilityCoin != nil {
		if err := service.setEligibilityCoin(cfg.EligibilityCoin); err != nil {
			cancel()
			return nil, err
		}
	}
	go service.run()
	return service, nil
}

func (s *cvAPDBNetworkServiceV2) EligibilityCoin(ctx context.Context) (*cvCoinOutputV2, error) {
	if s == nil {
		return nil, fmt.Errorf("nil CV V2 network service")
	}
	invocation, err := cvEligibilityCoinInvocationV2(s.cfg.SID, s.cfg.Epoch)
	if err != nil {
		return nil, err
	}
	output, err := s.runCoin(ctx, invocation)
	if err != nil {
		return nil, err
	}
	if err := s.setEligibilityCoin(output); err != nil {
		return nil, err
	}
	return output, nil
}

func (s *cvAPDBNetworkServiceV2) ContributorCoin(
	ctx context.Context, pool *cvPoolV2, certificate *cvPoolCertificateV2,
) (*cvCoinOutputV2, error) {
	if s == nil {
		return nil, fmt.Errorf("nil CV V2 network service")
	}
	if _, err := s.validatePool(pool); err != nil {
		return nil, err
	}
	if err := cvVerifyPoolCertificateV2(pool, certificate, s.controlSigner); err != nil {
		return nil, fmt.Errorf("CV V2 contributor coin requires PoolCert: %w", err)
	}
	invocation, err := cvContributorCoinInvocationV2(pool.ContextDigest, pool.ProposerID, pool.Digest)
	if err != nil {
		return nil, err
	}
	return s.runCoin(ctx, invocation)
}

func (s *cvAPDBNetworkServiceV2) setEligibilityCoin(output *cvCoinOutputV2) error {
	invocation, err := cvEligibilityCoinInvocationV2(s.cfg.SID, s.cfg.Epoch)
	if err != nil || cvVerifyCoinOutputV2(output, invocation, s.coinSigner) != nil {
		return fmt.Errorf("invalid CV V2 network eligibility coin")
	}
	proposers, validators, err := cvDeriveEligibilitySamplesV2(
		s.cfg.OldRoster, output.Value, s.cfg.Params.proposerSampleSize, s.cfg.Params.validatorSampleSize,
	)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.eligibilityValue) != 0 && !bytes.Equal(s.eligibilityValue, output.Value) {
		return fmt.Errorf("conflicting CV V2 network eligibility coin")
	}
	s.eligibilityValue = append([]byte(nil), output.Value...)
	s.eligibleProposers = nodeSet(proposers)
	s.validatorSample = append([]int(nil), validators...)
	return nil
}

func (s *cvAPDBNetworkServiceV2) CertifyPool(ctx context.Context, pool *cvPoolV2) (*cvPoolCertificateV2, error) {
	if s == nil || ctx == nil || pool == nil || pool.ProposerID != s.cfg.LocalNode {
		return nil, fmt.Errorf("invalid CV V2 pool certification caller")
	}
	poolWire, err := s.validatePool(pool)
	if err != nil {
		return nil, err
	}
	statement, err := cvPoolCertificateStatementV2(pool.ContextDigest, pool.ProposerID, pool.Digest)
	if err != nil {
		return nil, err
	}
	localShare, err := s.controlSigner.SignShare(s.cfg.LocalNode, cvPoolCertV2Domain, statement)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	slot := s.poolSlotLocked(pool.ProposerID)
	if err := slot.state.observePool(pool); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if slot.certifying {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV V2 pool certification already active")
	}
	if !slot.state.signed {
		if err := slot.state.markSigned(pool.Digest); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		slot.localShare = append([]byte(nil), localShare...)
		slot.shares[s.cfg.LocalNode] = append([]byte(nil), localShare...)
	} else if len(slot.localShare) == 0 {
		s.mu.Unlock()
		return nil, fmt.Errorf("incomplete CV V2 pool proposer slot")
	}
	slot.poolWire = append([]byte(nil), poolWire...)
	slot.certifying = true
	if len(slot.shares) >= s.controlSigner.Threshold() {
		cvNotifyAPDBV2(slot.sharesReady)
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		slot.certifying = false
		s.mu.Unlock()
	}()

	retry := time.NewTicker(100 * time.Millisecond)
	defer retry.Stop()
	for {
		for _, member := range s.cfg.OldRoster {
			if member != s.cfg.LocalNode {
				_ = s.send(member, cvTagPoolOfferV2, poolWire)
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-slot.sharesReady:
			goto recoverCertificate
		case <-retry.C:
		}
	}

recoverCertificate:
	s.mu.Lock()
	shares := make(map[int][]byte, len(slot.shares))
	for member, share := range slot.shares {
		shares[member] = append([]byte(nil), share...)
	}
	s.mu.Unlock()
	recovered, err := s.controlSigner.Recover(cvPoolCertV2Domain, statement, shares)
	if err != nil {
		return nil, err
	}
	certificate := &cvPoolCertificateV2{PoolDigest: append([]byte(nil), pool.Digest...), Certificate: recovered}
	if err := cvVerifyPoolCertificateV2(pool, certificate, s.controlSigner); err != nil {
		return nil, err
	}
	certWire, err := cvPoolCertificateV2CanonicalBytes(certificate)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if err := slot.state.observeCertificate(certificate); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	slot.certWire = append([]byte(nil), certWire...)
	cvNotifyAPDBV2(slot.certReady)
	s.mu.Unlock()
	for _, member := range s.cfg.OldRoster {
		if member != s.cfg.LocalNode {
			_ = s.send(member, cvTagPoolCertV2, certWire)
		}
	}
	// Late pool waiters may not have been listening when the first broadcast
	// was sent. A bounded resend keeps the academic network path live without
	// retaining arbitrary certificates.
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case <-ticker.C:
				for _, member := range s.cfg.OldRoster {
					if member != s.cfg.LocalNode {
						_ = s.send(member, cvTagPoolOfferV2, poolWire)
						_ = s.send(member, cvTagPoolCertV2, certWire)
					}
				}
			case <-deadline.C:
				return
			case <-s.ctx.Done():
				return
			}
		}
	}()
	return certificate, nil
}

func (s *cvAPDBNetworkServiceV2) AwaitCertifiedPool(ctx context.Context, proposer int) (*cvPoolV2, *cvPoolCertificateV2, error) {
	if s == nil || ctx == nil {
		return nil, nil, fmt.Errorf("invalid CV V2 certified-pool wait")
	}
	s.mu.Lock()
	if _, eligible := s.eligibleProposers[proposer]; !eligible {
		s.mu.Unlock()
		return nil, nil, fmt.Errorf("CV V2 pool proposer is not eligible")
	}
	slot := s.poolSlotLocked(proposer)
	ready := slot.state.certSeen
	certReady := slot.certReady
	s.mu.Unlock()
	if !ready {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, nil, s.ctx.Err()
		case <-certReady:
		}
	}
	s.mu.Lock()
	poolWire := append([]byte(nil), slot.poolWire...)
	certWire := append([]byte(nil), slot.certWire...)
	s.mu.Unlock()
	pool, err := cvDecodePoolV2(poolWire, s.cfg.Params)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := cvDecodePoolCertificateV2(certWire)
	if err != nil || cvVerifyPoolCertificateV2(pool, certificate, s.controlSigner) != nil {
		return nil, nil, fmt.Errorf("invalid CV V2 certified pool state")
	}
	return pool, certificate, nil
}

func (s *cvAPDBNetworkServiceV2) CertifyAggregate(
	ctx context.Context, request *cvValidationRequestV2,
) (*cvValidationCertificateV2, error) {
	if s == nil || ctx == nil || request == nil || request.Header.ProposerID != s.cfg.LocalNode ||
		s.cfg.LeafContext == nil || s.cfg.Receivers == nil || s.cfg.Validators == nil {
		return nil, fmt.Errorf("invalid CV V2 aggregate certification caller")
	}
	s.mu.Lock()
	eligible := make(map[int]struct{}, len(s.eligibleProposers))
	for member := range s.eligibleProposers {
		eligible[member] = struct{}{}
	}
	validatorSample := append([]int(nil), s.validatorSample...)
	s.mu.Unlock()
	if err := cvVerifyValidationRequestPublicV2(request, s.cfg.ExpectedContext, s.cfg.Params, eligible,
		s.apdbSigner, s.controlSigner, s.coinSigner); err != nil {
		return nil, err
	}
	requestWire, err := cvValidationRequestV2CanonicalBytes(request, s.cfg.Params)
	if err != nil {
		return nil, err
	}
	request, err = cvDecodeValidationRequestV2(requestWire, s.cfg.Params)
	if err != nil {
		return nil, err
	}
	statement, err := cvValidationStatementV2(validatorSample, &request.Header)
	if err != nil {
		return nil, err
	}
	key := string(statement)
	pending := &cvPendingValidationV2{requestWire: append([]byte(nil), requestWire...), request: request,
		statement: statement, signatures: make(map[int][]byte), ready: make(chan struct{}, 1)}
	s.mu.Lock()
	if _, exists := s.pendingValidation[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV V2 aggregate certification already active")
	}
	s.pendingValidation[key] = pending
	record := s.validationRecords[key]
	if record == nil {
		record = &cvValidationRecordV2{requestWire: append([]byte(nil), requestWire...), resultReady: make(chan struct{}, 1)}
		s.validationRecords[key] = record
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingValidation[key] == pending {
			delete(s.pendingValidation, key)
		}
		s.mu.Unlock()
	}()

	retry := time.NewTicker(100 * time.Millisecond)
	defer retry.Stop()
	for {
		for _, member := range s.cfg.OldRoster {
			_ = s.send(member, cvTagValidationRequestV2, requestWire)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-pending.ready:
			goto buildCertificate
		case <-retry.C:
		}
	}

buildCertificate:
	s.mu.Lock()
	signatures := make(map[int][]byte, len(pending.signatures))
	for member, signature := range pending.signatures {
		signatures[member] = append([]byte(nil), signature...)
	}
	s.mu.Unlock()
	certificate, err := cvBuildValidationCertificateV2(
		&request.Header, validatorSample, s.cfg.Params.validatorThreshold, signatures, s.cfg.Validators,
	)
	if err != nil {
		return nil, err
	}
	resultWire, err := cvValidationResultV2CanonicalBytes(
		&cvValidationResultV2{Statement: statement, Certificate: *certificate}, validatorSample,
	)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	record.resultWire = append([]byte(nil), resultWire...)
	cvNotifyAPDBV2(record.resultReady)
	s.certifiedValidation[request.Header.ProposerID] = &cvCertifiedValidationV2{request: request, certificate: certificate}
	cvNotifyAPDBV2(s.certifiedReadyLocked(request.Header.ProposerID))
	s.mu.Unlock()
	for _, member := range s.cfg.OldRoster {
		if member != s.cfg.LocalNode {
			_ = s.send(member, cvTagValidationResultV2, resultWire)
		}
	}
	return certificate, nil
}

func (s *cvAPDBNetworkServiceV2) AwaitCertifiedValidationV2(
	ctx context.Context, proposer int,
) (*cvValidationRequestV2, *cvValidationCertificateV2, error) {
	if s == nil || ctx == nil || proposer < 0 {
		return nil, nil, fmt.Errorf("invalid CV V2 certified validation wait")
	}
	s.mu.Lock()
	certified := s.certifiedValidation[proposer]
	ready := s.certifiedReadyLocked(proposer)
	s.mu.Unlock()
	if certified == nil {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, nil, s.ctx.Err()
		case <-ready:
		}
		s.mu.Lock()
		certified = s.certifiedValidation[proposer]
		s.mu.Unlock()
	}
	if certified == nil {
		return nil, nil, fmt.Errorf("missing CV V2 certified validation")
	}
	return certified.request, certified.certificate, nil
}

func (s *cvAPDBNetworkServiceV2) certifiedReadyLocked(proposer int) chan struct{} {
	ready := s.certifiedReady[proposer]
	if ready == nil {
		ready = make(chan struct{}, 1)
		s.certifiedReady[proposer] = ready
	}
	return ready
}

func (s *cvAPDBNetworkServiceV2) AwaitValidationResult(
	ctx context.Context, request *cvValidationRequestV2,
) (*cvValidationCertificateV2, error) {
	if s == nil || ctx == nil || request == nil {
		return nil, fmt.Errorf("invalid CV V2 validation-result wait")
	}
	s.mu.Lock()
	validatorSample := append([]int(nil), s.validatorSample...)
	s.mu.Unlock()
	statement, err := cvValidationStatementV2(validatorSample, &request.Header)
	if err != nil {
		return nil, err
	}
	key := string(statement)
	s.mu.Lock()
	record := s.validationRecords[key]
	if record == nil {
		wire, encodeErr := cvValidationRequestV2CanonicalBytes(request, s.cfg.Params)
		if encodeErr != nil {
			s.mu.Unlock()
			return nil, encodeErr
		}
		record = &cvValidationRecordV2{requestWire: wire, resultReady: make(chan struct{}, 1)}
		s.validationRecords[key] = record
	}
	ready := len(record.resultWire) != 0
	resultReady := record.resultReady
	s.mu.Unlock()
	if !ready {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-resultReady:
		}
	}
	s.mu.Lock()
	resultWire := append([]byte(nil), record.resultWire...)
	s.mu.Unlock()
	result, err := cvDecodeValidationResultV2(resultWire, validatorSample)
	if err != nil || !bytes.Equal(result.Statement, statement) ||
		cvVerifyValidationCertificateV2(&result.Certificate, &request.Header, validatorSample,
			s.cfg.Params.validatorThreshold, s.cfg.Validators) != nil {
		return nil, fmt.Errorf("invalid CV V2 validation result state")
	}
	return &result.Certificate, nil
}

func (s *cvAPDBNetworkServiceV2) FinalizeDecision(
	ctx context.Context, decided *cvAgreementObjectV2,
) (*cvHandoffV2, error) {
	if s == nil || ctx == nil || decided == nil || s.cfg.DecisionStore == nil ||
		!cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) {
		return nil, fmt.Errorf("invalid CV V2 decision finalization input")
	}
	statement, err := cvDecisionStatementV2(s.cfg.ExpectedContext, &decided.Header, &decided.ARC)
	if err != nil {
		return nil, err
	}
	localShare, err := s.cfg.DecisionStore.SignHandoffOnce(
		s.cfg.SID, s.cfg.Epoch, s.cfg.LocalNode, s.cfg.ExpectedContext,
		&decided.Header, &decided.ARC, s.controlSigner,
	)
	if err != nil {
		return nil, err
	}
	shareWire, err := cvDecisionShareV2CanonicalBytes(&cvDecisionShareV2{Statement: statement, Signature: localShare})
	if err != nil {
		return nil, err
	}
	key := string(statement)
	pending := &cvPendingDecisionV2{statement: statement, shares: map[int][]byte{
		s.cfg.LocalNode: append([]byte(nil), localShare...),
	}, ready: make(chan struct{}, 1)}
	s.mu.Lock()
	if _, exists := s.pendingDecisions[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV V2 decision finalization already active")
	}
	s.pendingDecisions[key] = pending
	s.decisionLocalShares[key] = append([]byte(nil), localShare...)
	if len(pending.shares) >= s.controlSigner.Threshold() {
		cvNotifyAPDBV2(pending.ready)
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingDecisions[key] == pending {
			delete(s.pendingDecisions, key)
		}
		s.mu.Unlock()
	}()
	retry := time.NewTicker(100 * time.Millisecond)
	defer retry.Stop()
	for {
		for _, member := range s.cfg.OldRoster {
			if member != s.cfg.LocalNode {
				_ = s.send(member, cvTagDecisionShareV2, shareWire)
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-pending.ready:
			goto recoverDecision
		case <-retry.C:
		}
	}

recoverDecision:
	s.mu.Lock()
	shares := make(map[int][]byte, len(pending.shares))
	for member, share := range pending.shares {
		shares[member] = append([]byte(nil), share...)
	}
	s.mu.Unlock()
	decCert, err := s.controlSigner.Recover(cvDecisionCertificateV2Domain, statement, shares)
	if err != nil {
		return nil, err
	}
	handoff := &cvHandoffV2{
		ContextDigest: append([]byte(nil), s.cfg.ExpectedContext...), Header: decided.Header,
		ARC: decided.ARC, DecCert: decCert,
	}
	if err := cvVerifyHandoffV2(handoff, s.cfg.ExpectedContext, s.apdbSigner, s.controlSigner); err != nil {
		return nil, err
	}
	handoffWire, err := cvHandoffV2CanonicalBytes(handoff)
	if err != nil {
		return nil, err
	}
	for _, receiver := range s.cfg.NewRoster {
		_ = s.send(receiver, cvTagHandoffV2, handoffWire)
	}
	return handoff, nil
}

func (s *cvAPDBNetworkServiceV2) AwaitHandoff(ctx context.Context) (*cvHandoffV2, error) {
	if s == nil || ctx == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 handoff wait")
	}
	s.mu.Lock()
	ready := len(s.acceptedHandoff) != 0
	handoffReady := s.handoffReady
	s.mu.Unlock()
	if !ready {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-handoffReady:
		}
	}
	s.mu.Lock()
	wire := append([]byte(nil), s.acceptedHandoff...)
	s.mu.Unlock()
	handoff, err := cvDecodeHandoffV2(wire)
	if err != nil || cvVerifyHandoffV2(handoff, s.cfg.ExpectedContext, s.apdbSigner, s.controlSigner) != nil {
		return nil, fmt.Errorf("invalid CV V2 accepted handoff")
	}
	return handoff, nil
}

func (s *cvAPDBNetworkServiceV2) RecoverAndExchangeScalarShare(
	ctx context.Context, handoff *cvHandoffV2,
) (*cvAggregateV2, fr.Element, *cvScalarShareOutputV2, bls12381.G1Affine, error) {
	if s == nil || ctx == nil || handoff == nil || s.cfg.LeafContext == nil || s.cfg.Receivers == nil ||
		s.cfg.ScalarStore == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.NewRoster) {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf("invalid CV V2 receiver recovery input")
	}
	requestWire, err := cvAggregateRecoveryRequestV2CanonicalBytes(
		&cvAggregateRecoveryRequestV2{Handoff: *handoff},
	)
	if err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, err
	}
	payload, err := s.RecoverAggregate(ctx, requestWire, func(recovered []byte) error {
		digest, digestErr := cvAggregatePayloadDigestV2(recovered)
		if digestErr != nil || !bytes.Equal(digest, handoff.Header.PayloadDigest) {
			return fmt.Errorf("CV V2 recovered aggregate payload mismatch")
		}
		return nil
	})
	if err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, err
	}
	aggregate, err := cvDecodeAggregateV2(payload, s.cfg.LeafContext, s.cfg.Params)
	if err != nil || cvVerifyAggregateHeaderPayloadV2(&handoff.Header, payload, aggregate) != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf("invalid CV V2 recovered aggregate")
	}
	receiverIndex, ok := s.cfg.Receivers.receiverIndex[s.cfg.LocalNode]
	secret, hasSecret := s.cfg.Receivers.localEncryptionSecrets[s.cfg.LocalNode]
	if !ok || !hasSecret {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf("missing local CV V2 receiver secret")
	}
	scalar, output, err := cvDecryptAggregateShareV2(
		aggregate, s.cfg.LeafContext, s.cfg.Params, s.cfg.LocalNode, receiverIndex,
		&s.cfg.Receivers.encryptionPublicKeys[receiverIndex-1], secret,
	)
	if err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, err
	}
	if err := s.cfg.ScalarStore.PersistOnce(
		s.cfg.SID, s.cfg.Epoch, s.cfg.LocalNode, aggregate.Digest, scalar, output,
	); err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf("persist CV V2 scalar before release: %w", err)
	}
	outputWire, err := cvScalarShareOutputV2CanonicalBytes(output)
	if err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, err
	}
	key := string(aggregate.Digest)
	pending := &cvPendingScalarSharesV2{aggregate: aggregate, outputs: map[int]*cvScalarShareOutputV2{
		s.cfg.LocalNode: output,
	}, ready: make(chan struct{}, 1)}
	s.mu.Lock()
	if _, exists := s.pendingScalarShares[key]; exists {
		s.mu.Unlock()
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf("CV V2 scalar exchange already active")
	}
	s.localScalarOutputs[key] = append([]byte(nil), outputWire...)
	s.pendingScalarShares[key] = pending
	if len(pending.outputs) >= s.cfg.Params.newShareThreshold {
		cvNotifyAPDBV2(pending.ready)
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingScalarShares[key] == pending {
			delete(s.pendingScalarShares, key)
		}
		s.mu.Unlock()
	}()
	retry := time.NewTicker(100 * time.Millisecond)
	defer retry.Stop()
	for {
		for _, receiver := range s.cfg.NewRoster {
			if receiver != s.cfg.LocalNode {
				_ = s.send(receiver, cvTagAggregateShareV2, outputWire)
			}
		}
		select {
		case <-ctx.Done():
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, ctx.Err()
		case <-s.ctx.Done():
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, s.ctx.Err()
		case <-pending.ready:
			goto recoverPublicKey
		case <-retry.C:
		}
	}

recoverPublicKey:
	s.mu.Lock()
	outputs := make([]*cvScalarShareOutputV2, 0, len(pending.outputs))
	for _, share := range pending.outputs {
		outputs = append(outputs, share)
	}
	s.mu.Unlock()
	publicKey, err := cvRecoverThresholdPublicKeyV2(
		outputs, aggregate, s.cfg.LeafContext, s.cfg.Params, s.cfg.Receivers,
	)
	if err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, err
	}
	return aggregate, scalar, output, publicKey, nil
}

func (s *cvAPDBNetworkServiceV2) validatePool(pool *cvPoolV2) ([]byte, error) {
	if pool == nil || !bytes.Equal(pool.ContextDigest, s.cfg.ExpectedContext) {
		return nil, fmt.Errorf("CV V2 pool context mismatch")
	}
	s.mu.Lock()
	_, eligible := s.eligibleProposers[pool.ProposerID]
	s.mu.Unlock()
	if !eligible {
		return nil, fmt.Errorf("CV V2 pool proposer is not eligible")
	}
	wire, err := cvPoolV2CanonicalBytes(pool, s.cfg.Params)
	if err != nil {
		return nil, err
	}
	for _, component := range pool.Components {
		if err := cvValidateComponentRefV2(component, s.apdbSigner); err != nil {
			return nil, fmt.Errorf("invalid CV V2 pool component: %w", err)
		}
	}
	return wire, nil
}

func (s *cvAPDBNetworkServiceV2) poolSlotLocked(proposer int) *cvNetworkPoolSlotV2 {
	slot := s.poolSlots[proposer]
	if slot == nil {
		slot = &cvNetworkPoolSlotV2{
			shares: make(map[int][]byte), sharesReady: make(chan struct{}, 1), certReady: make(chan struct{}, 1),
		}
		s.poolSlots[proposer] = slot
	}
	return slot
}

// Coin runs either V2 threshold-coin invocation among the old committee.
// The invocation itself is domain separated by cvEligibilityCoinInvocationV2
// or cvContributorCoinInvocationV2 before reaching this method.
func (s *cvAPDBNetworkServiceV2) runCoin(ctx context.Context, invocation []byte) (*cvCoinOutputV2, error) {
	if s == nil || ctx == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) ||
		!cvV2SignerHasRole(s.coinSigner, cvV2RoleCoin) {
		return nil, fmt.Errorf("invalid CV V2 network coin input")
	}
	digest, err := cvCoinInvocationDigestV2(invocation)
	if err != nil {
		return nil, err
	}
	localSignature, err := s.coinSigner.SignShare(s.cfg.LocalNode, cvV2CoinDomain, digest)
	if err != nil {
		return nil, err
	}
	message, err := cvCoinShareV2CanonicalBytes(&cvCoinShareV2{InvocationDigest: digest, Signature: localSignature})
	if err != nil {
		return nil, err
	}
	pending := &cvPendingCoinV2{invocation: append([]byte(nil), invocation...), shares: make(map[int][]byte), ready: make(chan struct{}, 1)}
	key := string(digest)
	s.mu.Lock()
	if _, exists := s.pendingCoins[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV V2 coin invocation already active")
	}
	pending.shares[s.cfg.LocalNode] = append([]byte(nil), localSignature...)
	s.pendingCoins[key] = pending
	s.localCoinShares[key] = append([]byte(nil), message...)
	if s.coinShareReplies[key] == nil {
		s.coinShareReplies[key] = make(map[int]struct{}, len(s.cfg.OldRoster)-1)
	}
	if len(pending.shares) >= s.coinSigner.Threshold() {
		cvNotifyAPDBV2(pending.ready)
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingCoins[key] == pending {
			delete(s.pendingCoins, key)
		}
		s.mu.Unlock()
	}()

	sendShare := func() {
		for _, member := range s.cfg.OldRoster {
			if member != s.cfg.LocalNode {
				_ = s.send(member, cvTagCoinShareV2, message)
			}
		}
	}
	sendShare()
	retry := time.NewTicker(100 * time.Millisecond)
	defer retry.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case <-pending.ready:
	case <-retry.C:
		for {
			sendShare()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-s.ctx.Done():
				return nil, s.ctx.Err()
			case <-pending.ready:
				goto recovered
			case <-retry.C:
			}
		}
	}

recovered:
	s.mu.Lock()
	shares := make(map[int][]byte, len(pending.shares))
	for member, share := range pending.shares {
		shares[member] = append([]byte(nil), share...)
	}
	s.mu.Unlock()
	certificate, err := s.coinSigner.Recover(cvV2CoinDomain, digest, shares)
	if err != nil {
		return nil, err
	}
	return cvBuildCoinOutputV2(invocation, certificate, s.coinSigner)
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
		s.cfg.ShardBytes <= 0 ||
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
	case cvTagCoinShareV2:
		share, err := cvDecodeCoinShareV2(msg.Body)
		if err != nil || !cvV2SignerHasRole(s.coinSigner, cvV2RoleCoin) ||
			!s.coinSigner.VerifyShare(msg.From, cvV2CoinDomain, share.InvocationDigest, share.Signature) {
			return
		}
		key := string(share.InvocationDigest)
		var reply []byte
		s.mu.Lock()
		pending := s.pendingCoins[key]
		if pending != nil {
			if _, duplicate := pending.shares[msg.From]; !duplicate {
				pending.shares[msg.From] = append([]byte(nil), share.Signature...)
			}
			if len(pending.shares) >= s.coinSigner.Threshold() {
				cvNotifyAPDBV2(pending.ready)
			}
		}
		if local := s.localCoinShares[key]; len(local) != 0 {
			replied := s.coinShareReplies[key]
			if _, duplicate := replied[msg.From]; !duplicate {
				replied[msg.From] = struct{}{}
				reply = append([]byte(nil), local...)
			}
		}
		s.mu.Unlock()
		if len(reply) != 0 {
			_ = s.send(msg.From, cvTagCoinShareV2, reply)
		}
	case cvTagPoolOfferV2:
		s.handlePoolOffer(msg)
	case cvTagPoolCertShareV2:
		s.handlePoolCertificateShare(msg)
	case cvTagPoolCertV2:
		s.handlePoolCertificate(msg)
	case cvTagValidationRequestV2:
		s.handleValidationRequest(msg)
	case cvTagValidationSignatureV2:
		s.handleValidationSignature(msg)
	case cvTagValidationResultV2:
		s.handleValidationResult(msg)
	case cvTagDecisionShareV2:
		s.handleDecisionShare(msg)
	case cvTagHandoffV2:
		s.handleHandoff(msg)
	case cvTagAggregateShareV2:
		s.handleAggregateShare(msg)
	case cvTagLaneOfferV2:
		s.handleLaneOfferV2(msg)
	case cvTagLaneACKV2:
		s.handleLaneACKV2(msg)
	case cvTagComponentRefV2:
		s.handleComponentRefV2(msg)
	}
}

func (s *cvAPDBNetworkServiceV2) handleLaneOfferV2(msg Message) {
	if s.cfg.Receivers == nil || s.cfg.LeafContext == nil {
		return
	}
	receiverIndex, ok := s.cfg.Receivers.receiverIndex[msg.To]
	secret, secretOK := s.cfg.Receivers.localEncryptionSecrets[msg.To]
	identitySecret, identityOK := s.cfg.Receivers.localIdentitySecrets[msg.To]
	if !ok || !secretOK || !identityOK {
		return
	}
	offer, err := cvDecodeReceiverLaneOfferV2(msg.Body, s.cfg.LeafContext, msg.From, msg.To,
		receiverIndex, &s.cfg.Receivers.encryptionPublicKeys[receiverIndex-1])
	if err != nil {
		return
	}
	evidence, _, _, err := cvVerifyDecryptAndSignACKV2(
		s.cfg.LeafContext, msg.From, offer, &s.cfg.Receivers.encryptionPublicKeys[receiverIndex-1],
		secret, s.cfg.Receivers.identityPublicKeys[receiverIndex-1], identitySecret,
	)
	if err != nil {
		return
	}
	message := &cvLaneACKMessageV2{DealerID: msg.From, ReceiverID: msg.To, ReceiverIndex: receiverIndex,
		OfferDigest: cvLaneOfferDigestV2(msg.Body), Evidence: *evidence}
	wire, err := cvLaneACKMessageV2CanonicalBytes(message, s.cfg.LeafContext)
	if err == nil {
		_ = s.send(msg.From, cvTagLaneACKV2, wire)
	}
}

func (s *cvAPDBNetworkServiceV2) handleLaneACKV2(msg Message) {
	s.mu.Lock()
	pending := s.pendingLaneACKsV2
	s.mu.Unlock()
	if pending == nil {
		return
	}
	message, err := cvDecodeLaneACKMessageV2(msg.Body, s.cfg.LeafContext)
	if err != nil || message.DealerID != s.cfg.LocalNode || message.ReceiverID != msg.From ||
		message.ReceiverIndex <= 0 || message.ReceiverIndex > len(s.cfg.NewRoster) ||
		s.cfg.NewRoster[message.ReceiverIndex-1] != msg.From {
		return
	}
	if !bytes.Equal(message.OfferDigest, cvLaneOfferDigestV2(func() []byte {
		wire, _ := cvReceiverLaneOfferV2CanonicalBytes(s.cfg.LeafContext, s.cfg.LocalNode,
			pending.offers[message.ReceiverIndex-1], &s.cfg.Receivers.encryptionPublicKeys[message.ReceiverIndex-1])
		return wire
	}())) {
		return
	}
	if err := cvVerifyACKV2(s.cfg.LeafContext, s.cfg.LocalNode, pending.offers[message.ReceiverIndex-1],
		&s.cfg.Receivers.encryptionPublicKeys[message.ReceiverIndex-1],
		s.cfg.Receivers.identityPublicKeys[message.ReceiverIndex-1], &message.Evidence); err != nil {
		return
	}
	s.mu.Lock()
	if _, duplicate := pending.acks[message.ReceiverIndex]; !duplicate {
		pending.acks[message.ReceiverIndex] = &message.Evidence
	}
	if len(pending.acks) == len(s.cfg.NewRoster) {
		cvNotifyAPDBV2(pending.ready)
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) handlePoolOffer(msg Message) {
	pool, err := cvDecodePoolV2(msg.Body, s.cfg.Params)
	if err != nil || pool.ProposerID != msg.From {
		return
	}
	poolWire, err := s.validatePool(pool)
	if err != nil {
		return
	}
	statement, err := cvPoolCertificateStatementV2(pool.ContextDigest, pool.ProposerID, pool.Digest)
	if err != nil {
		return
	}
	localShare, err := s.controlSigner.SignShare(s.cfg.LocalNode, cvPoolCertV2Domain, statement)
	if err != nil {
		return
	}
	s.mu.Lock()
	slot := s.poolSlotLocked(pool.ProposerID)
	if slot.state.observePool(pool) != nil {
		s.mu.Unlock()
		return
	}
	if len(slot.certWire) != 0 {
		if certificate, decodeErr := cvDecodePoolCertificateV2(slot.certWire); decodeErr == nil &&
			cvVerifyPoolCertificateV2(pool, certificate, s.controlSigner) == nil {
			_ = slot.state.observeCertificate(certificate)
			cvNotifyAPDBV2(slot.certReady)
		}
	}
	if !slot.state.signed {
		if slot.state.markSigned(pool.Digest) != nil {
			s.mu.Unlock()
			return
		}
		slot.poolWire = append([]byte(nil), poolWire...)
		slot.localShare = append([]byte(nil), localShare...)
	} else if len(slot.localShare) == 0 || !bytes.Equal(slot.state.poolDigest, pool.Digest) {
		s.mu.Unlock()
		return
	}
	shareWire, err := cvPoolCertificateShareV2CanonicalBytes(&cvPoolCertificateShareV2{
		ProposerID: pool.ProposerID, PoolDigest: pool.Digest, Signature: slot.localShare,
	})
	s.mu.Unlock()
	if err == nil {
		_ = s.send(pool.ProposerID, cvTagPoolCertShareV2, shareWire)
	}
}

func (s *cvAPDBNetworkServiceV2) handlePoolCertificateShare(msg Message) {
	share, err := cvDecodePoolCertificateShareV2(msg.Body)
	if err != nil || share.ProposerID != s.cfg.LocalNode {
		return
	}
	s.mu.Lock()
	slot := s.poolSlots[share.ProposerID]
	if slot == nil || !slot.state.poolSeen || !bytes.Equal(slot.state.poolDigest, share.PoolDigest) {
		s.mu.Unlock()
		return
	}
	statement, err := cvPoolCertificateStatementV2(s.cfg.ExpectedContext, share.ProposerID, share.PoolDigest)
	if err != nil || !s.controlSigner.VerifyShare(msg.From, cvPoolCertV2Domain, statement, share.Signature) {
		s.mu.Unlock()
		return
	}
	if _, duplicate := slot.shares[msg.From]; !duplicate {
		slot.shares[msg.From] = append([]byte(nil), share.Signature...)
	}
	if len(slot.shares) >= s.controlSigner.Threshold() {
		cvNotifyAPDBV2(slot.sharesReady)
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) handlePoolCertificate(msg Message) {
	certificate, err := cvDecodePoolCertificateV2(msg.Body)
	if err != nil {
		return
	}
	s.mu.Lock()
	slot := s.poolSlots[msg.From]
	if slot == nil {
		slot = s.poolSlotLocked(msg.From)
	}
	if !slot.state.poolSeen {
		slot.certWire = append([]byte(nil), msg.Body...)
		s.mu.Unlock()
		return
	}
	if !bytes.Equal(slot.state.poolDigest, certificate.PoolDigest) {
		s.mu.Unlock()
		return
	}
	poolWire := append([]byte(nil), slot.poolWire...)
	s.mu.Unlock()
	pool, err := cvDecodePoolV2(poolWire, s.cfg.Params)
	if err != nil || pool.ProposerID != msg.From || cvVerifyPoolCertificateV2(pool, certificate, s.controlSigner) != nil {
		return
	}
	s.mu.Lock()
	if slot.state.observeCertificate(certificate) == nil {
		slot.certWire = append([]byte(nil), msg.Body...)
		cvNotifyAPDBV2(slot.certReady)
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) handleValidationRequest(msg Message) {
	if s.cfg.LeafContext == nil || s.cfg.Receivers == nil || s.cfg.Validators == nil {
		return
	}
	request, err := cvDecodeValidationRequestV2(msg.Body, s.cfg.Params)
	if err != nil || request.Header.ProposerID != msg.From {
		return
	}
	s.mu.Lock()
	eligible := make(map[int]struct{}, len(s.eligibleProposers))
	for member := range s.eligibleProposers {
		eligible[member] = struct{}{}
	}
	validatorSample := append([]int(nil), s.validatorSample...)
	s.mu.Unlock()
	if err := cvVerifyValidationRequestPublicV2(request, s.cfg.ExpectedContext, s.cfg.Params, eligible,
		s.apdbSigner, s.controlSigner, s.coinSigner); err != nil {
		return
	}
	statement, err := cvValidationStatementV2(validatorSample, &request.Header)
	if err != nil {
		return
	}
	key := string(statement)
	s.mu.Lock()
	record := s.validationRecords[key]
	if record == nil {
		record = &cvValidationRecordV2{requestWire: append([]byte(nil), msg.Body...), resultReady: make(chan struct{}, 1)}
		s.validationRecords[key] = record
	} else if !bytes.Equal(record.requestWire, msg.Body) {
		s.mu.Unlock()
		return
	}
	localShare := append([]byte(nil), s.validationLocalShares[key]...)
	_, inFlight := s.validationInFlight[key]
	isValidator := cvContainsID(validatorSample, s.cfg.LocalNode)
	if isValidator && len(localShare) == 0 && !inFlight {
		s.validationInFlight[key] = struct{}{}
	}
	s.mu.Unlock()
	if len(localShare) != 0 {
		shareWire, encodeErr := cvValidationSignatureV2CanonicalBytes(
			&cvValidationSignatureV2{Statement: statement, Signature: localShare},
		)
		if encodeErr == nil {
			_ = s.send(request.Header.ProposerID, cvTagValidationSignatureV2, shareWire)
		}
		return
	}
	if isValidator && !inFlight {
		go s.validateAndSignAggregate(request, statement, key)
	}
}

func (s *cvAPDBNetworkServiceV2) validateAndSignAggregate(
	request *cvValidationRequestV2, statement []byte, key string,
) {
	defer func() {
		s.mu.Lock()
		delete(s.validationInFlight, key)
		s.mu.Unlock()
	}()
	leaves := make([]*cvLeafV2, len(request.SelectedIndices))
	for i, poolIndex := range request.SelectedIndices {
		component := request.Pool.Components[poolIndex]
		payload, err := s.RecoverComponent(s.ctx, &component.Lock, func(recovered []byte) error {
			if !bytes.Equal(cvComponentPayloadDigestV2(recovered), component.Header.PayloadDigest) {
				return fmt.Errorf("CV V2 validation component payload mismatch")
			}
			return nil
		})
		if err != nil {
			return
		}
		leaves[i], err = cvDecodeLeafV2(payload, s.cfg.LeafContext, s.cfg.Receivers, s.cfg.Validators)
		if err != nil {
			return
		}
	}
	aggregatePayload, err := s.RecoverComponent(s.ctx, &request.ARC, func(recovered []byte) error {
		digest, digestErr := cvAggregatePayloadDigestV2(recovered)
		if digestErr != nil || !bytes.Equal(digest, request.Header.PayloadDigest) {
			return fmt.Errorf("CV V2 validation aggregate payload mismatch")
		}
		return nil
	})
	if err != nil {
		return
	}
	aggregate, err := cvAVerV2(aggregatePayload, leaves, s.cfg.LeafContext, s.cfg.Params, s.cfg.Receivers, s.cfg.Validators)
	if err != nil || cvVerifyAggregateHeaderPayloadV2(&request.Header, aggregatePayload, aggregate) != nil {
		return
	}
	s.mu.Lock()
	validatorSample := append([]int(nil), s.validatorSample...)
	s.mu.Unlock()
	signature, err := cvSignValidationV2(s.cfg.LocalNode, &request.Header, validatorSample, s.cfg.Validators)
	if err != nil {
		return
	}
	s.mu.Lock()
	if previous := s.signedValidation[request.Header.ProposerID]; len(previous) != 0 && !bytes.Equal(previous, statement) {
		s.mu.Unlock()
		return
	}
	s.signedValidation[request.Header.ProposerID] = append([]byte(nil), statement...)
	s.validationLocalShares[key] = append([]byte(nil), signature...)
	s.mu.Unlock()
	shareWire, err := cvValidationSignatureV2CanonicalBytes(
		&cvValidationSignatureV2{Statement: statement, Signature: signature},
	)
	if err == nil {
		_ = s.send(request.Header.ProposerID, cvTagValidationSignatureV2, shareWire)
	}
}

func (s *cvAPDBNetworkServiceV2) handleValidationSignature(msg Message) {
	value, err := cvDecodeValidationSignatureV2(msg.Body)
	if err != nil || s.cfg.Validators == nil {
		return
	}
	key := string(value.Statement)
	s.mu.Lock()
	pending := s.pendingValidation[key]
	validatorSample := append([]int(nil), s.validatorSample...)
	if pending == nil || !cvContainsID(validatorSample, msg.From) {
		s.mu.Unlock()
		return
	}
	index, ok := s.cfg.Validators.memberIndex[msg.From]
	if !ok || !cvVerifyValidatorSignatureV2(&s.cfg.Validators.publicKeys[index],
		cvValidationCertificateV2Domain, value.Statement, value.Signature) {
		s.mu.Unlock()
		return
	}
	if _, duplicate := pending.signatures[msg.From]; !duplicate {
		pending.signatures[msg.From] = append([]byte(nil), value.Signature...)
	}
	if len(pending.signatures) >= s.cfg.Params.validatorThreshold {
		cvNotifyAPDBV2(pending.ready)
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) handleValidationResult(msg Message) {
	if s.cfg.Validators == nil {
		return
	}
	s.mu.Lock()
	validatorSample := append([]int(nil), s.validatorSample...)
	s.mu.Unlock()
	result, err := cvDecodeValidationResultV2(msg.Body, validatorSample)
	if err != nil {
		return
	}
	key := string(result.Statement)
	s.mu.Lock()
	record := s.validationRecords[key]
	if record == nil || len(record.requestWire) == 0 {
		s.mu.Unlock()
		return
	}
	requestWire := append([]byte(nil), record.requestWire...)
	s.mu.Unlock()
	request, err := cvDecodeValidationRequestV2(requestWire, s.cfg.Params)
	if err != nil || request.Header.ProposerID != msg.From ||
		cvVerifyValidationCertificateV2(&result.Certificate, &request.Header, validatorSample,
			s.cfg.Params.validatorThreshold, s.cfg.Validators) != nil {
		return
	}
	wantStatement, err := cvValidationStatementV2(validatorSample, &request.Header)
	if err != nil || !bytes.Equal(wantStatement, result.Statement) {
		return
	}
	s.mu.Lock()
	record.resultWire = append([]byte(nil), msg.Body...)
	cvNotifyAPDBV2(record.resultReady)
	s.certifiedValidation[request.Header.ProposerID] = &cvCertifiedValidationV2{request: request, certificate: &result.Certificate}
	cvNotifyAPDBV2(s.certifiedReadyLocked(request.Header.ProposerID))
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) handleDecisionShare(msg Message) {
	share, err := cvDecodeDecisionShareV2(msg.Body)
	if err != nil || !s.controlSigner.VerifyShare(
		msg.From, cvDecisionCertificateV2Domain, share.Statement, share.Signature,
	) {
		return
	}
	key := string(share.Statement)
	s.mu.Lock()
	pending := s.pendingDecisions[key]
	localShare := append([]byte(nil), s.decisionLocalShares[key]...)
	if pending != nil {
		if _, duplicate := pending.shares[msg.From]; !duplicate {
			pending.shares[msg.From] = append([]byte(nil), share.Signature...)
		}
		if len(pending.shares) >= s.controlSigner.Threshold() {
			cvNotifyAPDBV2(pending.ready)
		}
	}
	s.mu.Unlock()
	if len(localShare) != 0 {
		wire, encodeErr := cvDecisionShareV2CanonicalBytes(
			&cvDecisionShareV2{Statement: share.Statement, Signature: localShare},
		)
		if encodeErr == nil {
			_ = s.send(msg.From, cvTagDecisionShareV2, wire)
		}
	}
}

func (s *cvAPDBNetworkServiceV2) handleHandoff(msg Message) {
	if !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.NewRoster) {
		return
	}
	handoff, err := cvDecodeHandoffV2(msg.Body)
	if err != nil || cvVerifyHandoffV2(handoff, s.cfg.ExpectedContext, s.apdbSigner, s.controlSigner) != nil {
		return
	}
	s.mu.Lock()
	if len(s.acceptedHandoff) == 0 {
		s.acceptedHandoff = append([]byte(nil), msg.Body...)
		cvNotifyAPDBV2(s.handoffReady)
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) handleAggregateShare(msg Message) {
	if s.cfg.LeafContext == nil || s.cfg.Receivers == nil {
		return
	}
	// The aggregate digest is the fixed first field after the domain. Decode it
	// only after locating a currently active aggregate, so unknown digests are
	// never retained.
	r := newCVWireReader(msg.Body)
	domain, err := r.bytes(len(cvAggregateShareWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateShareWireDomainV2)) {
		return
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return
	}
	key := string(digest)
	s.mu.Lock()
	pending := s.pendingScalarShares[key]
	localWire := append([]byte(nil), s.localScalarOutputs[key]...)
	s.mu.Unlock()
	if pending == nil {
		return
	}
	output, err := cvDecodeScalarShareOutputV2(
		msg.Body, pending.aggregate, s.cfg.LeafContext, s.cfg.Params, s.cfg.Receivers,
	)
	if err != nil || output.ReceiverID != msg.From {
		return
	}
	s.mu.Lock()
	if _, duplicate := pending.outputs[msg.From]; !duplicate {
		pending.outputs[msg.From] = output
	}
	if len(pending.outputs) >= s.cfg.Params.newShareThreshold {
		cvNotifyAPDBV2(pending.ready)
	}
	s.mu.Unlock()
	if len(localWire) != 0 {
		_ = s.send(msg.From, cvTagAggregateShareV2, localWire)
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
