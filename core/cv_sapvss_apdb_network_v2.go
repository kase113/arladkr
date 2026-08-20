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
	aggregate bool
}

type cvAPDBPendingRecoveryV2 struct {
	collector *cvAPDBRecoveryCollectorV2
	ready     chan struct{}
	purpose   cvRecoveryPurposeV2
}

type cvRecoveryPurposeV2 uint8

const (
	cvRecoveryUnclassifiedV2 cvRecoveryPurposeV2 = iota
	cvRecoveryProposerCatalogV2
	cvRecoveryValidatorComponentV2
	cvRecoveryValidatorAggregateV2
	cvRecoveryNewAggregateV2
)

const (
	cvControlRetryIntervalV2    = 250 * time.Millisecond
	cvControlRetryMaxAttemptsV2 = 4
	cvFanoutMaxParallelV2       = 16
)

type cvFanoutSendResultV2 struct {
	recipient int
	wireBytes int
	err       error
}

type cvOutboundMessageV2 struct {
	to       int
	tag      string
	payload  []byte
	onResult func(error)
}

type cvCryptoJobKindV2 uint8

const (
	cvCryptoJobLaneOfferV2 cvCryptoJobKindV2 = iota + 1
	cvCryptoJobCertifiedCandidateV2
)

type cvCryptoJobV2 struct {
	kind cvCryptoJobKindV2
	msg  Message
}

type cvServiceExperimentMetricsV2 struct {
	proposerRecoverySentBytes           uint64
	proposerRecoveryRecvBytes           uint64
	proposerRecoveryLatency             time.Duration
	proposerCatalogScanCount            int
	proposerRejectedCount               int
	validatorComponentRecoverySentBytes uint64
	validatorComponentRecoveryRecvBytes uint64
	validatorComponentRecoveryLatency   time.Duration
	validatorAggregateRecoverySentBytes uint64
	validatorAggregateRecoveryRecvBytes uint64
	validatorAggregateRecoveryLatency   time.Duration
	newAggregateRecoverySentBytes       uint64
	newAggregateRecoveryRecvBytes       uint64
	newAggregateRecoveryLatency         time.Duration
	arcFormationLatency                 time.Duration
	validationCertificateLatency        time.Duration
	decisionCertificateLatency          time.Duration
	scalarBoundedDLogLatency            time.Duration
	blindingGroupDecryptionLatency      time.Duration
	componentDispersalSentBytes         uint64
	componentDispersalRecvBytes         uint64
	aggregateDispersalSentBytes         uint64
	aggregateDispersalRecvBytes         uint64
	coinFanoutLatency                   time.Duration
	aggregateOfferSendLatency           time.Duration
	candidateFanoutACKWaitLatency       time.Duration
	candidateFanoutRetryWaitLatency     time.Duration
	candidateFanoutMaxPeerLatency       time.Duration
	candidateFanoutAttempts             int
	candidateFanoutRetries              int
	tagSentBytes                        map[string]uint64
	tagRecvBytes                        map[string]uint64
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
	statement   []byte
	shares      map[int][]byte
	certificate []byte
	ready       chan struct{}
}

type cvPendingScalarSharesV2 struct {
	aggregate *cvAggregateV2
	outputs   map[int]*cvScalarShareOutputV2
	ready     chan struct{}
}

type cvVerifiedComponentV2 struct {
	ref        cvComponentRefV2
	leafDigest []byte
	payload    []byte
	leaf       *cvLeafV2
}

type cvVerifiedComponentCallV2 struct {
	ref  cvComponentRefV2
	leaf *cvLeafV2
	err  error
	done chan struct{}
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

	mu                     sync.Mutex
	experimentMu           sync.Mutex
	verifiedCatalogMu      sync.Mutex
	pendingLocks           map[string]*cvAPDBPendingLockV2
	pendingComponents      map[string]*cvAPDBPendingRecoveryV2
	pendingAggregates      map[string]*cvAPDBPendingRecoveryV2
	pendingCoins           map[string]*cvPendingCoinV2
	localCoinShares        map[string][]byte
	coinShareReplies       map[string]map[int]struct{}
	coinShareReplyInFlight map[string]map[int]struct{}
	poolSlots              map[int]*cvNetworkPoolSlotV2
	eligibleProposers      map[int]struct{}
	eligibilityValue       []byte
	eligibilityCoin        *cvCoinOutputV2
	validatorSample        []int
	pendingValidation      map[string]*cvPendingValidationV2
	validationRecords      map[string]*cvValidationRecordV2
	validationInFlight     map[string]struct{}
	validationOneShot      map[int][]byte
	validationLocalShares  map[string][]byte
	certifiedValidation    map[int]*cvCertifiedValidationV2
	certifiedReady         map[int]chan struct{}
	pendingDecisions       map[string]*cvPendingDecisionV2
	decisionLocalShares    map[string][]byte
	decisionCertificates   map[string][]byte
	acceptedHandoff        []byte
	handoffReady           chan struct{}
	localScalarOutputs     map[string][]byte
	pendingScalarShares    map[string]*cvPendingScalarSharesV2
	pendingLaneACKsV2      *cvPendingLaneACKsV2
	componentRefsV2        map[int]cvComponentRefV2
	verifiedComponentsV2   map[int]cvVerifiedComponentV2
	verifiedComponentCalls map[int]*cvVerifiedComponentCallV2
	rejectedComponentsV2   map[int]struct{}
	verifiedCatalogV2      []cvComponentRefV2
	localComponentRefV2    []byte
	componentRefUpdatesV2  chan struct{}
	certifiedCandidatesV2  map[string][]byte
	candidateFanoutV2      map[string]*cvCandidateFanoutStateV2
	certifiedCandidateChV2 chan *cvAgreementObjectV2
	outbound               chan cvOutboundMessageV2
	outboundWG             sync.WaitGroup
	cryptoQueue            chan cvCryptoJobV2
	cryptoWG               sync.WaitGroup
	processingLaneOffersV2 map[[2]int]struct{}
	processingCandidatesV2 map[string]struct{}
	experimentMetrics      cvServiceExperimentMetricsV2
	done                   chan struct{}
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
		pendingLocks:           make(map[string]*cvAPDBPendingLockV2),
		pendingComponents:      make(map[string]*cvAPDBPendingRecoveryV2),
		pendingAggregates:      make(map[string]*cvAPDBPendingRecoveryV2),
		pendingCoins:           make(map[string]*cvPendingCoinV2),
		localCoinShares:        make(map[string][]byte, 2),
		coinShareReplies:       make(map[string]map[int]struct{}, 2),
		coinShareReplyInFlight: make(map[string]map[int]struct{}, 2),
		poolSlots:              make(map[int]*cvNetworkPoolSlotV2, cfg.Params.proposerSampleSize),
		eligibleProposers:      make(map[int]struct{}, cfg.Params.proposerSampleSize),
		pendingValidation:      make(map[string]*cvPendingValidationV2),
		validationRecords:      make(map[string]*cvValidationRecordV2),
		validationInFlight:     make(map[string]struct{}),
		validationOneShot:      make(map[int][]byte),
		validationLocalShares:  make(map[string][]byte),
		certifiedValidation:    make(map[int]*cvCertifiedValidationV2),
		certifiedReady:         make(map[int]chan struct{}),
		pendingDecisions:       make(map[string]*cvPendingDecisionV2),
		decisionLocalShares:    make(map[string][]byte),
		decisionCertificates:   make(map[string][]byte),
		handoffReady:           make(chan struct{}, 1),
		localScalarOutputs:     make(map[string][]byte),
		pendingScalarShares:    make(map[string]*cvPendingScalarSharesV2),
		componentRefsV2:        make(map[int]cvComponentRefV2, cfg.Params.poolSize),
		verifiedComponentsV2:   make(map[int]cvVerifiedComponentV2, cfg.Params.poolSize),
		verifiedComponentCalls: make(map[int]*cvVerifiedComponentCallV2),
		rejectedComponentsV2:   make(map[int]struct{}),
		componentRefUpdatesV2:  make(chan struct{}, 1),
		certifiedCandidatesV2:  make(map[string][]byte, cfg.Params.proposerSampleSize),
		candidateFanoutV2:      make(map[string]*cvCandidateFanoutStateV2),
		certifiedCandidateChV2: make(chan *cvAgreementObjectV2, cfg.Params.proposerSampleSize),
		outbound:               make(chan cvOutboundMessageV2, cvOutboundQueueCapacityV2(len(cfg.OldRoster)+len(cfg.NewRoster))),
		cryptoQueue:            make(chan cvCryptoJobV2, cvCryptoQueueCapacityV2(len(cfg.OldRoster)+len(cfg.NewRoster))),
		processingLaneOffersV2: make(map[[2]int]struct{}, len(cfg.OldRoster)),
		processingCandidatesV2: make(map[string]struct{}, cfg.Params.proposerSampleSize),
		experimentMetrics: cvServiceExperimentMetricsV2{
			tagSentBytes: make(map[string]uint64), tagRecvBytes: make(map[string]uint64),
		},
		done: make(chan struct{}),
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
	workers := len(cfg.OldRoster) + len(cfg.NewRoster)
	if workers < 1 {
		workers = 1
	}
	if workers > 8 {
		workers = 8
	}
	service.outboundWG.Add(workers)
	for range workers {
		go service.runOutbound()
	}
	cryptoWorkers := cvCryptoWorkers(cap(service.cryptoQueue))
	service.cryptoWG.Add(cryptoWorkers)
	for range cryptoWorkers {
		go service.runCryptoWorkerV2()
	}
	go service.run()
	return service, nil
}

func cvOutboundQueueCapacityV2(committeeSize int) int {
	capacity := committeeSize * 32
	if capacity < 128 {
		return 128
	}
	if capacity > 4096 {
		return 4096
	}
	return capacity
}

func cvCryptoQueueCapacityV2(committeeSize int) int {
	capacity := committeeSize * 2
	if capacity < 64 {
		return 64
	}
	if capacity > 2048 {
		return 2048
	}
	return capacity
}

func (s *cvAPDBNetworkServiceV2) runCryptoWorkerV2() {
	defer s.cryptoWG.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.cryptoQueue:
			s.runCryptoJobV2(job)
		}
	}
}

func (s *cvAPDBNetworkServiceV2) runCryptoJobV2(job cvCryptoJobV2) {
	switch job.kind {
	case cvCryptoJobLaneOfferV2:
		key := [2]int{job.msg.From, job.msg.To}
		defer func() {
			s.mu.Lock()
			delete(s.processingLaneOffersV2, key)
			s.mu.Unlock()
		}()
		s.handleLaneOfferV2(job.msg)
	case cvCryptoJobCertifiedCandidateV2:
		digest := cvCertifiedCandidateDigestV2(job.msg.Body)
		defer func() {
			s.mu.Lock()
			delete(s.processingCandidatesV2, digest)
			s.mu.Unlock()
		}()
		s.processCertifiedCandidateV2(job.msg)
	}
}

func (s *cvAPDBNetworkServiceV2) enqueueLaneOfferV2(msg Message) {
	key := [2]int{msg.From, msg.To}
	s.mu.Lock()
	if _, duplicate := s.processingLaneOffersV2[key]; duplicate {
		s.mu.Unlock()
		return
	}
	s.processingLaneOffersV2[key] = struct{}{}
	s.mu.Unlock()
	select {
	case s.cryptoQueue <- cvCryptoJobV2{kind: cvCryptoJobLaneOfferV2, msg: msg}:
	case <-s.ctx.Done():
		s.mu.Lock()
		delete(s.processingLaneOffersV2, key)
		s.mu.Unlock()
	}
}

func (s *cvAPDBNetworkServiceV2) runOutbound() {
	defer s.outboundWG.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case message := <-s.outbound:
			err := s.send(message.to, message.tag, message.payload)
			if message.onResult != nil {
				message.onResult(err)
			}
		}
	}
}

// sendAsync keeps the protocol dispatch loop free of transport ACK waits.
// The bounded queue supplies backpressure without dropping protocol replies.
func (s *cvAPDBNetworkServiceV2) sendAsync(to int, tag string, payload []byte, onResult func(error)) error {
	if s == nil || s.ctx == nil || tag == "" || len(payload) == 0 {
		return fmt.Errorf("invalid asynchronous CV V2 send")
	}
	message := cvOutboundMessageV2{to: to, tag: tag, payload: append([]byte(nil), payload...), onResult: onResult}
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case s.outbound <- message:
		return nil
	}
}

func cvControlRetryDelayV2(attempt int) time.Duration {
	delay := cvControlRetryIntervalV2
	for i := 0; i < attempt && delay < 2*time.Second; i++ {
		delay *= 2
	}
	if delay > 2*time.Second {
		return 2 * time.Second
	}
	return delay
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
	coinWire, err := cvCoinOutputV2CanonicalBytes(output)
	if err != nil {
		return err
	}
	coin, err := cvDecodeCoinOutputV2(coinWire)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.eligibilityValue) != 0 && !bytes.Equal(s.eligibilityValue, output.Value) {
		return fmt.Errorf("conflicting CV V2 network eligibility coin")
	}
	s.eligibilityValue = append([]byte(nil), output.Value...)
	s.eligibilityCoin = coin
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
		localShare, signErr := s.controlSigner.SignShare(s.cfg.LocalNode, cvPoolCertV2Domain, statement)
		if signErr != nil {
			s.mu.Unlock()
			return nil, signErr
		}
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

	// The transport already acknowledges delivery into the peer inbox. Send
	// once, then retry only peers that have not contributed a share. This keeps
	// a WAN RTT from turning a whole-fleet ticker into a resend storm.
	_ = s.sendFanoutMeasuredV2(s.cfg.OldRoster, s.cfg.LocalNode, cvTagPoolOfferV2, poolWire)
	for attempt := 0; attempt < cvControlRetryMaxAttemptsV2; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-slot.sharesReady:
			goto recoverCertificate
		case <-time.After(cvControlRetryDelayV2(attempt)):
		}
		s.mu.Lock()
		missing := make([]int, 0, len(s.cfg.OldRoster))
		for _, member := range s.cfg.OldRoster {
			if member != s.cfg.LocalNode {
				if _, ok := slot.shares[member]; !ok {
					missing = append(missing, member)
				}
			}
		}
		s.mu.Unlock()
		if len(missing) == 0 {
			continue
		}
		_ = s.sendFanoutMeasuredV2(missing, -1, cvTagPoolOfferV2, poolWire)
	}
	select {
	case <-slot.sharesReady:
		goto recoverCertificate
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
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
	_ = s.sendFanoutMeasuredV2(s.cfg.OldRoster, s.cfg.LocalNode, cvTagPoolCertV2, certWire)
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
	if err := s.validateKnownComponentRefsV2(request.Pool.Components); err != nil {
		return nil, err
	}
	if err := cvVerifyValidationRequestPublicAfterComponentValidationV2(request, s.cfg.ExpectedContext, s.cfg.Params, eligible,
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

	_ = s.sendFanoutMeasuredV2(s.cfg.OldRoster, -1, cvTagValidationRequestV2, requestWire)
	for attempt := 0; attempt < cvControlRetryMaxAttemptsV2; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-pending.ready:
			goto buildCertificate
		case <-time.After(cvControlRetryDelayV2(attempt)):
		}
		s.mu.Lock()
		missing := make([]int, 0, len(validatorSample))
		for _, member := range validatorSample {
			if _, ok := pending.signatures[member]; !ok {
				missing = append(missing, member)
			}
		}
		s.mu.Unlock()
		if len(missing) > 0 {
			_ = s.sendFanoutMeasuredV2(missing, -1, cvTagValidationRequestV2, requestWire)
		}
	}
	select {
	case <-pending.ready:
		goto buildCertificate
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}

buildCertificate:
	s.mu.Lock()
	signatures := make(map[int][]byte, len(pending.signatures))
	for member, signature := range pending.signatures {
		signatures[member] = append([]byte(nil), signature...)
	}
	s.mu.Unlock()
	formationStarted := time.Now()
	certificate, err := cvBuildValidationCertificateV2(
		&request.Header, validatorSample, s.cfg.Params.validatorThreshold, signatures, s.cfg.Validators,
	)
	s.recordCertificateFormationV2(cvCertificateValidationV2, time.Since(formationStarted))
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
	if certificate := s.decisionCertificates[key]; len(certificate) != 0 {
		pending.certificate = append([]byte(nil), certificate...)
	}
	if len(pending.certificate) != 0 || len(pending.shares) >= s.controlSigner.Threshold() {
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
	for attempt := 0; ; attempt++ {
		s.mu.Lock()
		missing := make([]int, 0, len(s.cfg.OldRoster))
		for _, member := range s.cfg.OldRoster {
			if member == s.cfg.LocalNode {
				continue
			}
			if _, received := pending.shares[member]; !received {
				missing = append(missing, member)
			}
		}
		shareCount := len(pending.shares)
		hasCertificate := len(pending.certificate) != 0
		s.mu.Unlock()
		if hasCertificate || shareCount >= s.controlSigner.Threshold() {
			break
		}
		if len(missing) != 0 {
			s.sendFanoutMeasuredV2(missing, -1, cvTagDecisionShareV2, shareWire)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-pending.ready:
			break
		default:
		}
		s.mu.Lock()
		shareCount = len(pending.shares)
		hasCertificate = len(pending.certificate) != 0
		s.mu.Unlock()
		if hasCertificate || shareCount >= s.controlSigner.Threshold() {
			break
		}
		if attempt >= cvControlRetryMaxAttemptsV2 {
			return nil, fmt.Errorf(
				"CV V2 decision finalization reached %d shares, need %d",
				shareCount, s.controlSigner.Threshold(),
			)
		}
		timer := time.NewTimer(cvControlRetryDelayV2(attempt))
		select {
		case <-ctx.Done():
			_ = timer.Stop()
			return nil, ctx.Err()
		case <-s.ctx.Done():
			_ = timer.Stop()
			return nil, s.ctx.Err()
		case <-pending.ready:
			_ = timer.Stop()
			break
		case <-timer.C:
		}
	}

	s.mu.Lock()
	decCert := append([]byte(nil), pending.certificate...)
	shares := make(map[int][]byte, len(pending.shares))
	for member, share := range pending.shares {
		shares[member] = append([]byte(nil), share...)
	}
	s.mu.Unlock()
	formationStarted := time.Now()
	if len(decCert) == 0 {
		decCert, err = s.controlSigner.Recover(cvDecisionCertificateV2Domain, statement, shares)
	}
	if err == nil && !s.controlSigner.VerifyRecovered(cvDecisionCertificateV2Domain, statement, decCert) {
		err = fmt.Errorf("invalid recovered CV V2 decision certificate")
	}
	s.recordCertificateFormationV2(cvCertificateDecisionV2, time.Since(formationStarted))
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
	recipients := sortedUnique(append(append([]int(nil), s.cfg.OldRoster...), s.cfg.NewRoster...))
	s.sendFanoutMeasuredV2(recipients, s.cfg.LocalNode, cvTagHandoffV2, handoffWire)
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
	scalar, output, decryptTimings, err := cvDecryptAggregateShareMeasuredV2(
		aggregate, s.cfg.LeafContext, s.cfg.Params, s.cfg.LocalNode, receiverIndex,
		&s.cfg.Receivers.encryptionPublicKeys[receiverIndex-1], secret,
	)
	if err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, err
	}
	s.experimentMu.Lock()
	s.experimentMetrics.scalarBoundedDLogLatency += decryptTimings.ScalarBoundedDLog
	s.experimentMetrics.blindingGroupDecryptionLatency += decryptTimings.BlindingGroupDecryption
	s.experimentMu.Unlock()
	if err := s.cfg.ScalarStore.PersistOnce(
		s.cfg.SID, s.cfg.Epoch, s.cfg.LocalNode, aggregate.Digest, scalar, output,
	); err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf("persist CV V2 scalar before release: %w", err)
	}
	outputWire, err := cvScalarShareOutputV2CanonicalBytesAfterValidation(output)
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
	for attempt := 0; ; attempt++ {
		s.mu.Lock()
		missing := make([]int, 0, len(s.cfg.NewRoster))
		for _, member := range s.cfg.NewRoster {
			if member == s.cfg.LocalNode {
				continue
			}
			if _, received := pending.outputs[member]; !received {
				missing = append(missing, member)
			}
		}
		outputCount := len(pending.outputs)
		s.mu.Unlock()
		if outputCount >= s.cfg.Params.newShareThreshold {
			break
		}
		if len(missing) != 0 {
			s.sendFanoutMeasuredV2(missing, -1, cvTagAggregateShareV2, outputWire)
		}
		select {
		case <-ctx.Done():
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, ctx.Err()
		case <-s.ctx.Done():
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, s.ctx.Err()
		case <-pending.ready:
			break
		default:
		}
		s.mu.Lock()
		outputCount = len(pending.outputs)
		s.mu.Unlock()
		if outputCount >= s.cfg.Params.newShareThreshold {
			break
		}
		if attempt >= cvControlRetryMaxAttemptsV2 {
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf(
				"CV V2 scalar-share exchange reached %d outputs, need %d",
				outputCount, s.cfg.Params.newShareThreshold,
			)
		}
		timer := time.NewTimer(cvControlRetryDelayV2(attempt))
		select {
		case <-ctx.Done():
			_ = timer.Stop()
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, ctx.Err()
		case <-s.ctx.Done():
			_ = timer.Stop()
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, s.ctx.Err()
		case <-pending.ready:
			_ = timer.Stop()
			break
		case <-timer.C:
		}
	}

	s.mu.Lock()
	outputs := make([]*cvScalarShareOutputV2, 0, len(pending.outputs))
	for _, share := range pending.outputs {
		outputs = append(outputs, share)
	}
	s.mu.Unlock()
	publicKey, err := cvRecoverThresholdPublicKeyAfterValidationV2(
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
	if err := s.validateKnownComponentRefsV2(pool.Components); err != nil {
		return nil, fmt.Errorf("invalid CV V2 pool component: %w", err)
	}
	return wire, nil
}

func (s *cvAPDBNetworkServiceV2) validateKnownComponentRefsV2(refs []cvComponentRefV2) error {
	for _, ref := range refs {
		s.mu.Lock()
		known, ok := s.componentRefsV2[ref.Header.DealerID]
		s.mu.Unlock()
		if ok && equalComponentRefsV2(known, ref) {
			continue
		}
		if ok {
			return fmt.Errorf("CV V2 component reference conflicts with verified cache")
		}
		if err := cvValidateComponentRefV2(ref, s.apdbSigner); err != nil {
			return err
		}
	}
	return nil
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
	if s.coinShareReplyInFlight[key] == nil {
		s.coinShareReplyInFlight[key] = make(map[int]struct{}, len(s.cfg.OldRoster)-1)
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

	sendShare := func(recipients []int) {
		started := time.Now()
		_ = s.sendFanoutMeasuredV2(recipients, s.cfg.LocalNode, cvTagCoinShareV2, message)
		s.recordCoinFanoutLatencyV2(time.Since(started))
	}
	sendShare(s.cfg.OldRoster)
	for attempt := 0; attempt < cvControlRetryMaxAttemptsV2; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-pending.ready:
			goto recovered
		case <-time.After(cvControlRetryDelayV2(attempt)):
		}
		s.mu.Lock()
		missing := make([]int, 0, len(s.cfg.OldRoster))
		for _, member := range s.cfg.OldRoster {
			if _, ok := pending.shares[member]; !ok {
				missing = append(missing, member)
			}
		}
		s.mu.Unlock()
		if len(missing) > 0 {
			sendShare(missing)
		}
	}
	select {
	case <-pending.ready:
		goto recovered
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
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
	s.outboundWG.Wait()
	s.cryptoWG.Wait()
	return nil
}

func (s *cvAPDBNetworkServiceV2) Lock(ctx context.Context, encoded *cvAPDBEncodedV2) (*cvAPDBLockV2, error) {
	return s.lockForPurposeV2(ctx, encoded, false)
}

func (s *cvAPDBNetworkServiceV2) LockAggregate(ctx context.Context, encoded *cvAPDBEncodedV2) (*cvAPDBLockV2, error) {
	return s.lockForPurposeV2(ctx, encoded, true)
}

func (s *cvAPDBNetworkServiceV2) lockForPurposeV2(
	ctx context.Context, encoded *cvAPDBEncodedV2, aggregate bool,
) (*cvAPDBLockV2, error) {
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
	pending := &cvAPDBPendingLockV2{collector: collector, ready: make(chan struct{}, 1), aggregate: aggregate}
	if err := s.registerLock(key, pending); err != nil {
		return nil, err
	}
	defer s.unregisterLock(key, pending)

	holders := collector.StoreRecipients()
	offers := make(map[int][]byte, len(holders))
	for _, holder := range holders {
		offer, offerErr := collector.StoreOffer(holder)
		if offerErr == nil {
			offers[holder] = offer
		}
	}
	started := time.Now()
	// Store offers are recipient-specific. Send them with the same bounded
	// fan-out used by other control paths instead of serializing WAN RTTs.
	if len(offers) != len(holders) {
		return nil, fmt.Errorf("CV V2 LockPD could not construct every store offer")
	}
	results := s.sendRecipientPayloadFanoutMeasuredV2(holders, cvTagAPDBStoreV2, offers)
	if aggregate {
		s.recordAggregateOfferSendLatencyV2(time.Since(started))
	}
	sent := 0
	for _, result := range results {
		if result.err == nil {
			sent++
			s.recordDispersalBytesV2(aggregate, true, result.wireBytes)
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
		formationStarted := time.Now()
		lock, recoverErr := collector.RecoverLock()
		if aggregate {
			s.recordCertificateFormationV2(cvCertificateARCV2, time.Since(formationStarted))
		}
		return lock, recoverErr
	}
}

func (s *cvAPDBNetworkServiceV2) RecoverComponent(
	ctx context.Context, lock *cvAPDBLockV2, bindingCheck func([]byte) error,
) ([]byte, error) {
	return s.recoverComponentForPurpose(ctx, lock, bindingCheck, cvRecoveryUnclassifiedV2)
}

func (s *cvAPDBNetworkServiceV2) recoverComponentForPurpose(
	ctx context.Context, lock *cvAPDBLockV2, bindingCheck func([]byte) error, purpose cvRecoveryPurposeV2,
) ([]byte, error) {
	if s == nil || ctx == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) {
		return nil, fmt.Errorf("invalid CV V2 component recovery caller")
	}
	started := time.Now()
	if purpose != cvRecoveryUnclassifiedV2 {
		defer func() { s.recordRecoveryLatencyV2(purpose, time.Since(started)) }()
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
	return s.runRecovery(ctx, cvTagAPDBRecoverGetV2, request, string(lock.InstanceDigest), collector, false, purpose)
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
	started := time.Now()
	defer func() { s.recordRecoveryLatencyV2(cvRecoveryNewAggregateV2, time.Since(started)) }()
	return s.runRecovery(ctx, cvTagAggregateRecoverGetV2, requestWire,
		string(collector.lock.InstanceDigest), collector, true, cvRecoveryNewAggregateV2)
}

func (s *cvAPDBNetworkServiceV2) runRecovery(
	ctx context.Context, requestTag string, request []byte, key string,
	collector *cvAPDBRecoveryCollectorV2, aggregate bool, purpose cvRecoveryPurposeV2,
) ([]byte, error) {
	pending := &cvAPDBPendingRecoveryV2{collector: collector, ready: make(chan struct{}, 1), purpose: purpose}
	if err := s.registerRecovery(key, pending, aggregate); err != nil {
		return nil, err
	}
	defer s.unregisterRecovery(key, pending, aggregate)
	ready, err := cvSendRecoveryRequestsWithRetryV2(
		ctx, s.ctx, pending.ready, collector.RequestRecipients(), collector.dataShards,
		cvControlRetryMaxAttemptsV2, cvControlRetryDelayV2,
		func(recipients []int) []cvFanoutSendResultV2 {
			return s.sendFanoutMeasuredV2(recipients, -1, requestTag, request)
		},
		func(result cvFanoutSendResultV2) {
			s.recordRecoveryBytesV2(purpose, true, result.wireBytes)
		},
	)
	if err != nil {
		return nil, err
	}
	if ready {
		return collector.Recover()
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

func cvSendRecoveryRequestsWithRetryV2(
	ctx, serviceCtx context.Context, ready <-chan struct{}, recipients []int, dataShards, maxRetries int,
	retryDelay func(int) time.Duration, send func([]int) []cvFanoutSendResultV2,
	onSuccess func(cvFanoutSendResultV2),
) (bool, error) {
	succeeded := make(map[int]struct{}, len(recipients))
	missing := append([]int(nil), recipients...)
	for attempt := 0; ; attempt++ {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-serviceCtx.Done():
			return false, serviceCtx.Err()
		case <-ready:
			return true, nil
		default:
		}
		results := send(missing)
		byRecipient := make(map[int]cvFanoutSendResultV2, len(results))
		for _, result := range results {
			byRecipient[result.recipient] = result
		}
		nextMissing := make([]int, 0, len(missing))
		for _, recipient := range missing {
			result, attempted := byRecipient[recipient]
			if !attempted || result.err != nil {
				nextMissing = append(nextMissing, recipient)
				continue
			}
			if _, duplicate := succeeded[recipient]; !duplicate {
				succeeded[recipient] = struct{}{}
				if onSuccess != nil {
					onSuccess(result)
				}
			}
		}
		if len(succeeded) >= dataShards {
			return false, nil
		}
		select {
		case <-ready:
			return true, nil
		default:
		}
		if attempt >= maxRetries {
			return false, fmt.Errorf("CV V2 APDB recovery reached %d holders, need %d", len(succeeded), dataShards)
		}
		missing = nextMissing
		timer := time.NewTimer(retryDelay(attempt))
		select {
		case <-ctx.Done():
			_ = timer.Stop()
			return false, ctx.Err()
		case <-serviceCtx.Done():
			_ = timer.Stop()
			return false, serviceCtx.Err()
		case <-ready:
			_ = timer.Stop()
			return true, nil
		case <-timer.C:
		}
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
	s.recordTagBytesV2(msg.Tag, false, msg.WireBytes)
	switch msg.Tag {
	case cvTagAPDBStoreV2:
		if s.holderStore == nil {
			return
		}
		response, err := cvHandleAPDBStoreOfferV2(s.cfg.SID, s.cfg.Epoch, msg.From, s.cfg.LocalNode,
			s.cfg.OldRoster, msg.Body, s.cfg.TotalShards, s.cfg.ShardBytes, s.holderStore, s.apdbSigner)
		if err == nil {
			_ = s.sendAsync(msg.From, cvTagAPDBStoredShareV2, response, nil)
		}
	case cvTagAPDBStoredShareV2:
		response, err := cvDecodeAPDBStoredShareV2(msg.Body)
		if err != nil {
			return
		}
		pending := s.lookupLock(string(response.InstanceDigest))
		if pending != nil {
			s.recordDispersalBytesV2(pending.aggregate, false, msg.WireBytes)
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
			_ = s.sendAsync(msg.From, cvTagAPDBRecoverStoreV2, response, nil)
		}
	case cvTagAggregateRecoverGetV2:
		if s.holderStore == nil {
			return
		}
		response, err := cvHandleAggregateRecoveryRequestV2(s.cfg.SID, s.cfg.Epoch, msg.From, s.cfg.LocalNode,
			s.cfg.OldRoster, s.cfg.NewRoster, msg.Body, s.cfg.ExpectedContext, s.cfg.TotalShards,
			s.cfg.ShardBytes, s.holderStore, s.apdbSigner, s.controlSigner)
		if err == nil {
			_ = s.sendAsync(msg.From, cvTagAggregateRecoverStoreV2, response, nil)
		}
	case cvTagAPDBRecoverStoreV2, cvTagAggregateRecoverStoreV2:
		store, err := cvDecodeAPDBStoreV2(msg.Body, s.cfg.TotalShards, s.cfg.ShardBytes)
		if err != nil {
			return
		}
		aggregate := msg.Tag == cvTagAggregateRecoverStoreV2
		pending := s.lookupRecovery(string(store.InstanceDigest), aggregate)
		if pending != nil {
			s.recordRecoveryBytesV2(pending.purpose, false, msg.WireBytes)
			if complete, addErr := pending.collector.AddStore(msg.From, msg.Body); addErr == nil {
				if complete {
					cvNotifyAPDBV2(pending.ready)
				}
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
		peer := msg.From
		if local := s.localCoinShares[key]; len(local) != 0 {
			replied := s.coinShareReplies[key]
			inFlight := s.coinShareReplyInFlight[key]
			if _, duplicate := replied[peer]; !duplicate {
				if _, queued := inFlight[peer]; !queued {
					inFlight[peer] = struct{}{}
					reply = append([]byte(nil), local...)
				}
			}
		}
		s.mu.Unlock()
		if len(reply) != 0 {
			err := s.sendAsync(peer, cvTagCoinShareV2, reply, func(sendErr error) {
				s.mu.Lock()
				delete(s.coinShareReplyInFlight[key], peer)
				if sendErr == nil {
					s.coinShareReplies[key][peer] = struct{}{}
				}
				s.mu.Unlock()
			})
			if err != nil {
				s.mu.Lock()
				delete(s.coinShareReplyInFlight[key], peer)
				s.mu.Unlock()
			}
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
		s.enqueueLaneOfferV2(msg)
	case cvTagLaneACKV2:
		s.handleLaneACKV2(msg)
	case cvTagComponentRefV2:
		s.handleComponentRefV2(msg)
	case cvTagCertifiedCandidateV2:
		s.enqueueCertifiedCandidateV2(msg)
	case cvTagCertifiedCandidateACKV2:
		digest, err := cvDecodeCertifiedCandidateACKV2(msg.Body)
		if err == nil {
			s.markCertifiedCandidateACKV2(digest, msg.From)
		}
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
	offer, err := cvDecodeReceiverLaneOfferBeforeVerificationV2(msg.Body, s.cfg.LeafContext, msg.From, msg.To,
		receiverIndex, &s.cfg.Receivers.encryptionPublicKeys[receiverIndex-1])
	if err != nil {
		return
	}
	evidence, _, _, err := cvVerifyDecryptAndSignACKAfterPointDecodingV2(
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
		wire, _ := cvReceiverLaneOfferV2CanonicalBytesAfterValidation(
			s.cfg.LeafContext, s.cfg.LocalNode, pending.offers[message.ReceiverIndex-1],
		)
		return wire
	}())) {
		return
	}
	if err := cvVerifyACKAfterLocalOwnershipValidationV2(
		s.cfg.LeafContext, s.cfg.LocalNode, pending.offers[message.ReceiverIndex-1],
		s.cfg.Receivers.identityPublicKeys[message.ReceiverIndex-1], &message.Evidence); err != nil {
		return
	}
	s.mu.Lock()
	if s.pendingLaneACKsV2 != pending || pending.frozen {
		s.mu.Unlock()
		return
	}
	if _, duplicate := pending.acks[message.ReceiverIndex]; !duplicate {
		pending.acks[message.ReceiverIndex] = &message.Evidence
	}
	if len(pending.acks) >= pending.quorum {
		cvNotifyAPDBV2(pending.ready)
	}
	if len(pending.acks) == len(s.cfg.NewRoster) {
		cvNotifyAPDBV2(pending.allReady)
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
		localShare, signErr := s.controlSigner.SignShare(s.cfg.LocalNode, cvPoolCertV2Domain, statement)
		if signErr != nil {
			s.mu.Unlock()
			return
		}
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
		_ = s.sendAsync(pool.ProposerID, cvTagPoolCertShareV2, shareWire, nil)
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
	statement, err := cvValidationStatementV2(validatorSample, &request.Header)
	if err != nil {
		return
	}
	key := string(statement)
	s.mu.Lock()
	record := s.validationRecords[key]
	if record != nil && !bytes.Equal(record.requestWire, msg.Body) {
		s.mu.Unlock()
		return
	}
	alreadyVerified := record != nil
	s.mu.Unlock()
	if !alreadyVerified {
		if err := s.validateKnownComponentRefsV2(request.Pool.Components); err != nil {
			return
		}
		if err := cvVerifyValidationRequestPublicAfterComponentValidationV2(request, s.cfg.ExpectedContext, s.cfg.Params, eligible,
			s.apdbSigner, s.controlSigner, s.coinSigner); err != nil {
			return
		}
		s.mu.Lock()
		record = s.validationRecords[key]
		if record == nil {
			record = &cvValidationRecordV2{
				requestWire: append([]byte(nil), msg.Body...), resultReady: make(chan struct{}, 1),
			}
			s.validationRecords[key] = record
		} else if !bytes.Equal(record.requestWire, msg.Body) {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	localShare := append([]byte(nil), s.validationLocalShares[key]...)
	_, inFlight := s.validationInFlight[key]
	isValidator := cvContainsID(validatorSample, s.cfg.LocalNode)
	if isValidator && len(localShare) == 0 && !inFlight {
		if !cvReserveValidationStatementV2(
			s.validationOneShot, request.Header.ProposerID, statement,
		) {
			s.mu.Unlock()
			return
		}
		s.validationInFlight[key] = struct{}{}
	}
	s.mu.Unlock()
	if len(localShare) != 0 {
		shareWire, encodeErr := cvValidationSignatureV2CanonicalBytes(
			&cvValidationSignatureV2{Statement: statement, Signature: localShare},
		)
		if encodeErr == nil {
			_ = s.sendAsync(request.Header.ProposerID, cvTagValidationSignatureV2, shareWire, nil)
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
	leaves, err := s.loadValidationLeavesV2(request)
	if err != nil {
		return
	}
	aggregatePayload, err := s.recoverComponentForPurpose(s.ctx, &request.ARC, func(recovered []byte) error {
		digest, digestErr := cvAggregatePayloadDigestV2(recovered)
		if digestErr != nil || !bytes.Equal(digest, request.Header.PayloadDigest) {
			return fmt.Errorf("CV V2 validation aggregate payload mismatch")
		}
		return nil
	}, cvRecoveryValidatorAggregateV2)
	if err != nil {
		return
	}
	aggregate, err := cvAVerVerifiedV2(aggregatePayload, leaves, s.cfg.LeafContext, s.cfg.Params)
	if err != nil || cvVerifyAggregateHeaderPayloadV2(&request.Header, aggregatePayload, aggregate) != nil {
		return
	}
	s.mu.Lock()
	validatorSample := append([]int(nil), s.validatorSample...)
	reservedStatement := append([]byte(nil), s.validationOneShot[request.Header.ProposerID]...)
	s.mu.Unlock()
	if !bytes.Equal(reservedStatement, statement) {
		return
	}
	signature, err := cvSignValidationV2(s.cfg.LocalNode, &request.Header, validatorSample, s.cfg.Validators)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.validationLocalShares[key] = append([]byte(nil), signature...)
	s.mu.Unlock()
	shareWire, err := cvValidationSignatureV2CanonicalBytes(
		&cvValidationSignatureV2{Statement: statement, Signature: signature},
	)
	if err == nil {
		_ = s.sendAsync(request.Header.ProposerID, cvTagValidationSignatureV2, shareWire, nil)
	}
}

func (s *cvAPDBNetworkServiceV2) loadValidationLeavesV2(
	request *cvValidationRequestV2,
) ([]*cvLeafV2, error) {
	if request == nil || len(request.SelectedIndices) != s.cfg.Params.componentCount {
		return nil, fmt.Errorf("invalid CV V2 validation leaf selection")
	}
	leaves := make([]*cvLeafV2, len(request.SelectedIndices))
	errs := make([]error, len(request.SelectedIndices))
	workers := cvLeafVerifyWorkers(len(request.SelectedIndices))
	jobs := make(chan int, len(request.SelectedIndices))
	for index := range request.SelectedIndices {
		jobs <- index
	}
	close(jobs)
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer group.Done()
			for index := range jobs {
				poolIndex := request.SelectedIndices[index]
				if poolIndex < 0 || poolIndex >= len(request.Pool.Components) {
					errs[index] = fmt.Errorf("invalid CV V2 validation pool index")
					continue
				}
				leaves[index], errs[index] = s.verifiedComponentLeafV2(
					s.ctx, request.Pool.Components[poolIndex], cvRecoveryValidatorComponentV2,
				)
			}
		}()
	}
	group.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return leaves, nil
}

func cvReserveValidationStatementV2(reservations map[int][]byte, proposer int, statement []byte) bool {
	if reservations == nil || proposer < 0 || len(statement) != 32 {
		return false
	}
	if previous, exists := reservations[proposer]; exists {
		return bytes.Equal(previous, statement)
	}
	reservations[proposer] = append([]byte(nil), statement...)
	return true
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
			_ = s.sendAsync(msg.From, cvTagDecisionShareV2, wire, nil)
		}
	}
}

func (s *cvAPDBNetworkServiceV2) handleHandoff(msg Message) {
	isOld := cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster)
	isNew := cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.NewRoster)
	if !isOld && !isNew {
		return
	}
	handoff, err := cvDecodeHandoffV2(msg.Body)
	if err != nil || cvVerifyHandoffV2(handoff, s.cfg.ExpectedContext, s.apdbSigner, s.controlSigner) != nil {
		return
	}
	s.mu.Lock()
	if isOld {
		statement, statementErr := cvDecisionStatementV2(
			s.cfg.ExpectedContext, &handoff.Header, &handoff.ARC,
		)
		if statementErr == nil {
			key := string(statement)
			if len(s.decisionCertificates[key]) == 0 {
				s.decisionCertificates[key] = append([]byte(nil), handoff.DecCert...)
			}
			if pending := s.pendingDecisions[key]; pending != nil && len(pending.certificate) == 0 {
				pending.certificate = append([]byte(nil), handoff.DecCert...)
				cvNotifyAPDBV2(pending.ready)
			}
		}
	}
	if isNew && len(s.acceptedHandoff) == 0 {
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
		_ = s.sendAsync(msg.From, cvTagAggregateShareV2, localWire, nil)
	}
}

func (s *cvAPDBNetworkServiceV2) send(to int, tag string, payload []byte) error {
	_, err := s.sendMeasured(to, tag, payload)
	return err
}

func (s *cvAPDBNetworkServiceV2) sendMeasured(to int, tag string, payload []byte) (int, error) {
	envelope, err := cvEncodeNetworkEnvelope(s.cfg.SID, int(s.cfg.Epoch), payload)
	if err != nil {
		return 0, err
	}
	wire, err := s.auth.seal(s.cfg.LocalNode, to, tag, envelope)
	if err != nil {
		return 0, err
	}
	message := Message{From: s.cfg.LocalNode, To: to, Tag: tag, Body: wire}
	if err := s.transport.Send(message); err != nil {
		return 0, err
	}
	wireBytes := tcpMessageFrameFixedBytes + len(tag) + len(wire)
	s.recordTagBytesV2(tag, true, wireBytes)
	return wireBytes, nil
}

// sendFanoutMeasuredV2 bounds goroutine count while allowing independent TCP
// destinations to make progress concurrently. It preserves the recipient set
// and returns only after every attempted send has completed.
func (s *cvAPDBNetworkServiceV2) sendFanoutMeasuredV2(
	recipients []int, excluded int, tag string, payload []byte,
) []cvFanoutSendResultV2 {
	targets := make([]int, 0, len(recipients))
	for _, recipient := range recipients {
		if recipient != excluded {
			targets = append(targets, recipient)
		}
	}
	if len(targets) == 0 {
		return nil
	}
	parallel := cvFanoutMaxParallelV2
	if parallel > len(targets) {
		parallel = len(targets)
	}
	jobs := make(chan int)
	results := make(chan cvFanoutSendResultV2, len(targets))
	var workers sync.WaitGroup
	for range parallel {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for target := range jobs {
				wireBytes, err := s.sendMeasured(target, tag, payload)
				results <- cvFanoutSendResultV2{recipient: target, wireBytes: wireBytes, err: err}
			}
		}()
	}
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)
	workers.Wait()
	close(results)
	out := make([]cvFanoutSendResultV2, 0, len(targets))
	for result := range results {
		out = append(out, result)
	}
	return out
}

// sendRecipientPayloadFanoutMeasuredV2 is the bounded-fanout equivalent for
// authenticated messages whose payload is intentionally recipient-specific.
func (s *cvAPDBNetworkServiceV2) sendRecipientPayloadFanoutMeasuredV2(
	recipients []int, tag string, payloads map[int][]byte,
) []cvFanoutSendResultV2 {
	if len(recipients) == 0 || len(payloads) == 0 {
		return nil
	}
	parallel := cvFanoutMaxParallelV2
	if parallel > len(recipients) {
		parallel = len(recipients)
	}
	jobs := make(chan int)
	results := make(chan cvFanoutSendResultV2, len(recipients))
	var workers sync.WaitGroup
	for range parallel {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for recipient := range jobs {
				payload := payloads[recipient]
				wireBytes, err := s.sendMeasured(recipient, tag, payload)
				results <- cvFanoutSendResultV2{recipient: recipient, wireBytes: wireBytes, err: err}
			}
		}()
	}
	for _, recipient := range recipients {
		jobs <- recipient
	}
	close(jobs)
	workers.Wait()
	close(results)
	out := make([]cvFanoutSendResultV2, 0, len(recipients))
	for result := range results {
		out = append(out, result)
	}
	return out
}

func (s *cvAPDBNetworkServiceV2) recordTagBytesV2(tag string, sent bool, n int) {
	if s == nil || tag == "" || n <= 0 {
		return
	}
	s.experimentMu.Lock()
	if s.experimentMetrics.tagSentBytes == nil {
		s.experimentMetrics.tagSentBytes = make(map[string]uint64)
	}
	if s.experimentMetrics.tagRecvBytes == nil {
		s.experimentMetrics.tagRecvBytes = make(map[string]uint64)
	}
	if sent {
		s.experimentMetrics.tagSentBytes[tag] += uint64(n)
	} else {
		s.experimentMetrics.tagRecvBytes[tag] += uint64(n)
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordDispersalBytesV2(aggregate, sent bool, n int) {
	if s == nil || n <= 0 {
		return
	}
	s.experimentMu.Lock()
	if aggregate {
		if sent {
			s.experimentMetrics.aggregateDispersalSentBytes += uint64(n)
		} else {
			s.experimentMetrics.aggregateDispersalRecvBytes += uint64(n)
		}
	} else if sent {
		s.experimentMetrics.componentDispersalSentBytes += uint64(n)
	} else {
		s.experimentMetrics.componentDispersalRecvBytes += uint64(n)
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordRecoveryBytesV2(purpose cvRecoveryPurposeV2, sent bool, n int) {
	if s == nil || purpose == cvRecoveryUnclassifiedV2 || n <= 0 {
		return
	}
	s.experimentMu.Lock()
	switch purpose {
	case cvRecoveryProposerCatalogV2:
		if sent {
			s.experimentMetrics.proposerRecoverySentBytes += uint64(n)
		} else {
			s.experimentMetrics.proposerRecoveryRecvBytes += uint64(n)
		}
	case cvRecoveryValidatorComponentV2:
		if sent {
			s.experimentMetrics.validatorComponentRecoverySentBytes += uint64(n)
		} else {
			s.experimentMetrics.validatorComponentRecoveryRecvBytes += uint64(n)
		}
	case cvRecoveryValidatorAggregateV2:
		if sent {
			s.experimentMetrics.validatorAggregateRecoverySentBytes += uint64(n)
		} else {
			s.experimentMetrics.validatorAggregateRecoveryRecvBytes += uint64(n)
		}
	case cvRecoveryNewAggregateV2:
		if sent {
			s.experimentMetrics.newAggregateRecoverySentBytes += uint64(n)
		} else {
			s.experimentMetrics.newAggregateRecoveryRecvBytes += uint64(n)
		}
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordRecoveryLatencyV2(purpose cvRecoveryPurposeV2, elapsed time.Duration) {
	if s == nil || purpose == cvRecoveryUnclassifiedV2 || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	if purpose == cvRecoveryProposerCatalogV2 {
		s.experimentMetrics.proposerRecoveryLatency += elapsed
	} else if purpose == cvRecoveryValidatorComponentV2 {
		s.experimentMetrics.validatorComponentRecoveryLatency += elapsed
	} else if purpose == cvRecoveryValidatorAggregateV2 {
		s.experimentMetrics.validatorAggregateRecoveryLatency += elapsed
	} else if purpose == cvRecoveryNewAggregateV2 {
		s.experimentMetrics.newAggregateRecoveryLatency += elapsed
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordCoinFanoutLatencyV2(elapsed time.Duration) {
	if s == nil || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	s.experimentMetrics.coinFanoutLatency += elapsed
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordAggregateOfferSendLatencyV2(elapsed time.Duration) {
	if s == nil || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	s.experimentMetrics.aggregateOfferSendLatency += elapsed
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordCandidateFanoutAttemptV2(wait time.Duration, retry bool) {
	if s == nil || wait < 0 {
		return
	}
	s.experimentMu.Lock()
	s.experimentMetrics.candidateFanoutACKWaitLatency += wait
	s.experimentMetrics.candidateFanoutAttempts++
	if retry {
		s.experimentMetrics.candidateFanoutRetryWaitLatency += wait
		s.experimentMetrics.candidateFanoutRetries++
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordCandidateFanoutPeerLatencyV2(elapsed time.Duration) {
	if s == nil || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	if elapsed > s.experimentMetrics.candidateFanoutMaxPeerLatency {
		s.experimentMetrics.candidateFanoutMaxPeerLatency = elapsed
	}
	s.experimentMu.Unlock()
}

type cvCertificatePurposeV2 uint8

const (
	cvCertificateARCV2 cvCertificatePurposeV2 = iota + 1
	cvCertificateValidationV2
	cvCertificateDecisionV2
)

func (s *cvAPDBNetworkServiceV2) recordCertificateFormationV2(purpose cvCertificatePurposeV2, elapsed time.Duration) {
	if s == nil || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	switch purpose {
	case cvCertificateARCV2:
		s.experimentMetrics.arcFormationLatency += elapsed
	case cvCertificateValidationV2:
		s.experimentMetrics.validationCertificateLatency += elapsed
	case cvCertificateDecisionV2:
		s.experimentMetrics.decisionCertificateLatency += elapsed
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) experimentMetricsV2() cvServiceExperimentMetricsV2 {
	if s == nil {
		return cvServiceExperimentMetricsV2{}
	}
	s.experimentMu.Lock()
	defer s.experimentMu.Unlock()
	metrics := s.experimentMetrics
	metrics.tagSentBytes = cloneUint64MapV2(metrics.tagSentBytes)
	metrics.tagRecvBytes = cloneUint64MapV2(metrics.tagRecvBytes)
	return metrics
}

func cloneUint64MapV2(input map[string]uint64) map[string]uint64 {
	output := make(map[string]uint64, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
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
