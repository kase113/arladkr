package core

import "time"

type Header struct {
	SID          string
	Epoch        int
	Dealer       int
	Root         []byte
	Commitment   []byte
	MetadataHash []byte
}

type RecoverabilityLock struct {
	Threshold       int
	Holders         []int
	ShareSignatures map[int][]byte
	Certificate     []byte
}

func (l RecoverabilityLock) Ready() bool {
	return len(l.Holders) >= l.Threshold
}

type Descriptor struct {
	Dealer      int
	Header      Header
	Lock        RecoverabilityLock
	Digest      []byte
	Fingerprint []byte
}

type AggHeader struct {
	SID             string
	Epoch           int
	Dealers         []int
	AggregateDigest []byte
	PayloadDigest   []byte
	FreshShardRoot  []byte
	MetadataHash    []byte
}

// AggLock is a quorum certificate over AggHeader only.
// It proves that enough old-committee holders accepted the aggregate header
// as a recoverable obligation; it does not carry materialized aggregate
// fragments or fragment-correctness proofs.
type AggLock struct {
	Threshold       int
	Holders         []int
	ShareSignatures map[int][]byte
	Certificate     []byte
}

// ARCHeaderShare is the explicit header-only recovery-obligation share carried
// by LockAgg. It binds an old-committee holder to a specific aggregate header
// digest for a specific epoch without carrying aggregate fragment material.
type ARCHeaderShare struct {
	Holder          int
	Epoch           int
	AggHeaderDigest []byte
	ObligationKind  string
	Signature       []byte
}

func (l AggLock) Ready() bool {
	return len(l.Holders) >= l.Threshold
}

type APVSSAggregate struct {
	Provider          string
	Dealers           []int
	AggregateDigest   []byte
	ListTranscript    *ListBackedAggregateTranscript // list-backed prototype providers
	BlsPVSSTranscript *BlsPVSSAggregateTranscript    // BLS12-381 pairing-based
}

// AggRLO is the aggregate recovery-lock object agreed by LockAgg/AgreeAgg.
// In header-only ARC mode, the lock certifies an aggregate header plus the
// obligation that Recover may later materialize and verify the aggregate
// fragment/object bound to Header.AggregateDigest.
type AggRLO struct {
	Header    AggHeader
	Lock      AggLock
	Aggregate APVSSAggregate
	Digest    []byte
}

// AggFragResponse is the recover-time response object bound to a single
// aggregate contribution under a header-only AggRLO.
type AggFragResponse struct {
	Provider           string
	Dealer             int
	ContributionDigest []byte
	Payload            []byte
	Ciphertexts        map[int][]byte
}

type DealerArtifact struct {
	Dealer             int
	Descriptor         Descriptor
	Payload            []byte
	Ciphertexts        map[int][]byte
	ContributionDigest []byte
	Fingerprint        []byte
}

type NodeOutput struct {
	NodeID     int
	DecidedSet []int
	Latency    time.Duration
}

type ReceiverState struct {
	NodeID           int
	Epoch            int
	PublicKey        []byte
	SecretKey        []byte
	ChainKey         []byte
	TransportKeyHash []byte
}

type EpochResult struct {
	AgreementMode string
	AblationMode  string
	LockedSet     []int
	SampledSet    []int
	AggRLODealers []int

	RecoveredPayloads               map[int][]byte
	RecoveredAggregate              []byte
	AggRLODigest                    []byte
	AggRLOReadyLatency              time.Duration
	AdmitAggAttempts                int
	AdmitAggPasses                  int
	RecoverAggSuccess               bool
	SetupLatency                    time.Duration
	DisperseLatency                 time.Duration
	DisperseLocalBuildLatency       time.Duration
	DisperseBroadcastLatency        time.Duration
	DisperseReadWaitLatency         time.Duration
	DisperseTrustedReadyLatency     time.Duration
	DisperseAggregatePrewarmLatency time.Duration
	LockAggLatency                  time.Duration
	LockAggReadyCandidatesLatency   time.Duration
	LockAggBuildAggregateLatency    time.Duration
	LockAggARCSharePrepareLatency   time.Duration
	LockAggARCShareAttachLatency    time.Duration
	LockAggCandidateCount           int
	LockAggARCShareSignedCount      int
	LockAggShareSignLatency         time.Duration
	LockAggCertRecoverLatency       time.Duration
	LockAggLocalAdmitLatency        time.Duration
	MVBAOnlyLatency                 time.Duration
	MVBAPeerWaitLatency             time.Duration
	AgreeAggLatency                 time.Duration
	RecoverBarrierWaitLatency       time.Duration
	RecoverServiceGraceLatency      time.Duration
	RecoverLatency                  time.Duration
	RecoverOnlyLatency              time.Duration
	RecoverVerifyLatency            time.Duration
	RecoverCollectLatency           time.Duration
	RecoverVerifyOnlyLatency        time.Duration
	RecoverMaterializeLatency       time.Duration
	DeriveLatency                   time.Duration
	TotalSentBytes                  uint64
	TotalRecvBytes                  uint64
	PhaseSentBytes                  map[string]uint64
	PhaseRecvBytes                  map[string]uint64
	NewShares                       map[int][]byte
	NewPublicKey                    []byte
	CVReceipts                      map[int][]byte
	CVComponentCount                int
	CVARCHolderCount                int
	CVRecoveredShardCount           int
	CVVerifiedReceiptCount          int
	CVLeafBuildLatency              time.Duration
	CVComponentDisperseLatency      time.Duration
	CVCommonCandidateLatency        time.Duration
	CVAggregateDisperseLatency      time.Duration
	CVAggregateAgreementLatency     time.Duration
	CVRecoverShardLatency           time.Duration
	CVReceiptLatency                time.Duration
	CVAPVSSACKCount                 int
	CVAPVSSFallbackCount            int
	CVAPVSSProofBytes               int
	CVAPVSSLeafWireBytes            int
	CVAggregateGateWaitLatency      time.Duration
	CVAggregateLeafLoadLatency      time.Duration
	CVAggregateBuildLatency         time.Duration
	CVAggregateRSLatency            time.Duration
	CVAggregateHeaderTokenLatency   time.Duration
	CVAggregateOfferSendLatency     time.Duration
	CVAggregateARCWaitLatency       time.Duration
	CVAggregateCertificateLatency   time.Duration

	PerNode        []NodeOutput
	ReceiverStates map[int]ReceiverState
}
