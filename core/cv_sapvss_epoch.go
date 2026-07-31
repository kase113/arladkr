package core

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const cvMaterializedAggRLOWitnessDomain = "ARL-CV-sAPVSS/materialized-aggrlo-certificate"

func cvMaterializedAggRLOWitnessCanonicalBytes(rlo *AggRLO) ([]byte, error) {
	if rlo == nil || rlo.Aggregate.Provider != "cv-sapvss" || rlo.Lock.Threshold <= 0 ||
		len(rlo.Lock.Certificate) == 0 || len(rlo.Lock.Certificate) > cvMaxComponentSignatureBytes ||
		len(rlo.Digest) != 32 || !bytes.Equal(rlo.Digest, digestAggRLO(*rlo)) {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS materialized AggRLO witness")
	}
	headerWire, err := cvNetworkAggHeaderCanonicalBytes(rlo.Header)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvMaterializedAggRLOWitnessDomain))
	_ = cvWriteBytes(&wire, headerWire)
	_ = cvWriteUint32(&wire, rlo.Lock.Threshold)
	_ = cvWriteBytes(&wire, rlo.Lock.Certificate)
	_ = cvWriteBytes(&wire, rlo.Digest)
	return wire.Bytes(), nil
}

func cvDecodeMaterializedAggRLOWitness(wire []byte, cfg Config) (*AggRLO, error) {
	c := NormalizeConfig(cfg)
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvMaterializedAggRLOWitnessDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvMaterializedAggRLOWitnessDomain)) {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS materialized AggRLO witness domain")
	}
	headerWire, err := r.bytes(1 << 20)
	if err != nil {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS materialized AggRLO header")
	}
	header, err := cvDecodeNetworkAggHeader(headerWire, c)
	if err != nil {
		return nil, err
	}
	threshold, err := r.uint32()
	if err != nil || threshold != len(c.OldCommittee)-c.FOld {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS ARC threshold")
	}
	certificate, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(certificate) == 0 {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS ARC certificate")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS materialized AggRLO digest")
	}
	rlo := &AggRLO{Header: header, Lock: AggLock{Threshold: threshold, Certificate: certificate}, Aggregate: APVSSAggregate{
		Provider: "cv-sapvss", Dealers: append([]int(nil), header.Dealers...),
		AggregateDigest: append([]byte(nil), header.AggregateDigest...)}, Digest: digest}
	if _, err := validateAggRLOShape(c, rlo); err != nil {
		return nil, err
	}
	if err := validateAggRLOLock(c, rlo); err != nil {
		return nil, err
	}
	if err := validateAggRLODigest(rlo); err != nil {
		return nil, err
	}
	canonical, err := cvMaterializedAggRLOWitnessCanonicalBytes(rlo)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical compact CV-sAPVSS materialized AggRLO witness")
	}
	return rlo, nil
}

func cvRunMaterializedAgreement(ctx context.Context, cfg Config, localRLO *AggRLO) (*AggRLO, time.Duration, error) {
	if localRLO == nil {
		return nil, 0, fmt.Errorf("missing local CV-sAPVSS materialized AggRLO")
	}
	wire, err := cvMaterializedAggRLOWitnessCanonicalBytes(localRLO)
	if err != nil {
		return nil, 0, err
	}
	predicate := func(_ int, payload []byte) bool {
		_, decodeErr := cvDecodeMaterializedAggRLOWitness(payload, cfg)
		return decodeErr == nil
	}
	payloads, peerWait, err := runArladkrMVBATCPInstance(ctx, cfg, "cv-materialized-aggrlo", wire, predicate)
	if err != nil {
		return nil, peerWait, err
	}
	if len(payloads) == 0 {
		return nil, peerWait, fmt.Errorf("CV-sAPVSS compact materialized agreement returned no witness")
	}
	decided, err := cvDecodeMaterializedAggRLOWitness(payloads[0], cfg)
	return decided, peerWait, err
}

func traceCVEpochPhase(cfg Config, node int, phase string) {
	if os.Getenv("RLADKR_CV_DEBUG") == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "CV_EPOCH_PHASE node=%d phase=%s\n", node, phase)
}

func cvBuildEpochLeafContext(cfg Config, material *cvReceiverKeyMaterial) (cvLeafContext, error) {
	c := NormalizeConfig(cfg)
	if material == nil || len(material.receiverPublicKeys) != len(c.NewCommittee) || len(material.registryDigest) != 32 {
		return cvLeafContext{}, fmt.Errorf("invalid CV-sAPVSS epoch receiver material")
	}
	policy := append([]byte("ARL-CV-sAPVSS/first-f-plus-one|registry="), material.registryDigest...)
	policy = append(policy, encodeInts(sortedUnique(c.OldCommittee))...)
	policy = append(policy, byte(c.Kappa>>24), byte(c.Kappa>>16), byte(c.Kappa>>8), byte(c.Kappa))
	context := cvLeafContext{
		sessionID:           []byte(c.SID),
		epoch:               uint64(c.Epoch),
		previousStateDigest: append([]byte(nil), c.PreviousEpochStateDigest...),
		sharingDegree:       c.FNew,
		profile:             cvChunkProfile{chunkBits: 8, maxComponents: c.Kappa},
		receiverPublicKeys:  append([]bls12381.G1Affine(nil), material.receiverPublicKeys...),
		dealerSetPolicy:     policy,
		proofProfile:        cvLeafStructuralProofProfile,
	}
	if err := cvValidateLeafContext(&context); err != nil {
		return cvLeafContext{}, err
	}
	return context, nil
}

func cvRandomDealerLeaf(context cvLeafContext, dealer int) (*cvLeaf, error) {
	leaf, _, err := cvRandomDealerLeafWithWitness(context, dealer)
	return leaf, err
}

func cvRandomDealerLeafWithWitness(
	context cvLeafContext,
	dealer int,
) (*cvLeaf, *apvssDealerWitness, error) {
	if dealer < 0 {
		return nil, nil, fmt.Errorf("invalid CV-sAPVSS dealer")
	}
	coefficientCount := context.sharingDegree + 1
	scalarCoefficients := make([]fr.Element, coefficientCount)
	blindingCoefficients := make([]fr.Element, coefficientCount)
	for i := 0; i < coefficientCount; i++ {
		if _, err := scalarCoefficients[i].SetRandom(); err != nil {
			return nil, nil, fmt.Errorf("sample CV-sAPVSS scalar coefficient: %w", err)
		}
		if _, err := blindingCoefficients[i].SetRandom(); err != nil {
			return nil, nil, fmt.Errorf("sample CV-sAPVSS blinding coefficient: %w", err)
		}
	}
	chunks, err := cvChunkCount(context.profile)
	if err != nil {
		return nil, nil, err
	}
	commonCoins := make([]fr.Element, chunks)
	for i := range commonCoins {
		if _, err := commonCoins[i].SetRandom(); err != nil {
			return nil, nil, fmt.Errorf("sample CV-sAPVSS chunk coin: %w", err)
		}
	}
	var commonBlindingCoin fr.Element
	if _, err := commonBlindingCoin.SetRandom(); err != nil {
		return nil, nil, fmt.Errorf("sample CV-sAPVSS blinding coin: %w", err)
	}
	scalarCoins := make([][]fr.Element, len(context.receiverPublicKeys))
	blindingCoins := make([]fr.Element, len(context.receiverPublicKeys))
	for i := range scalarCoins {
		scalarCoins[i] = append([]fr.Element(nil), commonCoins...)
		blindingCoins[i] = commonBlindingCoin
	}
	leaf, err := cvReferenceDeal(
		context, uint64(dealer), scalarCoefficients, blindingCoefficients, scalarCoins, blindingCoins,
	)
	if err != nil {
		return nil, nil, err
	}
	witness := &apvssDealerWitness{
		scalars:       make([]fr.Element, len(context.receiverPublicKeys)),
		blindings:     make([]fr.Element, len(context.receiverPublicKeys)),
		scalarCoins:   scalarCoins,
		blindingCoins: blindingCoins,
	}
	for i := range context.receiverPublicKeys {
		witness.scalars[i] = evalPolyInt(scalarCoefficients, int64(i+1))
		witness.blindings[i] = evalPolyInt(blindingCoefficients, int64(i+1))
	}
	return leaf, witness, nil
}

func RunCVEpoch(ctx context.Context, cfg Config) (*EpochResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil CV epoch context")
	}
	start := time.Now()
	cfg = NormalizeConfig(cfg)
	if err := validateCVEpochConfig(cfg); err != nil {
		return nil, err
	}
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if err := ensureRuntime(&cfg); err != nil {
		return nil, err
	}
	localNode := cfg.LocalNodeIDs[0]
	perfStart := cvPerfSnapshotNow()
	defer traceCVPerfCounters(localNode, perfStart)
	traceCVEpochPhase(cfg, localNode, "runtime_ready")
	material, err := cvLoadReceiverKeyMaterial(
		cfg.CVPublicKeyDir,
		cfg.CVLocalSecretDir,
		cfg.SID,
		sortedUnique(cfg.NewCommittee),
		cfg.CVLocalReceiverIDs,
	)
	if err != nil {
		return nil, err
	}
	traceCVEpochPhase(cfg, localNode, "keys_loaded")
	leafContext, err := cvBuildEpochLeafContext(cfg, material)
	if err != nil {
		return nil, err
	}
	traceCVEpochPhase(cfg, localNode, "transport_ready")

	transport := cfg.protocolTransport
	ownedTransport := false
	if transport == nil {
		transportNodes := sortedUnique(append(
			append([]int(nil), cfg.runtime.oldOrder...), material.receiverOrder...,
		))
		transport, err = newAgreementTransport(cfg, transportNodes, len(transportNodes)*64)
		if err != nil {
			return nil, err
		}
		ownedTransport = true
	}
	if ownedTransport {
		defer transport.Close()
	}
	localActors := []int{localNode}
	for receiverID := range material.localReceiverSecrets {
		localActors = append(localActors, receiverID)
	}
	var networkAuth *cvNetworkAuthenticator
	if cfg.StrictNetwork {
		networkAuth, err = newCVNetworkAuthenticator(
			cfg.runtime.lockSigner, material.receiverOrder, material.receiverPublicKeys,
			material.localReceiverSecrets,
		)
		if err != nil {
			return nil, err
		}
	}
	router, err := newCVSAPVSSRouterWithReceivers(
		ctx, transport, cfg.SID, cfg.Epoch,
		cfg.runtime.oldOrder, material.receiverOrder, sortedUnique(localActors),
		(len(cfg.runtime.oldOrder)+len(material.receiverOrder))*64, networkAuth,
	)
	if err != nil {
		return nil, err
	}
	traceCVEpochPhase(cfg, localNode, "component_service_ready")
	defer router.Close()
	store, err := newCVComponentLeafStore(cfg.ArtifactCacheDir)
	if err != nil {
		return nil, err
	}
	service, err := newCVComponentServiceWithReceivers(
		ctx, cfg, &leafContext, localNode, transport, router, store,
		material.receiverOrder, material.localReceiverSecrets,
	)
	if err != nil {
		return nil, err
	}
	defer service.Close()
	setupLatency := time.Since(start)

	leafBuildStart := time.Now()
	leaf, witness, err := cvRandomDealerLeafWithWitness(leafContext, localNode)
	if err != nil {
		return nil, err
	}
	prototype, err := service.CollectAPVSSLaneACKs(ctx, leaf, witness)
	if err != nil {
		return nil, err
	}
	proofBytes, err := apvssProofMaterialBytes(prototype)
	if err != nil {
		return nil, err
	}
	prototypeWire, err := apvssLeafPrototypeCanonicalBytes(prototype)
	if err != nil {
		return nil, err
	}
	leafBuildLatency := time.Since(leafBuildStart)
	traceCVEpochPhase(cfg, localNode, "leaf_built")
	cfg.runtime.setCommPhase("component_disperse")
	phaseStart := time.Now()
	_, err = service.DisperseAPVSS(ctx, prototype)
	if err != nil {
		return nil, err
	}
	traceCVEpochPhase(cfg, localNode, "component_certified")
	componentLatency := time.Since(phaseStart)

	cfg.runtime.setCommPhase("common_candidate")
	phaseStart = time.Now()
	descriptors, err := service.CollectComponentCandidates(ctx)
	if err != nil {
		return nil, err
	}
	traceCVEpochPhase(cfg, localNode, "component_candidates_collected")
	commonLatency := time.Since(phaseStart)

	cfg.runtime.setCommPhase("aggregate_disperse")
	phaseStart = time.Now()
	materialized, err := service.MaterializeFirstCertified(ctx, descriptors)
	if err != nil {
		return nil, err
	}
	traceCVEpochPhase(cfg, localNode, "aggregate_arc_ready")
	aggregateLatency := time.Since(phaseStart)
	// Receipt material remains local until agreement. Precomputing it here
	// overlaps bounded-DLog/DLEQ work with MVBA without releasing shares for an
	// aggregate that has not been decided.
	service.StartReceiptPreparation(
		materialized.aggregate, material.receiverOrder, material.localReceiverSecrets,
	)

	cfg.runtime.setCommPhase("aggregate_agreement")
	phaseStart = time.Now()
	decidedRLO, aggregatePeerWait, err := cvRunMaterializedAgreement(ctx, cfg, materialized.rlo)
	if err != nil {
		return nil, err
	}
	traceCVEpochPhase(cfg, localNode, "aggregate_agreed")
	aggregateAgreementLatency := time.Since(phaseStart)

	cfg.runtime.setCommPhase("recover_shard")
	phaseStart = time.Now()
	recovered, err := service.RecoverAggregate(ctx, decidedRLO)
	if err != nil {
		return nil, err
	}
	traceCVEpochPhase(cfg, localNode, "aggregate_recovered")
	recoverLatency := time.Since(phaseStart)
	recoveredWire, err := cvAggregateCanonicalBytes(recovered)
	if err != nil {
		return nil, err
	}
	traceCVEpochPhase(cfg, localNode, "receipts_exchanged")

	cfg.runtime.setCommPhase("receipt")
	phaseStart = time.Now()
	shares, receipts, publicKey, err := service.ExchangeReceipts(
		ctx, recovered, material.receiverOrder, material.localReceiverSecrets,
	)
	if err != nil {
		return nil, err
	}
	receiptLatency := time.Since(phaseStart)
	totalSent, totalRecv := cfg.runtime.commStats()
	phaseSent, phaseRecv := cfg.runtime.phaseCommStats()
	dealers := append([]int(nil), decidedRLO.Header.Dealers...)
	totalLatency := time.Since(start)
	return &EpochResult{
		AgreementMode: "cv-single-mvba-aggrlo", AblationMode: cfg.AblationMode,
		LockedSet: dealers, SampledSet: append([]int(nil), dealers...), AggRLODealers: append([]int(nil), dealers...),
		RecoveredAggregate: recoveredWire, AggRLODigest: append([]byte(nil), decidedRLO.Digest...),
		AggRLOReadyLatency: componentLatency + commonLatency + aggregateLatency,
		AdmitAggAttempts:   1, AdmitAggPasses: 1, RecoverAggSuccess: true,
		SetupLatency: setupLatency, DisperseLatency: componentLatency,
		LockAggLatency: aggregateLatency, MVBAOnlyLatency: aggregateAgreementLatency,
		MVBAPeerWaitLatency: aggregatePeerWait,
		AgreeAggLatency:     commonLatency + aggregateLatency + aggregateAgreementLatency,
		RecoverLatency:      recoverLatency, RecoverOnlyLatency: recoverLatency, DeriveLatency: receiptLatency,
		TotalSentBytes: totalSent, TotalRecvBytes: totalRecv, PhaseSentBytes: phaseSent, PhaseRecvBytes: phaseRecv,
		NewShares: shares, NewPublicKey: publicKey, CVReceipts: receipts,
		CVComponentCount: len(descriptors), CVARCHolderCount: decidedRLO.Lock.Threshold,
		CVRecoveredShardCount: len(cfg.OldCommittee) - 2*cfg.FOld, CVVerifiedReceiptCount: len(receipts),
		CVLeafBuildLatency:         leafBuildLatency,
		CVComponentDisperseLatency: componentLatency, CVCommonCandidateLatency: commonLatency,
		CVAggregateDisperseLatency: aggregateLatency, CVAggregateAgreementLatency: aggregateAgreementLatency,
		CVRecoverShardLatency: recoverLatency, CVReceiptLatency: receiptLatency,
		CVAPVSSACKCount: len(prototype.acks), CVAPVSSFallbackCount: apvssPrototypeFallbackCount(prototype),
		CVAPVSSProofBytes: proofBytes, CVAPVSSLeafWireBytes: len(prototypeWire),
		CVAggregateGateWaitLatency:    materialized.metrics.gateWait,
		CVAggregateLeafLoadLatency:    materialized.metrics.leafLoad,
		CVAggregateBuildLatency:       materialized.metrics.aggregate,
		CVAggregateRSLatency:          materialized.metrics.rsDisperse,
		CVAggregateHeaderTokenLatency: materialized.metrics.headerToken,
		CVAggregateOfferSendLatency:   materialized.metrics.offerSend,
		CVAggregateARCWaitLatency:     materialized.metrics.arcWait,
		CVAggregateCertificateLatency: materialized.metrics.certificate,
		PerNode:                       []NodeOutput{{NodeID: localNode, DecidedSet: append([]int(nil), dealers...), Latency: totalLatency}},
	}, nil
}
