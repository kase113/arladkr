package core

import (
	"bytes"
	"context"
	"fmt"
	"time"
)

// RunCVEpochV2 composes the scalar/group V2 network stages. The current
// academic network path requires all receiver ACKs for each component.
func RunCVEpochV2(ctx context.Context, cfg Config) (*EpochResult, error) {
	started := time.Now()
	c := NormalizeConfig(cfg)
	if ctx == nil {
		return nil, fmt.Errorf("nil CV V2 epoch context")
	}
	if err := validateCVEpochConfig(c); err != nil {
		return nil, err
	}
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	runtime, err := cvLoadEpochRuntimeV2(c)
	if err != nil {
		return nil, err
	}
	localOld := c.LocalNodeIDs[0]
	localReceiver := c.CVLocalReceiverIDs[0]
	contextDigest, err := cvLeafContextDigestV2(runtime.context)
	if err != nil {
		return nil, err
	}
	shardBytes, err := cvAllACKLeafShardBytesV2(
		runtime.context, runtime.receivers, runtime.validators, runtime.params.recoveryThreshold,
	)
	if err != nil {
		return nil, err
	}

	transport := c.protocolTransport
	ownedTransport := false
	if transport == nil {
		nodes := sortedUnique(append(append([]int(nil), c.OldCommittee...), c.NewCommittee...))
		transport, err = newAgreementTransport(c, nodes, len(nodes)*256)
		if err != nil {
			return nil, err
		}
		ownedTransport = true
	}
	if ownedTransport {
		defer transport.Close()
	}
	router, err := newCVSAPVSSRouterWithReceivers(
		ctx, transport, c.SID, c.Epoch, c.OldCommittee, c.NewCommittee,
		[]int{localOld, localReceiver}, (len(c.OldCommittee)+len(c.NewCommittee))*256, runtime.authenticator,
	)
	if err != nil {
		return nil, err
	}
	defer router.Close()
	holderStore, err := newCVAPDBHolderStoreV2(c.ArtifactCacheDir)
	if err != nil {
		return nil, err
	}
	decisionStore, err := newCVDecisionSignStoreV2(c.ArtifactCacheDir)
	if err != nil {
		return nil, err
	}
	scalarStore, err := newCVScalarStoreV2(c.ArtifactCacheDir)
	if err != nil {
		return nil, err
	}
	baseServiceCfg := cvAPDBNetworkServiceConfigV2{
		SID: c.SID, Epoch: uint64(c.Epoch), OldRoster: c.OldCommittee, NewRoster: c.NewCommittee,
		ExpectedContext: contextDigest, TotalShards: len(c.OldCommittee),
		DataShards: runtime.params.recoveryThreshold, ShardBytes: shardBytes, MaximumPayload: cvMaxLeafWireBytes,
		Params: runtime.params, LeafContext: runtime.context, Receivers: runtime.receivers, Validators: runtime.validators,
	}
	oldCfg := baseServiceCfg
	oldCfg.LocalNode = localOld
	oldCfg.Receivers = cvPublicReceiverMaterialV2(runtime.receivers)
	oldCfg.DecisionStore = decisionStore
	oldService, err := newCVAPDBNetworkServiceV2(ctx, oldCfg, transport, router, runtime.authenticator,
		holderStore, runtime.apdbSigner, runtime.controlSigner, runtime.coinSigner)
	if err != nil {
		return nil, err
	}
	defer oldService.Close()
	receiverCfg := baseServiceCfg
	receiverCfg.LocalNode = localReceiver
	receiverCfg.Validators = cvPublicValidatorMaterialV2(runtime.validators)
	receiverCfg.ScalarStore = scalarStore
	receiverService, err := newCVAPDBNetworkServiceV2(ctx, receiverCfg, transport, router, runtime.authenticator,
		nil, runtime.apdbSigner, runtime.controlSigner, runtime.coinSigner)
	if err != nil {
		return nil, err
	}
	defer receiverService.Close()

	leafStarted := time.Now()
	leaf, err := oldService.BuildAllACKLeafV2(ctx)
	if err != nil {
		return nil, fmt.Errorf("build CV V2 all-ACK leaf: %w", err)
	}
	leafLatency := time.Since(leafStarted)
	componentStarted := time.Now()
	if _, err := oldService.PublishComponentV2(ctx, leaf); err != nil {
		return nil, fmt.Errorf("publish CV V2 component: %w", err)
	}
	componentLatency := time.Since(componentStarted)

	coinStarted := time.Now()
	eligibilityCoin, err := oldService.EligibilityCoin(ctx)
	if err != nil {
		return nil, fmt.Errorf("collect CV V2 eligibility coin: %w", err)
	}
	proposers, _, err := cvDeriveEligibilitySamplesV2(
		c.OldCommittee, eligibilityCoin.Value, runtime.params.proposerSampleSize, runtime.params.validatorSampleSize,
	)
	if err != nil || len(proposers) == 0 {
		return nil, fmt.Errorf("derive CV V2 eligibility samples: %w", err)
	}
	proposer := proposers[0]
	var pool *cvPoolV2
	var poolCert *cvPoolCertificateV2
	if localOld == proposer {
		refs, waitErr := oldService.AwaitComponentRefsV2(ctx)
		if waitErr != nil {
			return nil, waitErr
		}
		pool, err = cvBuildPoolV2(contextDigest, proposer, refs, runtime.params)
		if err == nil {
			poolCert, err = oldService.CertifyPool(ctx, pool)
		}
	} else {
		pool, poolCert, err = oldService.AwaitCertifiedPool(ctx, proposer)
	}
	if err != nil {
		return nil, fmt.Errorf("build CV V2 certified pool: %w", err)
	}
	contributorCoin, err := oldService.ContributorCoin(ctx, pool, poolCert)
	if err != nil {
		return nil, fmt.Errorf("collect CV V2 contributor coin: %w", err)
	}
	selected, err := cvSelectedPoolIndicesV2(runtime.params.poolSize, runtime.params.componentCount, contributorCoin.Value)
	if err != nil {
		return nil, fmt.Errorf("build CV V2 certified aggregate: %w", err)
	}
	coinPoolLatency := time.Since(coinStarted)

	aggregateStarted := time.Now()
	var validationRequest *cvValidationRequestV2
	var vCert *cvValidationCertificateV2
	if localOld == proposer {
		selectedLeaves := make([]*cvLeafV2, len(selected))
		for i, poolIndex := range selected {
			component := pool.Components[poolIndex]
			payload, recoverErr := oldService.RecoverComponent(ctx, &component.Lock, func(recovered []byte) error {
				if !bytes.Equal(cvComponentPayloadDigestV2(recovered), component.Header.PayloadDigest) {
					return fmt.Errorf("CV V2 selected component payload mismatch")
				}
				return nil
			})
			if recoverErr != nil {
				return nil, recoverErr
			}
			selectedLeaves[i], err = cvDecodeLeafV2(payload, runtime.context, runtime.receivers, runtime.validators)
			if err != nil {
				return nil, err
			}
		}
		aggregate, aggregateErr := cvAggV2(selectedLeaves, runtime.context, runtime.params, runtime.receivers, runtime.validators)
		if aggregateErr != nil {
			return nil, aggregateErr
		}
		aggregatePayload, aggregateErr := cvAggregateV2CanonicalBytes(aggregate, runtime.context, runtime.params)
		if aggregateErr != nil {
			return nil, aggregateErr
		}
		selectionDigest, aggregateErr := cvSelectionDigestV2(contributorCoin, selected, runtime.params.poolSize, runtime.params.componentCount)
		if aggregateErr != nil {
			return nil, aggregateErr
		}
		aggregateInstance, aggregateErr := cvAggregateInstanceDigestV2(contextDigest, proposer, pool.Digest, selectionDigest)
		if aggregateErr != nil {
			return nil, aggregateErr
		}
		aggregateEncoded, aggregateErr := cvAPDBEncodeSizedV2(
			aggregateInstance, aggregatePayload, runtime.params.recoveryThreshold, len(c.OldCommittee), shardBytes, cvMaxLeafWireBytes,
		)
		if aggregateErr != nil {
			return nil, aggregateErr
		}
		arc, aggregateErr := oldService.Lock(ctx, aggregateEncoded)
		if aggregateErr != nil {
			return nil, aggregateErr
		}
		payloadDigest, aggregateErr := cvAggregatePayloadDigestV2(aggregatePayload)
		if aggregateErr != nil {
			return nil, aggregateErr
		}
		header := cvAggregateHeaderV2{
			ContextDigest: contextDigest, ProposerID: proposer, PoolDigest: append([]byte(nil), pool.Digest...),
			SelectionDigest: selectionDigest, AggregateDigest: append([]byte(nil), aggregate.Digest...),
			PayloadDigest: payloadDigest, APDBInstance: aggregateInstance, APDBRoot: append([]byte(nil), arc.Root...),
		}
		validationRequest = &cvValidationRequestV2{Header: header, Pool: *pool, PoolCert: *poolCert,
			ContributorCoin: *contributorCoin, SelectedIndices: selected, ARC: *arc}
		vCert, err = oldService.CertifyAggregate(ctx, validationRequest)
	} else {
		validationRequest, vCert, err = oldService.AwaitCertifiedValidationV2(ctx, proposer)
	}
	if err != nil {
		return nil, err
	}
	aggregateLatency := time.Since(aggregateStarted)

	candidate := &cvAgreementObjectV2{
		Header: validationRequest.Header, Pool: validationRequest.Pool, PoolCert: validationRequest.PoolCert,
		ContributorCoin: validationRequest.ContributorCoin, SelectedIndices: append([]int(nil), validationRequest.SelectedIndices...),
		VCert: *vCert, ARC: validationRequest.ARC,
	}
	public := cvAgreementPublicContextV2{SID: c.SID, Epoch: uint64(c.Epoch), ContextDigest: contextDigest,
		OldCommittee: c.OldCommittee, EligibilityCoin: eligibilityCoin, Params: runtime.params,
		APDBSigner: runtime.apdbSigner, ControlSigner: runtime.controlSigner, CoinSigner: runtime.coinSigner,
		ValidatorKeys: runtime.validators}
	agreementStarted := time.Now()
	decided, agreementWire, peerWait, err := cvRunAgreementV2(ctx, c, candidate, public)
	if err != nil {
		return nil, fmt.Errorf("run CV V2 agreement: %w", err)
	}
	agreementLatency := time.Since(agreementStarted)
	handoffStarted := time.Now()
	handoff, err := oldService.FinalizeDecision(ctx, decided)
	if err != nil {
		return nil, fmt.Errorf("finalize CV V2 decision: %w", err)
	}
	accepted, err := receiverService.AwaitHandoff(ctx)
	if err != nil {
		return nil, fmt.Errorf("await CV V2 handoff: %w", err)
	}
	if !bytes.Equal(accepted.Header.AggregateDigest, handoff.Header.AggregateDigest) {
		return nil, fmt.Errorf("CV V2 local receiver accepted a different handoff")
	}
	handoffLatency := time.Since(handoffStarted)
	recoveryStarted := time.Now()
	aggregate, scalar, output, publicKey, err := receiverService.RecoverAndExchangeScalarShare(ctx, accepted)
	if err != nil {
		return nil, fmt.Errorf("recover CV V2 aggregate share: %w", err)
	}
	aggregateWire, err := cvAggregateV2CanonicalBytes(aggregate, runtime.context, runtime.params)
	if err != nil {
		return nil, err
	}
	shareWire, err := cvScalarShareOutputV2CanonicalBytes(output)
	if err != nil {
		return nil, err
	}
	scalarBytes := scalar.Bytes()
	publicKeyBytes := publicKey.Bytes()
	agreementDigest := hashBytes([]byte("ARL-CV-sAPVSS/v2-scalar-group/agreement-result"), agreementWire)
	selectedDealers := make([]int, len(selected))
	for i, index := range selected {
		selectedDealers[i] = pool.Components[index].Header.DealerID
	}
	return &EpochResult{
		AgreementMode: "single-mvba-v2", AblationMode: c.AblationMode, CVAPVSSMode: cvSAPVSSV2ProtocolVersion,
		LockedSet: append([]int(nil), poolDealerIDsV2(pool)...), SampledSet: selectedDealers, AggRLODealers: selectedDealers,
		RecoveredAggregate: aggregateWire, AggRLODigest: agreementDigest, RecoverAggSuccess: true,
		NewShares:    map[int][]byte{localReceiver: append([]byte(nil), scalarBytes[:]...)},
		NewPublicKey: append([]byte(nil), publicKeyBytes[:]...), CVReceipts: map[int][]byte{localReceiver: shareWire},
		CVComponentCount: runtime.params.poolSize, CVARCHolderCount: runtime.params.apdbLockThreshold,
		CVRecoveredShardCount: runtime.params.recoveryThreshold, CVVerifiedReceiptCount: runtime.params.newShareThreshold,
		CVLeafBuildLatency: leafLatency, CVComponentDisperseLatency: componentLatency,
		CVComponentCollectionLatency: coinPoolLatency, CVAggregateDisperseLatency: aggregateLatency,
		CVAggregateAgreementLatency: agreementLatency, MVBAPeerWaitLatency: peerWait,
		CVRecoverShardLatency: time.Since(recoveryStarted), CVReceiptLatency: handoffLatency,
		PerNode: []NodeOutput{{NodeID: localOld, DecidedSet: selectedDealers, Latency: time.Since(started)}},
	}, nil
}

func poolDealerIDsV2(pool *cvPoolV2) []int {
	if pool == nil {
		return nil
	}
	dealers := make([]int, len(pool.Components))
	for i := range pool.Components {
		dealers[i] = pool.Components[i].Header.DealerID
	}
	return dealers
}
