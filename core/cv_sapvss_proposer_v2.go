package core

import (
	"context"
	"fmt"
)

type cvProposerSlotRunnerV2 func(context.Context, int) error

type cvProposerSlotResultV2 struct {
	proposer int
	err      error
}

func cvRunSampledProposerSlotsV2(
	ctx context.Context,
	proposers []int,
	candidates <-chan *cvAgreementObjectV2,
	run cvProposerSlotRunnerV2,
) (*cvAgreementObjectV2, error) {
	if ctx == nil || len(proposers) == 0 || candidates == nil || run == nil ||
		len(sortedUnique(proposers)) != len(proposers) {
		return nil, fmt.Errorf("invalid CV V2 sampled proposer slots")
	}
	pipelineCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	started := make(chan int, len(proposers))
	results := make(chan cvProposerSlotResultV2, len(proposers))
	for _, proposer := range proposers {
		proposer := proposer
		go func() {
			started <- proposer
			results <- cvProposerSlotResultV2{proposer: proposer, err: run(pipelineCtx, proposer)}
		}()
	}
	for range proposers {
		select {
		case <-started:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	failed := make(map[int]error, len(proposers))
	for len(failed) < len(proposers) {
		select {
		case candidate, ok := <-candidates:
			if !ok || candidate == nil {
				return nil, fmt.Errorf("invalid CV V2 certified candidate channel")
			}
			return candidate, nil
		case result := <-results:
			failed[result.proposer] = result.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	select {
	case candidate, ok := <-candidates:
		if ok && candidate != nil {
			return candidate, nil
		}
	default:
	}
	return nil, fmt.Errorf("all sampled CV V2 proposer slots failed")
}

func runCVProposerSlotV2(
	ctx context.Context, cfg Config, runtime *cvEpochRuntimeV2, service *cvAPDBNetworkServiceV2,
	localOld, proposer int, contextDigest []byte, shardBytes int,
) error {
	if ctx == nil || runtime == nil || service == nil || !cvContainsID(runtime.context.OldRoster, proposer) {
		return fmt.Errorf("invalid CV V2 proposer slot")
	}
	var pool *cvPoolV2
	var poolCert *cvPoolCertificateV2
	var err error
	if localOld == proposer {
		refs, waitErr := service.AwaitVerifiedComponentCatalogV2(ctx)
		if waitErr != nil {
			return waitErr
		}
		pool, err = cvBuildPoolV2(contextDigest, proposer, refs, runtime.params)
		if err == nil {
			poolCert, err = service.CertifyPool(ctx, pool)
		}
	} else {
		pool, poolCert, err = service.AwaitCertifiedPool(ctx, proposer)
	}
	if err != nil {
		return fmt.Errorf("certify CV V2 proposer %d Pool: %w", proposer, err)
	}
	contributorCoin, err := service.ContributorCoin(ctx, pool, poolCert)
	if err != nil {
		return fmt.Errorf("collect CV V2 proposer %d contributor coin: %w", proposer, err)
	}
	selected, err := cvSelectedPoolIndicesV2(runtime.params.poolSize, runtime.params.componentCount, contributorCoin.Value)
	if err != nil {
		return err
	}

	var request *cvValidationRequestV2
	var vCert *cvValidationCertificateV2
	if localOld == proposer {
		leaves, selectedErr := service.VerifiedComponentLeavesV2(pool, selected)
		if selectedErr != nil {
			return selectedErr
		}
		aggregate, aggregateErr := cvAggVerifiedV2(leaves, runtime.context, runtime.params)
		if aggregateErr != nil {
			return aggregateErr
		}
		aggregatePayload, aggregateErr := cvAggregateV2CanonicalBytesAfterValidation(
			aggregate, runtime.context, runtime.params,
		)
		if aggregateErr != nil {
			return aggregateErr
		}
		selectionDigest, aggregateErr := cvSelectionDigestV2(
			contributorCoin, selected, runtime.params.poolSize, runtime.params.componentCount,
		)
		if aggregateErr != nil {
			return aggregateErr
		}
		aggregateInstance, aggregateErr := cvAggregateInstanceDigestV2(contextDigest, proposer, pool.Digest, selectionDigest)
		if aggregateErr != nil {
			return aggregateErr
		}
		aggregateEncoded, aggregateErr := cvAPDBEncodeSizedV2(
			aggregateInstance, aggregatePayload, runtime.params.recoveryThreshold,
			len(cfg.OldCommittee), shardBytes, cvMaxLeafWireBytes,
		)
		if aggregateErr != nil {
			return aggregateErr
		}
		arc, aggregateErr := service.LockAggregate(ctx, aggregateEncoded)
		if aggregateErr != nil {
			return aggregateErr
		}
		payloadDigest, aggregateErr := cvAggregatePayloadDigestV2(aggregatePayload)
		if aggregateErr != nil {
			return aggregateErr
		}
		header := cvAggregateHeaderV2{
			ContextDigest: contextDigest, ProposerID: proposer, PoolDigest: append([]byte(nil), pool.Digest...),
			SelectionDigest: selectionDigest, AggregateDigest: append([]byte(nil), aggregate.Digest...),
			PayloadDigest: payloadDigest, APDBInstance: aggregateInstance, APDBRoot: append([]byte(nil), arc.Root...),
		}
		request = &cvValidationRequestV2{
			Header: header, Pool: *pool, PoolCert: *poolCert, ContributorCoin: *contributorCoin,
			SelectedIndices: selected, ARC: *arc,
		}
		vCert, err = service.CertifyAggregate(ctx, request)
	} else {
		request, vCert, err = service.AwaitCertifiedValidationV2(ctx, proposer)
	}
	if err != nil {
		return fmt.Errorf("certify CV V2 proposer %d aggregate: %w", proposer, err)
	}
	candidate := &cvAgreementObjectV2{
		Header: request.Header, Pool: request.Pool, PoolCert: request.PoolCert,
		ContributorCoin: request.ContributorCoin, SelectedIndices: append([]int(nil), request.SelectedIndices...),
		VCert: *vCert, ARC: request.ARC,
	}
	return service.PublishCertifiedCandidateV2(ctx, candidate)
}
