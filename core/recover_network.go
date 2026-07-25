package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type recoverAggFragWire struct {
	Response AggFragResponse `json:"response"`
}

func recoverResponseBroadcastParallelism(n int) int {
	switch {
	case n >= 192:
		return 8
	case n >= 128:
		return 12
	case n >= 96:
		return 16
	default:
		return 24
	}
}

func CollectAggFragResponses(
	ctx context.Context,
	cfg Config,
	rlo *AggRLO,
	artifacts map[int]*DealerArtifact,
) ([]AggFragResponse, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.RecoverResponseMode))
	if mode == "" || mode == "network" {
		if isListBackedAPVSSProvider(strings.ToLower(strings.TrimSpace(rlo.Aggregate.Provider))) {
			if recoverLocalFastPathEnabled() && hasCompleteLocalAggFragMaterial(rlo, artifacts) {
				return BuildAggFragResponses(cfg, rlo, artifacts)
			}
			return collectAggFragResponsesNetwork(ctx, cfg, rlo, artifacts)
		}
	}
	return BuildAggFragResponses(cfg, rlo, artifacts)
}

func recoverLocalFastPathEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("RLADKR_RECOVER_LOCAL_FASTPATH")))
	return v == "1" || v == "true" || v == "on"
}

func hasCompleteLocalAggFragMaterial(rlo *AggRLO, artifacts map[int]*DealerArtifact) bool {
	if rlo == nil || rlo.Aggregate.ListTranscript == nil {
		return false
	}
	tx := rlo.Aggregate.ListTranscript
	for _, dealer := range sortedUnique(rlo.Header.Dealers) {
		art, ok := artifacts[dealer]
		if !ok || art == nil {
			return false
		}
		if len(tx.ContributionDigests[dealer]) == 0 {
			return false
		}
	}
	return true
}

func collectAggFragResponsesNetwork(
	ctx context.Context,
	cfg Config,
	rlo *AggRLO,
	artifacts map[int]*DealerArtifact,
) ([]AggFragResponse, error) {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	if c.runtime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}
	transport := c.protocolTransport
	closeTransport := false
	if transport == nil {
		var err error
		transport, err = newAgreementTransport(c, c.runtime.oldOrder, len(c.runtime.oldOrder)*32)
		if err != nil {
			return nil, err
		}
		closeTransport = true
	}
	if closeTransport {
		defer transport.Close()
	}

	localNodes := sortedUnique(c.LocalNodeIDs)
	if len(localNodes) == 0 {
		localNodes = sortedUnique(c.runtime.oldOrder)
	}
	chans := make(map[int]<-chan Message, len(localNodes))
	for _, node := range localNodes {
		ch, chErr := transport.RecvChan(node)
		if chErr != nil {
			return nil, chErr
		}
		chans[node] = ch
	}

	localDealerSet := nodeSet(sortedUnique(c.LocalNodeIDs))
	localResponseDealers := make([]int, 0, len(rlo.Header.Dealers))
	for _, dealer := range sortedUnique(rlo.Header.Dealers) {
		if _, isLocal := localDealerSet[dealer]; isLocal {
			localResponseDealers = append(localResponseDealers, dealer)
		}
	}
	produced, err := buildAggFragResponsesForDealers(c, rlo, artifacts, localResponseDealers)
	if err != nil {
		return nil, err
	}
	respByDealer := make(map[int]AggFragResponse, len(produced))
	for _, resp := range produced {
		respByDealer[resp.Dealer] = resp
	}

	prevPhase := c.runtime.commPhaseName()
	c.runtime.setCommPhase("recover_response")
	defer c.runtime.setCommPhase(prevPhase)

	for _, dealer := range sortedUnique(rlo.Header.Dealers) {
		if _, isLocal := localDealerSet[dealer]; !isLocal {
			continue
		}
		resp, ok := respByDealer[dealer]
		if !ok {
			return nil, fmt.Errorf("missing local AggFrag response for dealer=%d", dealer)
		}
		body, mErr := json.Marshal(recoverAggFragWire{Response: resp})
		if mErr != nil {
			return nil, mErr
		}
		if err := broadcastWithRetryLimit(
			c,
			transport,
			dealer,
			c.runtime.oldOrder,
			"RECOVER_AGGFRAG_RESPONSE",
			body,
			recoverResponseBroadcastParallelism(len(c.runtime.oldOrder)),
		); err != nil {
			return nil, err
		}
	}

	targetDealers := sortedUnique(rlo.Header.Dealers)
	collected := make(map[int]AggFragResponse, len(targetDealers))
	for _, dealer := range targetDealers {
		if _, isLocal := localDealerSet[dealer]; !isLocal {
			continue
		}
		if resp, ok := respByDealer[dealer]; ok {
			collected[dealer] = resp
		}
	}

	deadline := time.Now().Add(4 * c.WaitSPBCTimeout)
	if c.WaitSPBCTimeout <= 0 {
		deadline = time.Now().Add(8 * time.Second)
	}
	for len(collected) < len(targetDealers) && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		progress := false
		for _, node := range localNodes {
			msg, ok := recvMessageWithTimeout(chans[node], 20*time.Millisecond)
			if !ok {
				continue
			}
			if msg.Tag != "RECOVER_AGGFRAG_RESPONSE" {
				continue
			}
			var wire recoverAggFragWire
			if err := json.Unmarshal(msg.Body, &wire); err != nil {
				continue
			}
			if wire.Response.Provider == "" {
				continue
			}
			if !containsInt(targetDealers, wire.Response.Dealer) {
				continue
			}
			if _, exists := collected[wire.Response.Dealer]; exists {
				continue
			}
			collected[wire.Response.Dealer] = wire.Response
			progress = true
		}
		if progress {
			continue
		}
	}
	if len(collected) != len(targetDealers) {
		return nil, fmt.Errorf("recover response collection incomplete: have=%d want=%d", len(collected), len(targetDealers))
	}
	out := make([]AggFragResponse, 0, len(targetDealers))
	for _, dealer := range targetDealers {
		out = append(out, collected[dealer])
	}
	return out, nil
}
