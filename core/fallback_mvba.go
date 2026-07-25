package core

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type descriptorProposal struct {
	Set    []int
	Blob   []byte
	Digest []byte
}

type fallbackProposalMsg struct {
	Round int    `json:"round"`
	Node  int    `json:"node"`
	Blob  string `json:"blob"`
}

type fallbackLeaderMsg struct {
	Round int    `json:"round"`
	Blob  string `json:"blob"`
}

type fallbackVoteMsg struct {
	Round  int    `json:"round"`
	Node   int    `json:"node"`
	Digest string `json:"digest"`
	Set    []int  `json:"set"`
}

func traceFallbackMVBA(cfg Config, node int, round int, phase string, start time.Time, detail string) {
	if strings.TrimSpace(os.Getenv("RLADKR_FALLBACK_TRACE")) == "" {
		return
	}
	fmt.Fprintf(
		os.Stderr,
		"RLADKR_FALLBACK_TRACE sid=%s node=%d round=%d phase=%s ms=%.2f detail=%s\n",
		cfg.SID,
		node,
		round,
		phase,
		float64(time.Since(start).Microseconds())/1000.0,
		detail,
	)
}

func runFallbackLegacyMVBA(
	ctx context.Context,
	cfg Config,
	descriptors map[int]Descriptor,
	artifacts map[int]*DealerArtifact,
) ([]int, []NodeOutput, error) {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, nil, err
	}
	if c.runtime == nil {
		return nil, nil, fmt.Errorf("runtime not initialized")
	}
	start := time.Now()
	required := c.F + 1
	if required <= 0 {
		required = 1
	}
	targetSize := c.Kappa
	if targetSize < required {
		targetSize = required
	}
	if targetSize > len(c.runtime.oldOrder) {
		targetSize = len(c.runtime.oldOrder)
	}
	proposals := make(map[int]descriptorProposal, len(c.runtime.oldOrder))
	seed := fallbackSeedDealers(c, descriptors, artifacts)
	for _, nodeID := range c.runtime.oldOrder {
		p := append([]int(nil), seed...)
		buildStart := time.Now()
		blob, bErr := BuildFallbackAggRLOProposal(c, p, artifacts)
		if bErr != nil {
			return nil, nil, bErr
		}
		traceFallbackMVBA(c, nodeID, 0, "initial_proposal_build", buildStart, fmt.Sprintf("dealers=%d", len(p)))
		proposals[nodeID] = descriptorProposal{
			Set:    p,
			Blob:   blob,
			Digest: digestFallbackBlob(c.SID, 0, blob),
		}
	}

	maxRounds := c.MVBARounds
	if maxRounds <= 0 {
		maxRounds = 3
	}
	threshold := len(c.runtime.oldOrder) - c.F
	if threshold <= 0 {
		threshold = 1
	}

	decided := []int(nil)
	decidedByNode := make(map[int][]int, len(c.runtime.oldOrder))
	for round := 0; round < maxRounds; round++ {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		leader := leaderForRound(c.SID, c.runtime.oldOrder, round)
		transport, err := newAgreementTransport(c, c.runtime.oldOrder, len(c.runtime.oldOrder)*24)
		if err != nil {
			return nil, nil, err
		}

		type roundOut struct {
			node     int
			decision descriptorProposal
			err      error
		}
		localNodes := c.LocalNodeIDs
		if len(localNodes) == 0 {
			localNodes = c.runtime.oldOrder
		}
		outCh := make(chan roundOut, len(localNodes))
		var wg sync.WaitGroup
		for _, nodeID := range localNodes {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				decision, runErr := runFallbackRoundNode(
					ctx,
					c,
					id,
					leader,
					round,
					targetSize,
					threshold,
					descriptors,
					artifacts,
					proposals[id],
					transport,
				)
				outCh <- roundOut{node: id, decision: decision, err: runErr}
			}(nodeID)
		}
		wg.Wait()
		_ = transport.Close()

		votes := make(map[string]int, len(localNodes))
		setByDigest := make(map[string][]int, len(localNodes))
		nextProps := make(map[int]descriptorProposal, len(c.runtime.oldOrder))
		for _, nodeID := range c.runtime.oldOrder {
			nextProps[nodeID] = proposals[nodeID]
		}
		for i := 0; i < len(localNodes); i++ {
			out := <-outCh
			if out.err != nil {
				return nil, nil, out.err
			}
			nextProps[out.node] = out.decision
			key := hex.EncodeToString(out.decision.Digest)
			votes[key]++
			setByDigest[key] = append([]int(nil), out.decision.Set...)
			decidedByNode[out.node] = append([]int(nil), out.decision.Set...)
		}
		proposals = nextProps
		if set, ok := pickThresholdSet(votes, setByDigest, threshold); ok {
			decided = normalizeCandidate(set, targetSize, c.runtime.oldOrder)
			break
		}
	}
	if len(decided) == 0 {
		decided = normalizeCandidate(mergeProposalSets(proposals, targetSize), targetSize, c.runtime.oldOrder)
	}

	localNodes := c.LocalNodeIDs
	if len(localNodes) == 0 {
		localNodes = c.runtime.oldOrder
	}
	perNode := make([]NodeOutput, 0, len(localNodes))
	for _, nodeID := range localNodes {
		perNodeSet := decidedByNode[nodeID]
		if len(perNodeSet) == 0 {
			perNodeSet = decided
		}
		perNode = append(perNode, NodeOutput{
			NodeID:     nodeID,
			DecidedSet: append([]int(nil), perNodeSet...),
			Latency:    time.Since(start),
		})
	}
	return decided, perNode, nil
}

func runFallbackRoundNode(
	ctx context.Context,
	cfg Config,
	node int,
	leader int,
	round int,
	targetSize int,
	threshold int,
	descriptors map[int]Descriptor,
	artifacts map[int]*DealerArtifact,
	local descriptorProposal,
	transport agreementTransport,
) (descriptorProposal, error) {
	ch, err := transport.RecvChan(node)
	if err != nil {
		return descriptorProposal{}, err
	}
	roundTimeout := cfg.WaitSPBCTimeout
	if roundTimeout <= 0 {
		roundTimeout = 2 * time.Second
	}
	leaderProposalTarget := len(cfg.runtime.oldOrder) - cfg.F
	if leaderProposalTarget <= 0 {
		leaderProposalTarget = 1
	}
	if node != leader {
		wire := fallbackProposalMsg{
			Round: round,
			Node:  node,
			Blob:  hex.EncodeToString(local.Blob),
		}
		body, mErr := json.Marshal(wire)
		if mErr != nil {
			return descriptorProposal{}, mErr
		}
		if err := sendWithRetry(cfg, transport, Message{
			From: node,
			To:   leader,
			Tag:  "FB_PROPOSE",
			Body: body,
		}); err != nil {
			return descriptorProposal{}, err
		}
	}

	var candidate []int
	var candidateBlob []byte
	if node == leader {
		leaderPool := make([]descriptorProposal, 0, len(cfg.runtime.oldOrder))
		leaderPool = append(leaderPool, local)
		deadline := time.Now().Add(roundTimeout)
		collectStart := time.Now()
		for len(leaderPool) < leaderProposalTarget && time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return descriptorProposal{}, ctx.Err()
			default:
			}
			msg, ok := recvMessageWithTimeout(ch, time.Until(deadline))
			if !ok || msg.Tag != "FB_PROPOSE" {
				continue
			}
			var wire fallbackProposalMsg
			if err := json.Unmarshal(msg.Body, &wire); err != nil {
				continue
			}
			blob, err := hex.DecodeString(wire.Blob)
			if err != nil {
				continue
			}
			validateStart := time.Now()
			set, err := ValidateFallbackAggRLOProposal(blob, cfg, targetSize, artifacts)
			if err != nil {
				continue
			}
			traceFallbackMVBA(cfg, node, round, "leader_validate_proposal", validateStart, fmt.Sprintf("from=%d dealers=%d", wire.Node, len(set)))
			leaderPool = append(leaderPool, descriptorProposal{
				Set:    set,
				Blob:   blob,
				Digest: digestFallbackBlob(cfg.SID, round, blob),
			})
		}
		traceFallbackMVBA(cfg, node, round, "leader_collect_proposals", collectStart, fmt.Sprintf("pool=%d target=%d", len(leaderPool), leaderProposalTarget))
		leaderChoice := chooseLeaderDescriptor(cfg.SID, round, leaderPool)
		candidate = append([]int(nil), leaderChoice.Set...)
		candidateBlob = append([]byte(nil), leaderChoice.Blob...)
		wire := fallbackLeaderMsg{
			Round: round,
			Blob:  hex.EncodeToString(candidateBlob),
		}
		body, mErr := json.Marshal(wire)
		if mErr != nil {
			return descriptorProposal{}, mErr
		}
		broadcastStart := time.Now()
		if err := broadcastWithRetry(cfg, transport, leader, cfg.runtime.oldOrder, "FB_LEADER", body); err != nil {
			return descriptorProposal{}, err
		}
		traceFallbackMVBA(cfg, node, round, "leader_broadcast", broadcastStart, fmt.Sprintf("peers=%d", len(cfg.runtime.oldOrder)-1))
	} else {
		deadline := time.Now().Add(roundTimeout)
		waitLeaderStart := time.Now()
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return descriptorProposal{}, ctx.Err()
			default:
			}
			msg, ok := recvMessageWithTimeout(ch, time.Until(deadline))
			if !ok || msg.Tag != "FB_LEADER" {
				continue
			}
			var wire fallbackLeaderMsg
			if err := json.Unmarshal(msg.Body, &wire); err != nil {
				continue
			}
			blob, err := hex.DecodeString(wire.Blob)
			if err != nil {
				continue
			}
			validateStart := time.Now()
			set, err := ValidateFallbackAggRLOProposal(blob, cfg, targetSize, artifacts)
			if err != nil {
				continue
			}
			traceFallbackMVBA(cfg, node, round, "follower_validate_leader", validateStart, fmt.Sprintf("leader=%d dealers=%d", leader, len(set)))
			candidate = set
			candidateBlob = blob
			break
		}
		traceFallbackMVBA(cfg, node, round, "follower_wait_leader", waitLeaderStart, fmt.Sprintf("got=%t", len(candidate) > 0))
	}
	if len(candidate) == 0 {
		candidate = normalizeCandidate(local.Set, targetSize, cfg.runtime.oldOrder)
		buildStart := time.Now()
		blob, bErr := BuildFallbackAggRLOProposal(cfg, candidate, artifacts)
		if bErr != nil {
			return descriptorProposal{}, bErr
		}
		traceFallbackMVBA(cfg, node, round, "fallback_local_proposal_build", buildStart, fmt.Sprintf("dealers=%d", len(candidate)))
		candidateBlob = blob
	}

	dig := digestFallbackBlob(cfg.SID, round, candidateBlob)
	key := hex.EncodeToString(dig)
	voteWire := fallbackVoteMsg{
		Round:  round,
		Node:   node,
		Digest: key,
		Set:    append([]int(nil), candidate...),
	}
	voteBody, err := json.Marshal(voteWire)
	if err != nil {
		return descriptorProposal{}, err
	}
	voteBroadcastStart := time.Now()
	for _, id := range cfg.runtime.oldOrder {
		if id == node {
			continue
		}
		if err := sendWithRetry(cfg, transport, Message{
			From: node,
			To:   id,
			Tag:  "FB_VOTE",
			Body: voteBody,
		}); err != nil {
			return descriptorProposal{}, err
		}
	}
	traceFallbackMVBA(cfg, node, round, "vote_broadcast", voteBroadcastStart, fmt.Sprintf("peers=%d", len(cfg.runtime.oldOrder)-1))

	votes := map[string]int{key: 1}
	setByDigest := map[string][]int{key: append([]int(nil), candidate...)}
	voteDeadline := time.Now().Add(roundTimeout)
	voteCollectStart := time.Now()
	for time.Now().Before(voteDeadline) {
		select {
		case <-ctx.Done():
			return descriptorProposal{}, ctx.Err()
		default:
		}
		msg, ok := recvMessageWithTimeout(ch, time.Until(voteDeadline))
		if !ok || msg.Tag != "FB_VOTE" {
			continue
		}
		var wire fallbackVoteMsg
		if err := json.Unmarshal(msg.Body, &wire); err != nil {
			continue
		}
		if len(wire.Set) == 0 {
			continue
		}
		normalized := normalizeCandidate(wire.Set, targetSize, cfg.runtime.oldOrder)
		votes[wire.Digest]++
		if _, exists := setByDigest[wire.Digest]; !exists {
			setByDigest[wire.Digest] = normalized
		}
		if votes[wire.Digest] >= threshold {
			traceFallbackMVBA(cfg, node, round, "vote_collect_threshold", voteCollectStart, fmt.Sprintf("digest_votes=%d threshold=%d", votes[wire.Digest], threshold))
			candidate = normalizeCandidate(setByDigest[wire.Digest], targetSize, cfg.runtime.oldOrder)
			buildStart := time.Now()
			blob, bErr := BuildFallbackAggRLOProposal(cfg, candidate, artifacts)
			if bErr != nil {
				return descriptorProposal{}, bErr
			}
			traceFallbackMVBA(cfg, node, round, "threshold_proposal_rebuild", buildStart, fmt.Sprintf("dealers=%d", len(candidate)))
			candidateBlob = blob
			dig = digestFallbackBlob(cfg.SID, round, candidateBlob)
			return descriptorProposal{
				Set:    append([]int(nil), candidate...),
				Blob:   append([]byte(nil), candidateBlob...),
				Digest: append([]byte(nil), dig...),
			}, nil
		}
	}
	traceFallbackMVBA(cfg, node, round, "vote_collect_end", voteCollectStart, fmt.Sprintf("vote_sets=%d", len(setByDigest)))
	if set, ok := pickThresholdSet(votes, setByDigest, threshold); ok {
		candidate = normalizeCandidate(set, targetSize, cfg.runtime.oldOrder)
		buildStart := time.Now()
		blob, bErr := BuildFallbackAggRLOProposal(cfg, candidate, artifacts)
		if bErr != nil {
			return descriptorProposal{}, bErr
		}
		traceFallbackMVBA(cfg, node, round, "final_threshold_rebuild", buildStart, fmt.Sprintf("dealers=%d", len(candidate)))
		candidateBlob = blob
		dig = digestFallbackBlob(cfg.SID, round, candidateBlob)
	} else if len(setByDigest) > 0 {
		coinSet := coinSelectFallbackSet(cfg.SID, cfg.Epoch, round, setByDigest, targetSize, cfg.runtime.oldOrder)
		candidate = coinSet
		buildStart := time.Now()
		blob, bErr := BuildFallbackAggRLOProposal(cfg, candidate, artifacts)
		if bErr != nil {
			return descriptorProposal{}, bErr
		}
		traceFallbackMVBA(cfg, node, round, "coinset_rebuild", buildStart, fmt.Sprintf("dealers=%d", len(candidate)))
		candidateBlob = blob
		dig = digestFallbackBlob(cfg.SID, round, candidateBlob)
	}
	return descriptorProposal{
		Set:    append([]int(nil), candidate...),
		Blob:   append([]byte(nil), candidateBlob...),
		Digest: append([]byte(nil), dig...),
	}, nil
}

func chooseLeaderDescriptor(sid string, round int, pool []descriptorProposal) descriptorProposal {
	if len(pool) == 0 {
		return descriptorProposal{}
	}
	sort.Slice(pool, func(i, j int) bool {
		di := hex.EncodeToString(pool[i].Digest)
		dj := hex.EncodeToString(pool[j].Digest)
		if di == dj {
			return len(pool[i].Set) < len(pool[j].Set)
		}
		return di < dj
	})
	return pool[0]
}

func mergeProposalSets(proposals map[int]descriptorProposal, k int) []int {
	uniq := make(map[int]struct{})
	for _, p := range proposals {
		for _, id := range p.Set {
			uniq[id] = struct{}{}
		}
	}
	all := make([]int, 0, len(uniq))
	for id := range uniq {
		all = append(all, id)
	}
	sort.Ints(all)
	if len(all) > k {
		all = all[:k]
	}
	return all
}

func normalizeCandidate(candidate []int, target int, universe []int) []int {
	seen := make(map[int]struct{}, len(candidate))
	out := make([]int, 0, target)
	valid := make(map[int]struct{}, len(universe))
	for _, id := range universe {
		valid[id] = struct{}{}
	}
	for _, id := range sortedCopy(candidate) {
		if _, ok := valid[id]; !ok {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
		if len(out) >= target {
			return out
		}
	}
	for _, id := range sortedCopy(universe) {
		if len(out) >= target {
			break
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func digestFallbackBlob(sid string, round int, blob []byte) []byte {
	return hashBytes(
		[]byte("rladkr-fallback-vote"),
		[]byte(sid),
		[]byte(fmt.Sprintf("|round=%d", round)),
		blob,
	)
}

func leaderForRound(sid string, oldIDs []int, round int) int {
	n := len(oldIDs)
	if n == 0 {
		return -1
	}
	seed := sha256.Sum256([]byte(fmt.Sprintf("%s|fallback|%d", sid, round)))
	idx := int(binary.BigEndian.Uint64(seed[:8]) % uint64(n))
	return oldIDs[idx]
}

func pickThresholdSet(votes map[string]int, setByDigest map[string][]int, threshold int) ([]int, bool) {
	bestKey := ""
	bestVotes := -1
	for key, cnt := range votes {
		if cnt > bestVotes || (cnt == bestVotes && key < bestKey) {
			bestVotes = cnt
			bestKey = key
		}
	}
	if bestVotes < threshold {
		return nil, false
	}
	set := setByDigest[bestKey]
	return append([]int(nil), set...), true
}

func coinSelectFallbackSet(
	sid string,
	epoch int,
	round int,
	setByDigest map[string][]int,
	targetSize int,
	universe []int,
) []int {
	keys := make([]string, 0, len(setByDigest))
	for k := range setByDigest {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return normalizeCandidate(universe, targetSize, universe)
	}
	coin := hashBytes(
		[]byte("rladkr-fallback-coin"),
		[]byte(sid),
		[]byte(fmt.Sprintf("|epoch=%d|round=%d", epoch, round)),
	)
	idx := int(binary.BigEndian.Uint64(coin[:8]) % uint64(len(keys)))
	chosen := keys[idx]
	return normalizeCandidate(setByDigest[chosen], targetSize, universe)
}
