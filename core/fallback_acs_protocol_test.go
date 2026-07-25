package core

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"
)

type probeTransport struct {
	mu sync.RWMutex

	inbox map[int]chan Message

	sent      []Message
	delivered []Message
	dropped   int

	failFn func(Message) error
	dropFn func(Message) bool
}

func newProbeTransport(
	nodes []int,
	buffer int,
	failFn func(Message) error,
	dropFn func(Message) bool,
) *probeTransport {
	if buffer <= 0 {
		buffer = 1024
	}
	inbox := make(map[int]chan Message, len(nodes))
	for _, id := range nodes {
		inbox[id] = make(chan Message, buffer)
	}
	return &probeTransport{
		inbox:  inbox,
		failFn: failFn,
		dropFn: dropFn,
	}
}

func (t *probeTransport) RecvChan(id int) (<-chan Message, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	ch, ok := t.inbox[id]
	if !ok {
		return nil, fmt.Errorf("node %d not registered", id)
	}
	return ch, nil
}

func (t *probeTransport) Send(msg Message) error {
	t.mu.Lock()
	t.sent = append(t.sent, cloneMessage(msg))
	failFn := t.failFn
	dropFn := t.dropFn
	ch, ok := t.inbox[msg.To]
	t.mu.Unlock()

	if !ok {
		return fmt.Errorf("node %d not registered", msg.To)
	}
	if failFn != nil {
		if err := failFn(msg); err != nil {
			return err
		}
	}
	if dropFn != nil && dropFn(msg) {
		t.mu.Lock()
		t.dropped++
		t.mu.Unlock()
		return nil
	}

	ch <- cloneMessage(msg)

	t.mu.Lock()
	t.delivered = append(t.delivered, cloneMessage(msg))
	t.mu.Unlock()
	return nil
}

func (t *probeTransport) Broadcast(from int, to []int, tag string, body []byte) {
	for _, id := range to {
		_ = t.Send(Message{
			From: from,
			To:   id,
			Tag:  tag,
			Body: append([]byte(nil), body...),
		})
	}
}

func (t *probeTransport) Close() error { return nil }

func (t *probeTransport) tagCount(tag string) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	count := 0
	for _, msg := range t.sent {
		if msg.Tag == tag {
			count++
		}
	}
	return count
}

func (t *probeTransport) sentMessagesByTag(tag string) []Message {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Message, 0)
	for _, msg := range t.sent {
		if msg.Tag == tag {
			out = append(out, cloneMessage(msg))
		}
	}
	return out
}

func (t *probeTransport) droppedCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.dropped
}

func cloneMessage(msg Message) Message {
	out := msg
	out.Body = append([]byte(nil), msg.Body...)
	return out
}

func buildRBCFixture(t *testing.T, cfg Config) (map[int]Descriptor, map[int]*DealerArtifact, map[int]descriptorProposal, int) {
	t.Helper()
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	descriptors := make(map[int]Descriptor, len(artifacts))
	ready := make([]int, 0, len(artifacts))
	for dealer, art := range artifacts {
		descriptors[dealer] = art.Descriptor
		if ValidateDescriptor(cfg, art.Descriptor) {
			ready = append(ready, dealer)
		}
	}
	sort.Ints(ready)

	required := cfg.F + 1
	if required <= 0 {
		required = 1
	}
	targetSize := cfg.Kappa
	if targetSize < required {
		targetSize = required
	}
	if targetSize > len(cfg.runtime.oldOrder) {
		targetSize = len(cfg.runtime.oldOrder)
	}
	if len(ready) < targetSize && len(ready) >= required {
		targetSize = len(ready)
	}

	proposals := make(map[int]descriptorProposal, len(cfg.runtime.oldOrder))
	for _, node := range cfg.runtime.oldOrder {
		candidate := stableFirst(ready, targetSize)
		if len(candidate) < required {
			candidate = stableFirst(cfg.runtime.oldOrder, required)
		}
		candidate = normalizeCandidate(candidate, targetSize, cfg.runtime.oldOrder)
		blob, bErr := BuildFallbackAggRLOProposal(cfg, candidate, artifacts)
		if bErr != nil {
			t.Fatalf("BuildFallbackAggRLOProposal failed: %v", bErr)
		}
		proposals[node] = descriptorProposal{
			Set:    candidate,
			Blob:   blob,
			Digest: rbcDigest(cfg.SID, node, blob),
		}
	}
	return descriptors, artifacts, proposals, targetSize
}

func withFallbackACSTransportFactoryForTest(
	t *testing.T,
	fn func(cfg Config, nodes []int, buffer int) (agreementTransport, error),
) {
	t.Helper()
	prev := fallbackACSTransportFactory
	fallbackACSTransportFactory = fn
	t.Cleanup(func() {
		fallbackACSTransportFactory = prev
	})
}

func TestRunBinaryABAForDealer_UsesESTAUXCONFAndCoinShareMessages(t *testing.T) {
	cfg := baseTestConfig()
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensureRuntime failed: %v", err)
	}
	probe := newProbeTransport(cfg.runtime.oldOrder, 4096, nil, nil)
	withFallbackACSTransportFactoryForTest(t, func(_ Config, _ []int, _ int) (agreementTransport, error) {
		return probe, nil
	})

	inputBits := make(map[int]int, len(cfg.runtime.oldOrder))
	for _, id := range cfg.runtime.oldOrder {
		inputBits[id] = id & 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runBinaryABAForDealer(ctx, cfg, cfg.runtime.oldOrder[0], inputBits)
	if err != nil {
		t.Fatalf("runBinaryABAForDealer failed: %v", err)
	}
	if len(out) != len(cfg.runtime.oldOrder) {
		t.Fatalf("unexpected output size: got=%d want=%d", len(out), len(cfg.runtime.oldOrder))
	}
	for _, tag := range []string{"ABA_EST", "ABA_AUX", "ABA_CONF", "ABA_COIN_SHARE"} {
		if probe.tagCount(tag) == 0 {
			t.Fatalf("expected ABA to send %s messages, but count is zero", tag)
		}
	}
}

func TestRunRBCAll_ReturnsErrorWhenRelayBroadcastFails(t *testing.T) {
	cfg := baseTestConfig()
	cfg.WaitSPBCTimeout = 20 * time.Millisecond
	cfg.SendRetryMax = 1
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensureRuntime failed: %v", err)
	}
	descriptors, artifacts, proposals, targetSize := buildRBCFixture(t, cfg)

	probe := newProbeTransport(cfg.runtime.oldOrder, 4096, func(msg Message) error {
		if msg.Tag == "RBC_ECHO" {
			return errors.New("injected echo relay send failure")
		}
		return nil
	}, nil)
	withFallbackACSTransportFactoryForTest(t, func(_ Config, _ []int, _ int) (agreementTransport, error) {
		return probe, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := runRBCAll(ctx, cfg, descriptors, artifacts, proposals, targetSize); err == nil {
		t.Fatalf("expected runRBCAll to fail when RBC_ECHO relay broadcast fails")
	}
	if probe.tagCount("RBC_ECHO") == 0 {
		t.Fatalf("test did not exercise RBC_ECHO relay path")
	}
}

func TestRunBinaryABAForDealer_CoinThresholdWorksWhenSomeSharesDropped(t *testing.T) {
	cfg := baseTestConfig()
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensureRuntime failed: %v", err)
	}
	dropFrom := cfg.runtime.oldOrder[len(cfg.runtime.oldOrder)-1]
	probe := newProbeTransport(cfg.runtime.oldOrder, 4096, nil, func(msg Message) bool {
		return msg.Tag == "ABA_COIN_SHARE" && msg.From == dropFrom
	})
	withFallbackACSTransportFactoryForTest(t, func(_ Config, _ []int, _ int) (agreementTransport, error) {
		return probe, nil
	})

	inputBits := make(map[int]int, len(cfg.runtime.oldOrder))
	for _, id := range cfg.runtime.oldOrder {
		inputBits[id] = 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := runBinaryABAForDealer(ctx, cfg, cfg.runtime.oldOrder[0], inputBits); err != nil {
		t.Fatalf("runBinaryABAForDealer failed with dropped coin shares: %v", err)
	}
	if probe.tagCount("ABA_COIN_SHARE") == 0 {
		t.Fatalf("expected ABA_COIN_SHARE message flow")
	}
	if probe.droppedCount() == 0 {
		t.Fatalf("expected test transport to drop some coin share messages")
	}
}

type restrictedProbeTransport struct {
	*probeTransport
	local map[int]struct{}
}

func newRestrictedProbeTransport(allNodes []int, localNodes []int, buffer int) *restrictedProbeTransport {
	local := make(map[int]struct{}, len(localNodes))
	for _, id := range localNodes {
		local[id] = struct{}{}
	}
	return &restrictedProbeTransport{
		probeTransport: newProbeTransport(allNodes, buffer, nil, nil),
		local:          local,
	}
}

func (t *restrictedProbeTransport) RecvChan(id int) (<-chan Message, error) {
	if _, ok := t.local[id]; !ok {
		return nil, fmt.Errorf("remote recv not allowed for node %d", id)
	}
	return t.probeTransport.RecvChan(id)
}

func injectTestMessage(t *testing.T, probe *restrictedProbeTransport, msg Message) {
	t.Helper()
	probe.mu.RLock()
	ch, ok := probe.inbox[msg.To]
	probe.mu.RUnlock()
	if !ok {
		t.Fatalf("missing inbox for node %d", msg.To)
	}
	ch <- cloneMessage(msg)
}

func TestRunRBCAll_LocalNodeSubsetDoesNotRequireRemoteRecvChan(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:          "rbc-local-subset",
		Epoch:        1,
		OldCommittee: []int{0, 1},
		NewCommittee: []int{0, 1},
		F:            0,
		LocalNodeIDs: []int{0},
	})
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensureRuntime failed: %v", err)
	}
	descriptors, artifacts, proposals, targetSize := buildRBCFixture(t, cfg)
	probe := newRestrictedProbeTransport(cfg.runtime.oldOrder, cfg.LocalNodeIDs, 4096)
	withFallbackACSTransportFactoryForTest(t, func(_ Config, _ []int, _ int) (agreementTransport, error) {
		return probe, nil
	})

	localNode := cfg.LocalNodeIDs[0]
	for sender, prop := range proposals {
		dig := hex.EncodeToString(rbcDigest(cfg.SID, sender, prop.Blob))
		blobHex := hex.EncodeToString(prop.Blob)
		if sender != localNode {
			body, _ := json.Marshal(rbcInitMsg{Sender: sender, Blob: blobHex})
			injectTestMessage(t, probe, Message{From: sender, To: localNode, Tag: "RBC_INIT", Body: body})
		}
		echoBody, _ := json.Marshal(rbcEchoMsg{Sender: sender, Node: 1, Digest: dig, Blob: blobHex})
		readyBody, _ := json.Marshal(rbcReadyMsg{Sender: sender, Node: 1, Digest: dig, Blob: blobHex})
		injectTestMessage(t, probe, Message{From: 1, To: localNode, Tag: "RBC_ECHO", Body: echoBody})
		injectTestMessage(t, probe, Message{From: 1, To: localNode, Tag: "RBC_READY", Body: readyBody})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runRBCAll(ctx, cfg, descriptors, artifacts, proposals, targetSize)
	if err != nil {
		t.Fatalf("runRBCAll failed: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected only local receiver outputs, got=%d", len(out))
	}
	if _, ok := out[localNode]; !ok {
		t.Fatalf("missing local node output")
	}
}

func TestRunBinaryABAForDealer_LocalNodeSubsetDoesNotRequireRemoteRecvChan(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:          "aba-local-subset",
		Epoch:        1,
		OldCommittee: []int{0, 1},
		NewCommittee: []int{0, 1},
		F:            0,
		LocalNodeIDs: []int{0},
	})
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensureRuntime failed: %v", err)
	}
	probe := newRestrictedProbeTransport(cfg.runtime.oldOrder, cfg.LocalNodeIDs, 4096)
	withFallbackACSTransportFactoryForTest(t, func(_ Config, _ []int, _ int) (agreementTransport, error) {
		return probe, nil
	})

	localNode := cfg.LocalNodeIDs[0]
	dealer := cfg.runtime.oldOrder[0]
	round := 0
	for _, tagBody := range []struct {
		tag  string
		body []byte
	}{
		{tag: "ABA_EST", body: mustJSON(t, abaEstMsg{Dealer: dealer, Round: round, Node: 1, Bit: 1})},
		{tag: "ABA_AUX", body: mustJSON(t, abaAuxMsg{Dealer: dealer, Round: round, Node: 1, Bit: 1})},
		{tag: "ABA_CONF", body: mustJSON(t, abaConfMsg{Dealer: dealer, Round: round, Node: 1, Bits: []int{1}})},
	} {
		injectTestMessage(t, probe, Message{From: 1, To: localNode, Tag: tagBody.tag, Body: tagBody.body})
	}
	digest := hashBytes(
		[]byte("rladkr-aba-coin"),
		[]byte(cfg.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d|round=%d", cfg.Epoch, dealer, round)),
	)
	share, err := cfg.runtime.coinSigner.SignShare(1, "ABA_COIN", digest)
	if err != nil {
		t.Fatalf("remote coin share failed: %v", err)
	}
	injectTestMessage(t, probe, Message{
		From: 1,
		To:   localNode,
		Tag:  "ABA_COIN_SHARE",
		Body: mustJSON(t, abaCoinShareMsg{Dealer: dealer, Round: round, Node: 1, Sig: hex.EncodeToString(share)}),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runBinaryABAForDealer(ctx, cfg, dealer, map[int]int{localNode: 1})
	if err != nil {
		t.Fatalf("runBinaryABAForDealer failed: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected local-only aba output, got=%d", len(out))
	}
	if out[localNode] != 1 {
		t.Fatalf("expected local node to decide 1, got=%d", out[localNode])
	}
}

func TestRunBinaryABAForDealer_LocalNodeSubsetBuffersOutOfPhaseMessages(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:          "aba-local-buffering",
		Epoch:        1,
		OldCommittee: []int{0, 1},
		NewCommittee: []int{0, 1},
		F:            0,
		LocalNodeIDs: []int{0},
	})
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensureRuntime failed: %v", err)
	}
	probe := newRestrictedProbeTransport(cfg.runtime.oldOrder, cfg.LocalNodeIDs, 4096)
	withFallbackACSTransportFactoryForTest(t, func(_ Config, _ []int, _ int) (agreementTransport, error) {
		return probe, nil
	})

	localNode := cfg.LocalNodeIDs[0]
	dealer := cfg.runtime.oldOrder[0]
	round := 0
	digest := hashBytes(
		[]byte("rladkr-aba-coin"),
		[]byte(cfg.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d|round=%d", cfg.Epoch, dealer, round)),
	)
	share, err := cfg.runtime.coinSigner.SignShare(1, "ABA_COIN", digest)
	if err != nil {
		t.Fatalf("remote coin share failed: %v", err)
	}

	// Deliver future-phase messages before EST to mimic a faster remote process.
	for _, tagBody := range []struct {
		tag  string
		body []byte
	}{
		{tag: "ABA_AUX", body: mustJSON(t, abaAuxMsg{Dealer: dealer, Round: round, Node: 1, Bit: 1})},
		{tag: "ABA_CONF", body: mustJSON(t, abaConfMsg{Dealer: dealer, Round: round, Node: 1, Bits: []int{1}})},
		{tag: "ABA_COIN_SHARE", body: mustJSON(t, abaCoinShareMsg{Dealer: dealer, Round: round, Node: 1, Sig: hex.EncodeToString(share)})},
		{tag: "ABA_EST", body: mustJSON(t, abaEstMsg{Dealer: dealer, Round: round, Node: 1, Bit: 1})},
	} {
		injectTestMessage(t, probe, Message{From: 1, To: localNode, Tag: tagBody.tag, Body: tagBody.body})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runBinaryABAForDealer(ctx, cfg, dealer, map[int]int{localNode: 1})
	if err != nil {
		t.Fatalf("runBinaryABAForDealer failed with out-of-phase messages: %v", err)
	}
	if out[localNode] != 1 {
		t.Fatalf("expected local node to decide 1, got=%d", out[localNode])
	}
}

func TestRunRBCAll_LocalNodeSubsetOnlyInitiatesLocalRBCInit(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:          "rbc-local-init-only",
		Epoch:        1,
		OldCommittee: []int{0, 1},
		NewCommittee: []int{0, 1},
		F:            0,
		LocalNodeIDs: []int{0},
	})
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensureRuntime failed: %v", err)
	}
	descriptors, artifacts, proposals, targetSize := buildRBCFixture(t, cfg)
	localNode := cfg.LocalNodeIDs[0]
	probe := newProbeTransport(cfg.runtime.oldOrder, 4096, func(msg Message) error {
		if msg.Tag == "RBC_INIT" && msg.From != localNode {
			return fmt.Errorf("remote node %d must not originate RBC_INIT in local-subset mode", msg.From)
		}
		return nil
	}, nil)
	withFallbackACSTransportFactoryForTest(t, func(_ Config, _ []int, _ int) (agreementTransport, error) {
		return probe, nil
	})
	for sender, prop := range proposals {
		dig := hex.EncodeToString(rbcDigest(cfg.SID, sender, prop.Blob))
		blobHex := hex.EncodeToString(prop.Blob)
		if sender != localNode {
			injectTestMessage(t, &restrictedProbeTransport{probeTransport: probe, local: nodeSet(cfg.runtime.oldOrder)}, Message{
				From: sender,
				To:   localNode,
				Tag:  "RBC_INIT",
				Body: mustJSON(t, rbcInitMsg{Sender: sender, Blob: blobHex}),
			})
		}
		injectTestMessage(t, &restrictedProbeTransport{probeTransport: probe, local: nodeSet(cfg.runtime.oldOrder)}, Message{
			From: 1,
			To:   localNode,
			Tag:  "RBC_ECHO",
			Body: mustJSON(t, rbcEchoMsg{Sender: sender, Node: 1, Digest: dig, Blob: blobHex}),
		})
		injectTestMessage(t, &restrictedProbeTransport{probeTransport: probe, local: nodeSet(cfg.runtime.oldOrder)}, Message{
			From: 1,
			To:   localNode,
			Tag:  "RBC_READY",
			Body: mustJSON(t, rbcReadyMsg{Sender: sender, Node: 1, Digest: dig, Blob: blobHex}),
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runRBCAll(ctx, cfg, descriptors, artifacts, proposals, targetSize)
	if err != nil {
		t.Fatalf("runRBCAll failed: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected one local output, got=%d", len(out))
	}
	initMsgs := probe.sentMessagesByTag("RBC_INIT")
	if len(initMsgs) == 0 {
		t.Fatalf("expected local RBC_INIT traffic")
	}
	for _, msg := range initMsgs {
		if msg.From != localNode {
			t.Fatalf("unexpected remote RBC_INIT origin: from=%d local=%d", msg.From, localNode)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal failed: %v", err)
	}
	return body
}
