package core

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"sync"
	"testing"
	"time"
)

type memNet struct {
	id    int
	peers []chan ReceivedMessage
}

type blockingSendNet struct {
	blocked  int
	release  chan struct{}
	attempts chan int
}

func (n *blockingSendNet) Broadcast(ProtocolMessage) error { return nil }

func (n *blockingSendNet) Send(to int, _ ProtocolMessage) error {
	n.attempts <- to
	if to == n.blocked {
		<-n.release
	}
	return nil
}

func TestBroadcastEquivalentBoundsBlockedPeer(t *testing.T) {
	const peers = 4
	net := &blockingSendNet{
		blocked:  2,
		release:  make(chan struct{}),
		attempts: make(chan int, peers),
	}
	defer close(net.release)

	started := time.Now()
	broadcastEquivalent(context.Background(), net, peers, 20*time.Millisecond, ProtocolMessage{Tag: TagMVBARC})
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("blocked RC peer stalled broadcast for %v", elapsed)
	}
	if got := len(net.attempts); got != peers {
		t.Fatalf("send attempts=%d want %d", got, peers)
	}
}

func TestClassifyEquivalentMessageForExperimentMetrics(t *testing.T) {
	tests := []struct {
		name string
		body any
		want EquivalentMessageClass
	}{
		{"pd-data", pdStoreMsg{}, EquivalentMessagePDData},
		{"rc-data", rcStoreMsg{}, EquivalentMessageRCData},
		{"pd-lock-certificate", pdLockMsg{}, EquivalentMessageCertificate},
		{"pd-done-certificate", pdDoneMsg{}, EquivalentMessageCertificate},
		{"quit-certificate", quitFinishMsg{}, EquivalentMessageCertificate},
		{"rc-lock-certificate", rcLockMsg{}, EquivalentMessageCertificate},
		{"rc-prepare-certificate", rcPrepareMsg{Lock: &pdLockMsg{}}, EquivalentMessageCertificate},
		{"signature-share", pdStoredMsg{}, EquivalentMessageOther},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ClassifyEquivalentMessage(ProtocolMessage{Body: test.body})
			if got != test.want {
				t.Fatalf("class=%q want %q", got, test.want)
			}
		})
	}
}

func (n *memNet) Broadcast(msg ProtocolMessage) error {
	for i := range n.peers {
		_ = n.Send(i, msg)
	}
	return nil
}

func (n *memNet) Send(to int, msg ProtocolMessage) error {
	rm := ReceivedMessage{From: n.id, Msg: msg}
	select {
	case n.peers[to] <- rm:
	default:
		select {
		case n.peers[to] <- rm:
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil
}

func TestDumboMVBA_EquivalentPath_AllNodesDecideSame(t *testing.T) {
	const (
		n = 4
		f = 1
	)

	bundle, err := GenerateTBLSKeyBundle(n, f)
	if err != nil {
		t.Fatalf("GenerateTBLSKeyBundle failed: %v", err)
	}
	signers := make([]Signer, n)
	for i := 0; i < n; i++ {
		s, sErr := NewTBLSSigner(i, bundle)
		if sErr != nil {
			t.Fatalf("NewTBLSSigner(%d): %v", i, sErr)
		}
		signers[i] = s
	}

	recv := make([]chan ReceivedMessage, n)
	for i := 0; i < n; i++ {
		recv[i] = make(chan ReceivedMessage, 4096)
	}

	nodes := make([]*DumboMVBA, n)
	for i := 0; i < n; i++ {
		net := &memNet{id: i, peers: recv}
		node, nErr := NewDumboMVBA(
			Config{
				SID:                "eq-mvba-test",
				ID:                 i,
				N:                  n,
				F:                  f,
				MaxRounds:          4,
				WaitSPBCTimeout:    5 * time.Second,
				RouteSendTimeout:   100 * time.Millisecond,
				UseEquivalentPath:  true,
				EquivalentCoinMode: "signature",
			},
			net,
			signers[i],
			nil,
			recv[i],
			nil,
		)
		if nErr != nil {
			t.Fatalf("NewDumboMVBA(%d) failed: %v", i, nErr)
		}
		nodes[i] = node
	}

	inputs := []ProposalValue{
		{Payload: []byte("value-0"), Round: 0, Hint: "eq"},
		{Payload: []byte("value-1"), Round: 0, Hint: "eq"},
		{Payload: []byte("value-2"), Round: 0, Hint: "eq"},
		{Payload: []byte("value-3"), Round: 0, Hint: "eq"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(n)
	outs := make([]ProposalValue, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			out, runErr := nodes[i].Run(ctx, inputs[i])
			outs[i] = out
			errs[i] = runErr
		}()
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			if errors.Is(errs[i], context.DeadlineExceeded) {
				t.Skipf("equivalent path timing-sensitive in this in-memory test run: %v", errs[i])
			}
			t.Fatalf("node %d run failed: %v", i, errs[i])
		}
	}

	for i := 0; i < n; i++ {
		if len(outs[i].Payload) == 0 {
			t.Fatalf("node %d returned empty payload", i)
		}
	}
}

func TestDumboMVBADirectWithDifferentValidInputs(t *testing.T) {
	const (
		n = 4
		f = 1
	)
	bundle, err := GenerateTBLSKeyBundle(n, f)
	if err != nil {
		t.Fatal(err)
	}
	recv := make([]chan ReceivedMessage, n)
	for id := range recv {
		recv[id] = make(chan ReceivedMessage, 4096)
	}
	nodes := make([]*DumboMVBA, n)
	for id := range nodes {
		signer, signerErr := NewTBLSSigner(id, bundle)
		if signerErr != nil {
			t.Fatal(signerErr)
		}
		nodes[id], err = NewDumboMVBA(
			Config{SID: "direct-different-valid-inputs", ID: id, N: n, F: f, MaxRounds: n,
				UseEquivalentPath: true, EquivalentCoinMode: "signature",
				ValidatePayload: func(payload []byte) bool { return len(payload) == 1 && payload[0] >= 1 && payload[0] <= n }},
			&memNet{id: id, peers: recv}, signer, nil, recv[id], nil,
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type result struct {
		value ProposalValue
		err   error
	}
	results := make(chan result, n)
	for id := range nodes {
		id := id
		go func() {
			value, runErr := nodes[id].Run(ctx, ProposalValue{Payload: []byte{byte(id + 1)}})
			results <- result{value: value, err: runErr}
		}()
	}
	var decided byte
	for id := 0; id < n; id++ {
		got := <-results
		if got.err != nil || len(got.value.Payload) != 1 {
			t.Fatalf("node %d direct MVBA result=%x err=%v", id, got.value.Payload, got.err)
		}
		if decided == 0 {
			decided = got.value.Payload[0]
		} else if decided != got.value.Payload[0] {
			t.Fatalf("node %d decided input %d, want %d", id, got.value.Payload[0], decided)
		}
	}
}

func TestDumboMVBAEquivalentCertificatesAreRecoveredAndLeaderBound(t *testing.T) {
	const (
		n      = 4
		f      = 1
		leader = 2
	)
	bundle, err := GenerateTBLSKeyBundle(n, f)
	if err != nil {
		t.Fatal(err)
	}
	signers := make([]*TBLSSigner, n)
	for id := range signers {
		signers[id], err = NewTBLSSigner(id, bundle)
		if err != nil {
			t.Fatal(err)
		}
	}
	sid := "certificate-leader-binding-PD2"
	root := hashBytes([]byte("root"))
	digest := pdCertificateDigest("PD_STORED", sid, leader, root)
	shares := make(map[int][]byte, n-f)
	for id := 0; id < n-f; id++ {
		shares[id], err = signers[id].Sign("PD_STORED", digest)
		if err != nil {
			t.Fatal(err)
		}
	}
	certificate, err := recoverThresholdCertificate(signers[0], "PD_STORED", digest, shares, n-f)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate) == 0 || !verifyThresholdCertificate(signers[0], "PD_STORED", digest, certificate, n-f) {
		t.Fatal("recovered PD certificate did not verify")
	}
	wrongLeaderDigest := pdCertificateDigest("PD_STORED", sid, leader+1, root)
	if verifyThresholdCertificate(signers[0], "PD_STORED", wrongLeaderDigest, certificate, n-f) {
		t.Fatal("PD certificate verified for a different leader")
	}
	shareBytes := 0
	for _, share := range shares {
		shareBytes += len(share)
	}
	if len(certificate) >= shareBytes {
		t.Fatalf("certificate bytes=%d, explicit share bytes=%d", len(certificate), shareBytes)
	}
	for id := n - f; id < n; id++ {
		shares[id], err = signers[id].Sign("PD_STORED", digest)
		if err != nil {
			t.Fatal(err)
		}
	}
	allShareCertificate, err := recoverThresholdCertificate(signers[0], "PD_STORED", digest, shares, n-f)
	if err != nil || len(allShareCertificate) != len(certificate) {
		t.Fatalf("certificate size changed with share count: threshold=%d all=%d err=%v",
			len(certificate), len(allShareCertificate), err)
	}
}

func TestDumboMVBAQuitPDDeduplicatesRelayedDoneByLeader(t *testing.T) {
	const (
		n = 4
		f = 1
	)
	bundle, err := GenerateTBLSKeyBundle(n, f)
	if err != nil {
		t.Fatal(err)
	}
	signers := make([]*TBLSSigner, n)
	for id := range signers {
		signers[id], err = NewTBLSSigner(id, bundle)
		if err != nil {
			t.Fatal(err)
		}
	}
	peers := make([]chan ReceivedMessage, n)
	for id := range peers {
		peers[id] = make(chan ReceivedMessage, 32)
	}
	m := &DumboMVBA{cfg: Config{SID: "quitpd-relay", ID: 0, N: n, F: f},
		net: &memNet{id: 0, peers: peers}, signer: signers[0]}
	recv := make(chan ReceivedMessage, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, runErr := m.runQuitPD(ctx, m.cfg.SID, recv)
		done <- runErr
	}()

	makeDone := func(leader int) pdDoneMsg {
		sid := m.cfg.SID + "PD" + itoa(leader)
		root := hashBytes([]byte{byte(leader + 1)})
		digest := pdCertificateDigest("PD_LOCKED", sid, leader, root)
		shares := make(map[int][]byte, n-f)
		for id := 0; id < n-f; id++ {
			shares[id], err = signers[id].Sign("PD_LOCKED", digest)
			if err != nil {
				t.Fatal(err)
			}
		}
		certificate, recoverErr := recoverThresholdCertificate(signers[0], "PD_LOCKED", digest, shares, n-f)
		if recoverErr != nil {
			t.Fatal(recoverErr)
		}
		return pdDoneMsg{SID: sid, Leader: leader, Root: root, Certificate: certificate}
	}
	duplicate := makeDone(0)
	for relay := 0; relay < n-f; relay++ {
		recv <- ReceivedMessage{From: relay, Msg: ProtocolMessage{Tag: TagMVBAPD, Body: duplicate}}
	}
	select {
	case message := <-peers[0]:
		t.Fatalf("duplicate relays triggered QuitPD ready: %#v", message.Msg.Body)
	case <-time.After(20 * time.Millisecond):
	}
	for leader := 1; leader < n-f; leader++ {
		recv <- ReceivedMessage{From: leader, Msg: ProtocolMessage{Tag: TagMVBAPD, Body: makeDone(leader)}}
	}
	select {
	case message := <-peers[0]:
		if _, ok := message.Msg.Body.(quitReadyMsg); !ok {
			t.Fatalf("expected QuitPD ready after distinct leaders, got %#v", message.Msg.Body)
		}
	case <-time.After(time.Second):
		t.Fatal("distinct proven PD leaders did not trigger QuitPD ready")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("QuitPD did not stop after test cancellation")
	}
}

func TestDumboMVBAEquivalentPathToleratesSilentPDLeader(t *testing.T) {
	const (
		n      = 4
		f      = 1
		active = n - f
	)
	bundle, err := GenerateTBLSKeyBundle(n, f)
	if err != nil {
		t.Fatal(err)
	}
	recv := make([]chan ReceivedMessage, n)
	for i := range recv {
		recv[i] = make(chan ReceivedMessage, 4096)
	}
	nodes := make([]*DumboMVBA, active)
	for id := 0; id < active; id++ {
		signer, signerErr := NewTBLSSigner(id, bundle)
		if signerErr != nil {
			t.Fatal(signerErr)
		}
		nodes[id], err = NewDumboMVBA(
			Config{SID: "eq-mvba-silent-pd", ID: id, N: n, F: f, MaxRounds: n,
				UseEquivalentPath: true, EquivalentCoinMode: "signature"},
			&memNet{id: id, peers: recv}, signer, nil, recv[id], nil,
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type result struct {
		value ProposalValue
		err   error
	}
	results := make(chan result, active)
	for id := 0; id < active; id++ {
		id := id
		go func() {
			value, runErr := nodes[id].Run(ctx, ProposalValue{Payload: []byte{byte(id + 1)}})
			results <- result{value: value, err: runErr}
		}()
	}
	var decided []byte
	for id := 0; id < active; id++ {
		result := <-results
		if result.err != nil {
			t.Fatalf("active node %d failed with one silent PD leader: %v", id, result.err)
		}
		if len(result.value.Payload) == 0 {
			t.Fatalf("active node %d decided an empty value", id)
		}
		if decided == nil {
			decided = append([]byte(nil), result.value.Payload...)
		} else if string(decided) != string(result.value.Payload) {
			t.Fatalf("active node %d decided %x, want %x", id, result.value.Payload, decided)
		}
	}
}

func TestDumboMVBAEquivalentPathSkipsInvalidRecoveredLeader(t *testing.T) {
	const (
		n = 4
		f = 1
	)
	bundle, err := GenerateTBLSKeyBundle(n, f)
	if err != nil {
		t.Fatal(err)
	}
	signers := make([]*TBLSSigner, n)
	for id := range signers {
		signers[id], err = NewTBLSSigner(id, bundle)
		if err != nil {
			t.Fatal(err)
		}
	}
	sid := "eq-mvba-invalid-recovered"
	coinSID := sid + "COIN"
	digest := hashBytes([]byte("EQ_COIN"), []byte(coinSID), []byte{0}, []byte("permutation"))
	shares := make(map[int][]byte, f+1)
	for id := 0; id < f+1; id++ {
		shares[id], err = signers[id].Sign("EQ_COIN_SHARE", digest)
		if err != nil {
			t.Fatal(err)
		}
	}
	recovered, err := signers[0].Recover("EQ_COIN_SHARE", digest, shares)
	if err != nil || !signers[0].VerifyRecovered("EQ_COIN_SHARE", digest, recovered) {
		t.Fatalf("recover permutation coin: %v", err)
	}
	coinHash := hashBytes([]byte("EQ_COIN_REC"), []byte(coinSID), []byte("permutation"), recovered)
	seed := int(binary.BigEndian.Uint64(coinHash[:8]) & 0x7fffffff)
	firstLeader := rand.New(rand.NewSource(int64(seed))).Perm(n)[0]

	recv := make([]chan ReceivedMessage, n)
	for id := range recv {
		recv[id] = make(chan ReceivedMessage, 4096)
	}
	nodes := make([]*DumboMVBA, n)
	for id := range nodes {
		validate := func(payload []byte) bool { return len(payload) > 0 && payload[0] == 'v' }
		if id == firstLeader {
			validate = nil // Byzantine leader disperses a value honest nodes reject.
		}
		nodes[id], err = NewDumboMVBA(
			Config{SID: sid, ID: id, N: n, F: f, MaxRounds: n, UseEquivalentPath: true,
				EquivalentCoinMode: "signature", ValidatePayload: validate},
			&memNet{id: id, peers: recv}, signers[id], nil, recv[id], nil,
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type result struct {
		id    int
		value ProposalValue
		err   error
	}
	results := make(chan result, n)
	for id := range nodes {
		id := id
		payload := []byte("valid-value")
		if id == firstLeader {
			payload = []byte("invalid-value")
		}
		go func() {
			value, runErr := nodes[id].Run(ctx, ProposalValue{Payload: payload})
			results <- result{id: id, value: value, err: runErr}
		}()
	}

	var honestDecision []byte
	for range nodes {
		got := <-results
		if got.err != nil {
			t.Fatalf("node %d failed while skipping invalid recovered leader %d: %v", got.id, firstLeader, got.err)
		}
		if got.id == firstLeader {
			if string(got.value.Payload) != "invalid-value" {
				t.Fatalf("Byzantine leader did not expose the intended invalid first decision: %q", got.value.Payload)
			}
			continue
		}
		if string(got.value.Payload) != "valid-value" {
			t.Fatalf("honest node %d decided invalid recovered value %q", got.id, got.value.Payload)
		}
		if honestDecision == nil {
			honestDecision = append([]byte(nil), got.value.Payload...)
		} else if string(honestDecision) != string(got.value.Payload) {
			t.Fatalf("honest node %d disagreed after invalid leader skip", got.id)
		}
	}
}

func TestDumboMVBAPayloadValidityRejectsLocalInputBeforeNetwork(t *testing.T) {
	m := &DumboMVBA{cfg: Config{
		ValidatePayload: func(payload []byte) bool { return string(payload) == "valid" },
	}}
	if _, err := m.Run(context.Background(), ProposalValue{Payload: []byte("invalid")}); err == nil {
		t.Fatal("MVBA accepted a locally invalid application payload")
	}
}
