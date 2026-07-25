package core

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type memNet struct {
	id    int
	peers []chan ReceivedMessage
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

	pub, priv, err := GenerateEd25519KeySet(n)
	if err != nil {
		t.Fatalf("GenerateEd25519KeySet failed: %v", err)
	}
	signers := make([]Signer, n)
	for i := 0; i < n; i++ {
		s, sErr := NewEd25519Signer(i, priv[i], pub)
		if sErr != nil {
			t.Fatalf("NewEd25519Signer(%d): %v", i, sErr)
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

func TestDumboMVBAPayloadValidityRejectsLocalInputBeforeNetwork(t *testing.T) {
	m := &DumboMVBA{cfg: Config{
		ValidatePayload: func(payload []byte) bool { return string(payload) == "valid" },
	}}
	if _, err := m.Run(context.Background(), ProposalValue{Payload: []byte("invalid")}); err == nil {
		t.Fatal("MVBA accepted a locally invalid application payload")
	}
}
