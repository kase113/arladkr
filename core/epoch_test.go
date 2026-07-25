package core

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func baseTestConfig() Config {
	return NormalizeConfig(Config{
		SID:                "rladkr-test-epoch",
		Epoch:              1,
		OldCommittee:       []int{0, 1, 2, 3},
		NewCommittee:       []int{0, 1, 2, 3},
		FOld:               1,
		FNew:               1,
		Kappa:              2,
		AgreementTransport: "tcp-distributed",
	})
}

func TestRunEpoch_DefaultUsesDumboMVBA(t *testing.T) {
	cfg := baseTestConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	res, err := RunEpoch(ctx, cfg)
	if err != nil {
		t.Fatalf("RunEpoch failed: %v", err)
	}
	if res.AgreementMode != "fallback-mvba" {
		t.Fatalf("unexpected agreement mode: %s", res.AgreementMode)
	}
	if len(res.LockedSet) != cfg.Kappa {
		t.Fatalf("locked set size mismatch: %d != %d", len(res.LockedSet), cfg.Kappa)
	}
	if len(res.PerNode) != len(cfg.OldCommittee) {
		t.Fatalf("MVBA per-node outputs mismatch: %d != %d", len(res.PerNode), len(cfg.OldCommittee))
	}
	want := toKey(res.LockedSet)
	for _, out := range res.PerNode {
		if len(out.DecidedSet) != cfg.Kappa {
			t.Fatalf("MVBA decided set size mismatch: node=%d have=%d want=%d", out.NodeID, len(out.DecidedSet), cfg.Kappa)
		}
		if toKey(out.DecidedSet) != want {
			t.Fatalf("MVBA per-node decision mismatch: node=%d", out.NodeID)
		}
	}
	// ARL-ADKR: no kappa-sampling; all locked dealers are processed.
	if len(res.SampledSet) != len(res.LockedSet) {
		t.Fatalf("sampled set mismatch: %d != %d", len(res.SampledSet), len(res.LockedSet))
	}
	if len(res.NewPublicKey) == 0 {
		t.Fatalf("empty new public key")
	}
	if len(res.NewShares) != len(cfg.NewCommittee) {
		t.Fatalf("share count mismatch: %d", len(res.NewShares))
	}
	if len(res.ReceiverStates) != len(cfg.NewCommittee) {
		t.Fatalf("receiver state count mismatch: %d", len(res.ReceiverStates))
	}
	for _, id := range cfg.NewCommittee {
		st, ok := res.ReceiverStates[id]
		if !ok {
			t.Fatalf("missing receiver state for id=%d", id)
		}
		if st.Epoch != cfg.Epoch+1 {
			t.Fatalf("receiver state epoch mismatch for id=%d: %d", id, st.Epoch)
		}
		if len(st.PublicKey) == 0 || len(st.SecretKey) == 0 || len(st.ChainKey) == 0 {
			t.Fatalf("receiver state key material missing for id=%d", id)
		}
	}
}

func TestRunEpoch_FallbackMVBA(t *testing.T) {
	cfg := baseTestConfig()
	cfg.ForceFallback = true

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	res, err := RunEpoch(ctx, cfg)
	if err != nil {
		t.Fatalf("RunEpoch failed: %v", err)
	}
	if res.AgreementMode != "fallback-mvba" {
		t.Fatalf("unexpected agreement mode: %s", res.AgreementMode)
	}
	if len(res.LockedSet) != cfg.Kappa {
		t.Fatalf("locked set size mismatch for valid descriptors: %d != %d", len(res.LockedSet), cfg.Kappa)
	}
	if len(res.PerNode) == 0 {
		t.Fatalf("fallback per-node outputs empty")
	}
	base := toKey(res.PerNode[0].DecidedSet)
	for _, out := range res.PerNode {
		if len(out.DecidedSet) != cfg.Kappa {
			t.Fatalf("fallback decided set size mismatch: node=%d have=%d want=%d", out.NodeID, len(out.DecidedSet), cfg.Kappa)
		}
		if toKey(out.DecidedSet) != base {
			t.Fatalf("per-node decision mismatch: node=%d", out.NodeID)
		}
	}
}

func TestRunEpoch_FallbackMVBA_N6(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:                "rladkr-test-fallback-n6",
		Epoch:              1,
		OldCommittee:       []int{0, 1, 2, 3, 4, 5},
		NewCommittee:       []int{0, 1, 2, 3, 4, 5},
		FOld:               1,
		FNew:               1,
		Kappa:              2,
		ForceFallback:      true,
		AgreementTransport: "tcp-distributed",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	res, err := RunEpoch(ctx, cfg)
	if err != nil {
		t.Fatalf("RunEpoch failed: %v", err)
	}
	if len(res.LockedSet) != cfg.Kappa {
		t.Fatalf("locked set size mismatch for n=6: %d != %d", len(res.LockedSet), cfg.Kappa)
	}
	for _, out := range res.PerNode {
		if len(out.DecidedSet) != cfg.Kappa {
			t.Fatalf("n=6 decided set size mismatch: node=%d have=%d want=%d", out.NodeID, len(out.DecidedSet), cfg.Kappa)
		}
	}
}

func TestRunEpoch_ForwardSecrecyStateProgression(t *testing.T) {
	cfg1 := baseTestConfig()
	ctx1, cancel1 := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel1()
	res1, err := RunEpoch(ctx1, cfg1)
	if err != nil {
		t.Fatalf("epoch1 RunEpoch failed: %v", err)
	}

	cfg2 := NormalizeConfig(Config{
		SID:                 cfg1.SID,
		Epoch:               2,
		OldCommittee:        append([]int(nil), cfg1.OldCommittee...),
		NewCommittee:        append([]int(nil), cfg1.NewCommittee...),
		FOld:                cfg1.FOld,
		FNew:                cfg1.FNew,
		Kappa:               cfg1.Kappa,
		InputReceiverStates: res1.ReceiverStates,
	})
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel2()
	res2, err := RunEpoch(ctx2, cfg2)
	if err != nil {
		t.Fatalf("epoch2 RunEpoch failed: %v", err)
	}
	for _, id := range cfg2.NewCommittee {
		st1 := res1.ReceiverStates[id]
		st2 := res2.ReceiverStates[id]
		if st2.Epoch != 3 {
			t.Fatalf("receiver %d epoch progression mismatch: %d", id, st2.Epoch)
		}
		if toHex(st1.PublicKey) == toHex(st2.PublicKey) {
			t.Fatalf("receiver %d public key not rotated across epochs", id)
		}
	}
}

func TestRunEpoch_MissingInputReceiverStatesForEpoch2(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:          "rladkr-test-fs-missing-state",
		Epoch:        2,
		OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: []int{0, 1, 2, 3},
		FOld:         1,
		FNew:         1,
		Kappa:        2,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := RunEpoch(ctx, cfg); err == nil {
		t.Fatalf("expected missing input receiver states error")
	}
}

func TestRunEpoch_ForwardSecrecyPosteriorCorruptionCannotDecryptPastCiphertext(t *testing.T) {
	cfg1 := baseTestConfig()
	ctx1, cancel1 := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel1()
	res1, err := RunEpoch(ctx1, cfg1)
	if err != nil {
		t.Fatalf("epoch1 RunEpoch failed: %v", err)
	}

	epoch2States := cloneReceiverStateMap(res1.ReceiverStates)
	cfg2 := NormalizeConfig(Config{
		SID:                 cfg1.SID,
		Epoch:               2,
		OldCommittee:        append([]int(nil), cfg1.OldCommittee...),
		NewCommittee:        append([]int(nil), cfg1.NewCommittee...),
		FOld:                cfg1.FOld,
		FNew:                cfg1.FNew,
		Kappa:               cfg1.Kappa,
		InputReceiverStates: epoch2States,
	})
	if err := ensureRuntime(&cfg2); err != nil {
		t.Fatalf("epoch2 runtime init failed: %v", err)
	}
	artifacts2, err := BuildDealerArtifacts(cfg2)
	if err != nil {
		t.Fatalf("epoch2 BuildDealerArtifacts failed: %v", err)
	}
	dealer := cfg2.OldCommittee[0]
	receiver := cfg2.NewCommittee[0]
	art2 := artifacts2[dealer]
	cipher2 := art2.Ciphertexts[receiver]
	root2 := art2.Descriptor.Header.Root
	if _, err := openForReceiver(cfg2, dealer, receiver, root2, cipher2); err != nil {
		t.Fatalf("epoch2 decrypt with current state should succeed: %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel2()
	res2, err := RunEpoch(ctx2, cfg2)
	if err != nil {
		t.Fatalf("epoch2 RunEpoch failed: %v", err)
	}

	cfg3 := NormalizeConfig(Config{
		SID:                 cfg1.SID,
		Epoch:               3,
		OldCommittee:        append([]int(nil), cfg1.OldCommittee...),
		NewCommittee:        append([]int(nil), cfg1.NewCommittee...),
		FOld:                cfg1.FOld,
		FNew:                cfg1.FNew,
		Kappa:               cfg1.Kappa,
		InputReceiverStates: cloneReceiverStateMap(res2.ReceiverStates),
	})
	if _, err := openForReceiver(cfg3, dealer, receiver, root2, cipher2); err == nil {
		t.Fatalf("epoch3 state should not decrypt epoch2 ciphertext")
	}
}

func toKey(v []int) string {
	if len(v) == 0 {
		return "[]"
	}
	parts := make([]string, 0, len(v))
	for _, n := range v {
		parts = append(parts, fmt.Sprintf("%d", n))
	}
	return strings.Join(parts, ",")
}

func toHex(v []byte) string {
	if len(v) == 0 {
		return ""
	}
	return strings.ToLower(fmt.Sprintf("%x", v))
}

func cloneReceiverStateMap(in map[int]ReceiverState) map[int]ReceiverState {
	out := make(map[int]ReceiverState, len(in))
	for id, st := range in {
		out[id] = cloneReceiverState(st)
	}
	return out
}
