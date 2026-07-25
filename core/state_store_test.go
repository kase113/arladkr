package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunEpoch_StateStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg1 := baseTestConfig()
	cfg1.StateStoreDir = dir
	cfg1.AgreementTransport = "tcp-loopback"

	ctx1, cancel1 := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel1()
	res1, err := RunEpoch(ctx1, cfg1)
	if err != nil {
		t.Fatalf("epoch1 RunEpoch failed: %v", err)
	}
	if len(res1.ReceiverStates) != len(cfg1.NewCommittee) {
		t.Fatalf("receiver states mismatch: %d", len(res1.ReceiverStates))
	}
	store := newReceiverStateStore(dir)
	loaded, err := store.Load(cfg1.SID, 2)
	if err != nil {
		t.Fatalf("state store load epoch2 failed: %v", err)
	}
	if len(loaded) != len(cfg1.NewCommittee) {
		t.Fatalf("stored receiver states mismatch: %d", len(loaded))
	}

	cfg2 := NormalizeConfig(Config{
		SID:                cfg1.SID,
		Epoch:              2,
		OldCommittee:       append([]int(nil), cfg1.OldCommittee...),
		NewCommittee:       append([]int(nil), cfg1.NewCommittee...),
		FOld:               cfg1.FOld,
		FNew:               cfg1.FNew,
		Kappa:              cfg1.Kappa,
		StateStoreDir:      dir,
		AgreementTransport: "tcp-loopback",
	})
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel2()
	res2, err := RunEpoch(ctx2, cfg2)
	if err != nil {
		t.Fatalf("epoch2 RunEpoch failed with store-loaded states: %v", err)
	}
	for _, id := range cfg2.NewCommittee {
		st := res2.ReceiverStates[id]
		if st.Epoch != 3 {
			t.Fatalf("unexpected state epoch after round trip for id=%d: %d", id, st.Epoch)
		}
	}
}

func TestRunEpoch_FallbackWithTCPLoopbackTransport(t *testing.T) {
	cfg := baseTestConfig()
	cfg.ForceFallback = true
	cfg.AgreementTransport = "tcp-loopback"
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	res, err := RunEpoch(ctx, cfg)
	if err != nil {
		t.Fatalf("RunEpoch fallback with tcp-loopback failed: %v", err)
	}
	if res.AgreementMode != "fallback-mvba" {
		t.Fatalf("unexpected agreement mode: %s", res.AgreementMode)
	}
	if len(res.LockedSet) != cfg.Kappa {
		t.Fatalf("locked set size mismatch: %d != %d", len(res.LockedSet), cfg.Kappa)
	}
}

func TestStateStore_EncryptedSnapshotAndAntiRollback(t *testing.T) {
	dir := t.TempDir()
	sid := "rladkr-test-state-store-security"
	store := newReceiverStateStore(dir)
	states := map[int]ReceiverState{
		0: {
			NodeID:           0,
			Epoch:            2,
			PublicKey:        []byte("pk"),
			SecretKey:        []byte("sk-secret-material"),
			ChainKey:         []byte("chain"),
			TransportKeyHash: []byte("th"),
		},
	}
	if err := store.Save(sid, 2, states); err != nil {
		t.Fatalf("save epoch2 failed: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, sanitizeSID(sid), "epoch_000002.json"))
	if err != nil {
		t.Fatalf("read snapshot failed: %v", err)
	}
	if strings.Contains(string(raw), "sk-secret-material") {
		t.Fatalf("snapshot should not store secret in plaintext")
	}
	if err := store.Save(sid, 1, states); err == nil {
		t.Fatalf("anti-rollback should reject older epoch save")
	}
}

func TestStateStore_LoadRejectsRollbackEpoch(t *testing.T) {
	dir := t.TempDir()
	sid := "rladkr-test-state-store-load-rollback"
	store := newReceiverStateStore(dir)
	states := map[int]ReceiverState{
		0: {
			NodeID:           0,
			Epoch:            3,
			PublicKey:        []byte("pk"),
			SecretKey:        []byte("sk"),
			ChainKey:         []byte("chain"),
			TransportKeyHash: []byte("th"),
		},
	}
	if err := store.Save(sid, 3, states); err != nil {
		t.Fatalf("save epoch3 failed: %v", err)
	}
	if _, err := store.Load(sid, 2); err == nil {
		t.Fatalf("expected rollback detection when loading older epoch")
	}
}
