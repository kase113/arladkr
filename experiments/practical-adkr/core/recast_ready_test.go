package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecastTCPReadinessCompletesWithoutAllPairs(t *testing.T) {
	artifactDir := t.TempDir()
	t.Setenv("PRACTICAL_ARTIFACT_CACHE_DIR", artifactDir)
	old := []int{0, 1, 2, 3}
	newCommittee := []int{10, 11, 12, 13}
	allIDs := append(append([]int(nil), old...), newCommittee...)
	addresses := buildAddrCSV(allIDs, nextTestBase(300))
	cfg := Config{
		SID: "recast-ready-missing-pair", Epoch: 31, OldCommittee: old,
		NewCommittee: newCommittee, F: 1, ProtocolNodeAddrs: addresses,
	}
	addrMap := parseNodeAddrMap(addresses)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	localSet := map[int]struct{}{0: {}, 10: {}}
	localListeners := make(map[int]net.Listener, 2)
	for _, id := range []int{0, 10} {
		listener, err := net.Listen("tcp", addrMap[id])
		if err != nil {
			t.Fatal(err)
		}
		localListeners[id] = listener
		defer listener.Close()
	}

	// Pairs (1,11) and (2,12) answer authenticated readiness probes. Pair
	// (3,13) is completely absent; n-f=3 complete pairs are still sufficient.
	for _, id := range []int{1, 11, 2, 12} {
		listener := startRecastReadyTestResponder(t, ctx, cfg, id, addrMap[id])
		defer listener.Close()
	}
	if err := waitForRecastReadyQuorum(ctx, cfg, old, newCommittee, localSet, localListeners, addrMap); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(artifactDir, "recast-ready")); !os.IsNotExist(err) {
		t.Fatalf("recast readiness created a filesystem barrier: err=%v", err)
	}
}

func TestRecastTCPReadinessRejectsContextMutation(t *testing.T) {
	old := []int{0, 1, 2, 3}
	newCommittee := []int{10, 11, 12, 13}
	allIDs := append(append([]int(nil), old...), newCommittee...)
	addresses := buildAddrCSV(allIDs, nextTestBase(300))
	cfg := Config{SID: "recast-ready-binding", Epoch: 44, OldCommittee: old, NewCommittee: newCommittee, F: 1, ProtocolNodeAddrs: addresses}
	addr := parseNodeAddrMap(addresses)[1]
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	listener := startRecastReadyTestResponder(t, ctx, cfg, 1, addr)
	defer listener.Close()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	bad := recastWire{Kind: "ready", SID: cfg.SID + "-wrong", Epoch: cfg.Epoch, Holder: 1}
	if err := json.NewEncoder(conn).Encode(bad); err != nil {
		t.Fatal(err)
	}
	var ack recastWire
	if err := json.NewDecoder(conn).Decode(&ack); err == nil {
		t.Fatal("recast readiness accepted a mismatched SID")
	}
}

func TestRecastCompletionBindsContextReceiverAndRoots(t *testing.T) {
	old := []int{0, 1, 2, 3}
	newCommittee := []int{10, 11, 12, 13}
	allIDs := append(append([]int(nil), old...), newCommittee...)
	cfg := Config{
		SID: "recast-completion-binding", Epoch: 52, OldCommittee: old, NewCommittee: newCommittee, F: 1,
		PaillierBits: 2048, ProtocolNodeAddrs: buildAddrCSV(allIDs, nextTestBase(300)),
		ProtocolLocalNodeIDs: buildIDsCSV(allIDs),
	}
	dxt := setupDXTBackend(t, cfg)
	root0 := sha256.Sum256([]byte("dealer-0"))
	root2 := sha256.Sum256([]byte("dealer-2"))
	roots := map[int][]byte{0: root0[:], 2: root2[:]}
	digest, err := recastCompletionDigest(cfg, 10, []int{2, 0}, roots)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := ecdsa.SignASN1(rand.Reader, dxt.recipientSignPriv[10], digest)
	if err != nil {
		t.Fatal(err)
	}
	wire := recastWire{
		Kind: "completion", SID: cfg.SID, Epoch: cfg.Epoch, Holder: 0, Recipient: 10,
		CompletionDigest: digest, Signature: signature,
	}
	if !verifyRecastCompletion(cfg, wire, []int{0, 2}, roots, dxt) {
		t.Fatal("valid receiver completion was rejected")
	}
	tampered := wire
	tampered.Epoch++
	if verifyRecastCompletion(cfg, tampered, []int{0, 2}, roots, dxt) {
		t.Fatal("completion with mutated epoch was accepted")
	}
	tampered = wire
	tampered.Recipient = 11
	if verifyRecastCompletion(cfg, tampered, []int{0, 2}, roots, dxt) {
		t.Fatal("completion replayed as another receiver was accepted")
	}
	tamperedRoots := map[int][]byte{0: root0[:], 2: append([]byte(nil), root2[:]...)}
	tamperedRoots[2][0] ^= 1
	if verifyRecastCompletion(cfg, wire, []int{0, 2}, tamperedRoots, dxt) {
		t.Fatal("completion with mutated recovered root was accepted")
	}
	if _, err := recastCompletionDigest(cfg, 10, []int{0, 0}, roots); err == nil {
		t.Fatal("completion digest accepted duplicate dealers")
	}
}

func startRecastReadyTestResponder(t *testing.T, ctx context.Context, cfg Config, localID int, addr string) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				var wire recastWire
				if json.NewDecoder(conn).Decode(&wire) == nil {
					respondRecastReady(conn, cfg, localID, wire)
				}
			}()
			select {
			case <-ctx.Done():
				_ = listener.Close()
				return
			default:
			}
		}
	}()
	return listener
}
