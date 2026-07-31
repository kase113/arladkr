package core

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestNetworkDXTCompletesWithoutAllReceiversOrDealers(t *testing.T) {
	old := []int{0, 1, 2, 3}
	newCommittee := []int{10, 11, 12, 13}
	allIDs := append(append([]int(nil), old...), newCommittee...)
	addresses := buildAddrCSV(allIDs, nextTestBase(300))
	cfg := Config{
		SID: "network-dxt-missing-participants", Epoch: 12,
		OldCommittee: old, NewCommittee: newCommittee, F: 1, PaillierBits: 2048,
		ProtocolNodeAddrs: addresses, DXTNodeAddrs: addresses,
	}
	dxt := setupDXTBackend(t, Config{
		SID: cfg.SID, Epoch: cfg.Epoch, OldCommittee: old, NewCommittee: newCommittee,
		F: cfg.F, PaillierBits: cfg.PaillierBits, ProtocolNodeAddrs: addresses,
		ProtocolLocalNodeIDs: buildIDsCSV(allIDs),
	})
	dxt.strictNetwork = true
	dxt.externalReceivers = true
	if err := dxt.setShareStoreDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	services := make(map[int]*dxtNetworkService, 3)
	for index := 0; index < 3; index++ {
		processCfg := cfg
		processCfg.ProtocolLocalNodeIDs = fmt.Sprintf("%d,%d", old[index], newCommittee[index])
		service, err := startDXTNetworkService(ctx, processCfg, old, dxt)
		if err != nil {
			t.Fatalf("start DXT node %d: %v", index, err)
		}
		services[index] = service
		defer service.close()
	}

	// Receiver 13 is absent. Each dealer must still collect exactly 2f+1 real
	// ACKs and create an exact VE fallback for the unavailable lane.
	for _, dealer := range old[:3] {
		transcript, _, err := dxt.Deal(ctx, dealer, nil)
		if err != nil {
			t.Fatalf("dealer %d: %v", dealer, err)
		}
		if len(transcript.Signatures) != 3 || len(transcript.Ciphertexts) != 1 || transcript.Ciphertexts[13] == nil {
			t.Fatalf("dealer %d partition: ACK=%d VE=%d", dealer, len(transcript.Signatures), len(transcript.Ciphertexts))
		}
		if !dxt.VerifyTranscript(0, transcript) {
			t.Fatalf("dealer %d transcript failed full verification", dealer)
		}
		if err := services[dealer].publishTranscript(ctx, dealer, transcript); err != nil {
			t.Fatalf("publish dealer %d: %v", dealer, err)
		}
	}

	// Dealer 3 is absent. The remaining services still cross the 2f+1 finished
	// dealer threshold without a filesystem readiness/transcript barrier.
	for node, service := range services {
		transcripts, err := service.waitForTranscripts(ctx, 3)
		if err != nil || len(transcripts) != 3 {
			t.Fatalf("node %d transcripts=%d err=%v", node, len(transcripts), err)
		}
		shares := service.shareSnapshot()
		localReceiver := newCommittee[node]
		for dealer := range transcripts {
			if shares[dealer][localReceiver].S == nil {
				t.Fatalf("node %d lacks its receiver-local share for dealer %d", node, dealer)
			}
			for _, other := range newCommittee[:3] {
				if other != localReceiver && shares[dealer][other].S != nil {
					t.Fatalf("node %d retained receiver %d share", node, other)
				}
			}
		}
	}
}

func TestNetworkDXTRejectsTranscriptBindingMutation(t *testing.T) {
	old := []int{0, 1, 2, 3}
	newCommittee := []int{10, 11, 12, 13}
	allIDs := append(append([]int(nil), old...), newCommittee...)
	addresses := buildAddrCSV(allIDs, nextTestBase(300))
	cfg := Config{
		SID: "network-dxt-binding", Epoch: 21, OldCommittee: old, NewCommittee: newCommittee, F: 1,
		PaillierBits: 2048, ProtocolNodeAddrs: addresses, DXTNodeAddrs: addresses,
		ProtocolLocalNodeIDs: buildIDsCSV(allIDs),
	}
	dxt := setupDXTBackend(t, cfg)
	transcript, _, err := dxt.Deal(context.Background(), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := dxtTranscriptDigest(transcript)
	if err != nil {
		t.Fatal(err)
	}
	wire := dxtTranscriptWire{
		Kind: dxtTranscriptWireKind, SID: cfg.SID + "-wrong", Epoch: cfg.Epoch,
		Dealer: 0, Transcript: transcript, TranscriptDigest: digest,
	}
	processCfg := cfg
	processCfg.ProtocolLocalNodeIDs = "0"
	service, err := startDXTNetworkService(context.Background(), processCfg, old, dxt)
	if err != nil {
		t.Fatal(err)
	}
	defer service.close()
	if sendDXTTranscript(context.Background(), cfg, 0, 0, parseNodeAddrMap(addresses)[0], wire) {
		t.Fatal("accepted transcript with mismatched SID")
	}
	if len(service.transcriptSnapshot()) != 0 {
		t.Fatal("binding-mutated transcript entered the local ready set")
	}
}
