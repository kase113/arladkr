package core

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"
)

func TestOptrandDealerArtifactsRetainLegacySchemaV1WireAndContributionDomain(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure runtime failed: %v", err)
	}
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("build artifacts failed: %v", err)
	}
	art := artifacts[cfg.runtime.oldOrder[0]]
	transcript, err := decodeDealerTranscript(art.Payload)
	if err != nil {
		t.Fatalf("decode transcript failed: %v", err)
	}
	if transcript.Version != 1 {
		t.Fatalf("optrand transcript version=%d, want 1", transcript.Version)
	}
	if transcript.Provider != "" {
		t.Fatalf("optrand transcript provider=%q, want omitted", transcript.Provider)
	}
	if transcript.Threshold != len(cfg.runtime.receiverOrder)-cfg.FNew {
		t.Fatalf("optrand threshold=%d, want %d", transcript.Threshold, len(cfg.runtime.receiverOrder)-cfg.FNew)
	}
	var transcriptObject map[string]json.RawMessage
	if err := json.Unmarshal(art.Payload, &transcriptObject); err != nil {
		t.Fatalf("decode transcript object failed: %v", err)
	}
	if _, present := transcriptObject["provider"]; present {
		t.Fatalf("optrand v1 transcript must omit provider")
	}

	receiver := cfg.runtime.receiverOrder[0]
	packet, err := openSharePacketForReceiver(cfg, art.Dealer, receiver, art.Descriptor.Header.Root, art.Ciphertexts[receiver])
	if err != nil {
		t.Fatalf("open share packet failed: %v", err)
	}
	var shareWire dealerShareWire
	if err := json.Unmarshal(packet, &shareWire); err != nil {
		t.Fatalf("decode share wire failed: %v", err)
	}
	if shareWire.Version != 1 {
		t.Fatalf("optrand share packet version=%d, want 1", shareWire.Version)
	}
	if shareWire.Provider != "" {
		t.Fatalf("optrand share packet provider=%q, want omitted", shareWire.Provider)
	}
	var shareObject map[string]json.RawMessage
	if err := json.Unmarshal(packet, &shareObject); err != nil {
		t.Fatalf("decode share object failed: %v", err)
	}
	if _, present := shareObject["provider"]; present {
		t.Fatalf("optrand schema-v1 share must omit provider")
	}
	decodedShare, err := decodeDealerSharePacket(packet)
	if err != nil {
		t.Fatalf("v1 share packet rejected: %v", err)
	}
	if decodedShare.Version != 1 || decodedShare.Provider != "" {
		t.Fatalf("decoded optrand share identity=(%q,%d), want (empty,1)", decodedShare.Provider, decodedShare.Version)
	}

	wantDigest := legacyOptrandContributionDigestForTest(art)
	if !bytesEq(art.ContributionDigest, wantDigest) {
		t.Fatalf("optrand contribution digest domain changed")
	}
}

func TestOptrandVERejectsScalarShamirSchemaV1SharePacket(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure runtime failed: %v", err)
	}
	dealer := cfg.runtime.oldOrder[0]
	receiver := cfg.runtime.receiverOrder[0]
	payload, packets, err := buildDealerTranscript(cfg, dealer)
	if err != nil {
		t.Fatalf("build optrand packets failed: %v", err)
	}
	var wire dealerShareWire
	if err := json.Unmarshal(packets[receiver], &wire); err != nil {
		t.Fatalf("decode optrand packet failed: %v", err)
	}
	wire.Provider = "scalar-shamir"
	scalarPacket, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal scalar schema-v1 packet failed: %v", err)
	}
	root := hashBytes([]byte("rladkr-root"), payload)
	if _, err := veEncryptSharePacket(cfg, dealer, receiver, root, scalarPacket); err == nil {
		t.Fatalf("optrand VE accepted scalar-shamir schema-v1 share packet")
	}
}

func TestOptrandRejectsScalarShamirSchemaWhenThresholdsCollide(t *testing.T) {
	scalarCfg := NormalizeConfig(Config{
		SID:           "provider-schema-threshold-collision",
		Epoch:         1,
		OldCommittee:  []int{0, 1, 2},
		NewCommittee:  []int{10, 11, 12},
		FOld:          1,
		FNew:          1,
		APVSSProvider: "scalar-shamir",
	})
	if err := ensureRuntime(&scalarCfg); err != nil {
		t.Fatalf("ensure scalar runtime failed: %v", err)
	}
	artifacts, err := BuildDealerArtifacts(scalarCfg)
	if err != nil {
		t.Fatalf("build scalar artifacts failed: %v", err)
	}
	optrandCfg := scalarCfg
	optrandCfg.APVSSProvider = "optrand"
	if err := ensureRuntime(&optrandCfg); err != nil {
		t.Fatalf("ensure optrand runtime failed: %v", err)
	}
	if err := OptrandShareVerify(optrandCfg, artifacts[0]); err == nil {
		t.Fatal("optrand accepted scalar-shamir schema when n-F equals F+1")
	}
}

func legacyOptrandContributionDigestForTest(art *DealerArtifact) []byte {
	receivers := make([]int, 0, len(art.Ciphertexts))
	for receiver := range art.Ciphertexts {
		receivers = append(receivers, receiver)
	}
	sort.Ints(receivers)
	parts := make([][]byte, 0, 5+2*len(receivers))
	parts = append(parts,
		[]byte("optrand-contrib"),
		[]byte(fmt.Sprintf("dealer=%d", art.Dealer)),
		art.Descriptor.Digest,
		art.Descriptor.Header.Root,
		art.Descriptor.Header.Commitment,
	)
	for _, receiver := range receivers {
		parts = append(parts, []byte(fmt.Sprintf("receiver=%d", receiver)))
		parts = append(parts, hashBytes([]byte("ct"), art.Ciphertexts[receiver]))
	}
	return hashBytes(parts...)
}

func TestOptrandShareVerify(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("build artifacts failed: %v", err)
	}
	for dealer, art := range artifacts {
		if err := OptrandShareVerify(cfg, art); err != nil {
			t.Fatalf("share verify failed for dealer=%d: %v", dealer, err)
		}
	}
}

func TestOptrandAggregateAndVerify(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("build artifacts failed: %v", err)
	}

	dealers := stableFirst(cfg.OldCommittee, cfg.Kappa)
	agg, err := BuildOptrandAggregatedTranscript(cfg, dealers, artifacts)
	if err != nil {
		t.Fatalf("build aggregate failed: %v", err)
	}
	if err := VerifyOptrandAggregatedTranscript(cfg, agg, artifacts); err != nil {
		t.Fatalf("verify aggregate failed: %v", err)
	}

	// Tampered aggregate digest must be rejected.
	bad := *agg
	bad.AggregateDigest = hashBytes([]byte("tampered"), agg.AggregateDigest)
	if err := VerifyOptrandAggregatedTranscript(cfg, &bad, artifacts); err == nil {
		t.Fatalf("expected tampered aggregate to fail verification")
	}
}
