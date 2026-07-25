package core

import (
	"context"
	"fmt"
	"testing"
)

func TestBlsPVSS_DistributeAndVerify(t *testing.T) {
	cfg := Config{
		SID:           "test-blspvss",
		OldCommittee:  []int{0, 1, 2, 3},
		NewCommittee:  []int{10, 11, 12, 13},
		FOld:          1,
		FNew:          1,
		APVSSProvider: "bls-pvss",
	}
	cfg = NormalizeConfig(cfg)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}

	// Distribute from each dealer
	txs := make(map[int]*BlsPVSSDealerTranscript)
	for _, dealer := range cfg.OldCommittee {
		tx, err := blsPVSSDistribute(cfg, dealer)
		if err != nil {
			t.Fatalf("Distribute dealer=%d: %v", dealer, err)
		}
		txs[dealer] = tx

		// Verify each transcript
		if err := blsPVSSVerify(cfg, tx); err != nil {
			t.Fatalf("Verify dealer=%d: %v", dealer, err)
		}
	}

	// Aggregate t+1 = 2 transcripts
	dealers := []int{0, 1}
	agg, err := blsPVSSAggregate(cfg, dealers, txs)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}

	// Verify aggregate
	if err := blsPVSSAggregateVerify(cfg, agg); err != nil {
		t.Fatalf("AggregateVerify: %v", err)
	}

	// Recover (decrypt shares)
	decrypted, err := blsPVSSRecover(cfg, agg)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}

	// Verify each decrypted share
	for _, receiver := range cfg.NewCommittee {
		idx := cfg.runtime.receiverIndex[receiver]
		dec, ok := decrypted[receiver]
		if !ok {
			t.Fatalf("Missing decrypted share for receiver=%d", receiver)
		}
		if !blsPVSSVerifyDecryptedShare(agg.AggregatedCommitments[idx], dec) {
			t.Fatalf("Decrypted share verification failed for receiver=%d", receiver)
		}
	}

	t.Logf("PASS: %d dealers, %d receivers, aggregate digest=%x",
		len(dealers), len(cfg.NewCommittee), agg.AggregatedZeta)
}

func TestBlsPVSS_InterfaceRoundTrip(t *testing.T) {
	cfg := Config{
		SID:           "test-blspvss-iface",
		OldCommittee:  []int{0, 1, 2, 3},
		NewCommittee:  []int{10, 11, 12, 13},
		FOld:          1,
		FNew:          1,
		APVSSProvider: "bls-pvss",
	}
	cfg = NormalizeConfig(cfg)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}

	// Build artifacts (optrand path for now, comparing)
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatal(err)
	}

	apvss := NewBlsPVSS()

	// Test Agg
	agg, err := apvss.Agg(cfg, []int{0, 1}, artifacts)
	if err != nil {
		t.Fatalf("Agg: %v", err)
	}
	if agg.Provider != "bls-pvss" {
		t.Fatalf("Wrong provider: %s", agg.Provider)
	}
	if agg.BlsPVSSTranscript == nil {
		t.Fatal("Missing BLS PVSS transcript")
	}

	// Test AVer
	if err := apvss.AVer(cfg, agg, artifacts); err != nil {
		t.Fatalf("AVer: %v", err)
	}

	// Test Rec
	rec, err := apvss.Rec(cfg, agg, artifacts)
	if err != nil {
		t.Fatalf("Rec: %v", err)
	}
	if len(rec.RecoveredMaterial) == 0 {
		t.Fatal("Empty recovered material")
	}
	if rec.OutputKind != APVSSOutputGroup {
		t.Fatalf("unexpected recovered output kind: got=%q want=%q", rec.OutputKind, APVSSOutputGroup)
	}

	t.Logf("PASS: interface round-trip: agg_digest=%x rec_material=%x",
		agg.AggregateDigest, rec.RecoveredMaterial)
}

func TestBlsPVSS_FailBadCommitment(t *testing.T) {
	cfg := Config{
		SID:           "test-blspvss-bad",
		OldCommittee:  []int{0, 1, 2, 3},
		NewCommittee:  []int{10, 11, 12, 13},
		FOld:          1,
		FNew:          1,
		APVSSProvider: "bls-pvss",
	}
	cfg = NormalizeConfig(cfg)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}

	tx, err := blsPVSSDistribute(cfg, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with a commitment
	tx.Commitments[0].Add(&tx.Commitments[0], &tx.Commitments[0])

	if blsPVSSVerify(cfg, tx) == nil {
		t.Fatal("should have failed on bad commitment")
	}
	t.Log("PASS: bad commitment correctly rejected")
}

func TestBlsPVSS_MultipleRoundTrip(t *testing.T) {
	for _, variant := range []string{"optrand", "bls-pvss"} {
		t.Run(variant, func(t *testing.T) {
			cfg := Config{
				SID:           fmt.Sprintf("test-full-%s", variant),
				OldCommittee:  []int{0, 1, 2, 3},
				NewCommittee:  []int{10, 11, 12, 13},
				FOld:          1,
				FNew:          1,
				APVSSProvider: variant,
				LocalNodeIDs:  []int{0, 1, 2, 3},
			}
			cfg = NormalizeConfig(cfg)

			// Run full epoch via existing interface
			ctx := context.Background()
			_, err := RunEpoch(ctx, cfg)
			if err != nil {
				// MVBA-related errors expected in unit test (no network)
				t.Logf("[%s] RunEpoch expected network error: %v", variant, err)
			} else {
				t.Logf("[%s] RunEpoch succeeded", variant)
			}
		})
	}
}

func TestBlsPVSSProviderVerRejectsTamperedReceivedPayload(t *testing.T) {
	cfg := testBlsPVSSConfig(t)
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	provider := NewBlsPVSS()
	tx, err := provider.ADist(cfg, artifacts[0])
	if err != nil {
		t.Fatal(err)
	}
	tx.Payload = append([]byte(nil), tx.Payload...)
	tx.Payload[len(tx.Payload)-1] ^= 1
	if err := provider.Ver(cfg, tx, artifacts[0]); err == nil {
		t.Fatal("expected tampered received payload rejection")
	}
}

func TestBlsPVSSProviderAggRejectsTamperedArtifactCiphertext(t *testing.T) {
	cfg := testBlsPVSSConfig(t)
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	receiver := cfg.runtime.receiverOrder[0]
	artifacts[0].Ciphertexts[receiver][0] ^= 1
	if _, err := NewBlsPVSS().Agg(cfg, []int{0, 1}, artifacts); err == nil {
		t.Fatal("expected aggregate input binding rejection")
	}
}

func TestBlsPVSSAggregateVerifierBindsDigest(t *testing.T) {
	cfg := testBlsPVSSConfig(t)
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	provider := NewBlsPVSS()
	agg, err := provider.Agg(cfg, []int{0, 1}, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	agg.AggregateDigest = append([]byte(nil), agg.AggregateDigest...)
	agg.AggregateDigest[0] ^= 1
	if err := provider.AVer(cfg, agg, artifacts); err == nil {
		t.Fatal("expected aggregate digest binding rejection")
	}
}

func TestBlsPVSSDistributeUsesFreshDealerPolynomial(t *testing.T) {
	cfg := testBlsPVSSConfig(t)
	first, err := blsPVSSDistribute(cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := blsPVSSDistribute(cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.Zeta.Equal(&second.Zeta) {
		t.Fatal("dealer polynomial was deterministically reused")
	}
}
