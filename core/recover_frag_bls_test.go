package core

import "testing"

func TestBlsAggFragResponsesCarryCanonicalVerifiablePayload(t *testing.T) {
	cfg := testBlsPVSSConfig(t)
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dealers := stableFirst(cfg.OldCommittee, cfg.Kappa)
	agg, err := NewBlsPVSS().Agg(cfg, dealers, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	rlo, _, err := BuildAggRLO(cfg, dealers, agg)
	if err != nil {
		t.Fatal(err)
	}
	if rlo.Aggregate.BlsPVSSTranscript == nil {
		t.Fatal("BuildAggRLO dropped the BLS aggregate transcript")
	}

	responses, err := BuildAggFragResponses(cfg, rlo, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != len(dealers) {
		t.Fatalf("response count mismatch: got=%d want=%d", len(responses), len(dealers))
	}
	for _, resp := range responses {
		tx, decodeErr := decodeBlsPVSSDealerTranscript(resp.Payload)
		if decodeErr != nil {
			t.Fatalf("dealer=%d response does not carry a canonical transcript: %v", resp.Dealer, decodeErr)
		}
		if verifyErr := blsPVSSVerify(cfg, tx); verifyErr != nil {
			t.Fatalf("dealer=%d response transcript verification failed: %v", resp.Dealer, verifyErr)
		}
		expectedDigest := hashBytes([]byte("bls-pvss-contribution"), resp.Payload)
		if !bytesEq(resp.ContributionDigest, expectedDigest) {
			t.Fatalf("dealer=%d contribution digest does not bind the wire payload", resp.Dealer)
		}
	}
	if err := VerifyAggFragResponses(cfg, rlo, responses, artifacts); err != nil {
		t.Fatalf("canonical BLS responses rejected: %v", err)
	}
}

func TestVerifyBlsAggFragResponsesRejectsTamperedCanonicalPayload(t *testing.T) {
	cfg := testBlsPVSSConfig(t)
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dealers := stableFirst(cfg.OldCommittee, cfg.Kappa)
	agg, err := NewBlsPVSS().Agg(cfg, dealers, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	rlo, _, err := BuildAggRLO(cfg, dealers, agg)
	if err != nil {
		t.Fatal(err)
	}
	responses, err := BuildAggFragResponses(cfg, rlo, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	responses[0].Payload = append([]byte(nil), responses[0].Payload...)
	responses[0].Payload[len(responses[0].Payload)-1] ^= 1
	responses[0].ContributionDigest = hashBytes(
		[]byte("bls-pvss-contribution"),
		responses[0].Payload,
	)
	if err := VerifyAggFragResponses(cfg, rlo, responses, artifacts); err == nil {
		t.Fatal("expected tampered BLS response transcript rejection")
	}
}

func TestRecoverAggBlsProviderRoundTrip(t *testing.T) {
	cfg := testBlsPVSSConfig(t)
	cfg.RecoverResponseMode = "local"
	cfg.DeriveMode = "aggregate"
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dealers := stableFirst(cfg.OldCommittee, cfg.Kappa)
	recoverOut, err := RecoverAgg(cfg, dealers, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if recoverOut.Recovered.OutputKind != APVSSOutputGroup {
		t.Fatalf("unexpected recovered output kind: %q", recoverOut.Recovered.OutputKind)
	}
	if len(recoverOut.AggFragResponses) != len(dealers) {
		t.Fatalf("response count mismatch: got=%d want=%d", len(recoverOut.AggFragResponses), len(dealers))
	}
	if _, _, shares, publicKey, err := RecoverAndDeriveFromAggRLO(cfg, recoverOut, artifacts); err != nil {
		t.Fatal(err)
	} else if len(shares) != len(cfg.NewCommittee) || len(publicKey) == 0 {
		t.Fatal("aggregate emulator derivation did not return receiver material")
	}
}
