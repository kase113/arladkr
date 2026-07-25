package core

import "testing"

func TestRecoverAndDerive_UsesReceiverQuorum(t *testing.T) {
	cfg := baseTestConfig()
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}

	lockedSet := []int{0, 1, 2}
	delete(artifacts[0].Ciphertexts, cfg.NewCommittee[0])

	sampled, recovered, shares, pk, err := RecoverAndDerive(cfg, lockedSet, artifacts)
	if err != nil {
		t.Fatalf("RecoverAndDerive failed: %v", err)
	}
	// ARL-ADKR: no κ-sampling; all locked dealers are processed.
	if len(sampled) != len(lockedSet) {
		t.Fatalf("sampled should match locked set: %d != %d", len(sampled), len(lockedSet))
	}
	if len(recovered[0]) == 0 {
		t.Fatalf("dealer 0 payload should still be recoverable via other receivers")
	}
	if len(shares) != len(cfg.NewCommittee) {
		t.Fatalf("share count mismatch: %d", len(shares))
	}
	if len(pk) == 0 {
		t.Fatalf("new public key should not be empty")
	}
}
