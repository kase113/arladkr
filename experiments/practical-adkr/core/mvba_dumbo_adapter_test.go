package core

import (
	"bytes"
	"testing"

	dmvba "dumbomvba_go/core"
)

func TestPracticalMVBADeterministicDualThresholdBundle(t *testing.T) {
	const n, f = 10, 3
	old := make([]int, n)
	for i := range old {
		old[i] = i
	}

	first, err := dmvba.GenerateDeterministicTBLSKeyBundle(
		n, f, practicalMVBADeterministicStream("test-seed", "test-sid", old, f),
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := dmvba.GenerateDeterministicTBLSKeyBundle(
		n, f, practicalMVBADeterministicStream("test-seed", "test-sid", old, f),
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		domain    string
		threshold int
	}{
		{"PD_STORED", n - f},
		{"PD_LOCKED", n - f},
		{"PD_QUIT_READY", f + 1},
		{"EQ_COIN_SHARE", f + 1},
	}
	digest := []byte("digest")
	for _, tc := range tests {
		t.Run(tc.domain, func(t *testing.T) {
			combiner, err := dmvba.NewTBLSSigner(0, first)
			if err != nil {
				t.Fatal(err)
			}
			if got := combiner.Threshold(tc.domain); got != tc.threshold {
				t.Fatalf("threshold=%d, want %d", got, tc.threshold)
			}
			shares := make(map[int][]byte, tc.threshold)
			for id := 0; id < tc.threshold; id++ {
				signer, signerErr := dmvba.NewTBLSSigner(id, second)
				if signerErr != nil {
					t.Fatal(signerErr)
				}
				share, signErr := signer.Sign(tc.domain, digest)
				if signErr != nil {
					t.Fatal(signErr)
				}
				if !combiner.Verify(id, tc.domain, digest, share) {
					t.Fatalf("share %d from independently derived bundle did not verify", id)
				}
				shares[id] = share
			}
			recovered, recoverErr := combiner.Recover(tc.domain, digest, shares)
			if recoverErr != nil {
				t.Fatal(recoverErr)
			}
			if len(recovered) == 0 || !combiner.VerifyRecovered(tc.domain, digest, recovered) {
				t.Fatal("recovered signature did not verify")
			}

			otherCombiner, _ := dmvba.NewTBLSSigner(0, second)
			otherRecovered, otherErr := otherCombiner.Recover(tc.domain, digest, shares)
			if otherErr != nil {
				t.Fatal(otherErr)
			}
			if !bytes.Equal(recovered, otherRecovered) {
				t.Fatal("deterministic bundles recovered different signatures")
			}
		})
	}
}
