package core

import "testing"

func testBlsPVSSConfig(t *testing.T) Config {
	t.Helper()
	cfg := NormalizeConfig(Config{
		SID:           "test-bls-provider",
		Epoch:         1,
		OldCommittee:  []int{0, 1, 2, 3},
		NewCommittee:  []int{10, 11, 12, 13},
		F:             1,
		APVSSProvider: "bls-pvss",
	})
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestBlsPVSSDealerTranscriptCodecRoundTrip(t *testing.T) {
	cfg := testBlsPVSSConfig(t)
	tx, err := blsPVSSDistribute(cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodeBlsPVSSDealerTranscript(tx)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBlsPVSSDealerTranscript(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := blsPVSSVerify(cfg, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.SID != cfg.SID || decoded.Epoch != cfg.Epoch {
		t.Fatalf("context mismatch: %+v", decoded)
	}
}

func TestBlsPVSSDealerTranscriptRejectsContextReplay(t *testing.T) {
	cfg := testBlsPVSSConfig(t)
	tx, err := blsPVSSDistribute(cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	tx.Epoch++
	if err := blsPVSSVerify(cfg, tx); err == nil {
		t.Fatal("expected epoch replay rejection")
	}
}

func TestBlsPVSSDealerTranscriptCodecRejectsMalformedLengths(t *testing.T) {
	cfg := testBlsPVSSConfig(t)
	tx, err := blsPVSSDistribute(cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodeBlsPVSSDealerTranscript(tx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeBlsPVSSDealerTranscript(payload[:len(payload)-1]); err == nil {
		t.Fatal("expected truncated payload rejection")
	}
	withTrailing := append(append([]byte(nil), payload...), 0)
	if _, err := decodeBlsPVSSDealerTranscript(withTrailing); err == nil {
		t.Fatal("expected trailing payload rejection")
	}
}
