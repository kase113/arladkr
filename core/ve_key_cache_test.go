package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateVEKeyCache_ReusesPersistedKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RLADKR_VE_KEY_CACHE_DIR", dir)

	cfg := NormalizeConfig(Config{
		SID:          "ve-cache-test",
		Epoch:        1,
		OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: []int{0, 1, 2, 3},
		FOld:         1,
		FNew:         1,
	})

	first, err := loadOrCreateVEKeyCache(&cfg, 2)
	if err != nil {
		t.Fatalf("first loadOrCreateVEKeyCache failed: %v", err)
	}
	cachePath := veKeyCachePath(dir, cfg.SID, cfg.Epoch, 2)
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("expected cache file at %s: %v", cachePath, err)
	}

	second, err := loadOrCreateVEKeyCache(&cfg, 2)
	if err != nil {
		t.Fatalf("second loadOrCreateVEKeyCache failed: %v", err)
	}
	if first.PublicKey.N.Cmp(second.PublicKey.N) != 0 {
		t.Fatalf("cached public modulus mismatch")
	}
	if first.Lambda.Cmp(second.Lambda) != 0 {
		t.Fatalf("cached private lambda mismatch")
	}
}

func TestVEKeyCachePathUsesSanitizedSID(t *testing.T) {
	got := veKeyCachePath("/tmp/cache", "sid with/slash", 3, 7)
	want := filepath.Join("/tmp/cache", "sid_with_slash", "epoch_000003", "receiver_000007.json")
	if got != want {
		t.Fatalf("unexpected cache path: got=%s want=%s", got, want)
	}
}
