package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestCVReceiverKeyMaterialV1GenerateAndLoadLocalOnly(t *testing.T) {
	root := t.TempDir()
	publicDir := filepath.Join(root, "public")
	secretDir := filepath.Join(root, "private")
	const sid = "cv-keys-session"
	receiverIDs := []int{10, 11, 12}
	if err := cvGenerateReceiverKeyMaterialV1(publicDir, secretDir, sid, receiverIDs); err != nil {
		t.Fatal(err)
	}

	registryPath := filepath.Join(publicDir, cvReceiverRegistryFilenameV1)
	registryRaw, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	var registry cvReceiverRegistryV1
	if err := json.Unmarshal(registryRaw, &registry); err != nil {
		t.Fatal(err)
	}
	if registry.Version != cvReceiverRegistryVersionV1 || registry.SID != sid {
		t.Fatalf("registry version/SID = %d/%q", registry.Version, registry.SID)
	}
	if len(registry.Receivers) != len(receiverIDs) {
		t.Fatalf("registry receiver count = %d, want %d", len(registry.Receivers), len(receiverIDs))
	}
	for i, entry := range registry.Receivers {
		if entry.ReceiverID != receiverIDs[i] || entry.ReceiverIndex != i+1 {
			t.Fatalf("registry entry %d = id/index %d/%d", i, entry.ReceiverID, entry.ReceiverIndex)
		}
		encoded, err := hex.DecodeString(entry.PublicKey)
		if err != nil || len(encoded) != 48 {
			t.Fatalf("registry entry %d has invalid compressed G1: %q", i, entry.PublicKey)
		}
	}
	assertCVKeyFileMode(t, registryPath, 0o644)
	for _, id := range receiverIDs {
		assertCVKeyFileMode(t, cvReceiverSecretPathV1(secretDir, id), 0o600)
	}

	// A corrupt non-local secret must not affect this process: strict loading
	// opens only the receiver IDs explicitly assigned to it.
	if err := os.WriteFile(cvReceiverSecretPathV1(secretDir, 12), []byte("not-a-scalar"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := cvLoadReceiverKeyMaterialV1(publicDir, secretDir, sid, receiverIDs, []int{11, 10})
	if err != nil {
		t.Fatalf("load local receiver keys: %v", err)
	}
	if len(keys.receiverPublicKeys) != len(receiverIDs) || len(keys.localReceiverSecrets) != 2 {
		t.Fatalf("loaded public/local key counts = %d/%d", len(keys.receiverPublicKeys), len(keys.localReceiverSecrets))
	}
	if _, ok := keys.localReceiverSecrets[12]; ok {
		t.Fatal("strict loader retained a non-local receiver secret")
	}
	for _, id := range []int{10, 11} {
		secret, ok := keys.localReceiverSecrets[id]
		if !ok {
			t.Fatalf("missing local receiver secret %d", id)
		}
		publicKey, err := cvReceiverPublicKey(secret)
		if err != nil {
			t.Fatal(err)
		}
		if !publicKey.Equal(&keys.receiverPublicKeys[keys.receiverIndex[id]-1]) {
			t.Fatalf("receiver %d secret/public registry mismatch", id)
		}
	}

	secondRoot := t.TempDir()
	secondPublicDir := filepath.Join(secondRoot, "public")
	secondSecretDir := filepath.Join(secondRoot, "private")
	if err := cvGenerateReceiverKeyMaterialV1(secondPublicDir, secondSecretDir, sid, receiverIDs); err != nil {
		t.Fatal(err)
	}
	firstSecret, err := os.ReadFile(cvReceiverSecretPathV1(secretDir, 10))
	if err != nil {
		t.Fatal(err)
	}
	secondSecret, err := os.ReadFile(cvReceiverSecretPathV1(secondSecretDir, 10))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstSecret, secondSecret) {
		t.Fatal("independent key generations reused a receiver scalar")
	}
}

func TestCVReceiverKeyMaterialV1RejectsMismatchedRegistryAndSecrets(t *testing.T) {
	const sid = "cv-keys-validation"
	receiverIDs := []int{20, 21, 22}

	t.Run("SID", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, "other-session", receiverIDs, []int{20}); err == nil {
			t.Fatal("accepted registry from another SID")
		}
	})

	t.Run("receiver order", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, []int{21, 20, 22}, []int{20}); err == nil {
			t.Fatal("accepted a registry with the wrong receiver order")
		}
	})

	t.Run("unknown local receiver", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs, []int{23}); err == nil {
			t.Fatal("accepted a local receiver outside the registry")
		}
	})

	t.Run("noncanonical scalar", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		noncanonical := fr.Modulus().FillBytes(make([]byte, fr.Bytes))
		if err := os.WriteFile(cvReceiverSecretPathV1(dirs.secret, 20), noncanonical, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs, []int{20}); err == nil {
			t.Fatal("accepted a noncanonical receiver scalar")
		}
	})

	t.Run("zero scalar", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		if err := os.WriteFile(cvReceiverSecretPathV1(dirs.secret, 20), make([]byte, fr.Bytes), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs, []int{20}); err == nil {
			t.Fatal("accepted a zero receiver scalar")
		}
	})

	t.Run("secret public mismatch", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		other, err := os.ReadFile(cvReceiverSecretPathV1(dirs.secret, 21))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cvReceiverSecretPathV1(dirs.secret, 20), other, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs, []int{20}); err == nil {
			t.Fatal("accepted a receiver scalar for another public key")
		}
	})

	t.Run("interpolation index", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		registry := readCVReceiverRegistryForTest(t, dirs.public)
		registry.Receivers[0].ReceiverIndex = 2
		writeCVReceiverRegistryForTest(t, dirs.public, registry)
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs, []int{20}); err == nil {
			t.Fatal("accepted a receiver with the wrong interpolation index")
		}
	})

	t.Run("public key", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		registry := readCVReceiverRegistryForTest(t, dirs.public)
		registry.Receivers[0].PublicKey = "00"
		writeCVReceiverRegistryForTest(t, dirs.public, registry)
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs, []int{20}); err == nil {
			t.Fatal("accepted a noncanonical compressed public key")
		}
	})
}

func TestCVReceiverRegistryDigestV1BindsReceiverIDs(t *testing.T) {
	const sid = "cv-registry-digest"
	receiverIDs := []int{30, 31, 32}
	dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
	original, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(original.registryDigest) != 32 {
		t.Fatalf("registry digest length = %d, want 32", len(original.registryDigest))
	}

	remappedIDs := []int{40, 41, 42}
	registry := readCVReceiverRegistryForTest(t, dirs.public)
	for i := range registry.Receivers {
		registry.Receivers[i].ReceiverID = remappedIDs[i]
	}
	writeCVReceiverRegistryForTest(t, dirs.public, registry)
	remapped, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, remappedIDs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original.registryDigest, remapped.registryDigest) {
		t.Fatal("registry digest did not bind receiver IDs")
	}
}

func TestCVReceiverKeyMaterialV1RejectsUnsafeFiles(t *testing.T) {
	const sid = "cv-keys-files"
	receiverIDs := []int{50, 51}

	t.Run("registry symlink", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		path := filepath.Join(dirs.public, cvReceiverRegistryFilenameV1)
		target := path + ".target"
		if err := os.Rename(path, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs, nil); err == nil {
			t.Fatal("accepted a symlinked receiver registry")
		}
	})

	t.Run("secret symlink", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		path := cvReceiverSecretPathV1(dirs.secret, 50)
		target := path + ".target"
		if err := os.Rename(path, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs, []int{50}); err == nil {
			t.Fatal("accepted a symlinked receiver secret")
		}
	})

	t.Run("non-regular registry", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		path := filepath.Join(dirs.public, cvReceiverRegistryFilenameV1)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs, nil); err == nil {
			t.Fatal("accepted a non-regular receiver registry")
		}
	})

	t.Run("non-regular secret", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		path := cvReceiverSecretPathV1(dirs.secret, 50)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs, []int{50}); err == nil {
			t.Fatal("accepted a non-regular receiver secret")
		}
	})

	t.Run("insecure secret mode", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		if err := os.Chmod(cvReceiverSecretPathV1(dirs.secret, 50), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs, []int{50}); err == nil {
			t.Fatal("accepted an insecure receiver secret mode")
		}
	})

	t.Run("oversized registry", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		path := filepath.Join(dirs.public, cvReceiverRegistryFilenameV1)
		if err := os.WriteFile(path, make([]byte, cvMaxReceiverRegistryBytesV1+1), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs, nil); err == nil {
			t.Fatal("accepted an oversized receiver registry")
		}
	})

	t.Run("oversized secret", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		path := cvReceiverSecretPathV1(dirs.secret, 50)
		if err := os.WriteFile(path, make([]byte, fr.Bytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs, []int{50}); err == nil {
			t.Fatal("accepted an oversized receiver secret")
		}
	})

	t.Run("generation does not overwrite", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		if err := cvGenerateReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs); err == nil {
			t.Fatal("key generation overwrote existing material")
		}
	})

	t.Run("loader requires separate directories", func(t *testing.T) {
		dirs := generateCVReceiverKeysForTest(t, sid, receiverIDs)
		secret, err := os.ReadFile(cvReceiverSecretPathV1(dirs.secret, 50))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cvReceiverSecretPathV1(dirs.public, 50), secret, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := cvLoadReceiverKeyMaterialV1(dirs.public, dirs.public, sid, receiverIDs, []int{50}); err == nil {
			t.Fatal("loader accepted one directory for public and local-secret material")
		}
	})
}

func TestCVOldLockKeyMaterialLoadsOnlyLocalSigningShare(t *testing.T) {
	root := t.TempDir()
	publicDir := filepath.Join(root, "public")
	secretDir := filepath.Join(root, "private")
	members := []int{0, 1, 2, 3}
	if err := cvGenerateOldLockKeyMaterialV1(publicDir, secretDir, "cv-old-lock", members, 3); err != nil {
		t.Fatal(err)
	}
	material, err := cvLoadOldLockKeyMaterialV1(publicDir, secretDir, "cv-old-lock", members, 3, []int{1})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := newTBLSThresholdSignerFromMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	sig, err := signer.SignShare(1, "CV_TEST", digest)
	if err != nil || !signer.VerifyShare(1, "CV_TEST", digest, sig) {
		t.Fatalf("local old-node share failed: %v", err)
	}
	if _, err := signer.SignShare(0, "CV_TEST", digest); err == nil {
		t.Fatal("strict old lock signer retained a non-local share")
	}
	if len(material.localShares) != 1 {
		t.Fatalf("loaded old-node secrets = %d, want 1", len(material.localShares))
	}
	peerMaterial, err := cvLoadOldLockKeyMaterialV1(publicDir, secretDir, "cv-old-lock", members, 3, []int{0})
	if err != nil {
		t.Fatal(err)
	}
	peerSigner, err := newTBLSThresholdSignerFromMaterial(peerMaterial)
	if err != nil {
		t.Fatal(err)
	}
	peerSig, err := peerSigner.SignShare(0, "CV_TEST", digest)
	if err != nil || !signer.VerifyShare(0, "CV_TEST", digest, peerSig) {
		t.Fatalf("public registry could not verify peer share: %v", err)
	}
}

func TestCVRuntimeUsesRegistryBoundOldLockSigner(t *testing.T) {
	root := t.TempDir()
	publicDir := filepath.Join(root, "public")
	secretDir := filepath.Join(root, "private")
	oldMembers := []int{0, 1, 2, 3}
	newMembers := []int{4, 5, 6, 7}
	if err := cvGenerateReceiverKeyMaterialV1(publicDir, secretDir, "cv-runtime-lock", newMembers); err != nil {
		t.Fatal(err)
	}
	if err := cvGenerateOldLockKeyMaterialV1(publicDir, secretDir, "cv-runtime-lock", oldMembers, 3); err != nil {
		t.Fatal(err)
	}
	cfg := NormalizeConfig(Config{
		SID: "cv-runtime-lock", OldCommittee: oldMembers, NewCommittee: newMembers, F: 1,
		APVSSProvider: "cv-sapvss", LocalNodeIDs: []int{2},
		CVPublicKeyDir: publicDir, CVLocalSecretDir: secretDir,
	})
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	if _, err := cfg.runtime.lockSigner.SignShare(2, "CV_RUNTIME_TEST", digest); err != nil {
		t.Fatalf("local registry share rejected: %v", err)
	}
	if _, err := cfg.runtime.lockSigner.SignShare(0, "CV_RUNTIME_TEST", digest); err == nil {
		t.Fatal("CV runtime fell back to a signer containing non-local old-node shares")
	}
}

type cvReceiverKeyDirsForTest struct {
	public string
	secret string
}

func generateCVReceiverKeysForTest(t testing.TB, sid string, receiverIDs []int) cvReceiverKeyDirsForTest {
	t.Helper()
	root := t.TempDir()
	dirs := cvReceiverKeyDirsForTest{
		public: filepath.Join(root, "public"),
		secret: filepath.Join(root, "private"),
	}
	if err := cvGenerateReceiverKeyMaterialV1(dirs.public, dirs.secret, sid, receiverIDs); err != nil {
		t.Fatal(err)
	}
	return dirs
}

func readCVReceiverRegistryForTest(t testing.TB, dir string) cvReceiverRegistryV1 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, cvReceiverRegistryFilenameV1))
	if err != nil {
		t.Fatal(err)
	}
	var registry cvReceiverRegistryV1
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	return registry
}

func writeCVReceiverRegistryForTest(t testing.TB, dir string, registry cvReceiverRegistryV1) {
	t.Helper()
	raw, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, cvReceiverRegistryFilenameV1), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertCVKeyFileMode(t testing.TB, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %04o, want %04o", path, got, want)
	}
}
