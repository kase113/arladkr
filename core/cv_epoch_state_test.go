package core

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestCVEpochStatePersistLoadAndRejectMutation(t *testing.T) {
	cfg, result := cvEpochStateFixture(t)
	root := t.TempDir()
	state, err := PersistCVEpochState(root, cfg, result)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCVEpochState(root, cfg.SID, cfg.Epoch, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.Digest, state.Digest) || !bytes.Equal(loaded.NewPublicKey, result.NewPublicKey) {
		t.Fatal("persisted CV epoch state did not round-trip")
	}

	dir := cvEpochStateDir(root, cfg.SID, cfg.Epoch)
	localPath := cvEpochLocalStatePath(dir, 0)
	raw, err := cvReadImmutableFile(localPath)
	if err != nil {
		t.Fatal(err)
	}
	var local cvEpochLocalState
	if err := json.Unmarshal(raw, &local); err != nil {
		t.Fatal(err)
	}
	local.Share[len(local.Share)-1] ^= 1
	raw, err = json.Marshal(&local)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCVEpochState(root, cfg.SID, cfg.Epoch, 0); err == nil {
		t.Fatal("state loader accepted a mutated private scalar share")
	}

	secondRoot := t.TempDir()
	if _, err := PersistCVEpochState(secondRoot, cfg, result); err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(cvEpochStateDir(secondRoot, cfg.SID, cfg.Epoch), cvEpochPublicFilename)
	raw, err = cvReadImmutableFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	var public CVEpochPublicState
	if err := json.Unmarshal(raw, &public); err != nil {
		t.Fatal(err)
	}
	public.NewPublicKey[len(public.NewPublicKey)-1] ^= 1
	raw, err = json.Marshal(&public)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCVEpochState(secondRoot, cfg.SID, cfg.Epoch, 0); err == nil {
		t.Fatal("state loader accepted a mutated public state")
	}
}

func TestCVEpochStateDigestBindsNextLeafContext(t *testing.T) {
	cfg, result := cvEpochStateFixture(t)
	state, _, err := BuildCVEpochState(cfg, result)
	if err != nil {
		t.Fatal(err)
	}
	_, context, _, _ := cvM4Fixture(t)
	context.epoch++
	withoutPrevious := cvLeafContextDigest(&context)
	context.previousStateDigest = append([]byte(nil), state.Digest...)
	withPrevious := cvLeafContextDigest(&context)
	if len(withoutPrevious) != 32 || len(withPrevious) != 32 || bytes.Equal(withoutPrevious, withPrevious) {
		t.Fatal("next CV leaf context does not bind the previous epoch state digest")
	}
}

func cvEpochStateFixture(t *testing.T) (Config, *EpochResult) {
	t.Helper()
	cfg, context, receiverSecrets, leaves := cvM4Fixture(t)
	aggregate, err := cvAgg(&context, leaves)
	if err != nil {
		t.Fatal(err)
	}
	aggregateWire, err := cvAggregateCanonicalBytes(aggregate)
	if err != nil {
		t.Fatal(err)
	}
	secretMap := make(map[int]fr.Element, len(receiverSecrets))
	for receiverID, secret := range receiverSecrets {
		secretMap[receiverID] = secret
	}
	shares, receipts, err := cvCreateLocalDecryptionOutputs(
		&context, aggregate, cfg.NewCommittee, secretMap,
	)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := cvThresholdPublicKeyFromReceipts(&context, aggregate, cfg.NewCommittee, receipts)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, &EpochResult{
		RecoveredAggregate: aggregateWire,
		AggRLODigest:       hashBytes([]byte("cv-epoch-state-test-rlo"), aggregate.digest),
		NewShares:          shares,
		NewPublicKey:       publicKey,
		CVReceipts:         receipts,
	}
}
