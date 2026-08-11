package core

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestCVReferenceEpochV2EndToEnd(t *testing.T) {
	first, context, receivers, validators := cvAllACKLeafV2Fixture(t)
	cfg := cvV2ParamsTestConfig()
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		t.Fatal(err)
	}
	leaves := []*cvLeafV2{first}
	for i := 1; i < params.poolSize; i++ {
		leaves = append(leaves, cvBuildAllACKLeafForDealerV2(
			t, context.OldRoster[i], context, receivers, validators,
		))
	}

	publicDir := filepath.Join(t.TempDir(), "old-threshold-public")
	secretDir := filepath.Join(t.TempDir(), "old-threshold-secret")
	if err := cvGenerateOldCommitteeKeyBundleV2(
		publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params,
	); err != nil {
		t.Fatal(err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleV2(
		publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params,
	)
	if err != nil {
		t.Fatal(err)
	}
	apdbSigner, err := newTBLSThresholdSignerFromV2Material(bundle.apdb)
	if err != nil {
		t.Fatal(err)
	}
	controlSigner, err := newTBLSThresholdSignerFromV2Material(bundle.control)
	if err != nil {
		t.Fatal(err)
	}
	coinSigner, err := newTBLSThresholdSignerFromV2Material(bundle.coin)
	if err != nil {
		t.Fatal(err)
	}

	result, err := cvRunReferenceEpochV2(cvReferenceEpochInputV2{
		Context: context, Params: params, Leaves: leaves, Receivers: receivers, Validators: validators,
		APDBSigner: apdbSigner, ControlSigner: controlSigner, CoinSigner: coinSigner,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Components) != params.poolSize || len(result.SelectedIndices) != params.componentCount ||
		len(result.ShareOutputs) != len(context.NewRoster) || result.PublicKey.IsInfinity() {
		t.Fatal("reference V2 epoch returned incomplete artifacts")
	}
	if !bytes.Equal(result.Aggregate.Digest, result.RecoveredAggregate.Digest) {
		t.Fatal("reference V2 aggregate recovery changed the aggregate digest")
	}
	if err := cvVerifyHandoffV2(
		&result.Handoff, result.Header.ContextDigest, apdbSigner, controlSigner,
	); err != nil {
		t.Fatal(err)
	}
	alternate, err := cvRecoverThresholdPublicKeyV2(
		result.ShareOutputs[1:], result.RecoveredAggregate, context, params, receivers,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !alternate.Equal(&result.PublicKey) {
		t.Fatal("reference V2 threshold share subsets produced different public keys")
	}
	if result.Timings.Total <= 0 || result.Timings.Components <= 0 || result.Timings.Shares <= 0 {
		t.Fatal("reference V2 epoch did not record experiment phase timings")
	}
	t.Logf("reference V2 timings: components=%s pool=%s aggregate=%s validation=%s agreement=%s handoff=%s recovery=%s shares=%s total=%s",
		result.Timings.Components, result.Timings.Pool, result.Timings.Aggregate,
		result.Timings.Validation, result.Timings.Agreement, result.Timings.Handoff,
		result.Timings.Recovery, result.Timings.Shares, result.Timings.Total)
}
