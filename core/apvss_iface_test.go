package core

import (
	"bytes"
	"strings"
	"testing"
)

func TestCloneRecoveredScalarFieldsAreIndependent(t *testing.T) {
	original := &APVSSRecovered{
		OutputKind:          APVSSOutputScalar,
		AggregateDigest:     []byte{1, 2, 3},
		RecoveredMaterial:   []byte{4, 5, 6},
		ContributionDigests: map[int][]byte{7: {8, 9}},
		ScalarThreshold:     2,
		ScalarShares:        map[int][]byte{1: {10, 11, 12}},
		ThresholdPublicKey:  []byte{13, 14, 15},
	}

	cloned := cloneAPVSSRecovered(original)
	if cloned == original {
		t.Fatal("clone returned original recovered value")
	}
	if !bytes.Equal(cloned.AggregateDigest, original.AggregateDigest) ||
		!bytes.Equal(cloned.RecoveredMaterial, original.RecoveredMaterial) ||
		!bytes.Equal(cloned.ContributionDigests[7], original.ContributionDigests[7]) ||
		cloned.ScalarThreshold != original.ScalarThreshold ||
		!bytes.Equal(cloned.ScalarShares[1], original.ScalarShares[1]) ||
		!bytes.Equal(cloned.ThresholdPublicKey, original.ThresholdPublicKey) {
		t.Fatalf("clone did not preserve recovered fields: got=%+v want=%+v", cloned, original)
	}

	cloned.AggregateDigest[0] = 16
	cloned.RecoveredMaterial[0] = 17
	cloned.ContributionDigests[7][0] = 18
	cloned.ContributionDigests[8] = []byte{19}
	cloned.ScalarShares[1][0] = 9
	cloned.ScalarShares[2] = []byte{7}
	cloned.ThresholdPublicKey[0] = 8
	if bytes.Equal(cloned.AggregateDigest, original.AggregateDigest) {
		t.Fatal("aggregate digest aliases original")
	}
	if bytes.Equal(cloned.RecoveredMaterial, original.RecoveredMaterial) {
		t.Fatal("recovered material aliases original")
	}
	if bytes.Equal(cloned.ContributionDigests[7], original.ContributionDigests[7]) {
		t.Fatal("contribution digest bytes alias original")
	}
	if _, ok := original.ContributionDigests[8]; ok {
		t.Fatal("contribution digests map aliases original")
	}
	if bytes.Equal(cloned.ScalarShares[1], original.ScalarShares[1]) {
		t.Fatal("scalar share bytes alias original")
	}
	if _, ok := original.ScalarShares[2]; ok {
		t.Fatal("scalar shares map aliases original")
	}
	if bytes.Equal(cloned.ThresholdPublicKey, original.ThresholdPublicKey) {
		t.Fatal("threshold public key aliases original")
	}
}

func TestOptrandAPVSSInterface_RoundTrip(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("build artifacts failed: %v", err)
	}

	apvss := NewOptrandAPVSS()
	for _, dealer := range stableFirst(cfg.OldCommittee, cfg.FastlaneMin) {
		art := artifacts[dealer]
		if art == nil {
			t.Fatalf("missing artifact for dealer=%d", dealer)
		}
		tx, err := apvss.ADist(cfg, art)
		if err != nil {
			t.Fatalf("ADist failed: %v", err)
		}
		if err := apvss.Ver(cfg, tx, art); err != nil {
			t.Fatalf("Ver failed for dealer=%d: %v", dealer, err)
		}
	}

	dealers := stableFirst(cfg.OldCommittee, cfg.Kappa)
	agg, err := apvss.Agg(cfg, dealers, artifacts)
	if err != nil {
		t.Fatalf("Agg failed: %v", err)
	}
	if err := apvss.AVer(cfg, agg, artifacts); err != nil {
		t.Fatalf("AVer failed: %v", err)
	}
	rec, err := apvss.Rec(cfg, agg, artifacts)
	if err != nil {
		t.Fatalf("Rec failed: %v", err)
	}
	if rec.OutputKind != APVSSOutputEmulated {
		t.Fatalf("unexpected recovered output kind: got=%q want=%q", rec.OutputKind, APVSSOutputEmulated)
	}
}

func TestAPVSSFactoryReturnsScalarShamirProvider(t *testing.T) {
	cfg := NormalizeConfig(Config{APVSSProvider: "scalar-shamir"})
	provider := newAPVSSFromConfig(cfg)
	if _, ok := provider.(*ScalarShamirProvider); !ok {
		t.Fatalf("factory returned %T, want *ScalarShamirProvider", provider)
	}
}

func TestAPVSSFactoryDoesNotDowngradeCVSAPVSS(t *testing.T) {
	provider := newAPVSSFromConfig(Config{APVSSProvider: "cv-sapvss"})
	if provider == nil {
		t.Fatal("cv-sapvss provider factory returned nil")
	}
	if _, downgraded := provider.(*OptrandAPVSS); downgraded {
		t.Fatal("cv-sapvss provider was silently downgraded to Optrand")
	}
}

func TestAggRLO_AdmitAgg(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("build artifacts failed: %v", err)
	}
	apvss := NewOptrandAPVSS()
	dealers := stableFirst(cfg.OldCommittee, cfg.Kappa)
	agg, err := apvss.Agg(cfg, dealers, artifacts)
	if err != nil {
		t.Fatalf("Agg failed: %v", err)
	}
	rlo, _, err := BuildAggRLO(cfg, dealers, agg)
	if err != nil {
		t.Fatalf("BuildAggRLO failed: %v", err)
	}
	if err := AdmitAgg(cfg, rlo, apvss, artifacts); err != nil {
		t.Fatalf("AdmitAgg failed: %v", err)
	}

	bad := *rlo
	bad.Digest = hashBytes([]byte("tamper"), rlo.Digest)
	if err := AdmitAgg(cfg, &bad, apvss, artifacts); err == nil {
		t.Fatalf("expected tampered AggRLO digest to fail AdmitAgg")
	}
}

func TestBuildAggRLORejectsDealerOutsideOldCommittee(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("build artifacts failed: %v", err)
	}
	apvss := NewOptrandAPVSS()
	dealers := stableFirst(cfg.OldCommittee, cfg.Kappa)
	agg, err := apvss.Agg(cfg, dealers, artifacts)
	if err != nil {
		t.Fatalf("Agg failed: %v", err)
	}
	outsideDealers := []int{dealers[0], 99}
	outsideAgg := cloneAPVSSAggregate(agg)
	outsideAgg.Dealers = append([]int(nil), outsideDealers...)
	if _, _, err := BuildAggRLO(cfg, outsideDealers, outsideAgg); err == nil || !strings.Contains(err.Error(), "outside old committee") {
		t.Fatalf("BuildAggRLO did not reject an outside dealer before signing: %v", err)
	}
}

func TestAggRLOAdmissionRejectsDealerOutsideOldCommittee(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("build artifacts failed: %v", err)
	}
	apvss := NewOptrandAPVSS()
	dealers := stableFirst(cfg.OldCommittee, cfg.Kappa)
	agg, err := apvss.Agg(cfg, dealers, artifacts)
	if err != nil {
		t.Fatalf("Agg failed: %v", err)
	}
	rlo, _, err := BuildAggRLO(cfg, dealers, agg)
	if err != nil {
		t.Fatalf("BuildAggRLO failed: %v", err)
	}
	mutated := cloneAggRLO(rlo)
	mutated.Header.Dealers[1] = 99
	mutated.Aggregate.Dealers[1] = 99

	t.Run("shape", func(t *testing.T) {
		if _, err := validateAggRLOShape(cfg, mutated); err == nil || !strings.Contains(err.Error(), "outside old committee") {
			t.Fatalf("validateAggRLOShape did not reject an outside dealer: %v", err)
		}
	})
	t.Run("local admission", func(t *testing.T) {
		if err := AdmitLocallyConstructedAgg(cfg, mutated); err == nil || !strings.Contains(err.Error(), "outside old committee") {
			t.Fatalf("AdmitLocallyConstructedAgg did not reject an outside dealer at shape validation: %v", err)
		}
	})
}
