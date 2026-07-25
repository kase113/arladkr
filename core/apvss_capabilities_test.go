package core

import (
	"strings"
	"testing"
)

func TestAPVSSCapabilitiesAreTruthful(t *testing.T) {
	optrand := NewOptrandAPVSS().Capabilities()
	if optrand.OutputKind != APVSSOutputEmulated || optrand.SupportsThresholdKeyOutput {
		t.Fatalf("unexpected optrand capabilities: %+v", optrand)
	}

	bls := NewBlsPVSS().Capabilities()
	if bls.OutputKind != APVSSOutputGroup || bls.SupportsThresholdKeyOutput {
		t.Fatalf("unexpected bls capabilities: %+v", bls)
	}
	if !bls.VerifiesReceivedTranscript || !bls.AggregatesReceivedInputs {
		t.Fatalf("BLS provider does not report its verified-input path: %+v", bls)
	}
	if bls.ProducesVerifiableShares || bls.UsesProductionRandomness {
		t.Fatalf("BLS provider overstates prototype capabilities: %+v", bls)
	}
}

func TestScalarShamirCapabilitiesAreTruthful(t *testing.T) {
	caps := NewScalarShamirAPVSS().Capabilities()
	if caps.OutputKind != APVSSOutputScalar ||
		!caps.VerifiesReceivedTranscript ||
		!caps.AggregatesReceivedInputs ||
		!caps.ProducesVerifiableShares ||
		!caps.SupportsThresholdKeyOutput {
		t.Fatalf("scalar Shamir provider understates required capabilities: %+v", caps)
	}
	if caps.UsesProductionRandomness {
		t.Fatalf("scalar Shamir provider overstates prototype randomness: %+v", caps)
	}
	if caps.SecurityProfile != "functional-scalar-prototype" {
		t.Fatalf("unexpected scalar Shamir security profile: %q", caps.SecurityProfile)
	}
}

func TestAPVSSCapabilitiesForConfigReturnsScalarShamirCapabilities(t *testing.T) {
	got := APVSSCapabilitiesForConfig(Config{APVSSProvider: "scalar-shamir"})
	want := NewScalarShamirAPVSS().Capabilities()
	if got != want {
		t.Fatalf("capability query returned wrong scalar Shamir contract: got=%+v want=%+v", got, want)
	}
}

func TestValidateConfigAcceptsScalarShamir(t *testing.T) {
	cfg := baseTestConfig()
	cfg.APVSSProvider = "scalar-shamir"
	cfg.DeriveMode = "scalar"
	cfg = NormalizeConfig(cfg)
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("ValidateConfig rejected scalar Shamir mode: %v", err)
	}
	if err := validateAPVSSDeriveMode(cfg, NewScalarShamirAPVSS()); err != nil {
		t.Fatalf("scalar Shamir provider failed scalar derive capability gate: %v", err)
	}
}

func TestScalarDeriveModeRejectsNonScalarProviders(t *testing.T) {
	cfg := NormalizeConfig(Config{DeriveMode: "scalar", APVSSProvider: "bls-pvss"})
	err := validateAPVSSDeriveMode(cfg, NewBlsPVSS())
	if err == nil || !strings.Contains(err.Error(), "requires scalar-output APVSS") {
		t.Fatalf("expected scalar capability error, got %v", err)
	}
}

func TestRecoverAndDeriveScalarModeFailsClosedAtEntry(t *testing.T) {
	cfg := NormalizeConfig(Config{DeriveMode: "scalar", APVSSProvider: "bls-pvss"})
	_, _, _, _, err := RecoverAndDeriveFromAggRLO(cfg, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "requires scalar-output APVSS") {
		t.Fatalf("expected recovery entry point to fail closed, got %v", err)
	}
}

func TestValidateConfigRejectsUnknownDeriveMode(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:           "invalid-derive-mode",
		OldCommittee:  []int{0, 1, 2, 3},
		NewCommittee:  []int{10, 11, 12, 13},
		FOld:          1,
		FNew:          1,
		DeriveMode:    "unknown",
		APVSSProvider: "optrand",
	})
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected invalid derive mode")
	}
}

func TestNormalizeConfigNormalizesAPVSSProvider(t *testing.T) {
	cfg := NormalizeConfig(Config{APVSSProvider: " BLS-PVSS "})
	if cfg.APVSSProvider != "bls-pvss" {
		t.Fatalf("provider was not normalized: %q", cfg.APVSSProvider)
	}
}

func TestValidateConfigRejectsUnknownAPVSSProvider(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:           "invalid-provider",
		OldCommittee:  []int{0, 1, 2, 3},
		NewCommittee:  []int{10, 11, 12, 13},
		FOld:          1,
		FNew:          1,
		APVSSProvider: "unknown",
	})
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected invalid APVSS provider rejection")
	}
}
