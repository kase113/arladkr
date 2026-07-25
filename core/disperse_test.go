package core

import "testing"

func TestValidateConfigRequiresFPlusOneAggregateDealers(t *testing.T) {
	cfg := baseTestConfig()
	cfg.Kappa = cfg.F + 2
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("ValidateConfig accepted Kappa=%d, want F+1=%d", cfg.Kappa, cfg.F+1)
	}
}

func TestNormalizeConfigPreservesNegativeKappaForValidation(t *testing.T) {
	omitted := baseTestConfig()
	omitted.Kappa = 0
	omitted = NormalizeConfig(omitted)
	if omitted.Kappa != omitted.F+1 {
		t.Fatalf("NormalizeConfig derived Kappa=%d, want F+1=%d", omitted.Kappa, omitted.F+1)
	}

	invalid := baseTestConfig()
	invalid.Kappa = -1
	invalid = NormalizeConfig(invalid)
	if invalid.Kappa != -1 {
		t.Fatalf("NormalizeConfig changed negative Kappa to %d, want -1", invalid.Kappa)
	}
	if err := ValidateConfig(invalid); err == nil {
		t.Fatal("ValidateConfig accepted negative Kappa")
	}
}

func TestValidateConfigRejectsImpossibleAggregateBounds(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{
			name: "fastlane minimum exceeds old committee",
			mutate: func(cfg *Config) {
				cfg.FastlaneMin = len(cfg.OldCommittee) + 1
			},
		},
		{
			name: "ARC candidate cap below kappa",
			mutate: func(cfg *Config) {
				cfg.MaxARCCandidatesPerEpoch = cfg.Kappa - 1
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseTestConfig()
			tt.mutate(&cfg)
			if err := ValidateConfig(cfg); err == nil {
				t.Fatal("ValidateConfig accepted impossible aggregate bounds")
			}
		})
	}
}

func TestDealerShareThresholdUsesProviderSemanticsAndClamps(t *testing.T) {
	tests := []struct {
		name          string
		provider      string
		f             int
		receiverCount int
		want          int
	}{
		{name: "optrand", provider: "optrand", f: 1, receiverCount: 4, want: 3},
		{name: "bls pvss", provider: "bls-pvss", f: 1, receiverCount: 4, want: 3},
		{name: "scalar shamir", provider: "scalar-shamir", f: 1, receiverCount: 4, want: 2},
		{name: "lower clamp", provider: "optrand", f: 9, receiverCount: 4, want: 1},
		{name: "scalar rejects insufficient receivers", provider: "scalar-shamir", f: 9, receiverCount: 4, want: 0},
		{name: "no receivers", provider: "scalar-shamir", f: 1, receiverCount: 0, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{APVSSProvider: tt.provider, F: tt.f}
			if got := dealerShareThreshold(cfg, tt.receiverCount); got != tt.want {
				t.Fatalf("dealerShareThreshold()=%d, want %d", got, tt.want)
			}
		})
	}
}

func TestValidateConfigRejectsScalarShamirReceiverSetBelowThreshold(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:           "scalar-shamir-insufficient-config",
		Epoch:         1,
		OldCommittee:  []int{0, 1, 2, 3},
		NewCommittee:  []int{10},
		F:             1,
		APVSSProvider: "scalar-shamir",
	})
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("ValidateConfig accepted scalar-shamir receiver count below F+1")
	}
}

func TestValidateConfigRejectsDuplicateCommitteeIDs(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "duplicate scalar-shamir receivers do not satisfy f plus one",
			cfg: Config{
				SID:           "scalar-shamir-duplicate-receivers",
				Epoch:         1,
				OldCommittee:  []int{0, 1, 2, 3},
				NewCommittee:  []int{10, 10},
				F:             1,
				APVSSProvider: "scalar-shamir",
			},
		},
		{
			name: "duplicate old committee members",
			cfg: Config{
				SID:           "duplicate-old-committee",
				Epoch:         1,
				OldCommittee:  []int{0, 0, 1, 2},
				NewCommittee:  []int{10, 11, 12, 13},
				F:             1,
				APVSSProvider: "optrand",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := NormalizeConfig(tt.cfg)
			if err := ValidateConfig(cfg); err == nil {
				t.Fatalf("ValidateConfig accepted duplicate committee IDs")
			}
		})
	}
}

func TestValidateConfigAcceptsUniqueScalarShamirCommittees(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:           "scalar-shamir-unique-committees",
		Epoch:         1,
		OldCommittee:  []int{0, 1, 2, 3},
		NewCommittee:  []int{10, 11},
		F:             1,
		APVSSProvider: "scalar-shamir",
	})
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("ValidateConfig rejected unique scalar-shamir committees: %v", err)
	}
}

func TestBuildDealerArtifactsRejectsScalarShamirReceiverSetBelowThreshold(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:           "scalar-shamir-insufficient-build",
		Epoch:         1,
		OldCommittee:  []int{0, 1, 2, 3},
		NewCommittee:  []int{10},
		F:             1,
		APVSSProvider: "scalar-shamir",
	})
	if _, err := BuildDealerArtifacts(cfg); err == nil {
		t.Fatalf("BuildDealerArtifacts accepted scalar-shamir receiver count below F+1")
	}
}

func TestBuildDealerArtifactsAndValidate(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:          "rladkr-test-disperse",
		Epoch:        1,
		OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: []int{0, 1, 2, 3},
		F:            1,
	})
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	if len(artifacts) != 4 {
		t.Fatalf("unexpected artifact count: %d", len(artifacts))
	}
	for dealer, art := range artifacts {
		if !ValidateDescriptor(cfg, art.Descriptor) {
			t.Fatalf("descriptor invalid for dealer %d", dealer)
		}
		cp := art.Descriptor
		cp.Digest[0] ^= 0x01
		if ValidateDescriptor(cfg, cp) {
			t.Fatalf("tampered descriptor should fail for dealer %d", dealer)
		}
	}
}
