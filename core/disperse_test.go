package core

import "testing"

func TestNormalizeConfigSeparatesOldAndNewFaultThresholds(t *testing.T) {
	balanced := NormalizeConfig(Config{FOld: 2, FNew: 2})
	if balanced.FOld != 2 || balanced.FNew != 2 || balanced.Kappa != 3 {
		t.Fatalf(
			"balanced fault normalization = FOld/FNew/Kappa %d/%d/%d",
			balanced.FOld,
			balanced.FNew,
			balanced.Kappa,
		)
	}

	separate := NormalizeConfig(Config{FOld: 1, FNew: 2})
	if separate.FOld != 1 || separate.FNew != 2 || separate.Kappa != 2 {
		t.Fatalf(
			"separate fault normalization = FOld/FNew/Kappa %d/%d/%d",
			separate.FOld,
			separate.FNew,
			separate.Kappa,
		)
	}

	zeroOld := NormalizeConfig(Config{FOld: 0, FNew: 1})
	if zeroOld.FOld != 0 || zeroOld.FNew != 1 || zeroOld.Kappa != 1 {
		t.Fatalf("explicit f_o=0/f_n=1 normalization = %d/%d/%d", zeroOld.FOld, zeroOld.FNew, zeroOld.Kappa)
	}
}

func TestValidateConfigUsesCommitteeSpecificFaultBounds(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:          "separate-fault-bounds",
		OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: []int{10, 11, 12, 13, 14, 15, 16},
		FOld:         1,
		FNew:         2,
	})
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("valid separate fault thresholds rejected: %v", err)
	}

	badOld := cfg
	badOld.OldCommittee = []int{0, 1, 2}
	if err := ValidateConfig(badOld); err == nil {
		t.Fatal("accepted n_o < 3f_o+1")
	}
	badNew := cfg
	badNew.NewCommittee = []int{10, 11, 12, 13, 14, 15}
	if err := ValidateConfig(badNew); err == nil {
		t.Fatal("accepted n_n < 3f_n+1")
	}
}

func TestAsymmetricCommitteeThresholdRoles(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:           "asymmetric-threshold-roles",
		OldCommittee:  []int{0, 1, 2, 3},
		NewCommittee:  []int{10, 11, 12, 13, 14, 15, 16},
		FOld:          1,
		FNew:          2,
		APVSSProvider: "cv-sapvss",
	})
	if err := ValidateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Kappa != 2 {
		t.Fatalf("aggregate dealer count=%d, want f_o+1=2", cfg.Kappa)
	}
	if cfg.runtime.lockSigner.t != 3 {
		t.Fatalf("component/ARC threshold=%d, want n_o-f_o=3", cfg.runtime.lockSigner.t)
	}
	if cfg.runtime.coinSigner.t != 2 {
		t.Fatalf("old-committee coin threshold=%d, want f_o+1=2", cfg.runtime.coinSigner.t)
	}
	if got := len(cfg.OldCommittee) - 2*cfg.FOld; got != 2 {
		t.Fatalf("aggregate RS data shards=%d, want n_o-2f_o=2", got)
	}
	if got := cfg.FNew + 1; got != 3 {
		t.Fatalf("APVSS scalar reconstruction threshold=%d, want f_n+1=3", got)
	}
}

func TestValidateConfigRequiresFOldPlusOneAggregateDealers(t *testing.T) {
	cfg := baseTestConfig()
	cfg.Kappa = cfg.FOld + 2
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("ValidateConfig accepted Kappa=%d, want f_o+1=%d", cfg.Kappa, cfg.FOld+1)
	}
}

func TestNormalizeConfigPreservesNegativeKappaForValidation(t *testing.T) {
	omitted := baseTestConfig()
	omitted.Kappa = 0
	omitted = NormalizeConfig(omitted)
	if omitted.Kappa != omitted.FOld+1 {
		t.Fatalf("NormalizeConfig derived Kappa=%d, want f_o+1=%d", omitted.Kappa, omitted.FOld+1)
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
			cfg := Config{APVSSProvider: tt.provider, FOld: tt.f, FNew: tt.f}
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
		FOld:          1,
		FNew:          1,
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
				FOld:          1,
				FNew:          1,
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
				FOld:          1,
				FNew:          1,
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
		FOld:          1,
		FNew:          1,
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
		FOld:          1,
		FNew:          1,
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
		FOld:         1,
		FNew:         1,
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
