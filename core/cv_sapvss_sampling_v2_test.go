package core

import (
	"math/big"
	"testing"
)

func TestCVV2FixedFractionSamplingDependsOnlyOnFailureTarget(t *testing.T) {
	tests := []struct {
		target                      string
		wantProposer, wantValidator int
	}{
		{target: "1e-8", wantProposer: 17, wantValidator: 313},
		{target: "1e-10", wantProposer: 21, wantValidator: 391},
		{target: "2^-80", wantProposer: 51, wantValidator: 943},
		{target: "2^-128", wantProposer: 81, wantValidator: 1507},
	}
	for _, test := range tests {
		t.Run(test.target, func(t *testing.T) {
			target, err := cvParseFailureTargetV2(test.target)
			if err != nil {
				t.Fatal(err)
			}
			proposer, validator := cvV2FixedFractionSampleSizes(target)
			if proposer != test.wantProposer || validator != test.wantValidator {
				t.Fatalf("fixed samples = (%d,%d), want (%d,%d)",
					proposer, validator, test.wantProposer, test.wantValidator)
			}
		})
	}
}

func TestResolveCVV2SamplingUsesCommitteeIndependentSecureSamples(t *testing.T) {
	first, err := ResolveCVV2Sampling(1024, 341, "1e-8", 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ResolveCVV2Sampling(2048, 682, "1e-8", 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if first.Policy != "fixed-fraction-1/3" || first.WorstCaseByzantineFraction != "1/3" ||
		first.ProposerSampleSize != second.ProposerSampleSize ||
		first.ValidatorSampleSize != second.ValidatorSampleSize {
		t.Fatalf("committee-dependent secure sampling: first=%+v second=%+v", first, second)
	}
	target := big.NewRat(1, 100000000)
	for name, value := range map[string]string{
		"proposer":  first.ProposerFailureBound,
		"validator": first.ValidatorCombinedFailureBound,
	} {
		bound, ok := new(big.Rat).SetString(value)
		if !ok || bound.Cmp(target) > 0 {
			t.Fatalf("%s exact finite-population bound %q exceeds target", name, value)
		}
	}
}

func TestResolveCVV2SamplingRejectsCommitteeBelowFixedSample(t *testing.T) {
	if _, err := ResolveCVV2Sampling(128, 42, "1e-8", 3, 3); err == nil {
		t.Fatal("secure policy silently shrank its fixed sample for a small committee")
	}
}

func TestResolveCVV2SamplingLabelsSmallSamplesAsSmoke(t *testing.T) {
	report, err := ResolveCVV2Sampling(7, 2, "smoke", 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if report.Target != "smoke" || report.ProposerSampleSize != 3 || report.ValidatorSampleSize != 3 ||
		report.Policy != "explicit-smoke" || report.ValidatorCombinedFailureBound != "1/7" {
		t.Fatalf("smoke sampling report=%+v", report)
	}
	if _, err := ResolveCVV2Sampling(7, 2, "smoke", 3, 2); err == nil {
		t.Fatal("accepted an even smoke validator sample")
	}
}

func TestResolveCVV2SamplingRejectsUnsupportedTarget(t *testing.T) {
	for _, target := range []string{"0.01", "1e-0", "2^-0", "unknown"} {
		if _, err := ResolveCVV2Sampling(128, 42, target, 3, 3); err == nil {
			t.Fatalf("accepted unsupported target %q", target)
		}
	}
}

func TestCVV2SamplingUnionBoundIsExactAndCapped(t *testing.T) {
	report, err := ResolveCVV2Sampling(7, 2, "smoke", 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if report.ContributorSamplingFailureBound != "0" {
		t.Fatalf("contributor sampling bound=%q, want 0", report.ContributorSamplingFailureBound)
	}
	if got, err := CVV2SamplingUnionBound(report, 3); err != nil || got != "3/7" {
		t.Fatalf("three-epoch union bound=%q err=%v", got, err)
	}
	if got, err := CVV2SamplingUnionBound(report, 8); err != nil || got != "1" {
		t.Fatalf("capped union bound=%q err=%v", got, err)
	}
}
