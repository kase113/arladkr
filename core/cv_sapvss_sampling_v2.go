package core

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

type CVV2SamplingReport struct {
	Target                               string `json:"target"`
	Policy                               string `json:"policy"`
	WorstCaseByzantineFraction           string `json:"worst_case_byzantine_fraction,omitempty"`
	ProposerSampleSize                   int    `json:"proposer_sample_size"`
	ValidatorSampleSize                  int    `json:"validator_sample_size"`
	ValidatorThreshold                   int    `json:"validator_threshold"`
	ProposerFailureBound                 string `json:"proposer_failure_bound"`
	ValidatorSoundnessFailureBound       string `json:"validator_soundness_failure_bound"`
	ValidatorLivenessFailureBound        string `json:"validator_liveness_failure_bound"`
	ValidatorCombinedFailureBound        string `json:"validator_combined_failure_bound"`
	ContributorSamplingFailureBound      string `json:"contributor_sampling_failure_bound"`
	PerEpochCombinedSamplingFailureBound string `json:"per_epoch_combined_sampling_failure_bound"`
}

func ResolveCVV2Sampling(
	n, f int, target string, smokeProposerSample, smokeValidatorSample int,
) (CVV2SamplingReport, error) {
	normalized := strings.ToLower(strings.TrimSpace(target))
	if normalized == "" {
		normalized = "smoke"
	}
	proposerSample := smokeProposerSample
	validatorSample := smokeValidatorSample
	policy := "explicit-smoke"
	worstCaseFraction := ""
	var targetRat *big.Rat
	var err error
	if normalized != "smoke" {
		targetRat, err = cvParseFailureTargetV2(normalized)
		if err != nil {
			return CVV2SamplingReport{}, err
		}
		if n < 3*f+1 {
			return CVV2SamplingReport{}, fmt.Errorf("CV V2 secure sampling requires n >= 3f+1")
		}
		proposerSample, validatorSample = cvV2FixedFractionSampleSizes(targetRat)
		if proposerSample > n || validatorSample > n {
			return CVV2SamplingReport{}, fmt.Errorf(
				"CV V2 fixed-fraction sampling target %s requires samples (%d,%d), exceeding n=%d",
				target, proposerSample, validatorSample, n,
			)
		}
		policy = "fixed-fraction-1/3"
		worstCaseFraction = "1/3"
	}
	if proposerSample <= 0 || proposerSample > n || validatorSample <= 0 ||
		validatorSample > n || validatorSample%2 == 0 {
		return CVV2SamplingReport{}, fmt.Errorf("invalid CV V2 smoke sampling parameters")
	}
	threshold := (validatorSample + 1) / 2
	proposer, err := cvV2ProposerFailureBound(n, f, proposerSample)
	if err != nil {
		return CVV2SamplingReport{}, err
	}
	soundness, liveness, combined, err := cvV2ValidatorFailureBounds(n, f, validatorSample, threshold)
	if err != nil {
		return CVV2SamplingReport{}, err
	}
	if targetRat != nil && (proposer.Cmp(targetRat) > 0 || combined.Cmp(targetRat) > 0) {
		return CVV2SamplingReport{}, fmt.Errorf(
			"CV V2 fixed samples do not meet target %s for n=%d f=%d", target, n, f,
		)
	}
	perEpoch := new(big.Rat).Add(proposer, combined)
	return CVV2SamplingReport{
		Target: normalized, Policy: policy, WorstCaseByzantineFraction: worstCaseFraction,
		ProposerSampleSize: proposerSample, ValidatorSampleSize: validatorSample,
		ValidatorThreshold: threshold, ProposerFailureBound: proposer.RatString(),
		ValidatorSoundnessFailureBound:       soundness.RatString(),
		ValidatorLivenessFailureBound:        liveness.RatString(),
		ValidatorCombinedFailureBound:        combined.RatString(),
		ContributorSamplingFailureBound:      "0",
		PerEpochCombinedSamplingFailureBound: perEpoch.RatString(),
	}, nil
}

// The secure policy fixes f/n <= 1/3. Proposer failure is at most (1/3)^c.
// For an odd validator sample, the hypergeometric majority tail obeys the
// without-replacement Chernoff bound (2*sqrt(2)/3)^c; squaring gives the exact
// rational comparison (8/9)^c <= target^2.
func cvV2FixedFractionSampleSizes(target *big.Rat) (proposer, validator int) {
	proposerBound := big.NewRat(1, 1)
	for proposer = 1; ; proposer++ {
		proposerBound.Mul(proposerBound, big.NewRat(1, 3))
		if proposerBound.Cmp(target) <= 0 {
			break
		}
	}
	targetSquared := new(big.Rat).Mul(new(big.Rat).Set(target), target)
	validatorBoundSquared := big.NewRat(8, 9)
	for validator = 1; validatorBoundSquared.Cmp(targetSquared) > 0; validator += 2 {
		validatorBoundSquared.Mul(validatorBoundSquared, big.NewRat(64, 81))
	}
	return proposer, validator
}

func CVV2SamplingUnionBound(report CVV2SamplingReport, epochs int) (string, error) {
	if epochs < 0 {
		return "", fmt.Errorf("CV V2 sampling epoch count must be non-negative")
	}
	perEpoch, ok := new(big.Rat).SetString(report.PerEpochCombinedSamplingFailureBound)
	if !ok || perEpoch.Sign() < 0 {
		return "", fmt.Errorf("invalid CV V2 per-epoch sampling failure bound")
	}
	bound := new(big.Rat).Mul(perEpoch, new(big.Rat).SetInt64(int64(epochs)))
	if bound.Cmp(big.NewRat(1, 1)) > 0 {
		bound.SetInt64(1)
	}
	return bound.RatString(), nil
}

func cvParseFailureTargetV2(value string) (*big.Rat, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if strings.HasPrefix(value, "2^-") {
		exponent, err := strconv.Atoi(strings.TrimPrefix(value, "2^-"))
		if err != nil || exponent <= 0 {
			return nil, fmt.Errorf("invalid CV V2 failure target %q", value)
		}
		return new(big.Rat).SetFrac(big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), uint(exponent))), nil
	}
	parts := strings.Split(value, "e-")
	if len(parts) == 2 {
		coefficient, ok := new(big.Int).SetString(parts[0], 10)
		exponent, err := strconv.Atoi(parts[1])
		if !ok || err != nil || coefficient.Sign() <= 0 || exponent <= 0 {
			return nil, fmt.Errorf("invalid CV V2 failure target %q", value)
		}
		denominator := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(exponent)), nil)
		target := new(big.Rat).SetFrac(coefficient, denominator)
		if target.Cmp(big.NewRat(1, 1)) >= 0 {
			return nil, fmt.Errorf("CV V2 failure target must be below one")
		}
		return target, nil
	}
	return nil, fmt.Errorf("unsupported CV V2 failure target %q", value)
}
