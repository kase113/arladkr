package core

import "context"

func PrepareRuntime(cfg Config) error {
	cfg = NormalizeConfig(cfg)
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	return ensureRuntime(&cfg)
}

func PrepareConfigRuntime(cfg Config) (Config, error) {
	cfg = NormalizeConfig(cfg)
	if err := ValidateConfig(cfg); err != nil {
		return cfg, err
	}
	if err := ensureRuntime(&cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// RunEpoch has one production protocol path: materialized CV-sAPVSS followed
// by a single aggregate-level MVBA.
func RunEpoch(ctx context.Context, cfg Config) (*EpochResult, error) {
	return RunCVEpoch(ctx, NormalizeConfig(cfg))
}
