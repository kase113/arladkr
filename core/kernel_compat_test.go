package core

import (
	"context"
	"testing"
	"time"
)

func TestRunEpoch_DefaultLegacyKernelUsesMVBA(t *testing.T) {
	cfg := baseTestConfig()
	cfg.AgreementKernel = "legacy-sim"
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	res, err := RunEpoch(ctx, cfg)
	if err != nil {
		t.Fatalf("RunEpoch default legacy kernel failed: %v", err)
	}
	if res.AgreementMode != "fallback-mvba" {
		t.Fatalf("unexpected agreement mode: %s", res.AgreementMode)
	}
}

func TestRunEpoch_FallbackLegacyKernel(t *testing.T) {
	cfg := baseTestConfig()
	cfg.ForceFallback = true
	cfg.AgreementKernel = "legacy-sim"
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	res, err := RunEpoch(ctx, cfg)
	if err != nil {
		t.Fatalf("RunEpoch fallback legacy kernel failed: %v", err)
	}
	if res.AgreementMode != "fallback-mvba" {
		t.Fatalf("unexpected agreement mode: %s", res.AgreementMode)
	}
	if len(res.LockedSet) == 0 {
		t.Fatalf("empty locked set")
	}
}

func TestRunEpoch_FallbackDistributedKernelRBCABA(t *testing.T) {
	cfg := baseTestConfig()
	cfg.ForceFallback = true
	cfg.AgreementKernel = "distributed-actor"
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	res, err := RunEpoch(ctx, cfg)
	if err != nil {
		t.Fatalf("RunEpoch fallback distributed kernel failed: %v", err)
	}
	if len(res.PerNode) != len(cfg.OldCommittee) {
		t.Fatalf("per-node outputs mismatch: %d", len(res.PerNode))
	}
	base := toKey(res.PerNode[0].DecidedSet)
	for i := 1; i < len(res.PerNode); i++ {
		if toKey(res.PerNode[i].DecidedSet) != base {
			t.Fatalf("distributed fallback node outputs diverged")
		}
	}
}
