package core

import (
	"encoding/json"
	"testing"
)

func TestDescriptorCodecAndValidation(t *testing.T) {
	cfg := baseTestConfig()
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	descriptors := make(map[int]Descriptor, len(artifacts))
	for dealer, art := range artifacts {
		descriptors[dealer] = art.Descriptor
	}

	cands := []int{3, 1, 2, 1}
	blob, err := BuildDescriptor(cands, descriptors)
	if err != nil {
		t.Fatalf("BuildDescriptor failed: %v", err)
	}
	digests, err := DecodeDescriptor(blob)
	if err != nil {
		t.Fatalf("DecodeDescriptor failed: %v", err)
	}
	if len(digests) != 3 {
		t.Fatalf("decoded digest count mismatch: %d", len(digests))
	}
	set, err := ValidateFallbackDescriptor(blob, cfg, descriptors, cfg.Kappa)
	if err != nil {
		t.Fatalf("ValidateFallbackDescriptor failed: %v", err)
	}
	if len(set) != cfg.Kappa {
		t.Fatalf("validated set size mismatch: %d != %d", len(set), cfg.Kappa)
	}
}

func TestDescriptorValidationRejectsDuplicateDigest(t *testing.T) {
	cfg := baseTestConfig()
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("BuildDealerArtifacts failed: %v", err)
	}
	descriptors := make(map[int]Descriptor, len(artifacts))
	for dealer, art := range artifacts {
		descriptors[dealer] = art.Descriptor
	}

	blob, err := BuildDescriptor([]int{0, 1, 2}, descriptors)
	if err != nil {
		t.Fatalf("BuildDescriptor failed: %v", err)
	}
	var payload descriptorPayload
	if err := json.Unmarshal(blob, &payload); err != nil {
		t.Fatalf("unmarshal descriptor failed: %v", err)
	}
	payload.Digests = append(payload.Digests, payload.Digests[0])
	bad, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal duplicate descriptor failed: %v", err)
	}
	if _, err := ValidateFallbackDescriptor(bad, cfg, descriptors, cfg.Kappa); err == nil {
		t.Fatalf("expected duplicate digest rejection")
	}
}
