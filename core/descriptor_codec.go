package core

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

type descriptorPayload struct {
	Version int      `json:"v"`
	Digests []string `json:"digests"`
}

type digestDealer struct {
	Dealer int
	Digest string
}

func BuildDescriptor(candidates []int, descriptors map[int]Descriptor) ([]byte, error) {
	seenDealer := make(map[int]struct{}, len(candidates))
	digests := make([]string, 0, len(candidates))
	for _, dealer := range candidates {
		if _, ok := seenDealer[dealer]; ok {
			continue
		}
		desc, ok := descriptors[dealer]
		if !ok {
			return nil, fmt.Errorf("missing descriptor for dealer %d", dealer)
		}
		if len(desc.Digest) == 0 {
			return nil, fmt.Errorf("empty descriptor digest for dealer %d", dealer)
		}
		seenDealer[dealer] = struct{}{}
		digests = append(digests, hex.EncodeToString(desc.Digest))
	}
	sort.Strings(digests)
	payload := descriptorPayload{
		Version: 1,
		Digests: digests,
	}
	return json.Marshal(payload)
}

func DecodeDescriptor(blob []byte) ([][]byte, error) {
	var payload descriptorPayload
	if err := json.Unmarshal(blob, &payload); err != nil {
		return nil, fmt.Errorf("decode descriptor: %w", err)
	}
	if payload.Version != 1 {
		return nil, fmt.Errorf("unsupported descriptor version: %d", payload.Version)
	}
	out := make([][]byte, 0, len(payload.Digests))
	for _, d := range payload.Digests {
		raw, err := hex.DecodeString(d)
		if err != nil {
			return nil, fmt.Errorf("invalid descriptor digest %q: %w", d, err)
		}
		out = append(out, raw)
	}
	return out, nil
}

func ValidateFallbackDescriptor(blob []byte, cfg Config, descriptors map[int]Descriptor, targetSize int) ([]int, error) {
	var payload descriptorPayload
	if err := json.Unmarshal(blob, &payload); err != nil {
		return nil, fmt.Errorf("decode descriptor: %w", err)
	}
	if payload.Version != 1 {
		return nil, fmt.Errorf("unsupported descriptor version: %d", payload.Version)
	}
	if len(payload.Digests) == 0 {
		return nil, fmt.Errorf("empty descriptor digests")
	}
	seenDigest := make(map[string]struct{}, len(payload.Digests))
	digestToDealer := make(map[string]int, len(descriptors))
	for dealer, desc := range descriptors {
		digestToDealer[hex.EncodeToString(desc.Digest)] = dealer
	}
	valid := make([]digestDealer, 0, len(payload.Digests))
	for _, d := range payload.Digests {
		if _, ok := seenDigest[d]; ok {
			return nil, fmt.Errorf("duplicate digest in descriptor")
		}
		seenDigest[d] = struct{}{}

		dealer, ok := digestToDealer[d]
		if !ok {
			return nil, fmt.Errorf("digest not found in local descriptor pool")
		}
		desc := descriptors[dealer]
		if !ValidateDescriptor(cfg, desc) {
			return nil, fmt.Errorf("descriptor member failed VerifyHeader/VerifyLock: dealer=%d", dealer)
		}
		valid = append(valid, digestDealer{Dealer: dealer, Digest: d})
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].Digest < valid[j].Digest })

	required := cfg.F + 1
	if required <= 0 {
		required = 1
	}
	if len(valid) < required {
		return nil, fmt.Errorf("descriptor contains too few valid members: %d < %d", len(valid), required)
	}
	if targetSize <= 0 {
		targetSize = len(valid)
	}
	if len(valid) < targetSize {
		return nil, fmt.Errorf("descriptor cannot be cropped to target size: have=%d need=%d", len(valid), targetSize)
	}
	out := make([]int, 0, targetSize)
	for i := 0; i < targetSize; i++ {
		out = append(out, valid[i].Dealer)
	}
	sort.Ints(out)
	return out, nil
}
