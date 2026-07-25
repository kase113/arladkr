package core

import (
	"bytes"
	"testing"
)

func TestCVComponentLeafArtifactCodecRoundTripAndRejectsMutation(t *testing.T) {
	_, leafContext, _, leaves := cvM4Fixture(t)
	leafWire, err := cvLeafV1CanonicalBytes(leaves[0])
	if err != nil {
		t.Fatal(err)
	}
	artifact := &cvComponentLeafArtifactV1{
		dealer:     int(leaves[0].dealerID),
		leafDigest: append([]byte(nil), leaves[0].digest...),
		leafWire:   leafWire,
	}
	wire, err := cvComponentLeafArtifactV1CanonicalBytes(artifact)
	if err != nil {
		t.Fatal(err)
	}
	decoded, leaf, err := cvDecodeComponentLeafArtifactV1(wire, &leafContext, artifact.dealer)
	if err != nil {
		t.Fatal(err)
	}
	decodedWire, err := cvComponentLeafArtifactV1CanonicalBytes(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedWire, wire) || !bytes.Equal(leaf.digest, artifact.leafDigest) {
		t.Fatal("component leaf artifact did not round-trip canonically")
	}

	t.Run("wrong expected dealer", func(t *testing.T) {
		if _, _, err := cvDecodeComponentLeafArtifactV1(wire, &leafContext, artifact.dealer+1); err == nil {
			t.Fatal("accepted component artifact for the wrong dealer")
		}
	})
	t.Run("digest mutation", func(t *testing.T) {
		bad := append([]byte(nil), wire...)
		digestOffset := 4 + len(cvComponentLeafArtifactDomainV1) + 8 + 4
		bad[digestOffset] ^= 1
		if _, _, err := cvDecodeComponentLeafArtifactV1(bad, &leafContext, artifact.dealer); err == nil {
			t.Fatal("accepted component artifact with a mutated leaf digest")
		}
	})
	t.Run("trailing bytes", func(t *testing.T) {
		if _, _, err := cvDecodeComponentLeafArtifactV1(append(wire, 0), &leafContext, artifact.dealer); err == nil {
			t.Fatal("accepted component artifact with trailing bytes")
		}
	})
}

func TestCVComponentDescriptorCodecPreservesIndividualShares(t *testing.T) {
	descriptor := &cvComponentDescriptorV1{
		dealer:     1,
		leafDigest: bytes.Repeat([]byte{0x11}, 32),
		holders:    []int{0, 1, 3},
		shareSignatures: map[int][]byte{
			0: {0xa0},
			1: {0xa1},
			3: {0xa3},
		},
		certificate: []byte{0xcc},
	}
	wire, err := cvComponentDescriptorV1CanonicalBytes(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeComponentDescriptorV1(wire, []int{0, 1, 2, 3}, 3)
	if err != nil {
		t.Fatal(err)
	}
	decodedWire, err := cvComponentDescriptorV1CanonicalBytes(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedWire, wire) || len(decoded.shareSignatures) != 3 ||
		!bytes.Equal(decoded.shareSignatures[3], []byte{0xa3}) {
		t.Fatal("component descriptor lost canonical holder shares")
	}

	t.Run("unsorted holders", func(t *testing.T) {
		bad := *descriptor
		bad.holders = []int{1, 0, 3}
		if _, err := cvComponentDescriptorV1CanonicalBytes(&bad); err == nil {
			t.Fatal("encoded a descriptor with non-canonical holder order")
		}
	})
	t.Run("share set mismatch", func(t *testing.T) {
		bad := *descriptor
		bad.shareSignatures = map[int][]byte{0: {0xa0}, 1: {0xa1}}
		if _, err := cvComponentDescriptorV1CanonicalBytes(&bad); err == nil {
			t.Fatal("encoded a descriptor whose shares do not match holders")
		}
	})
	t.Run("holder outside roster", func(t *testing.T) {
		if _, err := cvDecodeComponentDescriptorV1(wire, []int{0, 1, 2}, 3); err == nil {
			t.Fatal("accepted a descriptor holder outside the old roster")
		}
	})
	t.Run("below threshold", func(t *testing.T) {
		if _, err := cvDecodeComponentDescriptorV1(wire, []int{0, 1, 2, 3}, 4); err == nil {
			t.Fatal("accepted a descriptor below its component threshold")
		}
	})
	t.Run("trailing bytes", func(t *testing.T) {
		if _, err := cvDecodeComponentDescriptorV1(append(wire, 0), []int{0, 1, 2, 3}, 3); err == nil {
			t.Fatal("accepted a descriptor with trailing bytes")
		}
	})
}

func TestCVComponentDescriptorValidation(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	makeDescriptor := func(dealer int, fill byte) *cvComponentDescriptorV1 {
		digest := bytes.Repeat([]byte{fill}, 32)
		statement, err := cvComponentStatementDigestV1(dealer, digest)
		if err != nil {
			t.Fatal(err)
		}
		holders := append([]int(nil), cfg.runtime.oldOrder[:len(cfg.OldCommittee)-cfg.F]...)
		shares := make(map[int][]byte, len(holders))
		for _, holder := range holders {
			shares[holder], err = cfg.runtime.lockSigner.SignShare(
				holder, cvComponentLockSignatureDomainV1, statement,
			)
			if err != nil {
				t.Fatal(err)
			}
		}
		certificate, err := cfg.runtime.lockSigner.Recover(
			cvComponentLockSignatureDomainV1, statement, shares,
		)
		if err != nil {
			t.Fatal(err)
		}
		return &cvComponentDescriptorV1{
			dealer:          dealer,
			leafDigest:      digest,
			holders:         holders,
			shareSignatures: shares,
			certificate:     certificate,
		}
	}

	descriptors := []*cvComponentDescriptorV1{
		makeDescriptor(0, 0x10),
		makeDescriptor(1, 0x11),
		makeDescriptor(2, 0x12),
	}
	for i, descriptor := range descriptors {
		if err := cvValidateComponentDescriptorV1(cfg, descriptor); err != nil {
			t.Fatalf("valid descriptor %d rejected: %v", i, err)
		}
	}

	t.Run("tampered individual share", func(t *testing.T) {
		bad := *descriptors[0]
		bad.shareSignatures = cloneSigMap(descriptors[0].shareSignatures)
		bad.shareSignatures[bad.holders[0]][0] ^= 1
		if err := cvValidateComponentDescriptorV1(cfg, &bad); err == nil {
			t.Fatal("accepted a component descriptor with a bad holder share")
		}
	})
	t.Run("tampered recovered certificate", func(t *testing.T) {
		bad := *descriptors[0]
		bad.certificate = append([]byte(nil), bad.certificate...)
		bad.certificate[0] ^= 1
		if err := cvValidateComponentDescriptorV1(cfg, &bad); err == nil {
			t.Fatal("accepted a component descriptor with a bad certificate")
		}
	})
}
