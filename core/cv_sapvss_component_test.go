package core

import (
	"bytes"
	"testing"
)

func TestCVComponentLeafArtifactCodecRoundTripAndRejectsMutation(t *testing.T) {
	_, leafContext, _, leaves := cvM4Fixture(t)
	leafWire, err := cvLeafCanonicalBytes(leaves[0])
	if err != nil {
		t.Fatal(err)
	}
	artifact := &cvComponentLeafArtifact{
		dealer:     int(leaves[0].dealerID),
		leafDigest: append([]byte(nil), leaves[0].digest...),
		leafWire:   leafWire,
	}
	wire, err := cvComponentLeafArtifactCanonicalBytes(artifact)
	if err != nil {
		t.Fatal(err)
	}
	decoded, leaf, err := cvDecodeComponentLeafArtifact(wire, &leafContext, artifact.dealer)
	if err != nil {
		t.Fatal(err)
	}
	decodedWire, err := cvComponentLeafArtifactCanonicalBytes(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedWire, wire) || !bytes.Equal(leaf.digest, artifact.leafDigest) {
		t.Fatal("component leaf artifact did not round-trip canonically")
	}

	t.Run("wrong expected dealer", func(t *testing.T) {
		if _, _, err := cvDecodeComponentLeafArtifact(wire, &leafContext, artifact.dealer+1); err == nil {
			t.Fatal("accepted component artifact for the wrong dealer")
		}
	})
	t.Run("digest mutation", func(t *testing.T) {
		bad := append([]byte(nil), wire...)
		digestOffset := 4 + len(cvComponentLeafArtifactDomain) + 8 + 4
		bad[digestOffset] ^= 1
		if _, _, err := cvDecodeComponentLeafArtifact(bad, &leafContext, artifact.dealer); err == nil {
			t.Fatal("accepted component artifact with a mutated leaf digest")
		}
	})
	t.Run("trailing bytes", func(t *testing.T) {
		if _, _, err := cvDecodeComponentLeafArtifact(append(wire, 0), &leafContext, artifact.dealer); err == nil {
			t.Fatal("accepted component artifact with trailing bytes")
		}
	})
}

func TestCVComponentDescriptorCodecDropsIndividualShares(t *testing.T) {
	descriptor := &cvComponentDescriptor{
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
	wire, err := cvComponentDescriptorCanonicalBytes(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeComponentDescriptor(wire, []int{0, 1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if decoded.dealer != descriptor.dealer || !bytes.Equal(decoded.leafDigest, descriptor.leafDigest) ||
		!bytes.Equal(decoded.certificate, descriptor.certificate) || len(decoded.holders) != 0 ||
		len(decoded.shareSignatures) != 0 {
		t.Fatal("compact component descriptor did not strip local recovery evidence")
	}

	t.Run("local evidence does not affect compact wire", func(t *testing.T) {
		bad := *descriptor
		bad.holders = []int{1, 0, 3}
		bad.shareSignatures = map[int][]byte{1: {0xa1}, 0: {0xa0}, 3: {0xa3}}
		badWire, err := cvComponentDescriptorCanonicalBytes(&bad)
		if err != nil || !bytes.Equal(badWire, wire) {
			t.Fatal("compact descriptor unexpectedly included local holder evidence")
		}
	})
	t.Run("invalid dealer", func(t *testing.T) {
		bad := *descriptor
		bad.dealer = -1
		if _, err := cvComponentDescriptorCanonicalBytes(&bad); err == nil {
			t.Fatal("encoded a descriptor with an invalid dealer")
		}
	})
	t.Run("holder outside roster", func(t *testing.T) {
		if _, err := cvDecodeComponentDescriptor(wire, []int{0, 2, 3}); err == nil {
			t.Fatal("accepted a descriptor dealer outside the old roster")
		}
	})
	t.Run("trailing bytes", func(t *testing.T) {
		if _, err := cvDecodeComponentDescriptor(append(wire, 0), []int{0, 1, 2, 3}); err == nil {
			t.Fatal("accepted a descriptor with trailing bytes")
		}
	})
}

func TestCVComponentDescriptorValidation(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	makeDescriptor := func(dealer int, fill byte) *cvComponentDescriptor {
		digest := bytes.Repeat([]byte{fill}, 32)
		statement, err := cvComponentStatementDigest(dealer, digest)
		if err != nil {
			t.Fatal(err)
		}
		holders := append([]int(nil), cfg.runtime.oldOrder[:len(cfg.OldCommittee)-cfg.FOld]...)
		shares := make(map[int][]byte, len(holders))
		for _, holder := range holders {
			shares[holder], err = cfg.runtime.lockSigner.SignShare(
				holder, cvComponentLockSignatureDomain, statement,
			)
			if err != nil {
				t.Fatal(err)
			}
		}
		certificate, err := cfg.runtime.lockSigner.Recover(
			cvComponentLockSignatureDomain, statement, shares,
		)
		if err != nil {
			t.Fatal(err)
		}
		return &cvComponentDescriptor{
			dealer:          dealer,
			leafDigest:      digest,
			holders:         holders,
			shareSignatures: shares,
			certificate:     certificate,
		}
	}

	descriptors := []*cvComponentDescriptor{
		makeDescriptor(0, 0x10),
		makeDescriptor(1, 0x11),
		makeDescriptor(2, 0x12),
	}
	for i, descriptor := range descriptors {
		if err := cvValidateComponentDescriptor(cfg, descriptor); err != nil {
			t.Fatalf("valid descriptor %d rejected: %v", i, err)
		}
	}
	compactWire, err := cvComponentDescriptorCanonicalBytes(descriptors[0])
	if err != nil {
		t.Fatal(err)
	}
	compact, err := cvDecodeComponentDescriptor(compactWire, cfg.OldCommittee)
	if err != nil {
		t.Fatal(err)
	}
	if len(compact.holders) != 0 || len(compact.shareSignatures) != 0 ||
		!bytes.Equal(compact.certificate, descriptors[0].certificate) {
		t.Fatal("compact descriptor retained individual holder evidence")
	}
	t.Run("tampered individual share", func(t *testing.T) {
		bad := *descriptors[0]
		bad.shareSignatures = cloneSigMap(descriptors[0].shareSignatures)
		bad.shareSignatures[bad.holders[0]][0] ^= 1
		if err := cvValidateComponentDescriptor(cfg, &bad); err == nil {
			t.Fatal("accepted a component descriptor with a bad holder share")
		}
	})
	t.Run("tampered recovered certificate", func(t *testing.T) {
		bad := *descriptors[0]
		bad.certificate = append([]byte(nil), bad.certificate...)
		bad.certificate[0] ^= 1
		if err := cvValidateComponentDescriptor(cfg, &bad); err == nil {
			t.Fatal("accepted a component descriptor with a bad certificate")
		}
	})
}
