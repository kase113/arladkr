package core

import (
	"bytes"
	"testing"
)

func TestCVComponentDescriptorCodecIsCertificateOnly(t *testing.T) {
	dispersal, _, err := cvDisperseComponent([]byte("component-codec"), 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := &cvComponentDescriptor{
		dealer:      1,
		leafDigest:  bytes.Repeat([]byte{0x11}, 32),
		dispersal:   *dispersal,
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
		!bytes.Equal(decoded.certificate, descriptor.certificate) {
		t.Fatal("compact component descriptor changed the recovered certificate")
	}
	t.Run("invalid dealer", func(t *testing.T) {
		bad := *descriptor
		bad.dealer = -1
		if _, err := cvComponentDescriptorCanonicalBytes(&bad); err == nil {
			t.Fatal("encoded a descriptor with an invalid dealer")
		}
	})
	t.Run("dealer outside roster", func(t *testing.T) {
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
		dispersal, _, err := cvDisperseComponent([]byte{fill, fill, fill}, len(cfg.OldCommittee), len(cfg.OldCommittee)-2*cfg.FOld)
		if err != nil {
			t.Fatal(err)
		}
		statement, err := cvComponentStatementDigest(dealer, digest, dispersal)
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
		return &cvComponentDescriptor{dealer: dealer, leafDigest: digest, dispersal: *dispersal, certificate: certificate}
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
	if !bytes.Equal(compact.certificate, descriptors[0].certificate) {
		t.Fatal("compact descriptor changed recovered certificate")
	}
	t.Run("tampered recovered certificate", func(t *testing.T) {
		bad := *descriptors[0]
		bad.certificate = append([]byte(nil), bad.certificate...)
		bad.certificate[0] ^= 1
		if err := cvValidateComponentDescriptor(cfg, &bad); err == nil {
			t.Fatal("accepted a component descriptor with a bad certificate")
		}
	})
}
