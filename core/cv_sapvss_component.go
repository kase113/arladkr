package core

import (
	"bytes"
	"fmt"
	"sort"
)

const (
	cvComponentLeafArtifactDomainV1  = "ARL-CV-sAPVSS-v1/component-leaf-artifact"
	cvComponentDescriptorDomainV1    = "ARL-CV-sAPVSS-v1/component-descriptor"
	cvComponentStatementDomainV1     = "ARL-CV-sAPVSS-v1/component-statement"
	cvComponentLockSignatureDomainV1 = "RL_CV_COMPONENT_LOCK"
	cvMaxComponentHoldersV1          = 1 << 16
	cvMaxComponentSignatureBytesV1   = 1 << 20
)

type cvComponentLeafArtifactV1 struct {
	dealer     int
	leafDigest []byte
	leafWire   []byte
}

type cvComponentDescriptorV1 struct {
	dealer          int
	leafDigest      []byte
	holders         []int
	shareSignatures map[int][]byte
	certificate     []byte
}

func cvComponentLeafPayloadDigestV1(wire []byte) []byte {
	if apvssHasLeafWireDomainV1(wire) {
		return hashBytes([]byte(apvssLeafDigestDomain), wire)
	}
	return hashBytes([]byte(cvLeafV1DigestDomain), wire)
}

func cvComponentStatementDigestV1(dealer int, leafDigest []byte) ([]byte, error) {
	if dealer < 0 || len(leafDigest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component statement")
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(cvComponentStatementDomainV1)); err != nil {
		return nil, err
	}
	cvWriteUint64(&wire, uint64(dealer))
	if err := cvWriteBytes(&wire, leafDigest); err != nil {
		return nil, err
	}
	return hashBytes([]byte(cvComponentStatementDomainV1), wire.Bytes()), nil
}

func cvComponentLeafArtifactV1CanonicalBytes(artifact *cvComponentLeafArtifactV1) ([]byte, error) {
	if artifact == nil || artifact.dealer < 0 || len(artifact.leafDigest) != 32 ||
		len(artifact.leafWire) == 0 || len(artifact.leafWire) > cvMaxLeafWireBytesV1 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component leaf artifact")
	}
	if !bytes.Equal(
		artifact.leafDigest,
		cvComponentLeafPayloadDigestV1(artifact.leafWire),
	) {
		return nil, fmt.Errorf("CV-sAPVSS component leaf artifact digest mismatch")
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(cvComponentLeafArtifactDomainV1)); err != nil {
		return nil, err
	}
	cvWriteUint64(&wire, uint64(artifact.dealer))
	if err := cvWriteBytes(&wire, artifact.leafDigest); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, artifact.leafWire); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

func cvDecodeComponentLeafArtifactV1(
	wire []byte,
	expectedContext *cvLeafContextV1,
	expectedDealer int,
) (*cvComponentLeafArtifactV1, *cvLeafV1, error) {
	if expectedContext == nil {
		return nil, nil, fmt.Errorf("nil expected CV-sAPVSS leaf context")
	}
	artifact, err := cvDecodeAvailableComponentLeafArtifactV1(wire, expectedDealer)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := cvDecodeLeafV1(artifact.leafWire, expectedContext)
	if err != nil {
		return nil, nil, err
	}
	if leaf.dealerID != uint64(expectedDealer) || !bytes.Equal(leaf.digest, artifact.leafDigest) {
		return nil, nil, fmt.Errorf("CV-sAPVSS component leaf artifact statement mismatch")
	}
	return artifact, leaf, nil
}

// cvDecodeAvailableComponentLeafArtifactV1 validates only the immutable byte
// statement certified by a component availability lock. It intentionally does
// not verify the embedded APVSS proof.
func cvDecodeAvailableComponentLeafArtifactV1(
	wire []byte,
	expectedDealer int,
) (*cvComponentLeafArtifactV1, error) {
	if expectedDealer < 0 || len(wire) == 0 ||
		len(wire) > cvMaxLeafWireBytesV1+1<<20 {
		return nil, fmt.Errorf("invalid expected CV-sAPVSS component leaf artifact")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentLeafArtifactDomainV1))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentLeafArtifactDomainV1)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component leaf artifact domain")
	}
	dealerWire, err := r.uint64()
	if err != nil || dealerWire > uint64(^uint(0)>>1) || int(dealerWire) != expectedDealer {
		return nil, fmt.Errorf("CV-sAPVSS component leaf artifact dealer mismatch")
	}
	leafDigest, err := r.bytes(32)
	if err != nil || len(leafDigest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component leaf digest")
	}
	leafWire, err := r.bytes(cvMaxLeafWireBytesV1)
	if err != nil || len(leafWire) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component leaf artifact framing")
	}
	if !bytes.Equal(leafDigest, cvComponentLeafPayloadDigestV1(leafWire)) {
		return nil, fmt.Errorf("CV-sAPVSS component leaf artifact digest mismatch")
	}
	artifact := &cvComponentLeafArtifactV1{
		dealer:     expectedDealer,
		leafDigest: append([]byte(nil), leafDigest...),
		leafWire:   append([]byte(nil), leafWire...),
	}
	canonical, err := cvComponentLeafArtifactV1CanonicalBytes(artifact)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS component leaf artifact")
	}
	return artifact, nil
}

func cvComponentDescriptorV1CanonicalBytes(descriptor *cvComponentDescriptorV1) ([]byte, error) {
	if err := cvValidateComponentDescriptorShapeV1(descriptor); err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(cvComponentDescriptorDomainV1)); err != nil {
		return nil, err
	}
	cvWriteUint64(&wire, uint64(descriptor.dealer))
	if err := cvWriteBytes(&wire, descriptor.leafDigest); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(descriptor.holders)); err != nil {
		return nil, err
	}
	for _, holder := range descriptor.holders {
		cvWriteUint64(&wire, uint64(holder))
		if err := cvWriteBytes(&wire, descriptor.shareSignatures[holder]); err != nil {
			return nil, err
		}
	}
	if err := cvWriteBytes(&wire, descriptor.certificate); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

func cvDecodeComponentDescriptorV1(
	wire []byte,
	oldNodes []int,
	threshold int,
) (*cvComponentDescriptorV1, error) {
	oldOrder := sortedUnique(oldNodes)
	if len(wire) == 0 || len(oldOrder) != len(oldNodes) || threshold <= 0 ||
		threshold > len(oldOrder) || len(oldOrder) > cvMaxComponentHoldersV1 {
		return nil, fmt.Errorf("invalid expected CV-sAPVSS component descriptor")
	}
	oldSet := nodeSet(oldOrder)
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentDescriptorDomainV1))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentDescriptorDomainV1)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component descriptor domain")
	}
	dealerWire, err := r.uint64()
	if err != nil || dealerWire > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component dealer")
	}
	dealer := int(dealerWire)
	if _, ok := oldSet[dealer]; !ok {
		return nil, fmt.Errorf("CV-sAPVSS component dealer is outside old roster")
	}
	leafDigest, err := r.bytes(32)
	if err != nil || len(leafDigest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component leaf digest")
	}
	holderCount, err := r.uint32()
	if err != nil || holderCount < threshold || holderCount > len(oldOrder) ||
		holderCount > cvMaxComponentHoldersV1 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component holder count")
	}
	holders := make([]int, holderCount)
	shares := make(map[int][]byte, holderCount)
	for i := 0; i < holderCount; i++ {
		holderWire, readErr := r.uint64()
		if readErr != nil || holderWire > uint64(^uint(0)>>1) {
			return nil, fmt.Errorf("invalid CV-sAPVSS component holder")
		}
		holder := int(holderWire)
		if _, ok := oldSet[holder]; !ok || (i > 0 && holder <= holders[i-1]) {
			return nil, fmt.Errorf("non-canonical CV-sAPVSS component holder order")
		}
		sig, readErr := r.bytes(cvMaxComponentSignatureBytesV1)
		if readErr != nil || len(sig) == 0 {
			return nil, fmt.Errorf("invalid CV-sAPVSS component holder signature")
		}
		holders[i] = holder
		shares[holder] = append([]byte(nil), sig...)
	}
	certificate, err := r.bytes(cvMaxComponentSignatureBytesV1)
	if err != nil || len(certificate) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component descriptor certificate")
	}
	descriptor := &cvComponentDescriptorV1{
		dealer:          dealer,
		leafDigest:      append([]byte(nil), leafDigest...),
		holders:         holders,
		shareSignatures: shares,
		certificate:     append([]byte(nil), certificate...),
	}
	canonical, err := cvComponentDescriptorV1CanonicalBytes(descriptor)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS component descriptor")
	}
	return descriptor, nil
}

func cvValidateComponentDescriptorShapeV1(descriptor *cvComponentDescriptorV1) error {
	if descriptor == nil || descriptor.dealer < 0 || len(descriptor.leafDigest) != 32 ||
		len(descriptor.holders) == 0 || len(descriptor.holders) > cvMaxComponentHoldersV1 ||
		len(descriptor.shareSignatures) != len(descriptor.holders) ||
		len(descriptor.certificate) == 0 || len(descriptor.certificate) > cvMaxComponentSignatureBytesV1 {
		return fmt.Errorf("invalid CV-sAPVSS component descriptor")
	}
	if !sort.IntsAreSorted(descriptor.holders) {
		return fmt.Errorf("non-canonical CV-sAPVSS component holder order")
	}
	for i, holder := range descriptor.holders {
		if holder < 0 || (i > 0 && holder == descriptor.holders[i-1]) {
			return fmt.Errorf("non-canonical CV-sAPVSS component holder order")
		}
		sig, ok := descriptor.shareSignatures[holder]
		if !ok || len(sig) == 0 || len(sig) > cvMaxComponentSignatureBytesV1 {
			return fmt.Errorf("invalid CV-sAPVSS component holder signature")
		}
	}
	return nil
}

func cvComponentDescriptorDigestV1(descriptor *cvComponentDescriptorV1) ([]byte, error) {
	wire, err := cvComponentDescriptorV1CanonicalBytes(descriptor)
	if err != nil {
		return nil, err
	}
	return hashBytes([]byte(cvComponentDescriptorDomainV1), wire), nil
}

func cvValidateComponentDescriptorV1(cfg Config, descriptor *cvComponentDescriptorV1) error {
	c := NormalizeConfig(cfg)
	if err := ValidateConfig(c); err != nil {
		return err
	}
	if err := ensureRuntime(&c); err != nil {
		return err
	}
	if c.runtime == nil || c.runtime.lockSigner == nil {
		return fmt.Errorf("CV-sAPVSS component lock signer is unavailable")
	}
	threshold := len(c.OldCommittee) - c.F
	wire, err := cvComponentDescriptorV1CanonicalBytes(descriptor)
	if err != nil {
		return err
	}
	if _, err := cvDecodeComponentDescriptorV1(wire, sortedUnique(c.OldCommittee), threshold); err != nil {
		return err
	}
	statement, err := cvComponentStatementDigestV1(descriptor.dealer, descriptor.leafDigest)
	if err != nil {
		return err
	}
	shares := make(map[int][]byte, len(descriptor.holders))
	for _, holder := range descriptor.holders {
		sig := descriptor.shareSignatures[holder]
		if !c.runtime.lockSigner.VerifyShare(
			holder, cvComponentLockSignatureDomainV1, statement, sig,
		) {
			return fmt.Errorf("invalid CV-sAPVSS component lock share from holder=%d", holder)
		}
		shares[holder] = append([]byte(nil), sig...)
	}
	recovered, err := c.runtime.lockSigner.Recover(
		cvComponentLockSignatureDomainV1, statement, shares,
	)
	if err != nil {
		return fmt.Errorf("recover CV-sAPVSS component lock: %w", err)
	}
	if !bytes.Equal(recovered, descriptor.certificate) ||
		!c.runtime.lockSigner.VerifyRecovered(
			cvComponentLockSignatureDomainV1, statement, descriptor.certificate,
		) {
		return fmt.Errorf("invalid CV-sAPVSS component lock certificate")
	}
	return nil
}
