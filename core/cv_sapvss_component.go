package core

import (
	"bytes"
	"fmt"
	"sort"
)

const (
	cvComponentLeafArtifactDomain  = "ARL-CV-sAPVSS/component-leaf-artifact"
	cvComponentDescriptorDomain    = "ARL-CV-sAPVSS/component-descriptor-certificate"
	cvComponentStatementDomain     = "ARL-CV-sAPVSS/component-statement"
	cvComponentLockSignatureDomain = "RL_CV_COMPONENT_LOCK"
	cvMaxComponentSignatureBytes   = 1 << 20
)

// cvComponentDescriptorCanonicalBytes is the compact, certificate-only
// descriptor used on the CV-sAPVSS network path. Holder identities and their
// individual signature shares remain local recovery evidence, but are not
// repeatedly embedded in every aggregate offer.
func cvComponentDescriptorCanonicalBytes(descriptor *cvComponentDescriptor) ([]byte, error) {
	if descriptor == nil || descriptor.dealer < 0 || len(descriptor.leafDigest) != 32 ||
		len(descriptor.certificate) == 0 || len(descriptor.certificate) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS component descriptor")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentDescriptorDomain))
	cvWriteUint64(&wire, uint64(descriptor.dealer))
	_ = cvWriteBytes(&wire, descriptor.leafDigest)
	_ = cvWriteBytes(&wire, descriptor.certificate)
	return wire.Bytes(), nil
}

func cvDecodeComponentDescriptor(wire []byte, oldNodes []int) (*cvComponentDescriptor, error) {
	if len(wire) == 0 || len(sortedUnique(oldNodes)) == 0 {
		return nil, fmt.Errorf("invalid expected compact CV-sAPVSS component descriptor")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentDescriptorDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentDescriptorDomain)) {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS component descriptor domain")
	}
	dealerWire, err := r.uint64()
	if err != nil || dealerWire > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS component dealer")
	}
	dealer := int(dealerWire)
	if _, ok := nodeSet(sortedUnique(oldNodes))[dealer]; !ok {
		return nil, fmt.Errorf("compact CV-sAPVSS component dealer outside old roster")
	}
	leafDigest, err := r.bytes(32)
	if err != nil || len(leafDigest) != 32 {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS component leaf digest")
	}
	certificate, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(certificate) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS component certificate")
	}
	descriptor := &cvComponentDescriptor{dealer: dealer, leafDigest: append([]byte(nil), leafDigest...), certificate: append([]byte(nil), certificate...)}
	canonical, err := cvComponentDescriptorCanonicalBytes(descriptor)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical compact CV-sAPVSS component descriptor")
	}
	return descriptor, nil
}

func cvValidateNetworkComponentDescriptor(cfg Config, descriptor *cvComponentDescriptor) error {
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
	wire, err := cvComponentDescriptorCanonicalBytes(descriptor)
	if err != nil {
		return err
	}
	if _, err := cvDecodeComponentDescriptor(wire, c.OldCommittee); err != nil {
		return err
	}
	statement, err := cvComponentStatementDigest(descriptor.dealer, descriptor.leafDigest)
	if err != nil {
		return err
	}
	if !c.runtime.lockSigner.VerifyRecovered(cvComponentLockSignatureDomain, statement, descriptor.certificate) {
		return fmt.Errorf("invalid compact CV-sAPVSS component lock certificate")
	}
	return nil
}

type cvComponentLeafArtifact struct {
	dealer     int
	leafDigest []byte
	leafWire   []byte
}

type cvComponentDescriptor struct {
	dealer          int
	leafDigest      []byte
	holders         []int
	shareSignatures map[int][]byte
	certificate     []byte
}

func cvComponentLeafPayloadDigest(wire []byte) []byte {
	if apvssHasLeafWireDomain(wire) {
		return hashBytes([]byte(apvssLeafDigestDomain), wire)
	}
	return hashBytes([]byte(cvLeafDigestDomain), wire)
}

func cvComponentStatementDigest(dealer int, leafDigest []byte) ([]byte, error) {
	if dealer < 0 || len(leafDigest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component statement")
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(cvComponentStatementDomain)); err != nil {
		return nil, err
	}
	cvWriteUint64(&wire, uint64(dealer))
	if err := cvWriteBytes(&wire, leafDigest); err != nil {
		return nil, err
	}
	return hashBytes([]byte(cvComponentStatementDomain), wire.Bytes()), nil
}

func cvComponentLeafArtifactCanonicalBytes(artifact *cvComponentLeafArtifact) ([]byte, error) {
	if artifact == nil || artifact.dealer < 0 || len(artifact.leafDigest) != 32 ||
		len(artifact.leafWire) == 0 || len(artifact.leafWire) > cvMaxLeafWireBytes {
		return nil, fmt.Errorf("invalid CV-sAPVSS component leaf artifact")
	}
	if !bytes.Equal(
		artifact.leafDigest,
		cvComponentLeafPayloadDigest(artifact.leafWire),
	) {
		return nil, fmt.Errorf("CV-sAPVSS component leaf artifact digest mismatch")
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(cvComponentLeafArtifactDomain)); err != nil {
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

func cvDecodeComponentLeafArtifact(
	wire []byte,
	expectedContext *cvLeafContext,
	expectedDealer int,
) (*cvComponentLeafArtifact, *cvLeaf, error) {
	if expectedContext == nil {
		return nil, nil, fmt.Errorf("nil expected CV-sAPVSS leaf context")
	}
	artifact, err := cvDecodeAvailableComponentLeafArtifact(wire, expectedDealer)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := cvDecodeLeaf(artifact.leafWire, expectedContext)
	if err != nil {
		return nil, nil, err
	}
	if leaf.dealerID != uint64(expectedDealer) || !bytes.Equal(leaf.digest, artifact.leafDigest) {
		return nil, nil, fmt.Errorf("CV-sAPVSS component leaf artifact statement mismatch")
	}
	return artifact, leaf, nil
}

// cvDecodeAvailableComponentLeafArtifact validates only the immutable byte
// statement certified by a component availability lock. It intentionally does
// not verify the embedded APVSS proof.
func cvDecodeAvailableComponentLeafArtifact(
	wire []byte,
	expectedDealer int,
) (*cvComponentLeafArtifact, error) {
	if expectedDealer < 0 || len(wire) == 0 ||
		len(wire) > cvMaxLeafWireBytes+1<<20 {
		return nil, fmt.Errorf("invalid expected CV-sAPVSS component leaf artifact")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentLeafArtifactDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentLeafArtifactDomain)) {
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
	leafWire, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil || len(leafWire) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component leaf artifact framing")
	}
	if !bytes.Equal(leafDigest, cvComponentLeafPayloadDigest(leafWire)) {
		return nil, fmt.Errorf("CV-sAPVSS component leaf artifact digest mismatch")
	}
	artifact := &cvComponentLeafArtifact{
		dealer:     expectedDealer,
		leafDigest: append([]byte(nil), leafDigest...),
		leafWire:   append([]byte(nil), leafWire...),
	}
	canonical, err := cvComponentLeafArtifactCanonicalBytes(artifact)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS component leaf artifact")
	}
	return artifact, nil
}

func cvValidateComponentDescriptorShape(descriptor *cvComponentDescriptor) error {
	if descriptor == nil || descriptor.dealer < 0 || len(descriptor.leafDigest) != 32 ||
		len(descriptor.holders) == 0 ||
		len(descriptor.shareSignatures) != len(descriptor.holders) ||
		len(descriptor.certificate) == 0 || len(descriptor.certificate) > cvMaxComponentSignatureBytes {
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
		if !ok || len(sig) == 0 || len(sig) > cvMaxComponentSignatureBytes {
			return fmt.Errorf("invalid CV-sAPVSS component holder signature")
		}
	}
	return nil
}

// cvValidateComponentDescriptor validates the complete local recovery evidence.
// The network wire carries only the recovered certificate.
func cvValidateComponentDescriptor(cfg Config, descriptor *cvComponentDescriptor) error {
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
	if err := cvValidateComponentDescriptorShape(descriptor); err != nil {
		return err
	}
	oldSet := nodeSet(sortedUnique(c.OldCommittee))
	if _, ok := oldSet[descriptor.dealer]; !ok {
		return fmt.Errorf("CV-sAPVSS component dealer is outside old roster")
	}
	if len(descriptor.holders) < len(c.OldCommittee)-c.FOld {
		return fmt.Errorf("CV-sAPVSS component descriptor is below lock threshold")
	}
	for _, holder := range descriptor.holders {
		if _, ok := oldSet[holder]; !ok {
			return fmt.Errorf("CV-sAPVSS component holder is outside old roster")
		}
	}
	statement, err := cvComponentStatementDigest(descriptor.dealer, descriptor.leafDigest)
	if err != nil {
		return err
	}
	shares := make(map[int][]byte, len(descriptor.holders))
	for _, holder := range descriptor.holders {
		sig := descriptor.shareSignatures[holder]
		if !c.runtime.lockSigner.VerifyShare(
			holder, cvComponentLockSignatureDomain, statement, sig,
		) {
			return fmt.Errorf("invalid CV-sAPVSS component lock share from holder=%d", holder)
		}
		shares[holder] = append([]byte(nil), sig...)
	}
	recovered, err := c.runtime.lockSigner.Recover(
		cvComponentLockSignatureDomain, statement, shares,
	)
	if err != nil {
		return fmt.Errorf("recover CV-sAPVSS component lock: %w", err)
	}
	if !bytes.Equal(recovered, descriptor.certificate) ||
		!c.runtime.lockSigner.VerifyRecovered(
			cvComponentLockSignatureDomain, statement, descriptor.certificate,
		) {
		return fmt.Errorf("invalid CV-sAPVSS component lock certificate")
	}
	return nil
}
