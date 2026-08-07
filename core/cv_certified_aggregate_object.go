package core

import (
	"bytes"
	"fmt"
)

const (
	cvCertifiedAggregateObjectDomain    = "ARL-CV-sAPVSS/certified-aggregate-object/v1"
	cvCertifiedAggregateObjectDigestDom = "ARL-CV-sAPVSS/certified-aggregate-object-digest/v1"
	cvCertifiedAggregateObjectARCDomain = "RL_CV_CERTIFIED_AGGREGATE_OBJECT_ARC_V1"
	cvCertifiedAggregateManifestDomain  = "ARL-CV-sAPVSS/certified-aggregate-manifest/v1"
)

// cvCertifiedAggregateObject is the compact value intended for the protocol's
// single MVBA. It contains references and certificates, never component leaf
// transcripts, aggregate payload bytes, shards, or signer-share maps.
type cvCertifiedAggregateObject struct {
	proposer       int
	manifest       []*cvComponentDescriptor
	header         AggHeader
	argument       *cvAggregateArgument
	proofDigest    []byte
	arcCertificate []byte
}

func cvCertifiedAggregateManifestDigest(manifest []*cvComponentDescriptor) ([]byte, error) {
	if len(manifest) == 0 {
		return nil, fmt.Errorf("empty certified aggregate manifest")
	}
	parts := make([][]byte, 0, len(manifest)+1)
	parts = append(parts, []byte(cvCertifiedAggregateManifestDomain))
	lastDealer := -1
	for _, descriptor := range manifest {
		if descriptor == nil || descriptor.dealer <= lastDealer {
			return nil, fmt.Errorf("invalid certified aggregate manifest order")
		}
		descriptorWire, err := cvComponentDescriptorCanonicalBytes(descriptor)
		if err != nil {
			return nil, err
		}
		lastDealer = descriptor.dealer
		parts = append(parts, descriptorWire)
	}
	return hashBytes(parts...), nil
}

func cvValidateCertifiedAggregateObjectShape(object *cvCertifiedAggregateObject) error {
	if object == nil || object.proposer < 0 || len(object.manifest) == 0 ||
		len(object.manifest) != len(object.header.Dealers) || object.argument == nil ||
		len(object.proofDigest) != 32 {
		return fmt.Errorf("invalid certified aggregate object")
	}
	if _, err := cvNetworkAggHeaderCanonicalBytes(object.header); err != nil {
		return err
	}
	for i, descriptor := range object.manifest {
		if descriptor == nil || descriptor.dealer != object.header.Dealers[i] {
			return fmt.Errorf("certified aggregate manifest/header mismatch")
		}
		if _, err := cvComponentDescriptorCanonicalBytes(descriptor); err != nil {
			return err
		}
	}
	manifestDigest, err := cvCertifiedAggregateManifestDigest(object.manifest)
	if err != nil {
		return err
	}
	statement := &object.argument.statement
	if statement.proposer != object.proposer ||
		!bytes.Equal(statement.manifestDigest, manifestDigest) ||
		!bytes.Equal(statement.aggregateDigest, object.header.AggregateDigest) ||
		!bytes.Equal(statement.payloadDigest, object.header.PayloadDigest) ||
		!bytes.Equal(statement.freshShardRoot, object.header.FreshShardRoot) {
		return fmt.Errorf("certified aggregate object argument binding mismatch")
	}
	wantProofDigest, err := cvAggregateArgumentDigest(object.argument)
	if err != nil || !bytes.Equal(object.proofDigest, wantProofDigest) {
		return fmt.Errorf("certified aggregate object proof digest mismatch")
	}
	return nil
}

func cvCertifiedAggregateObjectARCStatement(object *cvCertifiedAggregateObject) ([]byte, error) {
	if err := cvValidateCertifiedAggregateObjectShape(object); err != nil {
		return nil, err
	}
	manifestDigest, _ := cvCertifiedAggregateManifestDigest(object.manifest)
	headerWire, _ := cvNetworkAggHeaderCanonicalBytes(object.header)
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvCertifiedAggregateObjectARCDomain))
	cvWriteUint64(&wire, uint64(object.proposer))
	_ = cvWriteBytes(&wire, manifestDigest)
	_ = cvWriteBytes(&wire, headerWire)
	_ = cvWriteBytes(&wire, object.proofDigest)
	return hashBytes([]byte(cvCertifiedAggregateObjectARCDomain), wire.Bytes()), nil
}

func cvCertifiedAggregateObjectCanonicalBytes(object *cvCertifiedAggregateObject) ([]byte, error) {
	if err := cvValidateCertifiedAggregateObjectShape(object); err != nil {
		return nil, err
	}
	if len(object.arcCertificate) == 0 || len(object.arcCertificate) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid certified aggregate object ARC certificate")
	}
	headerWire, _ := cvNetworkAggHeaderCanonicalBytes(object.header)
	argumentWire, _ := cvAggregateArgumentCanonicalBytes(object.argument)
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvCertifiedAggregateObjectDomain))
	cvWriteUint64(&wire, uint64(object.proposer))
	_ = cvWriteUint32(&wire, len(object.manifest))
	for _, descriptor := range object.manifest {
		descriptorWire, _ := cvComponentDescriptorCanonicalBytes(descriptor)
		_ = cvWriteBytes(&wire, descriptorWire)
	}
	_ = cvWriteBytes(&wire, headerWire)
	_ = cvWriteBytes(&wire, argumentWire)
	_ = cvWriteBytes(&wire, object.proofDigest)
	_ = cvWriteBytes(&wire, object.arcCertificate)
	return wire.Bytes(), nil
}

func cvDecodeCertifiedAggregateObject(wire []byte, cfg Config) (*cvCertifiedAggregateObject, error) {
	c := NormalizeConfig(cfg)
	if err := ValidateConfig(c); err != nil {
		return nil, err
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvCertifiedAggregateObjectDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvCertifiedAggregateObjectDomain)) {
		return nil, fmt.Errorf("invalid certified aggregate object domain")
	}
	proposer, err := r.uint64()
	if err != nil || proposer > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid certified aggregate proposer")
	}
	manifestCount, err := r.uint32()
	if err != nil || manifestCount != c.FOld+1 || manifestCount > len(c.OldCommittee) {
		return nil, fmt.Errorf("invalid certified aggregate manifest count")
	}
	manifest := make([]*cvComponentDescriptor, manifestCount)
	for i := range manifest {
		descriptorWire, readErr := r.bytes(cvMaxNetworkPayloadBytes)
		if readErr != nil {
			return nil, fmt.Errorf("invalid certified aggregate manifest entry")
		}
		manifest[i], readErr = cvDecodeComponentDescriptor(descriptorWire, c.OldCommittee)
		if readErr != nil {
			return nil, readErr
		}
	}
	headerWire, err := r.bytes(1 << 20)
	if err != nil {
		return nil, fmt.Errorf("invalid certified aggregate header wire")
	}
	header, err := cvDecodeNetworkAggHeader(headerWire, c)
	if err != nil {
		return nil, err
	}
	argumentWire, err := r.bytes(cvMaxAggregateArgumentProofBytes + 4096)
	if err != nil {
		return nil, fmt.Errorf("invalid certified aggregate argument wire")
	}
	argument, err := cvDecodeAggregateArgument(argumentWire)
	if err != nil {
		return nil, err
	}
	proofDigest, err := r.bytes(32)
	if err != nil || len(proofDigest) != 32 {
		return nil, fmt.Errorf("invalid certified aggregate proof digest")
	}
	arcCertificate, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(arcCertificate) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid certified aggregate ARC certificate")
	}
	object := &cvCertifiedAggregateObject{
		proposer: int(proposer), manifest: manifest, header: header, argument: argument,
		proofDigest: proofDigest, arcCertificate: arcCertificate,
	}
	canonical, err := cvCertifiedAggregateObjectCanonicalBytes(object)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical certified aggregate object")
	}
	return object, nil
}

func cvCertifiedAggregateObjectDigest(object *cvCertifiedAggregateObject) ([]byte, error) {
	wire, err := cvCertifiedAggregateObjectCanonicalBytes(object)
	if err != nil {
		return nil, err
	}
	return hashBytes([]byte(cvCertifiedAggregateObjectDigestDom), wire), nil
}

func cvVerifyCertifiedAggregateObject(
	cfg Config,
	leafContext *cvLeafContext,
	object *cvCertifiedAggregateObject,
	verifier cvAggregateArgumentVerifier,
) error {
	if err := cvRequireProductionAggregateArgumentVerifier(verifier); err != nil {
		return err
	}
	c := NormalizeConfig(cfg)
	if err := ensureRuntime(&c); err != nil {
		return err
	}
	if err := cvValidateCertifiedAggregateObjectShape(object); err != nil {
		return err
	}
	if len(object.arcCertificate) == 0 || len(object.arcCertificate) > cvMaxComponentSignatureBytes {
		return fmt.Errorf("invalid certified aggregate object ARC certificate")
	}
	expectedStatement, err := cvBuildAggregateArgumentStatement(
		c, leafContext, object.proposer, object.argument.statement.manifestDigest, object.header,
	)
	if err != nil {
		return err
	}
	for _, descriptor := range object.manifest {
		if err := cvValidateNetworkComponentDescriptor(c, descriptor); err != nil {
			return fmt.Errorf("invalid certified aggregate component: %w", err)
		}
	}
	if err := cvVerifyAggregateArgument(object.argument, expectedStatement, verifier); err != nil {
		return err
	}
	arcStatement, err := cvCertifiedAggregateObjectARCStatement(object)
	if err != nil {
		return err
	}
	if c.runtime == nil || c.runtime.lockSigner == nil || !c.runtime.lockSigner.VerifyRecovered(
		cvCertifiedAggregateObjectARCDomain, arcStatement, object.arcCertificate,
	) {
		return fmt.Errorf("invalid certified aggregate object ARC")
	}
	return nil
}
