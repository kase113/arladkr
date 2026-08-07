package core

import (
	"bytes"
	"fmt"
	"testing"
)

func cvCertifiedAggregateObjectTestConfig() Config {
	return NormalizeConfig(Config{
		SID: "certified-aggregate-object", Epoch: 4,
		OldCommittee: []int{0, 1, 2, 3}, NewCommittee: []int{0, 1, 2, 3},
		FOld: 1, FNew: 1, Kappa: 2,
	})
}

func cvCertifiedAggregateObjectTestDescriptor(dealer int, marker byte) *cvComponentDescriptor {
	return &cvComponentDescriptor{
		dealer: dealer, leafDigest: bytes.Repeat([]byte{marker}, 32),
		dispersal: cvComponentDispersal{
			nonce: bytes.Repeat([]byte{marker + 1}, 32), dataShards: 1, shardBytes: 1,
			payloadDigest:      bytes.Repeat([]byte{marker + 2}, 32),
			semanticCommitment: cvCertifiedAggregateObjectTestCommitment(marker + 3),
			root:               bytes.Repeat([]byte{marker + 4}, 32),
			dataFingerprints:   [][]byte{bytes.Repeat([]byte{marker + 5}, cvComponentCodewordChecks)},
		},
		certificate: []byte{marker + 6},
	}
}

func cvCertifiedAggregateObjectTestCommitment(marker byte) []byte {
	commitment := make([]byte, 32)
	commitment[31] = marker
	return commitment
}

func cvCertifiedAggregateObjectTestFixture(t *testing.T) (Config, *cvCertifiedAggregateObject) {
	t.Helper()
	cfg := cvCertifiedAggregateObjectTestConfig()
	manifest := []*cvComponentDescriptor{
		cvCertifiedAggregateObjectTestDescriptor(0, 10),
		cvCertifiedAggregateObjectTestDescriptor(1, 30),
	}
	manifestDigest, err := cvCertifiedAggregateManifestDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	header := AggHeader{
		SID: cfg.SID, Epoch: cfg.Epoch, Dealers: []int{0, 1},
		AggregateDigest: bytes.Repeat([]byte{60}, 32), PayloadDigest: bytes.Repeat([]byte{61}, 32),
		FreshShardRoot: bytes.Repeat([]byte{62}, 32),
	}
	header.MetadataHash = hashBytes(
		[]byte("aggrlo-meta"), []byte(cfg.SID), []byte(fmt.Sprintf("|epoch=%d", cfg.Epoch)),
		encodeInts(header.Dealers), header.AggregateDigest, header.PayloadDigest, header.FreshShardRoot,
	)
	argument := &cvAggregateArgument{
		statement: cvAggregateArgumentStatement{
			contextDigest: bytes.Repeat([]byte{63}, 32), proposer: 2,
			manifestDigest: manifestDigest, aggregateDigest: append([]byte(nil), header.AggregateDigest...),
			payloadDigest: append([]byte(nil), header.PayloadDigest...), freshShardRoot: append([]byte(nil), header.FreshShardRoot...),
		},
		proofProfile: "gnark-groth16-bn254/v1", circuitDigest: bytes.Repeat([]byte{64}, 32),
		verificationKeyDigest: bytes.Repeat([]byte{65}, 32), proof: []byte{66, 67, 68},
	}
	proofDigest, err := cvAggregateArgumentDigest(argument)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, &cvCertifiedAggregateObject{
		proposer: 2, manifest: manifest, header: header, argument: argument,
		proofDigest: proofDigest, arcCertificate: []byte{69, 70},
	}
}

func TestCVCertifiedAggregateObjectCodec(t *testing.T) {
	cfg, object := cvCertifiedAggregateObjectTestFixture(t)
	wire, err := cvCertifiedAggregateObjectCanonicalBytes(object)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeCertifiedAggregateObject(wire, cfg)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := cvCertifiedAggregateObjectCanonicalBytes(decoded)
	if err != nil || !bytes.Equal(reencoded, wire) {
		t.Fatalf("certified aggregate object did not round trip: %v", err)
	}
	digest, err := cvCertifiedAggregateObjectDigest(object)
	if err != nil || len(digest) != 32 {
		t.Fatalf("invalid certified aggregate object digest: %v", err)
	}
	for _, malformed := range [][]byte{wire[:len(wire)-1], append(append([]byte(nil), wire...), 0)} {
		if _, err := cvDecodeCertifiedAggregateObject(malformed, cfg); err == nil {
			t.Fatal("accepted malformed certified aggregate object")
		}
	}
}

func TestCVCertifiedAggregateObjectBindsManifestHeaderAndProof(t *testing.T) {
	_, object := cvCertifiedAggregateObjectTestFixture(t)
	arcStatement, err := cvCertifiedAggregateObjectARCStatement(object)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := *object
	unsigned.arcCertificate = nil
	unsignedStatement, err := cvCertifiedAggregateObjectARCStatement(&unsigned)
	if err != nil || !bytes.Equal(unsignedStatement, arcStatement) {
		t.Fatalf("ARC statement cannot be computed before certificate recovery: %v", err)
	}

	wrongManifest := *object
	wrongManifest.manifest = append([]*cvComponentDescriptor(nil), object.manifest...)
	wrongManifest.manifest[0], wrongManifest.manifest[1] = wrongManifest.manifest[1], wrongManifest.manifest[0]
	if _, err := cvCertifiedAggregateObjectCanonicalBytes(&wrongManifest); err == nil {
		t.Fatal("certified aggregate object accepted reordered manifest")
	}
	mutatedDescriptor := *object
	mutatedDescriptor.manifest = append([]*cvComponentDescriptor(nil), object.manifest...)
	first := *mutatedDescriptor.manifest[0]
	first.certificate = append([]byte(nil), first.certificate...)
	first.certificate[0] ^= 1
	mutatedDescriptor.manifest[0] = &first
	if _, err := cvCertifiedAggregateObjectCanonicalBytes(&mutatedDescriptor); err == nil {
		t.Fatal("certified aggregate object argument did not bind full component descriptor")
	}
	wrongProofDigest := *object
	wrongProofDigest.proofDigest = append([]byte(nil), object.proofDigest...)
	wrongProofDigest.proofDigest[0] ^= 1
	if _, err := cvCertifiedAggregateObjectCanonicalBytes(&wrongProofDigest); err == nil {
		t.Fatal("certified aggregate object accepted wrong proof digest")
	}
	wrongHeader := *object
	wrongHeader.header = object.header
	wrongHeader.header.AggregateDigest = append([]byte(nil), object.header.AggregateDigest...)
	wrongHeader.header.AggregateDigest[0] ^= 1
	wrongHeader.header.MetadataHash = hashBytes(
		[]byte("aggrlo-meta"), []byte(wrongHeader.header.SID),
		[]byte(fmt.Sprintf("|epoch=%d", wrongHeader.header.Epoch)), encodeInts(wrongHeader.header.Dealers),
		wrongHeader.header.AggregateDigest, wrongHeader.header.PayloadDigest, wrongHeader.header.FreshShardRoot,
	)
	if _, err := cvCertifiedAggregateObjectCanonicalBytes(&wrongHeader); err == nil {
		t.Fatal("certified aggregate object accepted header/argument mismatch")
	}
}
