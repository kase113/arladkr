package core

import (
	"bytes"
	"io"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type cvAggregateCircuitArtifactTestWriter []byte

func (w cvAggregateCircuitArtifactTestWriter) WriteTo(dst io.Writer) (int64, error) {
	n, err := dst.Write([]byte(w))
	return int64(n), err
}

type cvAggregateCircuitArtifactTestBackend struct {
	wantStatement []byte
	wantProof     []byte
}

func (b *cvAggregateCircuitArtifactTestBackend) Verify(statementWire, proof []byte) error {
	if !bytes.Equal(statementWire, b.wantStatement) || !bytes.Equal(proof, b.wantProof) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func cvAggregateCircuitArtifactTestProfile() *cvAggregateCircuitProfile {
	return &cvAggregateCircuitProfile{
		proofProfile:        cvAggregateCircuitProofProfile,
		backend:             cvAggregateCircuitBackend,
		curve:               cvAggregateCircuitCurve,
		relation:            cvAggregateCircuitRelation,
		receiptMode:         cvAggregateCircuitReceiptMode,
		componentCount:      2,
		receiverCount:       7,
		maxFallback:         2,
		digitCount:          32,
		aggregatePointCount: 3,
		statementCapacity:   16,
		certificateCapacity: 4,
		dispersalCapacity:   8,
	}
}

func TestCVAggregateCircuitProfileCanonicalBinding(t *testing.T) {
	profile := cvAggregateCircuitArtifactTestProfile()
	wire, err := cvAggregateCircuitProfileCanonicalBytes(profile)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAggregateCircuitProfile(wire)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := cvAggregateCircuitProfileCanonicalBytes(decoded)
	if err != nil || !bytes.Equal(reencoded, wire) {
		t.Fatalf("aggregate circuit profile did not round trip: %v", err)
	}
	digest, err := cvAggregateCircuitProfileDigest(profile)
	if err != nil || len(digest) != 32 {
		t.Fatalf("invalid aggregate circuit profile digest: %v", err)
	}
	mutatedProfile := *profile
	mutatedProfile.aggregatePointCount++
	mutatedDigest, err := cvAggregateCircuitProfileDigest(&mutatedProfile)
	if err != nil || bytes.Equal(mutatedDigest, digest) {
		t.Fatalf("circuit shape mutation was not bound: %v", err)
	}
	for _, mutate := range []func(*cvAggregateCircuitProfile){
		func(p *cvAggregateCircuitProfile) { p.proofProfile += "/mutated" },
		func(p *cvAggregateCircuitProfile) { p.receiptMode = "pedersen" },
		func(p *cvAggregateCircuitProfile) { p.maxFallback = p.receiverCount },
		func(p *cvAggregateCircuitProfile) { p.statementCapacity = 0 },
	} {
		bad := *profile
		mutate(&bad)
		if _, err := cvAggregateCircuitProfileCanonicalBytes(&bad); err == nil {
			t.Fatal("accepted invalid aggregate circuit profile mutation")
		}
	}
	for _, malformed := range [][]byte{
		wire[:len(wire)-1], append(append([]byte(nil), wire...), 0),
	} {
		if _, err := cvDecodeAggregateCircuitProfile(malformed); err == nil {
			t.Fatal("accepted malformed aggregate circuit profile wire")
		}
	}
}

func TestCVAggregateCircuitArtifactBindsLocalSetup(t *testing.T) {
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(), r1cs.NewBuilder,
		cvAggregateDispersalBindingShape(8),
	)
	if err != nil {
		t.Fatal(err)
	}
	profile := cvAggregateCircuitArtifactTestProfile()
	vk := cvAggregateCircuitArtifactTestWriter{1, 2, 3, 4}
	artifact, err := cvBuildAggregateCircuitArtifact(profile, ccs, vk)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvAggregateCircuitArtifactCanonicalBytes(artifact)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAggregateCircuitArtifact(wire)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ProofProfile() != "" || decoded.CircuitDigest() != nil ||
		decoded.VerificationKeyDigest() != nil {
		t.Fatal("decoded artifact exposed unvalidated setup identity")
	}
	if err := cvValidateAggregateCircuitArtifactAgainst(decoded, ccs, vk); err != nil {
		t.Fatal(err)
	}
	if decoded.ProofProfile() != profile.proofProfile ||
		!bytes.Equal(decoded.CircuitDigest(), artifact.CircuitDigest()) ||
		!bytes.Equal(decoded.VerificationKeyDigest(), artifact.VerificationKeyDigest()) {
		t.Fatal("aggregate circuit artifact lost setup identity")
	}

	badCircuit := *decoded
	badCircuit.circuitDigest = append([]byte(nil), decoded.circuitDigest...)
	badCircuit.circuitDigest[0] ^= 1
	if err := cvValidateAggregateCircuitArtifactAgainst(&badCircuit, ccs, vk); err == nil {
		t.Fatal("accepted artifact with mutated circuit digest")
	}
	if err := cvValidateAggregateCircuitArtifactAgainst(decoded, ccs, cvAggregateCircuitArtifactTestWriter{1, 2, 3, 5}); err == nil {
		t.Fatal("accepted artifact with mutated verification key bytes")
	}
	if _, err := cvDecodeAggregateCircuitArtifact(wire[:len(wire)-1]); err == nil {
		t.Fatal("accepted truncated aggregate circuit artifact")
	}
}

func TestCVArtifactBoundAggregateArgumentVerifier(t *testing.T) {
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(), r1cs.NewBuilder,
		cvAggregateDispersalBindingShape(8),
	)
	if err != nil {
		t.Fatal(err)
	}
	vk := cvAggregateCircuitArtifactTestWriter{9, 8, 7, 6}
	artifact, err := cvBuildAggregateCircuitArtifact(
		cvAggregateCircuitArtifactTestProfile(), ccs, vk,
	)
	if err != nil {
		t.Fatal(err)
	}
	argument := cvAggregateArgumentTestProof()
	argument.proofProfile = artifact.ProofProfile()
	argument.circuitDigest = artifact.CircuitDigest()
	argument.verificationKeyDigest = artifact.VerificationKeyDigest()
	statementWire, err := cvAggregateArgumentStatementCanonicalBytes(&argument.statement)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := cvBindAggregateArgumentVerifier(artifact, &cvAggregateCircuitArtifactTestBackend{
		wantStatement: statementWire, wantProof: append([]byte(nil), argument.proof...),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyAggregateArgument(argument, &argument.statement, verifier); err != nil {
		t.Fatal(err)
	}

	wire, err := cvAggregateCircuitArtifactCanonicalBytes(artifact)
	if err != nil {
		t.Fatal(err)
	}
	unvalidated, err := cvDecodeAggregateCircuitArtifact(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvBindAggregateArgumentVerifier(unvalidated, verifier.backend); err == nil {
		t.Fatal("bound aggregate verifier to an unvalidated setup artifact")
	}
	if _, err := cvBindAggregateArgumentVerifier(artifact, nil); err == nil {
		t.Fatal("bound aggregate verifier without a proof backend")
	}
}
