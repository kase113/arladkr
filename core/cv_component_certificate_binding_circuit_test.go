package core

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func cvComponentCertificateBindingFixture(t testing.TB) (Config, *cvComponentDescriptor) {
	t.Helper()
	cfg, _, _, _ := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	leafDigest := bytes.Repeat([]byte{0x41}, 32)
	dispersal, _, err := cvDisperseComponent(
		[]byte("component-certificate-binding"),
		len(cfg.OldCommittee), len(cfg.OldCommittee)-2*cfg.FOld,
	)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := cvComponentStatementDigest(0, leafDigest, dispersal)
	if err != nil {
		t.Fatal(err)
	}
	shares := make(map[int][]byte)
	for _, holder := range cfg.runtime.oldOrder[:len(cfg.OldCommittee)-cfg.FOld] {
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
	descriptor := &cvComponentDescriptor{
		dealer: 0, leafDigest: leafDigest, dispersal: *dispersal, certificate: certificate,
	}
	if err := cvValidateComponentDescriptor(cfg, descriptor); err != nil {
		t.Fatal(err)
	}
	return cfg, descriptor
}

func cvComponentCertificateBindingShape(statementCapacity, certificateCapacity int) *cvComponentCertificateBindingCircuit {
	return &cvComponentCertificateBindingCircuit{
		Statement: cvPoseidon2BytesWitness{
			Chunks: make([]frontend.Variable, statementCapacity),
			Active: make([]frontend.Variable, statementCapacity),
		},
		Certificate: cvPoseidon2BytesWitness{
			Chunks: make([]frontend.Variable, certificateCapacity),
			Active: make([]frontend.Variable, certificateCapacity),
		},
	}
}

func TestCVComponentCertificateBindingCircuit(t *testing.T) {
	cfg, descriptor := cvComponentCertificateBindingFixture(t)
	statementWire, err := cvComponentStatementCanonicalBytes(
		descriptor.dealer, descriptor.leafDigest, &descriptor.dispersal,
	)
	if err != nil {
		t.Fatal(err)
	}
	statementCapacity := (len(statementWire) + cvSemanticCommitmentChunkBytes - 1) / cvSemanticCommitmentChunkBytes
	certificateCapacity := (len(descriptor.certificate) + cvSemanticCommitmentChunkBytes - 1) / cvSemanticCommitmentChunkBytes
	circuit := cvComponentCertificateBindingShape(statementCapacity, certificateCapacity)
	assignment, err := cvComponentCertificateBindingAssignment(
		descriptor, statementCapacity, certificateCapacity,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}

	mutatedStatement := *assignment
	mutatedStatement.Statement.Chunks = append([]frontend.Variable(nil), assignment.Statement.Chunks...)
	mutatedStatement.Statement.Chunks[0] = 1
	if err := test.IsSolved(circuit, &mutatedStatement, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("component binding accepted a mutated statement")
	}

	mutatedCertificate := *assignment
	mutatedCertificate.Certificate.Chunks = append([]frontend.Variable(nil), assignment.Certificate.Chunks...)
	mutatedCertificate.Certificate.Chunks[0] = 1
	if err := test.IsSolved(circuit, &mutatedCertificate, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("component binding accepted a mutated certificate")
	}

	badDescriptor := *descriptor
	badDescriptor.certificate = append([]byte(nil), descriptor.certificate...)
	badDescriptor.certificate[0] ^= 1
	if err := cvValidateComponentDescriptor(cfg, &badDescriptor); err == nil {
		t.Fatal("native verifier accepted a mutated component certificate")
	}
}

func TestCVComponentCertificateBindingCircuitConstraintBudget(t *testing.T) {
	_, descriptor := cvComponentCertificateBindingFixture(t)
	statementWire, err := cvComponentStatementCanonicalBytes(
		descriptor.dealer, descriptor.leafDigest, &descriptor.dispersal,
	)
	if err != nil {
		t.Fatal(err)
	}
	statementCapacity := (len(statementWire) + cvSemanticCommitmentChunkBytes - 1) / cvSemanticCommitmentChunkBytes
	certificateCapacity := (len(descriptor.certificate) + cvSemanticCommitmentChunkBytes - 1) / cvSemanticCommitmentChunkBytes
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(), r1cs.NewBuilder,
		cvComponentCertificateBindingShape(statementCapacity, certificateCapacity),
	)
	if err != nil {
		t.Fatal(err)
	}
	const maximumConstraints = 40_000
	if constraints := ccs.GetNbConstraints(); constraints > maximumConstraints {
		t.Fatalf("component certificate binding grew to %d constraints", constraints)
	} else {
		t.Logf(
			"component certificate binding statement_bytes=%d certificate_bytes=%d constraints=%d",
			len(statementWire), len(descriptor.certificate), constraints,
		)
	}
}
