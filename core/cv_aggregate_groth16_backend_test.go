package core

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type cvAggregateGroth16WrongProfileBuilder struct {
	cvAggregateStatementBindingWitnessBuilder
}

func (cvAggregateGroth16WrongProfileBuilder) ProofProfile() string {
	return cvAggregateCircuitProofProfile
}

func cvAggregateStatementBindingTestProfile() *cvAggregateCircuitProfile {
	return &cvAggregateCircuitProfile{
		proofProfile:        cvAggregateStatementBindingProfile,
		backend:             cvAggregateCircuitBackend,
		curve:               cvAggregateCircuitCurve,
		relation:            cvAggregateStatementBindingRelation,
		receiptMode:         cvAggregateCircuitReceiptMode,
		componentCount:      1,
		receiverCount:       1,
		maxFallback:         0,
		digitCount:          1,
		aggregatePointCount: 1,
		statementCapacity:   16,
		certificateCapacity: 1,
		dispersalCapacity:   1,
	}
}

func TestCVBN254Groth16StatementBindingBackend(t *testing.T) {
	statement := cvAggregateArgumentTestStatement()
	statementWire, err := cvAggregateArgumentStatementCanonicalBytes(&statement)
	if err != nil {
		t.Fatal(err)
	}
	capacity := (len(statementWire) + cvSemanticCommitmentChunkBytes - 1) / cvSemanticCommitmentChunkBytes
	assignment, err := cvAggregateStatementBindingAssignment(statementWire, capacity)
	if err != nil {
		t.Fatal(err)
	}
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(), r1cs.NewBuilder,
		cvAggregateStatementBindingShape(capacity),
	)
	if err != nil {
		t.Fatal(err)
	}
	provingKey, verifyingKey, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := cvBuildAggregateCircuitArtifact(
		cvAggregateStatementBindingTestProfile(), ccs, verifyingKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvNewBN254Groth16AggregateBackend(
		artifact, ccs, verifyingKey, cvAggregateGroth16WrongProfileBuilder{},
	); err == nil {
		t.Fatal("Groth16 backend accepted a public-witness builder for another profile")
	}
	backend, err := cvNewBN254Groth16AggregateBackend(
		artifact, ccs, verifyingKey, cvAggregateStatementBindingWitnessBuilder{},
	)
	if err != nil {
		t.Fatal(err)
	}
	boundVerifier, err := cvBindAggregateArgumentVerifier(artifact, backend)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, provingKey, witness)
	if err != nil {
		t.Fatal(err)
	}
	var proofWire bytes.Buffer
	if _, err := proof.WriteTo(&proofWire); err != nil {
		t.Fatal(err)
	}
	t.Logf(
		"aggregate statement binding statement_bytes=%d constraints=%d proof_bytes=%d",
		len(statementWire), ccs.GetNbConstraints(), proofWire.Len(),
	)
	argument := &cvAggregateArgument{
		statement:             statement,
		proofProfile:          boundVerifier.ProofProfile(),
		circuitDigest:         boundVerifier.CircuitDigest(),
		verificationKeyDigest: boundVerifier.VerificationKeyDigest(),
		proof:                 proofWire.Bytes(),
	}
	if err := cvVerifyAggregateArgument(argument, &statement, boundVerifier); err != nil {
		t.Fatal(err)
	}

	wrongStatement := statement
	wrongStatement.aggregateDigest = append([]byte(nil), statement.aggregateDigest...)
	wrongStatement.aggregateDigest[0] ^= 1
	if err := cvVerifyAggregateArgument(argument, &wrongStatement, boundVerifier); err == nil {
		t.Fatal("Groth16 statement-binding backend accepted a wrong statement")
	}
	trailing := append([]byte(nil), proofWire.Bytes()...)
	trailing = append(trailing, 0)
	argument.proof = trailing
	if err := cvVerifyAggregateArgument(argument, &statement, boundVerifier); err == nil {
		t.Fatal("Groth16 backend accepted proof trailing bytes")
	}
	if err := cvRequireProductionAggregateArgumentVerifier(boundVerifier); err == nil {
		t.Fatal("statement-binding backend passed production aggregate profile gate")
	}
}
