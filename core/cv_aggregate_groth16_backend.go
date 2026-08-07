package core

import (
	"bytes"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

type cvAggregateGroth16PublicWitnessBuilder interface {
	ProofProfile() string
	PublicWitness(statementWire []byte) (witness.Witness, error)
}

type cvBN254Groth16AggregateBackend struct {
	verifyingKey groth16.VerifyingKey
	builder      cvAggregateGroth16PublicWitnessBuilder
}

func cvNewBN254Groth16AggregateBackend(
	artifact *cvAggregateCircuitArtifact,
	ccs constraint.ConstraintSystem,
	verifyingKey groth16.VerifyingKey,
	builder cvAggregateGroth16PublicWitnessBuilder,
) (*cvBN254Groth16AggregateBackend, error) {
	if ccs == nil || verifyingKey == nil || builder == nil ||
		verifyingKey.CurveID() != ecc.BN254 || ccs.Field().Cmp(ecc.BN254.ScalarField()) != 0 {
		return nil, fmt.Errorf("invalid BN254 Groth16 aggregate backend setup")
	}
	if err := cvValidateAggregateCircuitArtifactAgainst(artifact, ccs, verifyingKey); err != nil {
		return nil, err
	}
	if builder.ProofProfile() != artifact.ProofProfile() {
		return nil, fmt.Errorf("Groth16 public witness builder profile mismatch")
	}
	return &cvBN254Groth16AggregateBackend{verifyingKey: verifyingKey, builder: builder}, nil
}

func (b *cvBN254Groth16AggregateBackend) Verify(statementWire, proofWire []byte) error {
	if b == nil || b.verifyingKey == nil || b.builder == nil ||
		len(proofWire) == 0 || len(proofWire) > cvMaxAggregateArgumentProofBytes {
		return fmt.Errorf("invalid BN254 Groth16 aggregate proof input")
	}
	reader := bytes.NewReader(proofWire)
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(reader); err != nil || reader.Len() != 0 {
		return fmt.Errorf("decode BN254 Groth16 aggregate proof")
	}
	var canonical bytes.Buffer
	if _, err := proof.WriteTo(&canonical); err != nil || !bytes.Equal(canonical.Bytes(), proofWire) {
		return fmt.Errorf("non-canonical BN254 Groth16 aggregate proof")
	}
	publicWitness, err := b.builder.PublicWitness(statementWire)
	if err != nil {
		return err
	}
	if err := groth16.Verify(proof, b.verifyingKey, publicWitness); err != nil {
		return fmt.Errorf("verify BN254 Groth16 aggregate proof: %w", err)
	}
	return nil
}

type cvAggregateStatementBindingWitnessBuilder struct{}

func (cvAggregateStatementBindingWitnessBuilder) ProofProfile() string {
	return cvAggregateStatementBindingProfile
}

func (cvAggregateStatementBindingWitnessBuilder) PublicWitness(
	statementWire []byte,
) (witness.Witness, error) {
	assignment, err := cvAggregateStatementBindingPublicAssignment(statementWire)
	if err != nil {
		return nil, err
	}
	return frontend.NewWitness(
		assignment, ecc.BN254.ScalarField(), frontend.PublicOnly(),
	)
}
