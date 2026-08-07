package core

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func cvFeldmanCircuitAssignment(receiver int, coefficients ...int64) *cvFeldmanEvaluationCircuit {
	commitments := make([]sw_bls12381.G1Affine, len(coefficients))
	evaluationScalar := big.NewInt(0)
	power := big.NewInt(1)
	for i, coefficient := range coefficients {
		var point bls12381.G1Affine
		point.ScalarMultiplication(&genG1, big.NewInt(coefficient))
		commitments[i] = sw_bls12381.NewG1Affine(point)
		evaluationScalar.Add(evaluationScalar, new(big.Int).Mul(big.NewInt(coefficient), power))
		power.Mul(power, big.NewInt(int64(receiver)))
	}
	var evaluation bls12381.G1Affine
	evaluation.ScalarMultiplication(&genG1, evaluationScalar)
	return &cvFeldmanEvaluationCircuit{
		Commitments: commitments, Evaluation: sw_bls12381.NewG1Affine(evaluation), receiverIndex: receiver,
	}
}

func TestCVFeldmanEvaluationCircuit(t *testing.T) {
	const receiver = 3
	circuit := &cvFeldmanEvaluationCircuit{
		Commitments: make([]sw_bls12381.G1Affine, 3), receiverIndex: receiver,
	}
	assignment := cvFeldmanCircuitAssignment(receiver, 5, 7, 11)
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	wrong := cvFeldmanCircuitAssignment(receiver, 5, 7, 11)
	wrong.Evaluation = cvFeldmanCircuitAssignment(receiver, 5, 7, 12).Evaluation
	if err := test.IsSolved(circuit, wrong, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("Feldman evaluation circuit accepted wrong receiver commitment")
	}
}

func TestCVFeldmanEvaluationCircuitAcceptsInfinityCoefficient(t *testing.T) {
	const receiver = 2
	circuit := &cvFeldmanEvaluationCircuit{
		Commitments: make([]sw_bls12381.G1Affine, 3), receiverIndex: receiver,
	}
	assignment := cvFeldmanCircuitAssignment(receiver, 5, 0, 11)
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

func TestCVFeldmanEvaluationCircuitRejectsMalformedCoefficient(t *testing.T) {
	const receiver = 2
	circuit := &cvFeldmanEvaluationCircuit{
		Commitments: make([]sw_bls12381.G1Affine, 3), receiverIndex: receiver,
	}
	assignment := cvFeldmanCircuitAssignment(receiver, 5, 7, 11)
	assignment.Commitments[1] = sw_bls12381.G1Affine{
		X: emulated.ValueOf[emulated.BLS12381Fp](1),
		Y: emulated.ValueOf[emulated.BLS12381Fp](1),
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("Feldman evaluation circuit accepted malformed coefficient commitment")
	}
}

func TestCVFeldmanEvaluationCircuitConstraintBudget(t *testing.T) {
	const receiver = 4
	circuit := &cvFeldmanEvaluationCircuit{
		Commitments: make([]sw_bls12381.G1Affine, 3), receiverIndex: receiver,
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	const maximumConstraints = 400_000
	if constraints := ccs.GetNbConstraints(); constraints > maximumConstraints {
		t.Fatalf("Feldman evaluation circuit grew to %d constraints", constraints)
	} else {
		t.Logf("Feldman degree=2 constraints=%d", constraints)
	}
}
