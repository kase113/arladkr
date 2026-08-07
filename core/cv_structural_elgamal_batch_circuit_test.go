package core

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/test"
)

func cvStructuralElGamalBatchShape(lanes, digits, chunkBits int) *cvStructuralElGamalBatchCircuit {
	circuit := &cvStructuralElGamalBatchCircuit{
		Lanes: make([]cvStructuralElGamalBatchLane, lanes), chunkBits: chunkBits,
	}
	for i := range circuit.Lanes {
		circuit.Lanes[i] = cvStructuralElGamalBatchLane{
			CiphertextR: make([]sw_bls12381.G1Affine, digits),
			CiphertextC: make([]sw_bls12381.G1Affine, digits),
			Digits:      make([]frontend.Variable, digits),
			Coins:       make([]sw_bls12381.Scalar, digits),
		}
	}
	return circuit
}

func cvStructuralElGamalBatchAssignment(
	chunkBits int,
	receiverSecret uint64,
	digits, coins [][]uint64,
) (*cvStructuralElGamalBatchCircuit, error) {
	assignment := &cvStructuralElGamalBatchCircuit{
		Lanes: make([]cvStructuralElGamalBatchLane, len(digits)), chunkBits: chunkBits,
	}
	for i := range digits {
		lane, err := cvStructuralElGamalAssignment(chunkBits, receiverSecret, digits[i], coins[i])
		if err != nil {
			return nil, err
		}
		if i == 0 {
			assignment.ReceiverPublicKey = lane.ReceiverPublicKey
		}
		assignment.Lanes[i] = cvStructuralElGamalBatchLane{
			CiphertextR: lane.CiphertextR,
			CiphertextC: lane.CiphertextC,
			Digits:      lane.Digits,
			Coins:       lane.Coins,
			Evaluation:  lane.Evaluation,
		}
	}
	return assignment, nil
}

func TestCVStructuralElGamalBatchCircuit(t *testing.T) {
	const chunkBits = 8
	circuit := cvStructuralElGamalBatchShape(2, 2, chunkBits)
	assignment, err := cvStructuralElGamalBatchAssignment(
		chunkBits, 17,
		[][]uint64{{5, 251}, {9, 37}},
		[][]uint64{{19, 23}, {29, 31}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}

	wrongCiphertext := *assignment
	wrongCiphertext.Lanes = append([]cvStructuralElGamalBatchLane(nil), assignment.Lanes...)
	wrongCiphertext.Lanes[1].CiphertextC = append(
		[]sw_bls12381.G1Affine(nil), assignment.Lanes[1].CiphertextC...,
	)
	wrongCiphertext.Lanes[1].CiphertextC[0] = assignment.Lanes[0].CiphertextC[0]
	if err := test.IsSolved(circuit, &wrongCiphertext, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("structural ElGamal batch accepted a cross-lane ciphertext replacement")
	}

	outOfRange := *assignment
	outOfRange.Lanes = append([]cvStructuralElGamalBatchLane(nil), assignment.Lanes...)
	outOfRange.Lanes[1].Digits = append([]frontend.Variable(nil), assignment.Lanes[1].Digits...)
	outOfRange.Lanes[1].Digits[0] = 256
	if err := test.IsSolved(circuit, &outOfRange, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("structural ElGamal batch accepted an out-of-range digit")
	}

	wrongEvaluation := *assignment
	wrongEvaluation.Lanes = append([]cvStructuralElGamalBatchLane(nil), assignment.Lanes...)
	wrongEvaluation.Lanes[1].Evaluation = assignment.Lanes[0].Evaluation
	if err := test.IsSolved(circuit, &wrongEvaluation, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("structural ElGamal batch accepted a cross-lane evaluation replacement")
	}
}

func TestCVStructuralElGamalBatchCircuitConstraintSavings(t *testing.T) {
	budgets := []struct {
		digits, maximum int
	}{
		{digits: 1, maximum: 750_000},
		{digits: 2, maximum: 1_150_000},
	}
	for _, budget := range budgets {
		batch, err := frontend.Compile(
			ecc.BN254.ScalarField(), r1cs.NewBuilder,
			cvStructuralElGamalBatchShape(2, budget.digits, 8),
		)
		if err != nil {
			t.Fatal(err)
		}
		single := &cvStructuralElGamalLaneCircuit{
			CiphertextR: make([]sw_bls12381.G1Affine, budget.digits),
			CiphertextC: make([]sw_bls12381.G1Affine, budget.digits),
			Digits:      make([]frontend.Variable, budget.digits),
			Coins:       make([]sw_bls12381.Scalar, budget.digits),
			chunkBits:   8,
		}
		singleCCS, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, single)
		if err != nil {
			t.Fatal(err)
		}
		constraints := batch.GetNbConstraints()
		unbatched := 2 * singleCCS.GetNbConstraints()
		if constraints > budget.maximum {
			t.Fatalf("structural ElGamal batch digits=%d grew to %d constraints", budget.digits, constraints)
		}
		if constraints >= unbatched {
			t.Fatalf("structural ElGamal batch did not save constraints: batch=%d unbatched=%d", constraints, unbatched)
		}
		t.Logf(
			"structural ElGamal batch lanes=2 digits=%d constraints=%d saved=%d",
			budget.digits, constraints, unbatched-constraints,
		)
	}
}
