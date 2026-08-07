package core

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func TestCVSemanticCommitmentCircuitMatchesNative(t *testing.T) {
	const capacity = 3
	circuit := &cvSemanticCommitmentCircuit{
		Chunks: make([]frontend.Variable, capacity), Active: make([]frontend.Variable, capacity),
	}
	for _, wire := range [][]byte{
		{1}, bytes.Repeat([]byte{2}, 31), bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 63),
	} {
		assignment, err := cvSemanticCommitmentCircuitAssignment(wire, capacity)
		if err != nil {
			t.Fatal(err)
		}
		if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("semantic commitment circuit rejected wire length %d: %v", len(wire), err)
		}
	}
}

func TestCVSemanticCommitmentCircuitRejectsMalformedWitness(t *testing.T) {
	const capacity = 3
	circuit := &cvSemanticCommitmentCircuit{
		Chunks: make([]frontend.Variable, capacity), Active: make([]frontend.Variable, capacity),
	}
	assignment, err := cvSemanticCommitmentCircuitAssignment(bytes.Repeat([]byte{7}, 32), capacity)
	if err != nil {
		t.Fatal(err)
	}
	assignment.Expected = new(big.Int).Add(assignment.Expected.(*big.Int), big.NewInt(1))
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("semantic commitment circuit accepted wrong digest")
	}

	assignment, err = cvSemanticCommitmentCircuitAssignment([]byte{9}, capacity)
	if err != nil {
		t.Fatal(err)
	}
	assignment.Chunks[1] = 1
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("semantic commitment circuit accepted nonzero inactive chunk")
	}

	assignment, err = cvSemanticCommitmentCircuitAssignment(bytes.Repeat([]byte{10}, 32), capacity)
	if err != nil {
		t.Fatal(err)
	}
	assignment.Active[1], assignment.Active[2] = 0, 1
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("semantic commitment circuit accepted non-prefix active chunks")
	}
}

func TestCVSemanticCommitmentCircuitConstraintBudget(t *testing.T) {
	for _, budget := range []struct {
		capacity           int
		maximumConstraints int
	}{
		{capacity: 4, maximumConstraints: 12_000},
		{capacity: 64, maximumConstraints: 50_000},
	} {
		circuit := &cvSemanticCommitmentCircuit{
			Chunks: make([]frontend.Variable, budget.capacity), Active: make([]frontend.Variable, budget.capacity),
		}
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		if err != nil {
			t.Fatal(err)
		}
		if constraints := ccs.GetNbConstraints(); constraints > budget.maximumConstraints {
			t.Fatalf("semantic commitment capacity=%d grew to %d constraints", budget.capacity, constraints)
		} else {
			t.Logf("semantic commitment capacity=%d constraints=%d", budget.capacity, constraints)
		}
	}
}
