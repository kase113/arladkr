package core

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func TestCVACKFallbackPartitionCircuit(t *testing.T) {
	const n, f = 7, 2
	circuit := cvACKFallbackPartitionShape(n, f)
	valid := cvACKFallbackPartitionAssignment(n, f, []int{1, 3, 4, 6, 7}, []int{2, 5})
	if err := test.IsSolved(circuit, valid, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	allACK := cvACKFallbackPartitionAssignment(n, f, []int{1, 2, 3, 4, 5, 6, 7}, nil)
	if err := test.IsSolved(circuit, allACK, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(*cvACKFallbackPartitionCircuit){
		"overlap": func(a *cvACKFallbackPartitionCircuit) {
			a.ACKIndices[1] = 2
		},
		"missing receiver": func(a *cvACKFallbackPartitionCircuit) {
			a.ACKIndices[1] = 4
		},
		"duplicate ACK": func(a *cvACKFallbackPartitionCircuit) {
			a.ACKIndices[1] = 1
		},
		"out of order ACK": func(a *cvACKFallbackPartitionCircuit) {
			a.ACKIndices[0], a.ACKIndices[1] = a.ACKIndices[1], a.ACKIndices[0]
		},
		"duplicate fallback": func(a *cvACKFallbackPartitionCircuit) {
			a.FallbackIndex[1] = 2
		},
		"out of order fallback": func(a *cvACKFallbackPartitionCircuit) {
			a.FallbackIndex[0], a.FallbackIndex[1] = a.FallbackIndex[1], a.FallbackIndex[0]
		},
		"out of range": func(a *cvACKFallbackPartitionCircuit) {
			a.FallbackIndex[1] = 8
		},
		"non-prefix active": func(a *cvACKFallbackPartitionCircuit) {
			a.ACKActive[1] = 0
		},
		"nonzero inactive index": func(a *cvACKFallbackPartitionCircuit) {
			a.ACKIndices[5] = 7
		},
		"selector mutation": func(a *cvACKFallbackPartitionCircuit) {
			a.FallbackForReceiver[1] = 0
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			assignment := cvACKFallbackPartitionAssignment(
				n, f, []int{1, 3, 4, 6, 7}, []int{2, 5},
			)
			mutate(assignment)
			if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("partition circuit accepted malformed assignment")
			}
		})
	}
}

func TestCVACKFallbackPartitionCircuitMatchesNativePrototype(t *testing.T) {
	const n, f = 7, 2
	fixture := apvssFixture(t, n, f)
	prototype, err := apvssBuildPrototype(
		&fixture.context, fixture.leaf,
		fixture.receiverSecrets, fixture.signingSecrets,
		&fixture.witness, []int{2, 5},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := apvssVerifyPrototype(&fixture.context, prototype); err != nil {
		t.Fatal(err)
	}
	ackIndices := make([]int, len(prototype.acks))
	for i := range prototype.acks {
		ackIndices[i] = prototype.acks[i].receiverIndex
	}
	fallbackIndices, err := apvssPrototypeFallbackIndices(prototype)
	if err != nil {
		t.Fatal(err)
	}
	assignment := cvACKFallbackPartitionAssignment(n, f, ackIndices, fallbackIndices)
	if err := test.IsSolved(
		cvACKFallbackPartitionShape(n, f), assignment, ecc.BN254.ScalarField(),
	); err != nil {
		t.Fatal(err)
	}
}

func TestCVACKFallbackPartitionCircuitConstraintBudget(t *testing.T) {
	budgets := []struct {
		n, f, maximum int
	}{
		{n: 7, f: 2, maximum: 2_000},
		{n: 31, f: 10, maximum: 20_000},
		{n: 64, f: 21, maximum: 80_000},
	}
	for _, budget := range budgets {
		ccs, err := frontend.Compile(
			ecc.BN254.ScalarField(), r1cs.NewBuilder,
			cvACKFallbackPartitionShape(budget.n, budget.f),
		)
		if err != nil {
			t.Fatal(err)
		}
		if constraints := ccs.GetNbConstraints(); constraints > budget.maximum {
			t.Fatalf("ACK/fallback partition n=%d f=%d grew to %d constraints", budget.n, budget.f, constraints)
		} else {
			t.Logf("ACK/fallback partition n=%d f=%d constraints=%d", budget.n, budget.f, constraints)
		}
	}
}
