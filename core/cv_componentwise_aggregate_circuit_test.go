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

func cvG1ComponentAggregateAssignment(scalars ...int64) *cvG1ComponentAggregateCircuit {
	components := make([]sw_bls12381.G1Affine, len(scalars))
	sum := big.NewInt(0)
	for i, scalar := range scalars {
		var point bls12381.G1Affine
		point.ScalarMultiplication(&genG1, big.NewInt(scalar))
		components[i] = sw_bls12381.NewG1Affine(point)
		sum.Add(sum, big.NewInt(scalar))
	}
	var aggregate bls12381.G1Affine
	aggregate.ScalarMultiplication(&genG1, sum)
	return &cvG1ComponentAggregateCircuit{
		Components: components,
		Aggregate:  sw_bls12381.NewG1Affine(aggregate),
	}
}

func cvG1PointArrayAggregateAssignment(scalars [][]int64) *cvG1PointArrayAggregateCircuit {
	componentCount := len(scalars)
	pointCount := 0
	if componentCount > 0 {
		pointCount = len(scalars[0])
	}
	assignment := &cvG1PointArrayAggregateCircuit{
		Components:     make([]sw_bls12381.G1Affine, componentCount*pointCount),
		Aggregates:     make([]sw_bls12381.G1Affine, pointCount),
		componentCount: componentCount,
		pointCount:     pointCount,
	}
	sums := make([]big.Int, pointCount)
	for componentIndex := range scalars {
		for pointIndex, scalar := range scalars[componentIndex] {
			var point bls12381.G1Affine
			point.ScalarMultiplication(&genG1, big.NewInt(scalar))
			assignment.Components[componentIndex*pointCount+pointIndex] = sw_bls12381.NewG1Affine(point)
			sums[pointIndex].Add(&sums[pointIndex], big.NewInt(scalar))
		}
	}
	for pointIndex := range sums {
		var point bls12381.G1Affine
		point.ScalarMultiplication(&genG1, &sums[pointIndex])
		assignment.Aggregates[pointIndex] = sw_bls12381.NewG1Affine(point)
	}
	return assignment
}

func TestCVG1ComponentAggregateCircuit(t *testing.T) {
	circuit := &cvG1ComponentAggregateCircuit{
		Components: make([]sw_bls12381.G1Affine, 3),
	}
	assignment := cvG1ComponentAggregateAssignment(5, 0, 11)
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	wrong := cvG1ComponentAggregateAssignment(5, 0, 11)
	wrong.Aggregate = cvG1ComponentAggregateAssignment(5, 0, 12).Aggregate
	if err := test.IsSolved(circuit, wrong, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("componentwise G1 aggregate circuit accepted a wrong sum")
	}
}

func TestCVG1ComponentAggregateCircuitRejectsMalformedComponent(t *testing.T) {
	circuit := &cvG1ComponentAggregateCircuit{
		Components: make([]sw_bls12381.G1Affine, 3),
	}
	assignment := cvG1ComponentAggregateAssignment(5, 7, 11)
	assignment.Components[1] = sw_bls12381.G1Affine{
		X: emulated.ValueOf[emulated.BLS12381Fp](1),
		Y: emulated.ValueOf[emulated.BLS12381Fp](1),
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("componentwise G1 aggregate circuit accepted a malformed component")
	}
}

func TestCVG1PointArrayAggregateCircuit(t *testing.T) {
	const componentCount, pointCount = 3, 2
	circuit := &cvG1PointArrayAggregateCircuit{
		Components:     make([]sw_bls12381.G1Affine, componentCount*pointCount),
		Aggregates:     make([]sw_bls12381.G1Affine, pointCount),
		componentCount: componentCount,
		pointCount:     pointCount,
	}
	assignment := cvG1PointArrayAggregateAssignment([][]int64{
		{5, 7},
		{0, 11},
		{13, 17},
	})
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}

	wrongPointOrder := cvG1PointArrayAggregateAssignment([][]int64{
		{5, 7},
		{0, 11},
		{13, 17},
	})
	wrongPointOrder.Components[0], wrongPointOrder.Components[1] =
		wrongPointOrder.Components[1], wrongPointOrder.Components[0]
	if err := test.IsSolved(circuit, wrongPointOrder, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("G1 point-array aggregate accepted a point-order mutation")
	}

	malformed := cvG1PointArrayAggregateAssignment([][]int64{
		{5, 7},
		{0, 11},
		{13, 17},
	})
	malformed.Components[3] = sw_bls12381.G1Affine{
		X: emulated.ValueOf[emulated.BLS12381Fp](1),
		Y: emulated.ValueOf[emulated.BLS12381Fp](1),
	}
	if err := test.IsSolved(circuit, malformed, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("G1 point-array aggregate accepted a malformed component")
	}
}

func TestCVG1ComponentAggregateCircuitConstraintBudget(t *testing.T) {
	circuit := &cvG1ComponentAggregateCircuit{
		Components: make([]sw_bls12381.G1Affine, 3),
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	const maximumConstraints = 280_000
	if constraints := ccs.GetNbConstraints(); constraints > maximumConstraints {
		t.Fatalf("componentwise G1 aggregate circuit grew to %d constraints", constraints)
	} else {
		t.Logf("componentwise G1 K=3 constraints=%d", constraints)
	}
}

func TestCVG1PointArrayAggregateCircuitConstraintBudget(t *testing.T) {
	const componentCount, pointCount = 3, 2
	circuit := &cvG1PointArrayAggregateCircuit{
		Components:     make([]sw_bls12381.G1Affine, componentCount*pointCount),
		Aggregates:     make([]sw_bls12381.G1Affine, pointCount),
		componentCount: componentCount,
		pointCount:     pointCount,
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	const maximumConstraints = 560_000
	if constraints := ccs.GetNbConstraints(); constraints > maximumConstraints {
		t.Fatalf("componentwise G1 point array grew to %d constraints", constraints)
	} else {
		t.Logf(
			"componentwise G1 point array K=%d points=%d constraints=%d",
			componentCount, pointCount, constraints,
		)
	}
}
