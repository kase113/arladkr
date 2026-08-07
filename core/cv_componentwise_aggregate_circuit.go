package core

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// cvG1ComponentAggregateCircuit verifies one componentwise G1 sum. The
// component count is a circuit-shape parameter and must be covered by the
// circuit digest used by the aggregate argument.
type cvG1ComponentAggregateCircuit struct {
	Components []sw_bls12381.G1Affine
	Aggregate  sw_bls12381.G1Affine
}

func (c *cvG1ComponentAggregateCircuit) Define(api frontend.API) error {
	if len(c.Components) == 0 {
		return fmt.Errorf("empty componentwise G1 aggregate circuit")
	}
	return cvAssertG1PointArrayAggregate(
		api, c.Components, []sw_bls12381.G1Affine{c.Aggregate}, len(c.Components), 1,
	)
}

// cvG1PointArrayAggregateCircuit verifies componentwise sums for a fixed-size
// array of G1 points. Components use component-major order. Both dimensions are
// circuit-shape parameters and must be covered by the aggregate circuit digest.
type cvG1PointArrayAggregateCircuit struct {
	Components []sw_bls12381.G1Affine
	Aggregates []sw_bls12381.G1Affine

	componentCount int
	pointCount     int
}

func (c *cvG1PointArrayAggregateCircuit) Define(api frontend.API) error {
	return cvAssertG1PointArrayAggregate(
		api, c.Components, c.Aggregates, c.componentCount, c.pointCount,
	)
}

func cvAssertG1PointArrayAggregate(
	api frontend.API,
	components, aggregates []sw_bls12381.G1Affine,
	componentCount, pointCount int,
) error {
	if componentCount <= 0 || pointCount <= 0 ||
		len(components) != componentCount*pointCount || len(aggregates) != pointCount {
		return fmt.Errorf("invalid componentwise G1 point-array circuit shape")
	}
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](
		api, sw_emulated.GetBLS12381Params(),
	)
	if err != nil {
		return err
	}
	g1, err := sw_bls12381.NewG1(api)
	if err != nil {
		return err
	}
	baseField, err := emulated.NewField[emulated.BLS12381Fp](api)
	if err != nil {
		return err
	}
	zero := baseField.Zero()
	infinity := sw_bls12381.G1Affine{X: *zero, Y: *zero}
	for i := range components {
		isInfinity := g1.IsEqual(&components[i], &infinity)
		pointForSubgroupCheck := curve.Select(isInfinity, curve.Generator(), &components[i])
		g1.AssertIsOnG1(pointForSubgroupCheck)
	}

	for pointIndex := 0; pointIndex < pointCount; pointIndex++ {
		result := &components[pointIndex]
		for componentIndex := 1; componentIndex < componentCount; componentIndex++ {
			component := &components[componentIndex*pointCount+pointIndex]
			result = curve.AddUnified(result, component)
		}
		curve.AssertIsEqual(result, &aggregates[pointIndex])
	}
	return nil
}
