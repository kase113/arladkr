package core

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// cvFeldmanEvaluationCircuit verifies one receiver evaluation against a hidden
// coefficient vector. receiverIndex and coefficient count are circuit-shape
// parameters and must therefore be covered by the circuit digest.
type cvFeldmanEvaluationCircuit struct {
	Commitments []sw_bls12381.G1Affine
	Evaluation  sw_bls12381.G1Affine

	receiverIndex int
}

func (c *cvFeldmanEvaluationCircuit) Define(api frontend.API) error {
	if c.receiverIndex <= 0 || len(c.Commitments) == 0 {
		return fmt.Errorf("invalid Feldman evaluation circuit shape")
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
	scalarField, err := emulated.NewField[emulated.BLS12381Fr](api)
	if err != nil {
		return err
	}
	zero := baseField.Zero()
	infinity := sw_bls12381.G1Affine{X: *zero, Y: *zero}
	for i := range c.Commitments {
		// AssertIsOnG1 uses incomplete formulas internally. Replace the allowed
		// infinity encoding with the generator for that check, while retaining
		// the original point for the complete-arithmetic evaluation below.
		isInfinity := g1.IsEqual(&c.Commitments[i], &infinity)
		pointForSubgroupCheck := curve.Select(isInfinity, curve.Generator(), &c.Commitments[i])
		g1.AssertIsOnG1(pointForSubgroupCheck)
	}

	result := &c.Commitments[0]
	power := big.NewInt(1)
	receiver := big.NewInt(int64(c.receiverIndex))
	for coefficient := 1; coefficient < len(c.Commitments); coefficient++ {
		power.Mul(power, receiver)
		var term *sw_emulated.AffinePoint[emulated.BLS12381Fp]
		if power.IsInt64() && power.Int64() == 1 {
			term = &c.Commitments[coefficient]
		} else {
			scalar := scalarField.NewElement(new(big.Int).Set(power))
			term = curve.ScalarMul(
				&c.Commitments[coefficient], scalar,
				algopts.WithNbScalarBits(power.BitLen()), algopts.WithCompleteArithmetic(),
			)
		}
		result = curve.AddUnified(result, term)
	}
	curve.AssertIsEqual(result, &c.Evaluation)
	return nil
}
