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

// cvStructuralElGamalLaneCircuit verifies the direct witness relation for one
// structural fallback lane. Evaluation must be constrained to the matching
// Feldman polynomial evaluation by the enclosing aggregate circuit.
type cvStructuralElGamalLaneCircuit struct {
	ReceiverPublicKey sw_bls12381.G1Affine
	CiphertextR       []sw_bls12381.G1Affine
	CiphertextC       []sw_bls12381.G1Affine
	Digits            []frontend.Variable
	Coins             []sw_bls12381.Scalar
	Evaluation        sw_bls12381.G1Affine

	chunkBits int
}

func cvValidStructuralElGamalLaneShape(
	ciphertextR, ciphertextC []sw_bls12381.G1Affine,
	digits []frontend.Variable,
	coins []sw_bls12381.Scalar,
	chunkBits int,
) bool {
	return chunkBits > 0 && chunkBits <= 16 && len(digits) > 0 &&
		len(digits) == len(coins) && len(digits) == len(ciphertextR) &&
		len(digits) == len(ciphertextC)
}

func cvAssertStructuralElGamalReceiverKey(
	api frontend.API,
	curve *sw_emulated.Curve[emulated.BLS12381Fp, emulated.BLS12381Fr],
	g1 *sw_bls12381.G1,
	baseField *emulated.Field[emulated.BLS12381Fp],
	receiverPublicKey *sw_bls12381.G1Affine,
) {
	zero := baseField.Zero()
	infinity := sw_bls12381.G1Affine{X: *zero, Y: *zero}
	isInfinity := g1.IsEqual(receiverPublicKey, &infinity)
	api.AssertIsEqual(isInfinity, 0)
	keyForSubgroupCheck := curve.Select(isInfinity, curve.Generator(), receiverPublicKey)
	g1.AssertIsOnG1(keyForSubgroupCheck)
}

func cvAssertStructuralElGamalLane(
	api frontend.API,
	curve *sw_emulated.Curve[emulated.BLS12381Fp, emulated.BLS12381Fr],
	scalarField *emulated.Field[emulated.BLS12381Fr],
	receiverPublicKey *sw_bls12381.G1Affine,
	ciphertextR, ciphertextC []sw_bls12381.G1Affine,
	digits []frontend.Variable,
	coins []sw_bls12381.Scalar,
	evaluation *sw_bls12381.G1Affine,
	chunkBits int,
) {
	digitScalars := make([]*emulated.Element[emulated.BLS12381Fr], len(digits))
	weightedScalar := scalarField.Zero()
	base := new(big.Int).Lsh(big.NewInt(1), uint(chunkBits))
	power := big.NewInt(1)
	for i := range digits {
		digitBits := api.ToBinary(digits[i], chunkBits)
		digitScalars[i] = scalarField.FromBits(digitBits...)
		digitPoint := curve.ScalarMul(
			curve.Generator(), digitScalars[i],
			algopts.WithNbScalarBits(chunkBits), algopts.WithCompleteArithmetic(),
		)
		coinPoint := curve.ScalarMul(
			curve.Generator(), &coins[i],
			algopts.WithNbScalarBits((emulated.BLS12381Fr{}).Modulus().BitLen()),
			algopts.WithCompleteArithmetic(),
		)
		curve.AssertIsEqual(coinPoint, &ciphertextR[i])
		keyTerm := curve.ScalarMul(
			receiverPublicKey, &coins[i],
			algopts.WithNbScalarBits((emulated.BLS12381Fr{}).Modulus().BitLen()),
			algopts.WithCompleteArithmetic(),
		)
		expectedCiphertext := curve.AddUnified(digitPoint, keyTerm)
		curve.AssertIsEqual(expectedCiphertext, &ciphertextC[i])

		weightedDigit := scalarField.Mul(digitScalars[i], scalarField.NewElement(new(big.Int).Set(power)))
		weightedScalar = scalarField.Add(weightedScalar, weightedDigit)
		power.Mul(power, base)
	}
	var expectedEvaluation *sw_emulated.AffinePoint[emulated.BLS12381Fp]
	if len(digitScalars) == 1 {
		expectedEvaluation = curve.ScalarMul(
			curve.Generator(), digitScalars[0],
			algopts.WithNbScalarBits(chunkBits), algopts.WithCompleteArithmetic(),
		)
	} else {
		expectedEvaluation = curve.ScalarMul(
			curve.Generator(), weightedScalar,
			algopts.WithNbScalarBits((emulated.BLS12381Fr{}).Modulus().BitLen()),
			algopts.WithCompleteArithmetic(),
		)
	}
	curve.AssertIsEqual(expectedEvaluation, evaluation)
}

func (c *cvStructuralElGamalLaneCircuit) Define(api frontend.API) error {
	if !cvValidStructuralElGamalLaneShape(
		c.CiphertextR, c.CiphertextC, c.Digits, c.Coins, c.chunkBits,
	) {
		return fmt.Errorf("invalid structural ElGamal lane circuit shape")
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
	cvAssertStructuralElGamalReceiverKey(api, curve, g1, baseField, &c.ReceiverPublicKey)
	cvAssertStructuralElGamalLane(
		api, curve, scalarField, &c.ReceiverPublicKey,
		c.CiphertextR, c.CiphertextC, c.Digits, c.Coins, &c.Evaluation, c.chunkBits,
	)
	return nil
}
