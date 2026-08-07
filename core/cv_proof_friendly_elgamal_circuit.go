package core

import (
	"fmt"
	"math/big"

	cryptoed "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	circuited "github.com/consensys/gnark/std/algebra/native/twistededwards"
)

// cvProofFriendlyElGamalLaneCircuit measures an alternative encryption
// relation on BN254's native companion curve. It is not wire-compatible with
// the current BLS12-381 APVSS backend and must not be enabled without a key,
// scalar-field and transcript migration.
type cvProofFriendlyElGamalLaneCircuit struct {
	ReceiverPublicKey circuited.Point
	CiphertextR       []circuited.Point
	CiphertextC       []circuited.Point
	Digits            []frontend.Variable
	Coins             []frontend.Variable
	Evaluation        circuited.Point

	chunkBits int
}

func cvAssertNativeEdwardsPointEqual(api frontend.API, left, right circuited.Point) {
	api.AssertIsEqual(left.X, right.X)
	api.AssertIsEqual(left.Y, right.Y)
}

func cvNativeEdwardsConstantScalarMul(
	curve circuited.Curve,
	point circuited.Point,
	scalar *big.Int,
) circuited.Point {
	result := point
	for bit := scalar.BitLen() - 2; bit >= 0; bit-- {
		result = curve.Double(result)
		if scalar.Bit(bit) == 1 {
			result = curve.Add(result, point)
		}
	}
	return result
}

func cvNativeEdwardsScalarMulAllowZero(
	api frontend.API,
	curve circuited.Curve,
	point circuited.Point,
	scalar frontend.Variable,
) circuited.Point {
	isZero := api.IsZero(scalar)
	nonzeroScalar := api.Select(isZero, 1, scalar)
	product := curve.ScalarMul(point, nonzeroScalar)
	return circuited.Point{
		X: api.Select(isZero, 0, product.X),
		Y: api.Select(isZero, 1, product.Y),
	}
}

func (c *cvProofFriendlyElGamalLaneCircuit) Define(api frontend.API) error {
	if c.chunkBits <= 0 || c.chunkBits > 16 || len(c.Digits) == 0 ||
		len(c.Digits) != len(c.Coins) || len(c.Digits) != len(c.CiphertextR) ||
		len(c.Digits) != len(c.CiphertextC) {
		return fmt.Errorf("invalid proof-friendly ElGamal circuit shape")
	}
	curve, err := circuited.NewEdCurve(api, cryptoed.BN254)
	if err != nil {
		return err
	}
	params := curve.Params()
	if (len(c.Digits)-1)*c.chunkBits >= params.Order.BitLen() {
		return fmt.Errorf("proof-friendly ElGamal digit capacity exceeds subgroup scalar")
	}
	base := circuited.Point{X: params.Base[0], Y: params.Base[1]}
	identity := circuited.Point{X: 0, Y: 1}
	curve.AssertIsOnCurve(c.ReceiverPublicKey)
	isIdentity := api.And(
		api.IsZero(c.ReceiverPublicKey.X),
		api.IsZero(api.Sub(c.ReceiverPublicKey.Y, 1)),
	)
	api.AssertIsEqual(isIdentity, 0)
	// The generic native ScalarMul hint is undefined when the constant scalar
	// equals the subgroup order. Constant double-and-add avoids that hint and
	// enforces [order]PK = identity directly.
	orderCheck := cvNativeEdwardsConstantScalarMul(curve, c.ReceiverPublicKey, params.Order)
	cvAssertNativeEdwardsPointEqual(api, orderCheck, identity)

	orderMinusOne := new(big.Int).Sub(new(big.Int).Set(params.Order), big.NewInt(1))
	weightedScalar := frontend.Variable(0)
	baseRadix := new(big.Int).Lsh(big.NewInt(1), uint(c.chunkBits))
	power := big.NewInt(1)
	for i := range c.Digits {
		digitBits := c.chunkBits
		if i == len(c.Digits)-1 {
			remainingBits := params.Order.BitLen() - i*c.chunkBits
			if remainingBits < digitBits {
				digitBits = remainingBits
			}
		}
		api.ToBinary(c.Digits[i], digitBits)
		api.AssertIsLessOrEqual(c.Coins[i], orderMinusOne)

		expectedR := cvNativeEdwardsScalarMulAllowZero(api, curve, base, c.Coins[i])
		cvAssertNativeEdwardsPointEqual(api, expectedR, c.CiphertextR[i])
		expectedC := curve.DoubleBaseScalarMul(
			base, c.ReceiverPublicKey, c.Digits[i], c.Coins[i],
		)
		cvAssertNativeEdwardsPointEqual(api, expectedC, c.CiphertextC[i])

		weightedScalar = api.Add(weightedScalar, api.Mul(c.Digits[i], new(big.Int).Set(power)))
		power.Mul(power, baseRadix)
	}
	api.AssertIsLessOrEqual(weightedScalar, orderMinusOne)
	expectedEvaluation := cvNativeEdwardsScalarMulAllowZero(api, curve, base, weightedScalar)
	cvAssertNativeEdwardsPointEqual(api, expectedEvaluation, c.Evaluation)
	return nil
}
