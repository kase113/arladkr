package core

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type cvStructuralElGamalBatchLane struct {
	CiphertextR []sw_bls12381.G1Affine
	CiphertextC []sw_bls12381.G1Affine
	Digits      []frontend.Variable
	Coins       []sw_bls12381.Scalar
	Evaluation  sw_bls12381.G1Affine
}

// cvStructuralElGamalBatchCircuit verifies several component lanes for one
// receiver. It shares receiver-key validity while retaining every exact
// range, encryption and Feldman-evaluation equation.
type cvStructuralElGamalBatchCircuit struct {
	ReceiverPublicKey sw_bls12381.G1Affine
	Lanes             []cvStructuralElGamalBatchLane

	chunkBits int
}

func (c *cvStructuralElGamalBatchCircuit) Define(api frontend.API) error {
	if len(c.Lanes) == 0 {
		return fmt.Errorf("empty structural ElGamal batch circuit")
	}
	for i := range c.Lanes {
		lane := &c.Lanes[i]
		if !cvValidStructuralElGamalLaneShape(
			lane.CiphertextR, lane.CiphertextC, lane.Digits, lane.Coins, c.chunkBits,
		) {
			return fmt.Errorf("invalid structural ElGamal batch lane %d shape", i)
		}
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
	for i := range c.Lanes {
		lane := &c.Lanes[i]
		cvAssertStructuralElGamalLane(
			api, curve, scalarField, &c.ReceiverPublicKey,
			lane.CiphertextR, lane.CiphertextC, lane.Digits, lane.Coins,
			&lane.Evaluation, c.chunkBits,
		)
	}
	return nil
}
