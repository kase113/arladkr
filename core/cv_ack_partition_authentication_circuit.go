package core

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// cvACKPartitionAuthenticationCircuit composes the canonical partition with
// the ACK side of its cryptographic relation. Receiver statement commitments
// and signing keys must be bound by the enclosing canonical leaf/registry
// relation. FallbackForReceiver remains an output for a later fallback gadget;
// this circuit alone is not a complete ACK/fallback proof.
type cvACKPartitionAuthenticationCircuit struct {
	Partition cvACKFallbackPartitionCircuit
	ACKs      []cvACKAuthenticationCircuit

	ReceiverStatementCommitments []frontend.Variable
	ReceiverSigningPublicKeys    []sw_bls12381.G1Affine

	receiverCount int
	maxFallback   int
}

func (c *cvACKPartitionAuthenticationCircuit) Define(api frontend.API) error {
	if c.receiverCount <= 0 || c.maxFallback < 0 || c.maxFallback >= c.receiverCount ||
		len(c.ACKs) != c.receiverCount ||
		len(c.ReceiverStatementCommitments) != c.receiverCount ||
		len(c.ReceiverSigningPublicKeys) != c.receiverCount {
		return fmt.Errorf("invalid ACK partition authentication circuit shape")
	}
	c.Partition.receiverCount = c.receiverCount
	c.Partition.maxFallback = c.maxFallback
	if err := c.Partition.Define(api); err != nil {
		return err
	}
	curve, err := sw_emulated.New[emulated.BLS12381Fp, emulated.BLS12381Fr](
		api, sw_emulated.GetBLS12381Params(),
	)
	if err != nil {
		return err
	}
	baseField, err := emulated.NewField[emulated.BLS12381Fp](api)
	if err != nil {
		return err
	}
	zero := baseField.Zero()
	zeroPoint := &sw_bls12381.G1Affine{X: *zero, Y: *zero}
	for slot := range c.ACKs {
		active := c.Partition.ACKActive[slot]
		if err := cvAssertSelectableACKAuthentication(api, &c.ACKs[slot], active); err != nil {
			return fmt.Errorf("ACK slot %d: %w", slot, err)
		}
		expectedStatement := frontend.Variable(0)
		expectedKey := zeroPoint
		for receiver := 1; receiver <= c.receiverCount; receiver++ {
			matches := api.Mul(
				active,
				api.IsZero(api.Sub(c.Partition.ACKIndices[slot], receiver)),
			)
			expectedStatement = api.Add(
				expectedStatement,
				api.Mul(matches, c.ReceiverStatementCommitments[receiver-1]),
			)
			expectedKey = curve.Select(
				matches, &c.ReceiverSigningPublicKeys[receiver-1], expectedKey,
			)
		}
		api.AssertIsEqual(c.ACKs[slot].StatementCommitment, expectedStatement)
		baseField.AssertIsEqual(&c.ACKs[slot].SigningPublicKey.X, &expectedKey.X)
		baseField.AssertIsEqual(&c.ACKs[slot].SigningPublicKey.Y, &expectedKey.Y)
	}
	return nil
}

func cvACKPartitionAuthenticationShape(n, f int) *cvACKPartitionAuthenticationCircuit {
	return &cvACKPartitionAuthenticationCircuit{
		Partition:                    *cvACKFallbackPartitionShape(n, f),
		ACKs:                         make([]cvACKAuthenticationCircuit, n),
		ReceiverStatementCommitments: make([]frontend.Variable, n),
		ReceiverSigningPublicKeys:    make([]sw_bls12381.G1Affine, n),
		receiverCount:                n,
		maxFallback:                  f,
	}
}
