package core

import (
	"fmt"
	"math/big"

	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// cvACKAuthenticationCircuit verifies the v2 APVSS receiver Schnorr
// signature. StatementCommitment must be constrained by the enclosing lane
// relation; leaving it unconstrained would not authenticate a lane.
type cvACKAuthenticationCircuit struct {
	StatementCommitment frontend.Variable
	SigningPublicKey    sw_bls12381.G1Affine
	Nonce               sw_bls12381.G1Affine
	Response            sw_bls12381.Scalar
}

// cvSelectableACKAuthenticationCircuit conditionally verifies one ACK. An
// inactive slot is forced to the all-zero external encoding and internally
// replaced with a fixed valid dummy relation; Enabled itself is constrained.
type cvSelectableACKAuthenticationCircuit struct {
	Enabled frontend.Variable
	ACK     cvACKAuthenticationCircuit
}

func cvACKChallengeDomainElement() *big.Int {
	var element bnfr.Element
	element.SetBytes(hashBytes([]byte(apvssACKChallengeDomain)))
	return element.BigInt(new(big.Int))
}

func cvACKCoordinateChunks(
	api frontend.API,
	field *emulated.Field[emulated.BLS12381Fp],
	coordinate *emulated.Element[emulated.BLS12381Fp],
) []frontend.Variable {
	coordinateBits := field.ToBitsCanonical(coordinate)
	for len(coordinateBits) < 48*8 {
		coordinateBits = append(coordinateBits, 0)
	}
	// Native canonical coordinates are 48-byte big-endian values split into
	// a 31-byte high chunk followed by a 17-byte low chunk.
	return []frontend.Variable{
		bits.FromBinary(api, coordinateBits[17*8:]),
		bits.FromBinary(api, coordinateBits[:17*8]),
	}
}

func (c *cvACKAuthenticationCircuit) Define(api frontend.API) error {
	return cvAssertSelectableACKAuthentication(api, c, 1)
}

func (c *cvSelectableACKAuthenticationCircuit) Define(api frontend.API) error {
	return cvAssertSelectableACKAuthentication(api, &c.ACK, c.Enabled)
}

func cvAssertZeroWhenDisabled(
	api frontend.API,
	disabled frontend.Variable,
	variables ...frontend.Variable,
) {
	for _, variable := range variables {
		api.AssertIsEqual(api.Mul(disabled, variable), 0)
	}
}

func cvAssertSelectableACKAuthentication(
	api frontend.API,
	ack *cvACKAuthenticationCircuit,
	enabled frontend.Variable,
) error {
	if ack == nil {
		return fmt.Errorf("nil selectable ACK authentication circuit")
	}
	api.AssertIsBoolean(enabled)
	disabled := api.Sub(1, enabled)
	cvAssertZeroWhenDisabled(api, disabled, ack.StatementCommitment)
	for _, element := range []*emulated.Element[emulated.BLS12381Fp]{
		&ack.SigningPublicKey.X, &ack.SigningPublicKey.Y,
		&ack.Nonce.X, &ack.Nonce.Y,
	} {
		cvAssertZeroWhenDisabled(api, disabled, element.Limbs...)
	}
	cvAssertZeroWhenDisabled(api, disabled, ack.Response.Limbs...)

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
	selectedSigningPublicKey := curve.Select(enabled, &ack.SigningPublicKey, curve.Generator())
	selectedNonce := curve.Select(enabled, &ack.Nonce, curve.Generator())
	assertValidNonInfinity := func(point *sw_bls12381.G1Affine) {
		isInfinity := g1.IsEqual(point, &infinity)
		api.AssertIsEqual(isInfinity, 0)
		pointForSubgroupCheck := curve.Select(isInfinity, curve.Generator(), point)
		g1.AssertIsOnG1(pointForSubgroupCheck)
	}
	assertValidNonInfinity(selectedSigningPublicKey)
	assertValidNonInfinity(selectedNonce)

	permutation, err := poseidon2.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return err
	}
	state := permutation.Compress(0, cvACKChallengeDomainElement())
	selectedStatementCommitment := api.Select(enabled, ack.StatementCommitment, 0)
	state = permutation.Compress(state, selectedStatementCommitment)
	for _, coordinate := range []*emulated.Element[emulated.BLS12381Fp]{
		&selectedNonce.X, &selectedNonce.Y,
	} {
		for _, chunk := range cvACKCoordinateChunks(api, baseField, coordinate) {
			state = permutation.Compress(state, chunk)
		}
	}
	challengeBits := api.ToBinary(state, bnfr.Modulus().BitLen())
	challenge := scalarField.FromBits(challengeBits...)
	dummyResponse := scalarField.Add(scalarField.One(), challenge)
	selectedResponse := scalarField.Select(enabled, &ack.Response, dummyResponse)

	lhs := curve.ScalarMul(
		curve.Generator(), selectedResponse,
		algopts.WithNbScalarBits(emulated.BLS12381Fr{}.Modulus().BitLen()),
		algopts.WithCompleteArithmetic(),
	)
	publicTerm := curve.ScalarMul(
		selectedSigningPublicKey, challenge,
		algopts.WithNbScalarBits(bnfr.Modulus().BitLen()),
		algopts.WithCompleteArithmetic(),
	)
	rhs := curve.AddUnified(selectedNonce, publicTerm)
	curve.AssertIsEqual(lhs, rhs)
	return nil
}

func cvACKCircuitStatementCommitment(statement []byte) ([]byte, error) {
	if len(statement) == 0 {
		return nil, fmt.Errorf("empty APVSS ACK circuit statement")
	}
	return cvPoseidon2BytesCommitment(apvssACKStatementDomain, statement, cvMaxLeafWireBytes)
}
