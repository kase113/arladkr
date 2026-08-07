package core

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func cvACKCircuitAssignment(statement []byte, secret, nonce uint64) (*cvACKAuthenticationCircuit, error) {
	statementCommitment, err := cvACKCircuitStatementCommitment(statement)
	if err != nil {
		return nil, err
	}
	var publicKey, noncePoint bls12381.G1Affine
	publicKey.ScalarMultiplication(&genG1, new(big.Int).SetUint64(secret))
	noncePoint.ScalarMultiplication(&genG1, new(big.Int).SetUint64(nonce))
	challenge, err := apvssACKChallenge(statementCommitment, &noncePoint)
	if err != nil {
		return nil, err
	}
	var secretScalar, nonceScalar, response, term blsfr.Element
	secretScalar.SetUint64(secret)
	nonceScalar.SetUint64(nonce)
	term.Mul(&challenge, &secretScalar)
	response.Add(&nonceScalar, &term)
	return &cvACKAuthenticationCircuit{
		StatementCommitment: new(big.Int).SetBytes(statementCommitment),
		SigningPublicKey:    sw_bls12381.NewG1Affine(publicKey),
		Nonce:               sw_bls12381.NewG1Affine(noncePoint),
		Response:            sw_bls12381.NewScalar(response),
	}, nil
}

func cvDisabledSelectableACKAssignment() *cvSelectableACKAuthenticationCircuit {
	var zeroPoint bls12381.G1Affine
	var zeroScalar blsfr.Element
	return &cvSelectableACKAuthenticationCircuit{
		Enabled: 0,
		ACK: cvACKAuthenticationCircuit{
			StatementCommitment: 0,
			SigningPublicKey:    sw_bls12381.NewG1Affine(zeroPoint),
			Nonce:               sw_bls12381.NewG1Affine(zeroPoint),
			Response:            sw_bls12381.NewScalar(zeroScalar),
		},
	}
}

func TestCVACKAuthenticationCircuit(t *testing.T) {
	circuit := &cvACKAuthenticationCircuit{}
	assignment, err := cvACKCircuitAssignment([]byte("canonical lane statement"), 17, 29)
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}

	wrongStatement, err := cvACKCircuitAssignment([]byte("different lane statement"), 17, 29)
	if err != nil {
		t.Fatal(err)
	}
	wrongStatement.Response = assignment.Response
	if err := test.IsSolved(circuit, wrongStatement, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("ACK authentication circuit accepted a signature for another statement")
	}

	wrongResponse := *assignment
	var response blsfr.Element
	response.SetUint64(1)
	wrongResponse.Response = sw_bls12381.NewScalar(response)
	if err := test.IsSolved(circuit, &wrongResponse, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("ACK authentication circuit accepted a wrong response")
	}
}

func TestCVACKAuthenticationCircuitRejectsMalformedSigningKey(t *testing.T) {
	circuit := &cvACKAuthenticationCircuit{}
	assignment, err := cvACKCircuitAssignment([]byte("canonical lane statement"), 17, 29)
	if err != nil {
		t.Fatal(err)
	}
	assignment.SigningPublicKey = sw_bls12381.G1Affine{
		X: emulated.ValueOf[emulated.BLS12381Fp](1),
		Y: emulated.ValueOf[emulated.BLS12381Fp](1),
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("ACK authentication circuit accepted a malformed signing key")
	}
}

func TestCVACKAuthenticationCircuitRejectsInfinityNonce(t *testing.T) {
	circuit := &cvACKAuthenticationCircuit{}
	assignment, err := cvACKCircuitAssignment([]byte("canonical lane statement"), 17, 29)
	if err != nil {
		t.Fatal(err)
	}
	assignment.Nonce = sw_bls12381.NewG1Affine(bls12381.G1Affine{})
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("ACK authentication circuit accepted an infinity nonce")
	}
}

func TestCVSelectableACKAuthenticationCircuit(t *testing.T) {
	circuit := &cvSelectableACKAuthenticationCircuit{}
	ack, err := cvACKCircuitAssignment([]byte("canonical selectable lane"), 17, 29)
	if err != nil {
		t.Fatal(err)
	}
	enabled := &cvSelectableACKAuthenticationCircuit{Enabled: 1, ACK: *ack}
	if err := test.IsSolved(circuit, enabled, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	disabled := cvDisabledSelectableACKAssignment()
	if err := test.IsSolved(circuit, disabled, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*cvSelectableACKAuthenticationCircuit){
		"non-boolean selector": func(a *cvSelectableACKAuthenticationCircuit) { a.Enabled = 2 },
		"inactive statement": func(a *cvSelectableACKAuthenticationCircuit) {
			a.ACK.StatementCommitment = 1
		},
		"inactive signing key": func(a *cvSelectableACKAuthenticationCircuit) {
			a.ACK.SigningPublicKey = sw_bls12381.G1Affine{
				X: emulated.ValueOf[emulated.BLS12381Fp](1),
				Y: emulated.ValueOf[emulated.BLS12381Fp](1),
			}
		},
		"inactive response": func(a *cvSelectableACKAuthenticationCircuit) {
			var one blsfr.Element
			one.SetOne()
			a.ACK.Response = sw_bls12381.NewScalar(one)
		},
	} {
		t.Run(name, func(t *testing.T) {
			assignment := cvDisabledSelectableACKAssignment()
			mutate(assignment)
			if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("selectable ACK circuit accepted malformed inactive witness")
			}
		})
	}

	wrongEnabled := &cvSelectableACKAuthenticationCircuit{Enabled: 1, ACK: *ack}
	var wrongResponse blsfr.Element
	wrongResponse.SetOne()
	wrongEnabled.ACK.Response = sw_bls12381.NewScalar(wrongResponse)
	if err := test.IsSolved(circuit, wrongEnabled, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("selectable ACK circuit accepted invalid enabled signature")
	}
}

func TestCVACKAuthenticationCircuitConstraintBudget(t *testing.T) {
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(), r1cs.NewBuilder, &cvACKAuthenticationCircuit{},
	)
	if err != nil {
		t.Fatal(err)
	}
	const maximumConstraints = 500_000
	if constraints := ccs.GetNbConstraints(); constraints > maximumConstraints {
		t.Fatalf("ACK authentication circuit grew to %d constraints", constraints)
	} else {
		t.Logf("ACK authentication constraints=%d", constraints)
	}
}

func TestCVSelectableACKAuthenticationCircuitConstraintBudget(t *testing.T) {
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(), r1cs.NewBuilder, &cvSelectableACKAuthenticationCircuit{},
	)
	if err != nil {
		t.Fatal(err)
	}
	const maximumConstraints = 520_000
	if constraints := ccs.GetNbConstraints(); constraints > maximumConstraints {
		t.Fatalf("selectable ACK authentication circuit grew to %d constraints", constraints)
	} else {
		t.Logf("selectable ACK authentication constraints=%d", constraints)
	}
}
