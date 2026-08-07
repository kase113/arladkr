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

func cvStructuralElGamalAssignment(
	chunkBits int,
	receiverSecret uint64,
	digits, coins []uint64,
) (*cvStructuralElGamalLaneCircuit, error) {
	var receiverScalar blsfr.Element
	receiverScalar.SetUint64(receiverSecret)
	receiverPublicKey, err := cvReceiverPublicKey(receiverScalar)
	if err != nil {
		return nil, err
	}
	assignment := &cvStructuralElGamalLaneCircuit{
		ReceiverPublicKey: sw_bls12381.NewG1Affine(receiverPublicKey),
		CiphertextR:       make([]sw_bls12381.G1Affine, len(digits)),
		CiphertextC:       make([]sw_bls12381.G1Affine, len(digits)),
		Digits:            make([]frontend.Variable, len(digits)),
		Coins:             make([]sw_bls12381.Scalar, len(digits)),
		chunkBits:         chunkBits,
	}
	base := new(big.Int).Lsh(big.NewInt(1), uint(chunkBits))
	power := big.NewInt(1)
	evaluationScalar := big.NewInt(0)
	for i := range digits {
		var digitScalar, coinScalar blsfr.Element
		digitScalar.SetUint64(digits[i])
		coinScalar.SetUint64(coins[i])
		var digitPoint bls12381.G1Affine
		digitPoint.ScalarMultiplication(&genG1, digitScalar.BigInt(new(big.Int)))
		ciphertext, err := cvEncryptPoint(&receiverPublicKey, &digitPoint, coinScalar)
		if err != nil {
			return nil, err
		}
		assignment.CiphertextR[i] = sw_bls12381.NewG1Affine(ciphertext.r)
		assignment.CiphertextC[i] = sw_bls12381.NewG1Affine(ciphertext.c)
		assignment.Digits[i] = digits[i]
		assignment.Coins[i] = sw_bls12381.NewScalar(coinScalar)
		evaluationScalar.Add(evaluationScalar, new(big.Int).Mul(new(big.Int).SetUint64(digits[i]), power))
		power.Mul(power, base)
	}
	var evaluation bls12381.G1Affine
	evaluation.ScalarMultiplication(&genG1, evaluationScalar)
	assignment.Evaluation = sw_bls12381.NewG1Affine(evaluation)
	return assignment, nil
}

func TestCVStructuralElGamalLaneCircuit(t *testing.T) {
	const chunkBits = 8
	circuit := &cvStructuralElGamalLaneCircuit{
		CiphertextR: make([]sw_bls12381.G1Affine, 2),
		CiphertextC: make([]sw_bls12381.G1Affine, 2),
		Digits:      make([]frontend.Variable, 2),
		Coins:       make([]sw_bls12381.Scalar, 2),
		chunkBits:   chunkBits,
	}
	assignment, err := cvStructuralElGamalAssignment(chunkBits, 17, []uint64{5, 251}, []uint64{19, 23})
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}

	wrongCiphertext := *assignment
	wrongCiphertext.CiphertextC = append([]sw_bls12381.G1Affine(nil), assignment.CiphertextC...)
	wrongCiphertext.CiphertextC[0] = assignment.CiphertextC[1]
	if err := test.IsSolved(circuit, &wrongCiphertext, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("structural ElGamal circuit accepted a replaced ciphertext")
	}

	outOfRange := *assignment
	outOfRange.Digits = append([]frontend.Variable(nil), assignment.Digits...)
	outOfRange.Digits[0] = 256
	if err := test.IsSolved(circuit, &outOfRange, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("structural ElGamal circuit accepted an out-of-range digit")
	}

	wrongEvaluation := *assignment
	other, err := cvStructuralElGamalAssignment(chunkBits, 17, []uint64{5, 250}, []uint64{19, 23})
	if err != nil {
		t.Fatal(err)
	}
	wrongEvaluation.Evaluation = other.Evaluation
	if err := test.IsSolved(circuit, &wrongEvaluation, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("structural ElGamal circuit accepted a wrong Feldman evaluation")
	}
}

func TestCVStructuralElGamalLaneCircuitAcceptsZeroEncryption(t *testing.T) {
	circuit := &cvStructuralElGamalLaneCircuit{
		CiphertextR: make([]sw_bls12381.G1Affine, 1),
		CiphertextC: make([]sw_bls12381.G1Affine, 1),
		Digits:      make([]frontend.Variable, 1),
		Coins:       make([]sw_bls12381.Scalar, 1),
		chunkBits:   8,
	}
	assignment, err := cvStructuralElGamalAssignment(8, 17, []uint64{0}, []uint64{0})
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

func TestCVStructuralElGamalLaneCircuitRejectsMalformedReceiverKey(t *testing.T) {
	circuit := &cvStructuralElGamalLaneCircuit{
		CiphertextR: make([]sw_bls12381.G1Affine, 1),
		CiphertextC: make([]sw_bls12381.G1Affine, 1),
		Digits:      make([]frontend.Variable, 1),
		Coins:       make([]sw_bls12381.Scalar, 1),
		chunkBits:   8,
	}
	assignment, err := cvStructuralElGamalAssignment(8, 17, []uint64{5}, []uint64{19})
	if err != nil {
		t.Fatal(err)
	}
	assignment.ReceiverPublicKey = sw_bls12381.G1Affine{
		X: emulated.ValueOf[emulated.BLS12381Fp](1),
		Y: emulated.ValueOf[emulated.BLS12381Fp](1),
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("structural ElGamal circuit accepted a malformed receiver key")
	}
}

func TestCVStructuralElGamalLaneCircuitConstraintBudget(t *testing.T) {
	budgets := []struct {
		digits  int
		maximum int
	}{
		{digits: 1, maximum: 420_000},
		{digits: 2, maximum: 700_000},
		{digits: 3, maximum: 850_000},
	}
	for _, budget := range budgets {
		circuit := &cvStructuralElGamalLaneCircuit{
			CiphertextR: make([]sw_bls12381.G1Affine, budget.digits),
			CiphertextC: make([]sw_bls12381.G1Affine, budget.digits),
			Digits:      make([]frontend.Variable, budget.digits),
			Coins:       make([]sw_bls12381.Scalar, budget.digits),
			chunkBits:   8,
		}
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		if err != nil {
			t.Fatal(err)
		}
		if constraints := ccs.GetNbConstraints(); constraints > budget.maximum {
			t.Fatalf("structural ElGamal digits=%d grew to %d constraints", budget.digits, constraints)
		} else {
			t.Logf("structural ElGamal digits=%d constraints=%d", budget.digits, constraints)
		}
	}
}
