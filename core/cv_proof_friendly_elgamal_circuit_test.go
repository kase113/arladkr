package core

import (
	"bytes"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	edbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	circuited "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/test"
)

func cvNativeEdwardsCircuitPoint(point *edbn254.PointAffine) circuited.Point {
	return circuited.Point{
		X: point.X.BigInt(new(big.Int)),
		Y: point.Y.BigInt(new(big.Int)),
	}
}

func cvProofFriendlyElGamalAssignment(
	chunkBits int,
	receiverSecret uint64,
	digits, coins []uint64,
) *cvProofFriendlyElGamalLaneCircuit {
	params := edbn254.GetEdwardsCurve()
	secret := new(big.Int).SetUint64(receiverSecret)
	var receiverPublicKey edbn254.PointAffine
	receiverPublicKey.ScalarMultiplication(&params.Base, secret)
	assignment := &cvProofFriendlyElGamalLaneCircuit{
		ReceiverPublicKey: cvNativeEdwardsCircuitPoint(&receiverPublicKey),
		CiphertextR:       make([]circuited.Point, len(digits)),
		CiphertextC:       make([]circuited.Point, len(digits)),
		Digits:            make([]frontend.Variable, len(digits)),
		Coins:             make([]frontend.Variable, len(digits)),
		chunkBits:         chunkBits,
	}
	baseRadix := new(big.Int).Lsh(big.NewInt(1), uint(chunkBits))
	power := big.NewInt(1)
	evaluationScalar := big.NewInt(0)
	for i := range digits {
		digit := new(big.Int).SetUint64(digits[i])
		coin := new(big.Int).SetUint64(coins[i])
		var r, digitPoint, keyTerm, ciphertext edbn254.PointAffine
		r.ScalarMultiplication(&params.Base, coin)
		digitPoint.ScalarMultiplication(&params.Base, digit)
		keyTerm.ScalarMultiplication(&receiverPublicKey, coin)
		ciphertext.Add(&digitPoint, &keyTerm)
		assignment.CiphertextR[i] = cvNativeEdwardsCircuitPoint(&r)
		assignment.CiphertextC[i] = cvNativeEdwardsCircuitPoint(&ciphertext)
		assignment.Digits[i] = digits[i]
		assignment.Coins[i] = coins[i]
		evaluationScalar.Add(
			evaluationScalar,
			new(big.Int).Mul(new(big.Int).SetUint64(digits[i]), power),
		)
		power.Mul(power, baseRadix)
	}
	var evaluation edbn254.PointAffine
	evaluation.ScalarMultiplication(&params.Base, evaluationScalar)
	assignment.Evaluation = cvNativeEdwardsCircuitPoint(&evaluation)
	return assignment
}

func cvProofFriendlyElGamalShape(digits, chunkBits int) *cvProofFriendlyElGamalLaneCircuit {
	return &cvProofFriendlyElGamalLaneCircuit{
		CiphertextR: make([]circuited.Point, digits),
		CiphertextC: make([]circuited.Point, digits),
		Digits:      make([]frontend.Variable, digits),
		Coins:       make([]frontend.Variable, digits),
		chunkBits:   chunkBits,
	}
}

func TestCVProofFriendlyElGamalLaneCircuit(t *testing.T) {
	circuit := cvProofFriendlyElGamalShape(2, 8)
	assignment := cvProofFriendlyElGamalAssignment(8, 17, []uint64{5, 251}, []uint64{19, 23})
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}

	wrongCiphertext := *assignment
	wrongCiphertext.CiphertextC = append([]circuited.Point(nil), assignment.CiphertextC...)
	wrongCiphertext.CiphertextC[0] = assignment.CiphertextC[1]
	if err := test.IsSolved(circuit, &wrongCiphertext, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("proof-friendly ElGamal circuit accepted a replaced ciphertext")
	}

	outOfRange := *assignment
	outOfRange.Digits = append([]frontend.Variable(nil), assignment.Digits...)
	outOfRange.Digits[0] = 256
	if err := test.IsSolved(circuit, &outOfRange, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("proof-friendly ElGamal circuit accepted an out-of-range digit")
	}

	wrongEvaluation := *assignment
	other := cvProofFriendlyElGamalAssignment(8, 17, []uint64{5, 250}, []uint64{19, 23})
	wrongEvaluation.Evaluation = other.Evaluation
	if err := test.IsSolved(circuit, &wrongEvaluation, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("proof-friendly ElGamal circuit accepted a wrong evaluation")
	}
}

func TestCVProofFriendlyElGamalLaneCircuitRejectsInvalidKey(t *testing.T) {
	circuit := cvProofFriendlyElGamalShape(1, 8)
	assignment := cvProofFriendlyElGamalAssignment(8, 17, []uint64{5}, []uint64{19})
	assignment.ReceiverPublicKey = circuited.Point{X: 0, Y: 1}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("proof-friendly ElGamal circuit accepted the identity receiver key")
	}
	assignment.ReceiverPublicKey = circuited.Point{X: 1, Y: 1}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("proof-friendly ElGamal circuit accepted a malformed receiver key")
	}
	assignment.ReceiverPublicKey = circuited.Point{
		X: 0,
		Y: new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1)),
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("proof-friendly ElGamal circuit accepted a small-subgroup receiver key")
	}
}

func TestCVProofFriendlyElGamalLaneCircuitCanonicalTopDigit(t *testing.T) {
	circuit := cvProofFriendlyElGamalShape(32, 8)
	digits := make([]uint64, 32)
	coins := make([]uint64, 32)
	assignment := cvProofFriendlyElGamalAssignment(8, 17, digits, coins)
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	digits[31] = 8
	outOfRange := cvProofFriendlyElGamalAssignment(8, 17, digits, coins)
	if err := test.IsSolved(circuit, outOfRange, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("proof-friendly ElGamal circuit accepted a scalar above its 251-bit capacity")
	}
}

func TestCVProofFriendlyElGamalLaneCircuitConstraintBudget(t *testing.T) {
	budgets := []struct {
		digits, maximum int
	}{
		{digits: 1, maximum: 30_000},
		{digits: 2, maximum: 40_000},
		{digits: 3, maximum: 50_000},
		{digits: 32, maximum: 300_000},
	}
	for _, budget := range budgets {
		ccs, err := frontend.Compile(
			ecc.BN254.ScalarField(), r1cs.NewBuilder,
			cvProofFriendlyElGamalShape(budget.digits, 8),
		)
		if err != nil {
			t.Fatal(err)
		}
		if constraints := ccs.GetNbConstraints(); constraints > budget.maximum {
			t.Fatalf("proof-friendly ElGamal digits=%d grew to %d constraints", budget.digits, constraints)
		} else {
			t.Logf("proof-friendly ElGamal digits=%d constraints=%d", budget.digits, constraints)
		}
	}
}

func BenchmarkCVProofFriendlyElGamalLaneCircuit32(b *testing.B) {
	circuit := cvProofFriendlyElGamalShape(32, 8)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		b.Fatal(err)
	}
	digits := make([]uint64, 32)
	coins := make([]uint64, 32)
	for i := range digits {
		digits[i] = uint64((i*17 + 3) & 0xff)
		coins[i] = uint64(i + 1)
	}
	// The companion curve has a 251-bit subgroup scalar, so the final radix
	// digit is restricted to three bits by the circuit.
	digits[len(digits)-1] &= 0x7
	assignment := cvProofFriendlyElGamalAssignment(8, 17, digits, coins)
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		b.Fatal(err)
	}
	setupStarted := time.Now()
	provingKey, verifyingKey, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatal(err)
	}
	setupDuration := time.Since(setupStarted)
	var provingKeyWire, verifyingKeyWire bytes.Buffer
	if _, err := provingKey.WriteTo(&provingKeyWire); err != nil {
		b.Fatal(err)
	}
	if _, err := verifyingKey.WriteTo(&verifyingKeyWire); err != nil {
		b.Fatal(err)
	}
	var proof groth16.Proof
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		proof, err = groth16.Prove(ccs, provingKey, witness)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	verifyStarted := time.Now()
	if err := groth16.Verify(proof, verifyingKey, publicWitness); err != nil {
		b.Fatal(err)
	}
	verifyDuration := time.Since(verifyStarted)
	var proofWire bytes.Buffer
	if _, err := proof.WriteTo(&proofWire); err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(ccs.GetNbConstraints()), "constraints")
	b.ReportMetric(float64(provingKeyWire.Len()), "pk_bytes")
	b.ReportMetric(float64(proofWire.Len()), "proof_bytes")
	b.ReportMetric(float64(setupDuration.Nanoseconds()), "setup_ns")
	b.ReportMetric(float64(verifyDuration.Nanoseconds()), "verify_ns")
	b.ReportMetric(float64(verifyingKeyWire.Len()), "vk_bytes")
}
