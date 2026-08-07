package core

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/test"
)

func cvACKPartitionAuthenticationAssignment(t testing.TB) *cvACKPartitionAuthenticationCircuit {
	t.Helper()
	const n, f = 2, 1
	statements := [][]byte{[]byte("receiver one lane"), []byte("receiver two lane")}
	secrets := []uint64{17, 19}
	assignment := cvACKPartitionAuthenticationShape(n, f)
	assignment.Partition = *cvACKFallbackPartitionAssignment(n, f, []int{1}, []int{2})
	for i := 0; i < n; i++ {
		commitment, err := cvACKCircuitStatementCommitment(statements[i])
		if err != nil {
			t.Fatal(err)
		}
		assignment.ReceiverStatementCommitments[i] = new(big.Int).SetBytes(commitment)
		var publicKey bls12381.G1Affine
		publicKey.ScalarMultiplication(&genG1, new(big.Int).SetUint64(secrets[i]))
		assignment.ReceiverSigningPublicKeys[i] = sw_bls12381.NewG1Affine(publicKey)
	}
	ack, err := cvACKCircuitAssignment(statements[0], secrets[0], 29)
	if err != nil {
		t.Fatal(err)
	}
	assignment.ACKs[0] = *ack
	assignment.ACKs[1] = cvDisabledSelectableACKAssignment().ACK
	return assignment
}

func TestCVACKPartitionAuthenticationCircuit(t *testing.T) {
	const n, f = 2, 1
	circuit := cvACKPartitionAuthenticationShape(n, f)
	assignment := cvACKPartitionAuthenticationAssignment(t)
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}

	wrongIndex := cvACKPartitionAuthenticationAssignment(t)
	wrongIndex.Partition.ACKIndices[0] = 2
	wrongIndex.Partition.FallbackIndex[0] = 1
	wrongIndex.Partition.FallbackForReceiver[0] = 1
	wrongIndex.Partition.FallbackForReceiver[1] = 0
	if err := test.IsSolved(circuit, wrongIndex, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("ACK partition accepted a signature under another receiver index")
	}

	wrongRegistry := cvACKPartitionAuthenticationAssignment(t)
	wrongRegistry.ReceiverSigningPublicKeys[0] = wrongRegistry.ReceiverSigningPublicKeys[1]
	if err := test.IsSolved(circuit, wrongRegistry, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("ACK partition accepted a mutated signing registry key")
	}

	nonzeroInactive := cvACKPartitionAuthenticationAssignment(t)
	nonzeroInactive.ACKs[1].StatementCommitment = 1
	if err := test.IsSolved(circuit, nonzeroInactive, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("ACK partition accepted nonzero inactive ACK witness")
	}
}

func TestCVACKPartitionAuthenticationCircuitConstraintBudget(t *testing.T) {
	const n, f = 2, 1
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(), r1cs.NewBuilder,
		cvACKPartitionAuthenticationShape(n, f),
	)
	if err != nil {
		t.Fatal(err)
	}
	const maximumConstraints = 700_000
	if constraints := ccs.GetNbConstraints(); constraints > maximumConstraints {
		t.Fatalf("ACK partition authentication grew to %d constraints", constraints)
	} else {
		t.Logf("ACK partition authentication n=%d f=%d constraints=%d", n, f, constraints)
	}
}
