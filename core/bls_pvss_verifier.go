package core

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// ── BLS PVSS Transcript Verification (Bacho-Loss Figure 2: Ver) ───────────

// blsPVSSVerify checks a single dealer transcript.
//
// 1. Pairing consistency: e(C_i, pk_i) == e(g, Y_i) ∀i
// 2. Dual-code low-degree test: <C, v> == 0 for random v ∈ LC⊥
// 3. Lagrange-at-0 check: zeta == Σ λ_i · C_i for first (t+1) commitments
// 4. Schnorr knowledge proof for DLOG_G1(zeta)
func blsPVSSVerify(
	cfg Config,
	tx *BlsPVSSDealerTranscript,
) error {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return err
	}
	if c.runtime == nil {
		return fmt.Errorf("runtime not initialized")
	}
	if tx == nil {
		return fmt.Errorf("nil transcript")
	}

	receiverOrder := c.runtime.receiverOrder
	n := len(receiverOrder)
	if tx.SID != c.SID {
		return fmt.Errorf("transcript SID mismatch: have=%q need=%q", tx.SID, c.SID)
	}
	if tx.Epoch != c.Epoch {
		return fmt.Errorf("transcript epoch mismatch: have=%d need=%d", tx.Epoch, c.Epoch)
	}
	if len(tx.ReceiverOrder) != len(receiverOrder) {
		return fmt.Errorf("transcript receiver order length mismatch: have=%d need=%d", len(tx.ReceiverOrder), len(receiverOrder))
	}
	for i := range receiverOrder {
		if tx.ReceiverOrder[i] != receiverOrder[i] {
			return fmt.Errorf("transcript receiver order mismatch at index=%d", i)
		}
	}
	t := n - c.F - 1
	if t < 0 {
		t = 0
	}

	if len(tx.Commitments) != n {
		return fmt.Errorf("commitments count mismatch: have=%d need=%d", len(tx.Commitments), n)
	}
	if len(tx.EncryptedShares) != n {
		return fmt.Errorf("encrypted shares count mismatch: have=%d need=%d", len(tx.EncryptedShares), n)
	}
	if tx.Zeta.IsInfinity() {
		return fmt.Errorf("zeta is identity")
	}

	// 1. Pairing consistency: e(C_i, pk_i) == e(g, Y_i)
	var gNeg bls12381.G1Affine
	gNeg.Neg(&genG1)
	for i := 0; i < n; i++ {
		pk, ok := c.runtime.blsPVSSPublicKey(receiverOrder[i])
		if !ok {
			return fmt.Errorf("missing PVSS public key for receiver=%d", receiverOrder[i])
		}
		ok, _ = bls12381.PairingCheck(
			[]bls12381.G1Affine{tx.Commitments[i], gNeg},
			[]bls12381.G2Affine{pk, tx.EncryptedShares[i]},
		)
		if !ok {
			return fmt.Errorf("pairing consistency failed for receiver=%d", receiverOrder[i])
		}
	}

	// 2. Dual-code low-degree test
	if t >= 0 && n > 0 && t < n {
		if !lowDegTestG1(tx.Commitments, t, n) {
			return fmt.Errorf("dual-code low-degree test failed")
		}
	}

	// 3. Lagrange-at-0 check: zeta == Σ λ_i · C_i (first t+1)
	checkLen := t + 1
	if checkLen > n {
		checkLen = n
	}
	lagrangeIndices := make([]int, checkLen)
	for i := 0; i < checkLen; i++ {
		lagrangeIndices[i] = i + 1 // 1-based evaluation points
	}
	coeffs := lagrangeCoeffsAtZeroInt(lagrangeIndices)

	var expectedZeta bls12381.G1Affine
	zero := big.NewInt(0)
	expectedZeta.ScalarMultiplication(&genG1, zero)
	for i := 0; i < checkLen; i++ {
		var term bls12381.G1Affine
		term.ScalarMultiplication(&tx.Commitments[i], coeffs[i].BigInt(new(big.Int)))
		expectedZeta.Add(&expectedZeta, &term)
	}
	if !expectedZeta.Equal(&tx.Zeta) {
		return fmt.Errorf("Lagrange-at-zero check failed")
	}

	// 4. Schnorr knowledge proof verification
	if tx.NIZKProof == nil {
		return fmt.Errorf("missing NIZK proof")
	}
	if !verifyChPeqProof(
		&tx.Zeta,
		tx.NIZKProof,
		tx.SID,
		tx.Epoch,
		tx.Dealer,
		tx.ReceiverOrder,
	) {
		return fmt.Errorf("Schnorr proof verification failed for dealer=%d", tx.Dealer)
	}

	return nil
}

// blsPVSSVerPairingCheck is a fast batch pairing check for verification step 1.
// Checks e(C_i, pk_i) == e(g, Y_i) for a single index.
func blsPVSSVerPairingCheck(
	com bls12381.G1Affine, encryptedShare bls12381.G2Affine,
	receiverPK bls12381.G2Affine,
) bool {
	var gNeg bls12381.G1Affine
	gNeg.Neg(&genG1)
	ok, _ := bls12381.PairingCheck(
		[]bls12381.G1Affine{com, gNeg},
		[]bls12381.G2Affine{receiverPK, encryptedShare},
	)
	return ok
}

// ── Share decryption and verification ──────────────────────────────────────

// blsPVSSDecryptShare decrypts a receiver's share: S_i = sk_i^{-1} * Y_i = f(i) * G2
func blsPVSSDecryptShare(
	sk fr.Element,
	encryptedShare bls12381.G2Affine,
) bls12381.G2Affine {
	var skInv fr.Element
	skInv.Inverse(&sk)
	var dec bls12381.G2Affine
	dec.ScalarMultiplication(&encryptedShare, skInv.BigInt(new(big.Int)))
	return dec
}

// blsPVSSVerifyDecryptedShare checks e(C_i, G2) == e(G1, dec_i)
// i.e., the decrypted G2 point corresponds to the G1 commitment.
func blsPVSSVerifyDecryptedShare(
	com bls12381.G1Affine,
	dec bls12381.G2Affine,
) bool {
	var gNeg bls12381.G1Affine
	gNeg.Neg(&genG1)
	ok, _ := bls12381.PairingCheck(
		[]bls12381.G1Affine{com, gNeg},
		[]bls12381.G2Affine{genG2, dec},
	)
	return ok
}

// ── Lagrange interpolation in G2 ───────────────────────────────────────────

// lagrangeInterpG2AtZero interpolates a set of G2 shares at x=0.
// Input: shares[playerIdx] = f(playerIdx+1) * G2
// Returns: f(0) * G2
func lagrangeInterpG2AtZero(
	players []int, // 1-based evaluation point indices
	shares []bls12381.G2Affine,
) (bls12381.G2Affine, error) {
	if len(players) != len(shares) {
		var zero bls12381.G2Affine
		return zero, fmt.Errorf("players and shares count mismatch")
	}
	coeffs := lagrangeCoeffsAtZeroInt(players)

	var result bls12381.G2Affine
	zero := big.NewInt(0)
	result.ScalarMultiplication(&genG2, zero)
	for i := range players {
		var term bls12381.G2Affine
		term.ScalarMultiplication(&shares[i], coeffs[i].BigInt(new(big.Int)))
		result.Add(&result, &term)
	}
	return result, nil
}
