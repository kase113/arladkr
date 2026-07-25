package core

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// ── Schnorr NIZK for DLOG Knowledge (Bacho-Loss Figure 1) ─────────────────

// buildChPeqProof generates a non-interactive Schnorr proof of knowledge of
// alpha = DLOG_g(zeta), made non-interactive with Fiat-Shamir:
//
//	k ← Z_p
//	R = k * G1
//	c = H(R || zeta || domain)
//	r = k + c·alpha
func buildChPeqProof(
	alpha fr.Element,
	sid string,
	epoch int,
	dealer int,
	receiverOrder []int,
) (*ChaumPedersenNIZK, error) {
	var k fr.Element
	if _, err := k.SetRandom(); err != nil {
		return nil, fmt.Errorf("sample randomness: %w", err)
	}

	// R = k * G1
	var R bls12381.G1Affine
	R.ScalarMultiplication(&genG1, k.BigInt(new(big.Int)))

	// zeta = alpha * G1
	var zeta bls12381.G1Affine
	zeta.ScalarMultiplication(&genG1, alpha.BigInt(new(big.Int)))

	c := hashToFr(
		[]byte("schnorr-dlog-v2"),
		[]byte(sid),
		encodeInts([]int{epoch, dealer}),
		encodeInts(receiverOrder),
		g1Bytes(&R), g1Bytes(&zeta),
	)

	// r = k + c·alpha
	var r fr.Element
	r.Mul(&c, &alpha)
	r.Add(&r, &k)

	var zeroG2 bls12381.G2Affine
	zeroG2.Set(&genG2)

	return &ChaumPedersenNIZK{
		Challenge:   c,
		Response:    r,
		Commitment1: R,
		Commitment2: zeroG2, // unused for Schnorr
	}, nil
}

// verifyChPeqProof verifies the Schnorr proof.
// Checks: c == H(g^r * zeta^{-c} || zeta || domain)
func verifyChPeqProof(
	zeta *bls12381.G1Affine,
	proof *ChaumPedersenNIZK,
	sid string,
	epoch int,
	dealer int,
	receiverOrder []int,
) bool {
	var cNeg fr.Element
	cNeg.Neg(&proof.Challenge)

	// R' = r*G1 + (-c)*zeta  =  g^r * zeta^{-c}
	var Rprime bls12381.G1Affine
	Rprime.ScalarMultiplication(&genG1, proof.Response.BigInt(new(big.Int)))
	var zetaTerm bls12381.G1Affine
	zetaTerm.ScalarMultiplication(zeta, cNeg.BigInt(new(big.Int)))
	Rprime.Add(&Rprime, &zetaTerm)

	// Recompute challenge
	cPrime := hashToFr(
		[]byte("schnorr-dlog-v2"),
		[]byte(sid),
		encodeInts([]int{epoch, dealer}),
		encodeInts(receiverOrder),
		g1Bytes(&Rprime), g1Bytes(zeta),
	)

	return cPrime.Equal(&proof.Challenge)
}

// hashToFr hashes arbitrary bytes to a scalar field element.
func hashToFr(parts ...[]byte) fr.Element {
	digest := hashBytes(parts...)
	var e fr.Element
	e.SetBytes(digest[:fr.Bytes])
	return e
}
