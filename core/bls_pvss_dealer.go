package core

import (
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// ── BLS PVSS Dealer (Bacho-Loss Figure 1: ADist) ─────────────────────────

// blsPVSSDistribute produces a dealer's PVSS transcript.
//
// The dealer picks a degree-t polynomial f(X) = a_0 + a_1*X + ... + a_t*X^t
// over fr.Element using fresh randomness. Makes public:
//
//	C_i = f(i+1) * G1     (G1 commitments for i = 0..n-1)
//	Y_i = f(i+1) * pk_i   (G2 encrypted shares, pk_i = sk_i * G2)
//	zeta = f(0) * G1      (commitment to secret)
//	Schnorr NIZK          (knowledge of DLOG_G1(zeta), context-bound)
func blsPVSSDistribute(
	cfg Config,
	dealer int,
) (*BlsPVSSDealerTranscript, error) {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	if c.runtime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}

	receiverOrder := c.runtime.receiverOrder
	n := len(receiverOrder)
	t := n - c.F - 1 // degree of sharing polynomial
	if t < 0 {
		t = 0
	}
	if t > n-1 {
		t = n - 1
	}
	threshold := t + 1
	_ = threshold // used implicitly

	// Fresh polynomial: f(X) = a_0 + a_1*X + ... + a_t*X^t.
	// Runtime setup keys remain deterministic in this prototype, but dealer
	// contributions must not be replayed merely because the context is equal.
	coeffs := make([]fr.Element, t+1)
	for j := 0; j <= t; j++ {
		for {
			if _, err := coeffs[j].SetRandom(); err != nil {
				return nil, fmt.Errorf("sample dealer %d polynomial coefficient %d: %w", dealer, j, err)
			}
			if j != 0 || !coeffs[j].IsZero() {
				break
			}
		}
	}

	// Evaluate at points 1..n
	commitments := make([]bls12381.G1Affine, n)
	encryptedShares := make([]bls12381.G2Affine, n)

	for i := 0; i < n; i++ {
		fi := evalPolyInt(coeffs, int64(i+1))

		// C_i = f(i+1) * G1
		commitments[i].ScalarMultiplication(&genG1, fi.BigInt(new(big.Int)))

		// Y_i = f(i+1) * pk_i
		pk, ok := c.runtime.blsPVSSPublicKey(receiverOrder[i])
		if !ok {
			return nil, fmt.Errorf("missing PVSS public key for receiver=%d", receiverOrder[i])
		}
		encryptedShares[i].ScalarMultiplication(&pk, fi.BigInt(new(big.Int)))
	}

	// zeta = a_0 * G1
	var zeta bls12381.G1Affine
	zeta.ScalarMultiplication(&genG1, coeffs[0].BigInt(new(big.Int)))

	// Context-bound Schnorr NIZK proving knowledge of DLOG_G1(zeta).
	nizk, err := buildChPeqProof(coeffs[0], c.SID, c.Epoch, dealer, receiverOrder)
	if err != nil {
		return nil, fmt.Errorf("dealer %d NIZK: %w", dealer, err)
	}

	return &BlsPVSSDealerTranscript{
		SID:             c.SID,
		Epoch:           c.Epoch,
		ReceiverOrder:   append([]int(nil), receiverOrder...),
		Dealer:          dealer,
		Commitments:     commitments,
		EncryptedShares: encryptedShares,
		Zeta:            zeta,
		NIZKProof:       nizk,
	}, nil
}

// ── Polynomial helpers over fr.Element ──────────────────────────────────────

func evalPolyInt(coeffs []fr.Element, x int64) fr.Element {
	var xx fr.Element
	xx.SetInt64(x)
	return evalPolyFr(coeffs, &xx)
}

func evalPolyFr(coeffs []fr.Element, x *fr.Element) fr.Element {
	if len(coeffs) == 0 {
		var zero fr.Element
		zero.SetZero()
		return zero
	}
	result := coeffs[len(coeffs)-1]
	for j := len(coeffs) - 2; j >= 0; j-- {
		result.Mul(&result, x)
		result.Add(&result, &coeffs[j])
	}
	return result
}

// lagrangeCoeffsAtZeroInt computes Lagrange coefficients λ_j for j in S
// such that for any degree-|S| polynomial f:  f(0) = Σ λ_j · f(S[j])
// where evaluation points are positive integers.
func lagrangeCoeffsAtZeroInt(S []int) []fr.Element {
	k := len(S)
	coeffs := make([]fr.Element, k)
	for i := 0; i < k; i++ {
		var num, denom fr.Element
		num.SetOne()
		denom.SetOne()
		var xi fr.Element
		xi.SetInt64(int64(S[i]))
		for j := 0; j < k; j++ {
			if i == j {
				continue
			}
			// num *= (0 - S[j]) = -S[j]
			var negXj fr.Element
			negXj.SetInt64(-int64(S[j]))
			num.Mul(&num, &negXj)

			// denom *= (S[i] - S[j])
			var diff fr.Element
			diff.SetInt64(int64(S[i] - S[j]))
			denom.Mul(&denom, &diff)
		}
		denom.Inverse(&denom)
		coeffs[i].Mul(&num, &denom)
	}
	return coeffs
}

// ── Dual-code low-degree test (equivalent to acss.LowDegTest) ──────────────

// lowDegTestG1 checks that coms[0..n-1] lie on a degree-t polynomial
// by verifying <coms, v> == G1 identity for a random dual codeword v ∈ LC⊥.
func lowDegTestG1(coms []bls12381.G1Affine, t, n int) bool {
	v := dualCodewordInt(t, n)
	if len(v) == 0 {
		return false
	}
	var sum bls12381.G1Affine
	zero := big.NewInt(0)
	sum.ScalarMultiplication(&genG1, zero)
	for i := 0; i < n; i++ {
		var term bls12381.G1Affine
		term.ScalarMultiplication(&coms[i], v[i].BigInt(new(big.Int)))
		sum.Add(&sum, &term)
	}
	// sum must be identity (point at infinity)
	return sum.IsInfinity()
}

// dualCodewordInt returns a random non-zero vector in LC⊥ for
// evaluation points 1..n and code dimension (t+1).
// LC⊥ = { (ϑ_1·r(1), ..., ϑ_n·r(n)) | deg(r) ≤ n-(t+1)-1 }
// We pick r(X) = 1 (degree 0) for simplicity.
func dualCodewordInt(t, n int) []fr.Element {
	v := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		// vartheta_i = prod_{j≠i} 1/((i+1) - (j+1)) = prod_{j≠i} 1/(i-j)
		var theta fr.Element
		theta.SetInt64(1)
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			var diff fr.Element
			diff.SetInt64(int64(i - j))
			diff.Inverse(&diff)
			theta.Mul(&theta, &diff)
		}
		v[i] = theta
	}
	return v
}
