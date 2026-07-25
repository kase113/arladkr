package core

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// ── BLS12-381 PVSS Types (Bacho-Loss CCS'23 OptRand APVSS) ──────────────

// ChaumPedersenNIZK is a legacy-named container for the prototype's Schnorr
// knowledge proof of DLOG_G1(zeta). It does not prove cross-group discrete-log
// equality. Commitment2 is retained only for wire compatibility and is ignored
// by verification.
type ChaumPedersenNIZK struct {
	Challenge   fr.Element        // c = H(domain || context || R1 || zeta)
	Response    fr.Element        // r = k + c * alpha
	Commitment1 bls12381.G1Affine // R1 = k * G1
	Commitment2 bls12381.G2Affine // legacy wire field; not part of the statement
}

// BlsPVSSDealerTranscript is the per-dealer PVSS output.
// Corresponds to T_L = {C_i, Y_i, pi}_{i∈[n]} in the paper.
type BlsPVSSDealerTranscript struct {
	SID             string
	Epoch           int
	ReceiverOrder   []int
	Dealer          int
	Commitments     []bls12381.G1Affine // C_i = g^{f(i)} for i ∈ [0..n-1]
	EncryptedShares []bls12381.G2Affine // Y_i = f(i) * pk_i for i ∈ [0..n-1]
	Zeta            bls12381.G1Affine   // ζ = g^{f(0)}
	NIZKProof       *ChaumPedersenNIZK  // Schnorr knowledge proof for DLOG_G1(zeta)
}

// BlsPVSSAggregateTranscript carries the aggregated PVSS proof after
// pointwise-multiplying t+1 valid dealer transcripts.
// C_agg[i] = prod_{d∈dealers} C_{d,i}  (G1) and similarly for Y_agg[i] (G2).
type BlsPVSSAggregateTranscript struct {
	Dealers                   []int
	AggregatedCommitments     []bls12381.G1Affine              // C_agg[i] = ∏ C_{d,i}
	AggregatedEncryptedShares []bls12381.G2Affine              // Y_agg[i] = ∏ Y_{d,i}
	AggregatedZeta            bls12381.G1Affine                // ζ_agg = ∏ ζ_d
	PerDealer                 map[int]*BlsPVSSDealerTranscript // kept for AVer re-check
}

// ── gnark-crypto byte conversion helpers ──────────────────────────────────
// gnark-crypto .Bytes() returns fixed-size arrays; these helpers convert to slices.

func g1Bytes(p *bls12381.G1Affine) []byte {
	arr := p.Bytes()
	return arr[:]
}

func g2Bytes(p *bls12381.G2Affine) []byte {
	arr := p.Bytes()
	return arr[:]
}

func frBytes(e *fr.Element) []byte {
	arr := e.Bytes()
	return arr[:]
}
