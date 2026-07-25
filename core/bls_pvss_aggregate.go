package core

import (
	"fmt"
	"math/big"
	"sort"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// ── BLS PVSS Aggregation (Bacho-Loss Figure 3: Agg & AVer) ────────────────

// blsPVSSAggregate pointwise-multiplies t+1 valid dealer transcripts into
// a single aggregated transcript (AGG in the paper).
func blsPVSSAggregate(
	cfg Config,
	dealers []int,
	transcripts map[int]*BlsPVSSDealerTranscript,
) (*BlsPVSSAggregateTranscript, error) {
	if len(dealers) == 0 {
		return nil, fmt.Errorf("empty dealer set")
	}

	// Verify all transcripts first
	txs := make([]*BlsPVSSDealerTranscript, len(dealers))
	for i, d := range dealers {
		tx, ok := transcripts[d]
		if !ok || tx == nil {
			return nil, fmt.Errorf("missing transcript for dealer=%d", d)
		}
		if err := blsPVSSVerify(cfg, tx); err != nil {
			return nil, fmt.Errorf("dealer %d transcript invalid: %w", d, err)
		}
		txs[i] = tx
	}

	// Pointwise multiply commitments and encrypted shares
	n := len(txs[0].Commitments)
	aggComs := make([]bls12381.G1Affine, n)
	aggEncs := make([]bls12381.G2Affine, n)

	// First transcript as base (copy)
	for i := 0; i < n; i++ {
		aggComs[i].Set(&txs[0].Commitments[i])
		aggEncs[i].Set(&txs[0].EncryptedShares[i])
	}
	// Add remaining transcripts (pointwise G1/G2 addition = multiplication)
	for j := 1; j < len(txs); j++ {
		for i := 0; i < n; i++ {
			aggComs[i].Add(&aggComs[i], &txs[j].Commitments[i])
			aggEncs[i].Add(&aggEncs[i], &txs[j].EncryptedShares[i])
		}
	}

	// Aggregated zeta = product of zetas
	var aggZeta bls12381.G1Affine
	aggZeta.Set(&txs[0].Zeta)
	for j := 1; j < len(txs); j++ {
		aggZeta.Add(&aggZeta, &txs[j].Zeta)
	}

	// Keep per-dealer transcripts for AVer re-check
	perDealer := make(map[int]*BlsPVSSDealerTranscript, len(dealers))
	for i, d := range dealers {
		perDealer[d] = txs[i]
	}

	agg := &BlsPVSSAggregateTranscript{
		Dealers:                   append([]int(nil), dealers...),
		AggregatedCommitments:     aggComs,
		AggregatedEncryptedShares: aggEncs,
		AggregatedZeta:            aggZeta,
		PerDealer:                 perDealer,
	}
	return agg, nil
}

// blsPVSSAggregateVerify checks the aggregated transcript (AVer in the paper).
func blsPVSSAggregateVerify(
	cfg Config,
	agg *BlsPVSSAggregateTranscript,
) error {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return err
	}
	if c.runtime == nil {
		return fmt.Errorf("runtime not initialized")
	}
	if agg == nil {
		return fmt.Errorf("nil aggregate transcript")
	}

	receiverOrder := c.runtime.receiverOrder
	n := len(receiverOrder)
	t := n - c.F - 1
	if t < 0 {
		t = 0
	}

	if len(agg.AggregatedCommitments) != n {
		return fmt.Errorf("agg commitments count mismatch")
	}
	if len(agg.AggregatedEncryptedShares) != n {
		return fmt.Errorf("agg encrypted shares count mismatch")
	}

	// 1. Pairing consistency on aggregated data
	var gNeg bls12381.G1Affine
	gNeg.Neg(&genG1)
	for i := 0; i < n; i++ {
		pk, ok := c.runtime.blsPVSSPublicKey(receiverOrder[i])
		if !ok {
			return fmt.Errorf("missing PVSS public key for receiver=%d", receiverOrder[i])
		}
		ok, _ = bls12381.PairingCheck(
			[]bls12381.G1Affine{agg.AggregatedCommitments[i], gNeg},
			[]bls12381.G2Affine{pk, agg.AggregatedEncryptedShares[i]},
		)
		if !ok {
			return fmt.Errorf("agg pairing consistency failed for receiver=%d", receiverOrder[i])
		}
	}

	// 2. Dual-code low-degree test on aggregated commitments
	if t >= 0 && n > 0 && t < n {
		if !lowDegTestG1(agg.AggregatedCommitments, t, n) {
			return fmt.Errorf("agg low-degree test failed")
		}
	}

	// 3. Lagrange-at-0 check on aggregated data
	checkLen := t + 1
	if checkLen > n {
		checkLen = n
	}
	lagrangeIndices := make([]int, checkLen)
	for i := 0; i < checkLen; i++ {
		lagrangeIndices[i] = i + 1
	}
	coeffs := lagrangeCoeffsAtZeroInt(lagrangeIndices)
	var expectedZeta bls12381.G1Affine
	zero := big.NewInt(0)
	expectedZeta.ScalarMultiplication(&genG1, zero)
	for i := 0; i < checkLen; i++ {
		var term bls12381.G1Affine
		term.ScalarMultiplication(&agg.AggregatedCommitments[i], coeffs[i].BigInt(new(big.Int)))
		expectedZeta.Add(&expectedZeta, &term)
	}
	if !expectedZeta.Equal(&agg.AggregatedZeta) {
		return fmt.Errorf("agg Lagrange-at-zero failed")
	}

	// 4. Re-verify per-dealer signatures and NIZK proofs
	for dealerID, tx := range agg.PerDealer {
		if tx.NIZKProof != nil {
			if !verifyChPeqProof(
				&tx.Zeta,
				tx.NIZKProof,
				tx.SID,
				tx.Epoch,
				dealerID,
				tx.ReceiverOrder,
			) {
				return fmt.Errorf("NIZK verify failed for dealer=%d", dealerID)
			}
		}
	}

	return nil
}

// blsPVSSRecover lets each receiver decrypt their aggregated share.
// Returns the set of decrypted G2 shares (one per receiver).
// Each receiver i computes: dec_i = sk_i^{-1} * Y_agg[i] = (Σ f_d(i)) * G2
func blsPVSSRecover(
	cfg Config,
	agg *BlsPVSSAggregateTranscript,
) (map[int]bls12381.G2Affine, error) {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	if c.runtime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}

	receiverOrder := c.runtime.receiverOrder
	n := len(receiverOrder)
	if len(agg.AggregatedEncryptedShares) != n {
		return nil, fmt.Errorf("encrypted shares count mismatch")
	}

	decrypted := make(map[int]bls12381.G2Affine, n)
	for i, receiver := range receiverOrder {
		sk, ok := c.runtime.blsPVSSSecretKey(receiver)
		if !ok {
			return nil, fmt.Errorf("missing PVSS secret key for receiver=%d", receiver)
		}
		dec := blsPVSSDecryptShare(sk, agg.AggregatedEncryptedShares[i])
		decrypted[receiver] = dec
	}
	return decrypted, nil
}

func digestBlsPVSSAggregate(agg *BlsPVSSAggregateTranscript) ([]byte, error) {
	if agg == nil {
		return nil, fmt.Errorf("nil BLS aggregate transcript")
	}
	dealers := sortedUnique(agg.Dealers)
	if len(dealers) == 0 || len(dealers) != len(agg.Dealers) {
		return nil, fmt.Errorf("BLS aggregate dealers must be non-empty and distinct")
	}
	for i := range dealers {
		if dealers[i] != agg.Dealers[i] {
			return nil, fmt.Errorf("BLS aggregate dealers are not canonical at index=%d", i)
		}
	}
	parts := make([][]byte, 0, 4+len(agg.AggregatedCommitments)+len(agg.AggregatedEncryptedShares)+len(dealers))
	parts = append(parts,
		[]byte("bls-pvss-aggregate-v2"),
		encodeInts(dealers),
		g1Bytes(&agg.AggregatedZeta),
	)
	for i := range agg.AggregatedCommitments {
		parts = append(parts, g1Bytes(&agg.AggregatedCommitments[i]))
	}
	for i := range agg.AggregatedEncryptedShares {
		parts = append(parts, g2Bytes(&agg.AggregatedEncryptedShares[i]))
	}
	for _, dealer := range dealers {
		tx := agg.PerDealer[dealer]
		if tx == nil {
			return nil, fmt.Errorf("missing BLS per-dealer transcript for dealer=%d", dealer)
		}
		payload, err := encodeBlsPVSSDealerTranscript(tx)
		if err != nil {
			return nil, fmt.Errorf("encode BLS per-dealer transcript dealer=%d: %w", dealer, err)
		}
		parts = append(parts, hashBytes([]byte("bls-pvss-contribution"), payload))
	}
	return hashBytes(parts...), nil
}

// marshalBlsPVSSDealerTranscript returns a canonical transcript digest for
// legacy descriptor/fingerprint call sites. Wire payloads use
// encodeBlsPVSSDealerTranscript directly.
func marshalBlsPVSSDealerTranscript(tx *BlsPVSSDealerTranscript) []byte {
	payload, err := encodeBlsPVSSDealerTranscript(tx)
	if err != nil {
		return nil
	}
	return hashBytes([]byte("bls-pvss-transcript-digest-v2"), payload)
}

func sortedDealers(m map[int]*BlsPVSSDealerTranscript) []int {
	ids := make([]int, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}
