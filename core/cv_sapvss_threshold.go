package core

import (
	"fmt"
	"math/big"
	"sort"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func cvCreateLocalDecryptionOutputs(
	context *cvLeafContext,
	agg *cvAggregateTranscript,
	receiverOrder []int,
	localSecrets map[int]fr.Element,
) (map[int][]byte, map[int][]byte, error) {
	indices, err := cvReceiverIndices(context, receiverOrder)
	if err != nil {
		return nil, nil, err
	}
	if err := cvCheckAggregateDigest(agg); err != nil {
		return nil, nil, err
	}
	shares := make(map[int][]byte, len(localSecrets))
	receipts := make(map[int][]byte, len(localSecrets))
	for receiverID, secret := range localSecrets {
		index, ok := indices[receiverID]
		if !ok {
			return nil, nil, fmt.Errorf("local CV-sAPVSS receiver %d is outside the roster", receiverID)
		}
		decrypted, receipt, err := cvDecShare(agg, secret, index)
		if err != nil {
			return nil, nil, err
		}
		if err := cvVerifyShare(context, agg, index, receipt); err != nil {
			return nil, nil, err
		}
		encodedShare := decrypted.scalar.Bytes()
		shares[receiverID] = append([]byte(nil), encodedShare[:]...)
		receiptWire, err := cvReceiptCanonicalBytes(receipt)
		if err != nil {
			return nil, nil, err
		}
		receipts[receiverID] = receiptWire
	}
	return shares, receipts, nil
}

func cvThresholdPublicKeyFromReceipts(
	context *cvLeafContext,
	agg *cvAggregateTranscript,
	receiverOrder []int,
	receiptWires map[int][]byte,
) ([]byte, error) {
	indices, err := cvReceiverIndices(context, receiverOrder)
	if err != nil {
		return nil, err
	}
	if err := cvCheckAggregateDigest(agg); err != nil {
		return nil, err
	}
	threshold := context.sharingDegree + 1
	if threshold <= 0 || len(receiptWires) < threshold {
		return nil, fmt.Errorf("insufficient CV-sAPVSS public receipts: have=%d need=%d", len(receiptWires), threshold)
	}
	type verifiedReceipt struct {
		index   int
		receipt *cvReceipt
	}
	verified := make([]verifiedReceipt, 0, len(receiptWires))
	for receiverID, wire := range receiptWires {
		index, ok := indices[receiverID]
		if !ok {
			return nil, fmt.Errorf("CV-sAPVSS receipt receiver %d is outside the roster", receiverID)
		}
		receipt, err := cvDecodeReceipt(wire, context, agg, index)
		if err != nil {
			return nil, err
		}
		verified = append(verified, verifiedReceipt{index: index, receipt: receipt})
	}
	sort.Slice(verified, func(i, j int) bool { return verified[i].index < verified[j].index })
	indicesAtZero := make([]int, len(verified))
	publicShares := make([]bls12381.G1Affine, len(verified))
	blindingShares := make([]bls12381.G1Affine, len(verified))
	for i := range verified {
		indicesAtZero[i] = verified[i].index
		publicShares[i] = verified[i].receipt.publicScalar
		blindingShares[i] = verified[i].receipt.blindingOpening
	}
	publicKey, err := cvInterpolateG1AtZero(indicesAtZero, publicShares)
	if err != nil {
		return nil, err
	}
	blindingConstant, err := cvInterpolateG1AtZero(indicesAtZero, blindingShares)
	if err != nil {
		return nil, err
	}
	var commitment bls12381.G1Affine
	commitment.Add(&publicKey, &blindingConstant)
	if len(agg.coefficientCommitments) == 0 || !commitment.Equal(&agg.coefficientCommitments[0]) {
		return nil, fmt.Errorf("CV-sAPVSS receipt interpolation does not match aggregate commitment")
	}
	if publicKey.IsInfinity() {
		return nil, fmt.Errorf("CV-sAPVSS threshold public key is identity")
	}
	encoded := publicKey.Bytes()
	return append([]byte(nil), encoded[:]...), nil
}

func cvReceiverIndices(context *cvLeafContext, receiverOrder []int) (map[int]int, error) {
	if err := cvValidateLeafContext(context); err != nil {
		return nil, err
	}
	if len(receiverOrder) != len(context.receiverPublicKeys) {
		return nil, fmt.Errorf("CV-sAPVSS receiver roster length mismatch")
	}
	indices := make(map[int]int, len(receiverOrder))
	for i, receiverID := range receiverOrder {
		if _, duplicate := indices[receiverID]; duplicate {
			return nil, fmt.Errorf("duplicate CV-sAPVSS receiver ID: %d", receiverID)
		}
		indices[receiverID] = i + 1
	}
	return indices, nil
}

func cvInterpolateG1AtZero(indices []int, points []bls12381.G1Affine) (bls12381.G1Affine, error) {
	if len(indices) == 0 || len(indices) != len(points) {
		return bls12381.G1Affine{}, fmt.Errorf("invalid CV-sAPVSS interpolation input")
	}
	seen := make(map[int]struct{}, len(indices))
	var result bls12381.G1Affine
	result.ScalarMultiplication(&genG1, big.NewInt(0))
	for i, xI := range indices {
		if xI <= 0 {
			return bls12381.G1Affine{}, fmt.Errorf("invalid CV-sAPVSS interpolation index")
		}
		if _, duplicate := seen[xI]; duplicate {
			return bls12381.G1Affine{}, fmt.Errorf("duplicate CV-sAPVSS interpolation index")
		}
		seen[xI] = struct{}{}
		var coefficient fr.Element
		coefficient.SetOne()
		for j, xJ := range indices {
			if i == j {
				continue
			}
			var numerator, denominator fr.Element
			numerator.SetInt64(int64(xJ))
			denominator.SetInt64(int64(xJ - xI))
			if denominator.IsZero() {
				return bls12381.G1Affine{}, fmt.Errorf("duplicate CV-sAPVSS interpolation index")
			}
			denominator.Inverse(&denominator)
			numerator.Mul(&numerator, &denominator)
			coefficient.Mul(&coefficient, &numerator)
		}
		var term bls12381.G1Affine
		term.ScalarMultiplication(&points[i], coefficient.BigInt(new(big.Int)))
		result.Add(&result, &term)
	}
	return result, nil
}
