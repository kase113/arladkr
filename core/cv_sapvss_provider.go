package core

import (
	"bytes"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvAggregateDomain = "ARL-CV-sAPVSS/aggregate"
	cvReceiptDomain   = "ARL-CV-sAPVSS/receipt"
	cvDLEQDomain      = "ARL-CV-sAPVSS/receipt-dleq"
)

type cvAggregateReceiver struct {
	receiverIndex     int
	receiverPublicKey bls12381.G1Affine
	scalarChunks      []cvElGamalCiphertext
	blinding          cvElGamalCiphertext
}

type cvAggregateTranscript struct {
	context                cvLeafContext
	dealerIDs              []uint64
	leafDigests            [][]byte
	coefficientCommitments []bls12381.G1Affine
	receivers              []cvAggregateReceiver
	digestWire             []byte
	digest                 []byte
}

// cvVerifiedLeaf carries the canonical bytes that were accepted by a full
// leaf verification. Callers must recheck those bytes before using the leaf so
// a mutable in-memory object cannot inherit stale verified status.
type cvVerifiedLeaf struct {
	leaf          *cvLeaf
	apvss         *apvssLeafPrototype
	contextDigest []byte
	leafDigest    []byte
	canonicalWire []byte
}

func cvAcceptedAPVSSLeaf(
	context *cvLeafContext,
	prototype *apvssLeafPrototype,
	canonicalWire []byte,
) (*cvVerifiedLeaf, error) {
	if err := apvssVerifyPrototype(context, prototype); err != nil {
		return nil, err
	}
	return cvAcceptedDecodedAPVSSLeaf(context, prototype, canonicalWire)
}

// cvAcceptedDecodedAPVSSLeaf wraps a prototype returned by
// apvssDecodeLeafPrototype. That decoder has already verified both the
// structural leaf and its ACK/fallback partition.
func cvAcceptedDecodedAPVSSLeaf(
	context *cvLeafContext,
	prototype *apvssLeafPrototype,
	canonicalWire []byte,
) (*cvVerifiedLeaf, error) {
	if err := cvValidateLeafContext(context); err != nil {
		return nil, err
	}
	if prototype == nil || prototype.leaf == nil ||
		!bytes.Equal(cvLeafContextDigest(context), cvLeafContextDigest(&prototype.leaf.context)) {
		return nil, fmt.Errorf("accepted APVSS leaf context mismatch")
	}
	wire, err := apvssLeafPrototypeCanonicalBytes(prototype)
	if err != nil {
		return nil, err
	}
	if len(canonicalWire) > 0 && !bytes.Equal(wire, canonicalWire) {
		return nil, fmt.Errorf("accepted APVSS leaf wire mismatch")
	}
	digest := hashBytes([]byte(apvssLeafDigestDomain), wire)
	if len(prototype.digest) > 0 && !bytes.Equal(prototype.digest, digest) {
		return nil, fmt.Errorf("accepted APVSS leaf digest mismatch")
	}
	prototype.digest = append([]byte(nil), digest...)
	return &cvVerifiedLeaf{
		leaf: prototype.leaf, apvss: prototype,
		contextDigest: append([]byte(nil), cvLeafContextDigest(context)...),
		leafDigest:    append([]byte(nil), digest...),
		canonicalWire: append([]byte(nil), wire...),
	}, nil
}

type cvMultiDLEQProof struct {
	tKey, tScalar, tBlinding bls12381.G1Affine
	z                        fr.Element
}

type cvReceipt struct {
	aggregateDigest []byte
	receiverIndex   int
	publicScalar    bls12381.G1Affine
	blindingOpening bls12381.G1Affine
	proof           cvMultiDLEQProof
	digestWire      []byte
	digest          []byte
}

func cvAgg(context *cvLeafContext, leaves []*cvLeaf) (*cvAggregateTranscript, error) {
	if cvPerfCountersEnabled {
		cvPerfCounters.aggCalls.Add(1)
	}
	if err := cvValidateLeafContext(context); err != nil {
		return nil, err
	}
	if len(leaves) == 0 || len(leaves) > context.profile.maxComponents {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate component count")
	}
	for _, leaf := range leaves {
		if leaf == nil {
			return nil, fmt.Errorf("nil CV-sAPVSS aggregate leaf")
		}
		if err := cvVerifyLeaf(context, leaf); err != nil {
			return nil, fmt.Errorf("dealer %d leaf: %w", leaf.dealerID, err)
		}
	}
	return cvAggregateAcceptedLeaves(context, leaves)
}

func cvAcceptedLeaf(context *cvLeafContext, leaf *cvLeaf, canonicalWire []byte) (*cvVerifiedLeaf, error) {
	if err := cvValidateLeafContext(context); err != nil {
		return nil, err
	}
	if leaf == nil || len(leaf.digest) != 32 {
		return nil, fmt.Errorf("invalid accepted CV-sAPVSS leaf")
	}
	wire, err := cvLeafCanonicalBytes(leaf)
	if err != nil {
		return nil, err
	}
	if len(canonicalWire) > 0 && !bytes.Equal(wire, canonicalWire) {
		return nil, fmt.Errorf("accepted CV-sAPVSS leaf wire mismatch")
	}
	contextDigest := cvLeafContextDigest(context)
	if !bytes.Equal(contextDigest, cvLeafContextDigest(&leaf.context)) ||
		!bytes.Equal(leaf.digest, hashBytes([]byte(cvLeafDigestDomain), wire)) {
		return nil, fmt.Errorf("accepted CV-sAPVSS leaf binding mismatch")
	}
	return &cvVerifiedLeaf{
		leaf: leaf, contextDigest: append([]byte(nil), contextDigest...),
		leafDigest: append([]byte(nil), leaf.digest...), canonicalWire: append([]byte(nil), wire...),
	}, nil
}

func cvValidateAcceptedLeaf(context *cvLeafContext, accepted *cvVerifiedLeaf) error {
	if accepted == nil || accepted.leaf == nil ||
		!bytes.Equal(accepted.contextDigest, cvLeafContextDigest(context)) {
		return fmt.Errorf("invalid verified CV-sAPVSS leaf token")
	}
	if accepted.apvss != nil {
		if accepted.apvss.leaf != accepted.leaf {
			return fmt.Errorf("invalid verified APVSS leaf token")
		}
		wire, err := apvssLeafPrototypeCanonicalBytes(accepted.apvss)
		if err != nil || !bytes.Equal(wire, accepted.canonicalWire) ||
			!bytes.Equal(accepted.leafDigest, accepted.apvss.digest) ||
			!bytes.Equal(accepted.leafDigest, hashBytes([]byte(apvssLeafDigestDomain), wire)) {
			return fmt.Errorf("mutated verified APVSS leaf")
		}
		return nil
	}
	if !bytes.Equal(accepted.leafDigest, accepted.leaf.digest) {
		return fmt.Errorf("invalid verified CV-sAPVSS leaf token")
	}
	wire, err := cvLeafCanonicalBytes(accepted.leaf)
	if err != nil || !bytes.Equal(wire, accepted.canonicalWire) ||
		!bytes.Equal(accepted.leafDigest, hashBytes([]byte(cvLeafDigestDomain), wire)) {
		return fmt.Errorf("mutated verified CV-sAPVSS leaf")
	}
	return nil
}

func cvAggVerified(context *cvLeafContext, accepted []*cvVerifiedLeaf) (*cvAggregateTranscript, error) {
	if cvPerfCountersEnabled {
		cvPerfCounters.aggVerifiedCalls.Add(1)
	}
	if err := cvValidateLeafContext(context); err != nil {
		return nil, err
	}
	if len(accepted) == 0 || len(accepted) > context.profile.maxComponents {
		return nil, fmt.Errorf("invalid CV-sAPVSS verified aggregate component count")
	}
	leaves := make([]*cvLeaf, len(accepted))
	for i := range accepted {
		if err := cvValidateAcceptedLeaf(context, accepted[i]); err != nil {
			return nil, err
		}
		leaves[i] = accepted[i].leaf
	}
	agg, err := cvAggregateAcceptedLeavesUnfinalized(context, leaves)
	if err != nil {
		return nil, err
	}
	for i := range accepted {
		agg.leafDigests[i] = append([]byte(nil), accepted[i].leafDigest...)
	}
	return cvFinalizeAggregate(agg)
}

func cvAggregateAcceptedLeaves(context *cvLeafContext, leaves []*cvLeaf) (*cvAggregateTranscript, error) {
	agg, err := cvAggregateAcceptedLeavesUnfinalized(context, leaves)
	if err != nil {
		return nil, err
	}
	return cvFinalizeAggregate(agg)
}

func cvAggregateAcceptedLeavesUnfinalized(context *cvLeafContext, leaves []*cvLeaf) (*cvAggregateTranscript, error) {
	agg := &cvAggregateTranscript{
		context:     cvCloneLeafContext(*context),
		dealerIDs:   make([]uint64, len(leaves)),
		leafDigests: make([][]byte, len(leaves)),
		coefficientCommitments: make([]bls12381.G1Affine,
			context.sharingDegree+1),
		receivers: make([]cvAggregateReceiver, len(context.receiverPublicKeys)),
	}
	for i, leaf := range leaves {
		if leaf == nil {
			return nil, fmt.Errorf("nil CV-sAPVSS aggregate leaf")
		}
		if i > 0 && leaf.dealerID <= leaves[i-1].dealerID {
			return nil, fmt.Errorf("CV-sAPVSS aggregate dealer manifest is not ordered and distinct")
		}
		agg.dealerIDs[i] = leaf.dealerID
		agg.leafDigests[i] = append([]byte(nil), leaf.digest...)
		for j := range agg.coefficientCommitments {
			if i == 0 {
				agg.coefficientCommitments[j] = leaf.coefficientCommitments[j]
			} else {
				agg.coefficientCommitments[j].Add(&agg.coefficientCommitments[j], &leaf.coefficientCommitments[j])
			}
		}
	}
	for receiverIndex := range agg.receivers {
		shares := make([]*cvEncryptedShare, len(leaves))
		for dealerIndex := range leaves {
			shares[dealerIndex] = leaves[dealerIndex].receivers[receiverIndex].encryptedShare
		}
		share, err := cvAggregate(context.profile, shares)
		if err != nil {
			return nil, fmt.Errorf("aggregate receiver %d: %w", receiverIndex+1, err)
		}
		agg.receivers[receiverIndex] = cvAggregateReceiver{
			receiverIndex:     receiverIndex + 1,
			receiverPublicKey: share.receiverPublicKey,
			scalarChunks:      share.scalarChunks,
			blinding:          share.blinding,
		}
	}
	return agg, nil
}

func cvFinalizeAggregate(agg *cvAggregateTranscript) (*cvAggregateTranscript, error) {
	wire, err := cvAggregateCanonicalBytes(agg)
	if err != nil {
		return nil, err
	}
	agg.digestWire = append([]byte(nil), wire...)
	agg.digest = hashBytes([]byte(cvAggregateDomain), wire)
	return agg, nil
}

func cvAVer(context *cvLeafContext, agg *cvAggregateTranscript, leaves []*cvLeaf) error {
	if cvPerfCountersEnabled {
		cvPerfCounters.averCalls.Add(1)
	}
	expected, err := cvAgg(context, leaves)
	if err != nil {
		return err
	}
	return cvCompareAggregate(agg, expected)
}

func cvAVerVerified(context *cvLeafContext, agg *cvAggregateTranscript, leaves []*cvVerifiedLeaf) error {
	if cvPerfCountersEnabled {
		cvPerfCounters.averVerifiedCalls.Add(1)
	}
	expected, err := cvAggVerified(context, leaves)
	if err != nil {
		return err
	}
	return cvCompareAggregate(agg, expected)
}

func cvCompareAggregate(agg, expected *cvAggregateTranscript) error {
	gotWire, err := cvAggregateCanonicalBytes(agg)
	if err != nil {
		return err
	}
	if !bytes.Equal(agg.digestWire, gotWire) || !bytes.Equal(gotWire, expected.digestWire) ||
		!bytes.Equal(agg.digest, hashBytes([]byte(cvAggregateDomain), gotWire)) {
		return fmt.Errorf("CV-sAPVSS Aggregate wire or digest mismatch")
	}
	if cvPerfCountersEnabled {
		cvPerfCounters.averSuccesses.Add(1)
	}
	return nil
}

func cvCheckAggregateDigest(agg *cvAggregateTranscript) error {
	wire, err := cvAggregateCanonicalBytes(agg)
	if err != nil {
		return err
	}
	if !bytes.Equal(agg.digestWire, wire) || !bytes.Equal(agg.digest, hashBytes([]byte(cvAggregateDomain), wire)) {
		return fmt.Errorf("CV-sAPVSS Aggregate wire or digest mismatch")
	}
	return nil
}

func cvValidateAggregate(agg *cvAggregateTranscript) error {
	if agg == nil {
		return fmt.Errorf("nil CV-sAPVSS Aggregate")
	}
	if err := cvValidateLeafContext(&agg.context); err != nil {
		return err
	}
	if len(agg.dealerIDs) == 0 || len(agg.dealerIDs) > agg.context.profile.maxComponents ||
		len(agg.leafDigests) != len(agg.dealerIDs) {
		return fmt.Errorf("invalid CV-sAPVSS aggregate dealer manifest")
	}
	for i, dealer := range agg.dealerIDs {
		if i > 0 && dealer <= agg.dealerIDs[i-1] {
			return fmt.Errorf("CV-sAPVSS aggregate dealer manifest is not canonical")
		}
		if len(agg.leafDigests[i]) != 32 {
			return fmt.Errorf("invalid CV-sAPVSS component leaf digest %d", i)
		}
	}
	if len(agg.coefficientCommitments) != agg.context.sharingDegree+1 ||
		len(agg.receivers) != len(agg.context.receiverPublicKeys) {
		return fmt.Errorf("invalid CV-sAPVSS aggregate statement size")
	}
	chunks, err := cvChunkCount(agg.context.profile)
	if err != nil {
		return err
	}
	for i := range agg.coefficientCommitments {
		if !cvValidG1(&agg.coefficientCommitments[i], true) {
			return fmt.Errorf("invalid aggregate coefficient commitment %d", i)
		}
	}
	for i, receiver := range agg.receivers {
		if receiver.receiverIndex != i+1 || !receiver.receiverPublicKey.Equal(&agg.context.receiverPublicKeys[i]) ||
			!cvValidG1(&receiver.receiverPublicKey, false) || len(receiver.scalarChunks) != chunks ||
			!cvValidCiphertext(&receiver.blinding) {
			return fmt.Errorf("invalid aggregate receiver %d", i+1)
		}
		for j := range receiver.scalarChunks {
			if !cvValidCiphertext(&receiver.scalarChunks[j]) {
				return fmt.Errorf("invalid aggregate scalar chunk %d", j)
			}
		}
	}
	return nil
}

func cvAggregateCanonicalBytes(agg *cvAggregateTranscript) ([]byte, error) {
	if err := cvValidateAggregate(agg); err != nil {
		return nil, err
	}
	contextWire, err := cvLeafContextCanonicalBytes(&agg.context)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(cvAggregateDomain)); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, contextWire); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, cvLeafContextDigest(&agg.context)); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(agg.dealerIDs)); err != nil {
		return nil, err
	}
	for i, dealer := range agg.dealerIDs {
		cvWriteUint64(&wire, dealer)
		if err := cvWriteBytes(&wire, agg.leafDigests[i]); err != nil {
			return nil, err
		}
	}
	if err := cvWritePointVector(&wire, agg.coefficientCommitments); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(agg.receivers)); err != nil {
		return nil, err
	}
	for i := range agg.receivers {
		receiver := &agg.receivers[i]
		if err := cvWriteUint32(&wire, receiver.receiverIndex); err != nil {
			return nil, err
		}
		cvWritePoint(&wire, &receiver.receiverPublicKey)
		if err := cvWriteUint32(&wire, len(receiver.scalarChunks)); err != nil {
			return nil, err
		}
		for j := range receiver.scalarChunks {
			cvWriteCiphertext(&wire, &receiver.scalarChunks[j])
		}
		cvWriteCiphertext(&wire, &receiver.blinding)
	}
	return wire.Bytes(), nil
}

func cvAggregateScalarCiphertext(agg *cvAggregateTranscript, receiverIndex int) (cvElGamalCiphertext, error) {
	if err := cvValidateAggregate(agg); err != nil {
		return cvElGamalCiphertext{}, err
	}
	if receiverIndex <= 0 || receiverIndex > len(agg.receivers) {
		return cvElGamalCiphertext{}, fmt.Errorf("invalid CV-sAPVSS aggregate receiver index")
	}
	base, _, chunks, _ := cvProfile(agg.context.profile)
	var baseScalar fr.Element
	baseScalar.SetUint64(base)
	powers := cvFrPowers(baseScalar, chunks)
	receiver := &agg.receivers[receiverIndex-1]
	var result cvElGamalCiphertext
	result.r.ScalarMultiplication(&genG1, big.NewInt(0))
	result.c.ScalarMultiplication(&genG1, big.NewInt(0))
	for i := range receiver.scalarChunks {
		result.r.Add(&result.r, pointPtr(cvPointTimes(&receiver.scalarChunks[i].r, &powers[i])))
		result.c.Add(&result.c, pointPtr(cvPointTimes(&receiver.scalarChunks[i].c, &powers[i])))
	}
	return result, nil
}

func cvDLEQTargets(agg *cvAggregateTranscript, receiverIndex int, publicScalar, blindingOpening *bls12381.G1Affine) (bls12381.G1Affine, bls12381.G1Affine, bls12381.G1Affine, bls12381.G1Affine, error) {
	scalarCipher, err := cvAggregateScalarCiphertext(agg, receiverIndex)
	if err != nil {
		return bls12381.G1Affine{}, bls12381.G1Affine{}, bls12381.G1Affine{}, bls12381.G1Affine{}, err
	}
	receiver := &agg.receivers[receiverIndex-1]
	var scalarTarget, blindingTarget bls12381.G1Affine
	scalarTarget.Sub(&scalarCipher.c, publicScalar)
	blindingTarget.Sub(&receiver.blinding.c, blindingOpening)
	return scalarCipher.r, scalarTarget, receiver.blinding.r, blindingTarget, nil
}

func cvDLEQChallenge(agg *cvAggregateTranscript, receiverIndex int, publicScalar, blindingOpening *bls12381.G1Affine, proof *cvMultiDLEQProof) (fr.Element, error) {
	scalarBase, scalarTarget, blindingBase, blindingTarget, err := cvDLEQTargets(agg, receiverIndex, publicScalar, blindingOpening)
	if err != nil {
		return fr.Element{}, err
	}
	var points bytes.Buffer
	for _, point := range []*bls12381.G1Affine{
		&agg.receivers[receiverIndex-1].receiverPublicKey,
		&scalarBase, &scalarTarget, &blindingBase, &blindingTarget,
		publicScalar, blindingOpening, &proof.tKey, &proof.tScalar, &proof.tBlinding,
	} {
		cvWritePoint(&points, point)
	}
	var indexWire bytes.Buffer
	cvWriteUint64(&indexWire, uint64(receiverIndex))
	return cvHashToFr(cvDLEQDomain, agg.digest, indexWire.Bytes(), points.Bytes())
}

func cvProveDLEQ(agg *cvAggregateTranscript, receiverIndex int, receiverSecret fr.Element, publicScalar, blindingOpening *bls12381.G1Affine) (*cvMultiDLEQProof, error) {
	var nonce fr.Element
	if _, err := nonce.SetRandom(); err != nil {
		return nil, fmt.Errorf("sample CV-sAPVSS receipt nonce: %w", err)
	}
	proof := &cvMultiDLEQProof{tKey: cvPointTimes(&genG1, &nonce)}
	scalarCipher, err := cvAggregateScalarCiphertext(agg, receiverIndex)
	if err != nil {
		return nil, err
	}
	proof.tScalar = cvPointTimes(&scalarCipher.r, &nonce)
	proof.tBlinding = cvPointTimes(&agg.receivers[receiverIndex-1].blinding.r, &nonce)
	challenge, err := cvDLEQChallenge(agg, receiverIndex, publicScalar, blindingOpening, proof)
	if err != nil {
		return nil, err
	}
	proof.z.Mul(&challenge, &receiverSecret).Add(&proof.z, &nonce)
	return proof, nil
}

func cvDecShare(agg *cvAggregateTranscript, receiverSecret fr.Element, receiverIndex int) (*cvDecryptedShare, *cvReceipt, error) {
	if err := cvValidateAggregate(agg); err != nil {
		return nil, nil, err
	}
	if err := cvCheckAggregateDigest(agg); err != nil {
		return nil, nil, err
	}
	if receiverIndex <= 0 || receiverIndex > len(agg.receivers) {
		return nil, nil, fmt.Errorf("invalid CV-sAPVSS aggregate receiver index")
	}
	receiver := &agg.receivers[receiverIndex-1]
	key, err := cvReceiverPublicKey(receiverSecret)
	if err != nil {
		return nil, nil, err
	}
	if !key.Equal(&receiver.receiverPublicKey) {
		return nil, nil, fmt.Errorf("CV-sAPVSS receiver secret does not match aggregate key")
	}
	share := &cvEncryptedShare{
		receiverPublicKey: receiver.receiverPublicKey,
		scalarChunks:      append([]cvElGamalCiphertext(nil), receiver.scalarChunks...),
		blinding:          receiver.blinding,
		commitment:        cvEvaluateCommitments(agg.coefficientCommitments, receiverIndex),
	}
	decrypted, err := cvDecryptShare(agg.context.profile, receiverSecret, share, len(agg.dealerIDs))
	if err != nil {
		return nil, nil, err
	}
	proof, err := cvProveDLEQ(agg, receiverIndex, receiverSecret, &decrypted.publicScalar, &decrypted.blindingOpening)
	if err != nil {
		return nil, nil, err
	}
	receipt := &cvReceipt{
		aggregateDigest: append([]byte(nil), agg.digest...),
		receiverIndex:   receiverIndex,
		publicScalar:    decrypted.publicScalar,
		blindingOpening: decrypted.blindingOpening,
		proof:           *proof,
	}
	wire, err := cvReceiptCanonicalBytes(receipt)
	if err != nil {
		return nil, nil, err
	}
	receipt.digestWire = wire
	receipt.digest = hashBytes([]byte(cvReceiptDomain), wire)
	return decrypted, receipt, nil
}

func cvReceiptCanonicalBytes(receipt *cvReceipt) ([]byte, error) {
	if receipt == nil || len(receipt.aggregateDigest) != 32 || receipt.receiverIndex <= 0 ||
		!cvValidG1(&receipt.publicScalar, true) || !cvValidG1(&receipt.blindingOpening, true) ||
		!cvValidG1(&receipt.proof.tKey, true) || !cvValidG1(&receipt.proof.tScalar, true) ||
		!cvValidG1(&receipt.proof.tBlinding, true) {
		return nil, fmt.Errorf("invalid CV-sAPVSS receipt")
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(cvReceiptDomain)); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, receipt.aggregateDigest); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, receipt.receiverIndex); err != nil {
		return nil, err
	}
	for _, point := range []*bls12381.G1Affine{
		&receipt.publicScalar, &receipt.blindingOpening,
		&receipt.proof.tKey, &receipt.proof.tScalar, &receipt.proof.tBlinding,
	} {
		cvWritePoint(&wire, point)
	}
	cvWriteScalar(&wire, &receipt.proof.z)
	return wire.Bytes(), nil
}

func cvVerifyShare(context *cvLeafContext, agg *cvAggregateTranscript, receiverIndex int, receipt *cvReceipt) error {
	if err := cvValidateLeafContext(context); err != nil {
		return err
	}
	if err := cvValidateAggregate(agg); err != nil {
		return err
	}
	if err := cvCheckAggregateDigest(agg); err != nil {
		return err
	}
	if receiverIndex <= 0 || receiverIndex > len(agg.receivers) {
		return fmt.Errorf("invalid CV-sAPVSS aggregate receiver index")
	}
	contextWire, err := cvLeafContextCanonicalBytes(context)
	if err != nil {
		return err
	}
	aggContextWire, err := cvLeafContextCanonicalBytes(&agg.context)
	if err != nil || !bytes.Equal(contextWire, aggContextWire) {
		return fmt.Errorf("CV-sAPVSS aggregate context mismatch")
	}
	if receipt == nil || receipt.receiverIndex != receiverIndex || !bytes.Equal(receipt.aggregateDigest, agg.digest) {
		return fmt.Errorf("CV-sAPVSS receipt binding mismatch")
	}
	receiptWire, err := cvReceiptCanonicalBytes(receipt)
	if err != nil {
		return err
	}
	if !bytes.Equal(receipt.digest, hashBytes([]byte(cvReceiptDomain), receiptWire)) {
		return fmt.Errorf("CV-sAPVSS receipt digest mismatch")
	}
	key := &agg.receivers[receiverIndex-1].receiverPublicKey
	scalarBase, scalarTarget, blindingBase, blindingTarget, err := cvDLEQTargets(agg, receiverIndex, &receipt.publicScalar, &receipt.blindingOpening)
	if err != nil {
		return err
	}
	challenge, err := cvDLEQChallenge(agg, receiverIndex, &receipt.publicScalar, &receipt.blindingOpening, &receipt.proof)
	if err != nil {
		return err
	}
	left := cvPointTimes(&genG1, &receipt.proof.z)
	right := cvPointSum(&receipt.proof.tKey, pointPtr(cvPointTimes(key, &challenge)))
	if !left.Equal(&right) {
		return fmt.Errorf("CV-sAPVSS receipt key DLEQ failed")
	}
	left = cvPointTimes(&scalarBase, &receipt.proof.z)
	right = cvPointSum(&receipt.proof.tScalar, pointPtr(cvPointTimes(&scalarTarget, &challenge)))
	if !left.Equal(&right) {
		return fmt.Errorf("CV-sAPVSS receipt scalar DLEQ failed")
	}
	left = cvPointTimes(&blindingBase, &receipt.proof.z)
	right = cvPointSum(&receipt.proof.tBlinding, pointPtr(cvPointTimes(&blindingTarget, &challenge)))
	if !left.Equal(&right) {
		return fmt.Errorf("CV-sAPVSS receipt blinding DLEQ failed")
	}
	evaluation := cvEvaluateCommitments(agg.coefficientCommitments, receiverIndex)
	var publicCommitment bls12381.G1Affine
	publicCommitment.Add(&receipt.publicScalar, &receipt.blindingOpening)
	if !publicCommitment.Equal(&evaluation) {
		return fmt.Errorf("CV-sAPVSS receipt evaluation commitment mismatch")
	}
	return nil
}
