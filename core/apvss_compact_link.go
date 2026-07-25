package core

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	apvssCompactLinkChallengeDomainV1 = "ARL-APVSS-v1/compact-link/challenge"
	apvssCompactLinkProofDomainV1     = "ARL-APVSS-v1/compact-link/proof"
)

type apvssCompactLinkDigitProofV1 struct {
	commitment  bls12381.G1Affine
	tCommitment bls12381.G1Affine
	tCoin       bls12381.G1Affine
	tCiphertext bls12381.G1Affine
	zDigit      fr.Element
	zCommitment fr.Element
	zCoin       fr.Element
}

type apvssCompactLinkLaneProofV1 struct {
	receiverIndex int
	digits        []apvssCompactLinkDigitProofV1
	tEvaluation   bls12381.G1Affine
	tBlindingCoin bls12381.G1Affine
	tBlinding     bls12381.G1Affine
	zBlinding     fr.Element
	zBlindingCoin fr.Element
}

// apvssCompactLinkProofV1 is only the joint representation/link layer. A
// compact range proof over every digit commitment is still required before
// compact-batch-v1 can be enabled by the APVSS backend gate.
type apvssCompactLinkProofV1 struct {
	lanes []apvssCompactLinkLaneProofV1
}

type apvssCompactLinkDigitMaskV1 struct {
	digit, commitment, coin fr.Element
}

type apvssCompactLinkLaneMaskV1 struct {
	digits                      []apvssCompactLinkDigitMaskV1
	blinding, blindingCoin      fr.Element
	digitValues, commitmentRhos []fr.Element
}

func apvssRandomFrV1() (fr.Element, error) {
	var scalar fr.Element
	if _, err := scalar.SetRandom(); err != nil {
		return fr.Element{}, fmt.Errorf("sample APVSS compact-link randomness: %w", err)
	}
	return scalar, nil
}

func apvssCompactLinkReceiverIndicesV1(proof *apvssCompactLinkProofV1) []int {
	if proof == nil {
		return nil
	}
	indices := make([]int, len(proof.lanes))
	for i := range proof.lanes {
		indices[i] = proof.lanes[i].receiverIndex
	}
	return indices
}

func apvssValidateCompactLinkShapeV1(
	leaf *cvLeafV1,
	proof *apvssCompactLinkProofV1,
) error {
	if leaf == nil || proof == nil || len(proof.lanes) == 0 ||
		len(proof.lanes) > leaf.context.sharingDegree {
		return fmt.Errorf("invalid APVSS compact-link proof shape")
	}
	_, _, chunks, err := cvProfile(leaf.context.profile)
	if err != nil {
		return err
	}
	previous := 0
	for laneIndex := range proof.lanes {
		lane := &proof.lanes[laneIndex]
		if lane.receiverIndex <= previous || lane.receiverIndex <= 0 ||
			lane.receiverIndex > len(leaf.receivers) || len(lane.digits) != chunks {
			return fmt.Errorf("invalid APVSS compact-link lane shape %d", laneIndex)
		}
		for digitIndex := range lane.digits {
			digit := &lane.digits[digitIndex]
			for _, point := range []*bls12381.G1Affine{
				&digit.commitment,
				&digit.tCommitment,
				&digit.tCoin,
				&digit.tCiphertext,
			} {
				if !cvValidG1(point, true) {
					return fmt.Errorf("invalid APVSS compact-link digit point %d/%d", laneIndex, digitIndex)
				}
			}
		}
		for _, point := range []*bls12381.G1Affine{
			&lane.tEvaluation,
			&lane.tBlindingCoin,
			&lane.tBlinding,
		} {
			if !cvValidG1(point, true) {
				return fmt.Errorf("invalid APVSS compact-link lane point %d", laneIndex)
			}
		}
		previous = lane.receiverIndex
	}
	return nil
}

func apvssCompactLinkFirstMoveBytesV1(
	leaf *cvLeafV1,
	proof *apvssCompactLinkProofV1,
) ([]byte, error) {
	if err := apvssValidateCompactLinkShapeV1(leaf, proof); err != nil {
		return nil, err
	}
	statementDigest, err := apvssFallbackSetStatementDigestV1(
		leaf,
		apvssCompactLinkReceiverIndicesV1(proof),
		apvssFallbackCompactBatchProfileV1,
	)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(apvssCompactLinkProofDomainV1)); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, statementDigest); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(proof.lanes)); err != nil {
		return nil, err
	}
	for laneIndex := range proof.lanes {
		lane := &proof.lanes[laneIndex]
		if err := cvWriteUint32(&wire, lane.receiverIndex); err != nil {
			return nil, err
		}
		if err := cvWriteUint32(&wire, len(lane.digits)); err != nil {
			return nil, err
		}
		for digitIndex := range lane.digits {
			digit := &lane.digits[digitIndex]
			for _, point := range []*bls12381.G1Affine{
				&digit.commitment,
				&digit.tCommitment,
				&digit.tCoin,
				&digit.tCiphertext,
			} {
				cvWritePoint(&wire, point)
			}
		}
		cvWritePoint(&wire, &lane.tEvaluation)
		cvWritePoint(&wire, &lane.tBlindingCoin)
		cvWritePoint(&wire, &lane.tBlinding)
	}
	return wire.Bytes(), nil
}

func apvssCompactLinkChallengeV1(
	leaf *cvLeafV1,
	proof *apvssCompactLinkProofV1,
) (fr.Element, error) {
	firstMove, err := apvssCompactLinkFirstMoveBytesV1(leaf, proof)
	if err != nil {
		return fr.Element{}, err
	}
	return cvHashToFrV1(apvssCompactLinkChallengeDomainV1, firstMove)
}

func apvssCompactLinkProofV1CanonicalBytes(
	leaf *cvLeafV1,
	proof *apvssCompactLinkProofV1,
) ([]byte, error) {
	wire, err := apvssCompactLinkFirstMoveBytesV1(leaf, proof)
	if err != nil {
		return nil, err
	}
	buffer := bytes.NewBuffer(append([]byte(nil), wire...))
	for laneIndex := range proof.lanes {
		lane := &proof.lanes[laneIndex]
		for digitIndex := range lane.digits {
			digit := &lane.digits[digitIndex]
			cvWriteScalar(buffer, &digit.zDigit)
			cvWriteScalar(buffer, &digit.zCommitment)
			cvWriteScalar(buffer, &digit.zCoin)
		}
		cvWriteScalar(buffer, &lane.zBlinding)
		cvWriteScalar(buffer, &lane.zBlindingCoin)
	}
	return buffer.Bytes(), nil
}

func apvssProveCompactLinkV1(
	leaf *cvLeafV1,
	witness *apvssDealerWitnessV1,
	receiverIndices []int,
) (*apvssCompactLinkProofV1, error) {
	return apvssProveCompactLinkWithOpeningsV1(leaf, witness, receiverIndices, nil, nil)
}

func apvssProveCompactLinkWithOpeningsV1(
	leaf *cvLeafV1,
	witness *apvssDealerWitnessV1,
	receiverIndices []int,
	digitValues *[]uint64,
	commitmentBlindings *[]fr.Element,
) (*apvssCompactLinkProofV1, error) {
	if leaf == nil || witness == nil || len(receiverIndices) == 0 ||
		len(witness.scalars) != len(leaf.receivers) ||
		len(witness.blindings) != len(leaf.receivers) ||
		len(witness.scalarCoins) != len(leaf.receivers) ||
		len(witness.blindingCoins) != len(leaf.receivers) {
		return nil, fmt.Errorf("invalid APVSS compact-link witness shape")
	}
	if _, err := apvssFallbackSetStatementDigestV1(
		leaf,
		receiverIndices,
		apvssFallbackCompactBatchProfileV1,
	); err != nil {
		return nil, err
	}
	base, _, chunks, err := cvProfile(leaf.context.profile)
	if err != nil {
		return nil, err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	proof := &apvssCompactLinkProofV1{lanes: make([]apvssCompactLinkLaneProofV1, len(receiverIndices))}
	if digitValues != nil {
		*digitValues = (*digitValues)[:0]
	}
	if commitmentBlindings != nil {
		*commitmentBlindings = (*commitmentBlindings)[:0]
	}
	masks := make([]apvssCompactLinkLaneMaskV1, len(receiverIndices))
	for laneIndex, receiverIndex := range receiverIndices {
		witnessIndex := receiverIndex - 1
		if err := apvssValidateFallbackLaneWitnessV1(
			leaf,
			receiverIndex,
			witness.scalars[witnessIndex],
			witness.blindings[witnessIndex],
			witness.scalarCoins[witnessIndex],
			witness.blindingCoins[witnessIndex],
		); err != nil {
			return nil, err
		}
		digits, err := cvScalarDigits(witness.scalars[witnessIndex], leaf.context.profile)
		if err != nil {
			return nil, err
		}
		lane, err := apvssLaneV1(leaf, receiverIndex)
		if err != nil {
			return nil, err
		}
		proofLane := &proof.lanes[laneIndex]
		proofLane.receiverIndex = receiverIndex
		proofLane.digits = make([]apvssCompactLinkDigitProofV1, chunks)
		maskLane := &masks[laneIndex]
		maskLane.digits = make([]apvssCompactLinkDigitMaskV1, chunks)
		maskLane.digitValues = make([]fr.Element, chunks)
		maskLane.commitmentRhos = make([]fr.Element, chunks)

		var evaluationMask, baseScalar fr.Element
		baseScalar.SetUint64(base)
		var power fr.Element
		power.SetOne()
		for chunk := 0; chunk < chunks; chunk++ {
			digitProof := &proofLane.digits[chunk]
			digitMask := &maskLane.digits[chunk]
			maskLane.digitValues[chunk].SetUint64(digits[chunk])
			maskLane.commitmentRhos[chunk], err = apvssRandomFrV1()
			if err != nil {
				return nil, err
			}
			digitMask.digit, err = apvssRandomFrV1()
			if err != nil {
				return nil, err
			}
			digitMask.commitment, err = apvssRandomFrV1()
			if err != nil {
				return nil, err
			}
			digitMask.coin, err = apvssRandomFrV1()
			if err != nil {
				return nil, err
			}

			digitProof.commitment = cvPointSum(
				pointPtr(cvPointTimes(&genG1, &maskLane.digitValues[chunk])),
				pointPtr(cvPointTimes(&h, &maskLane.commitmentRhos[chunk])),
			)
			if digitValues != nil {
				*digitValues = append(*digitValues, digits[chunk])
			}
			if commitmentBlindings != nil {
				*commitmentBlindings = append(*commitmentBlindings, maskLane.commitmentRhos[chunk])
			}
			digitProof.tCommitment = cvPointSum(
				pointPtr(cvPointTimes(&genG1, &digitMask.digit)),
				pointPtr(cvPointTimes(&h, &digitMask.commitment)),
			)
			digitProof.tCoin = cvPointTimes(&genG1, &digitMask.coin)
			digitProof.tCiphertext = cvPointSum(
				pointPtr(cvPointTimes(&genG1, &digitMask.digit)),
				pointPtr(cvPointTimes(&lane.receiverPublicKey, &digitMask.coin)),
			)
			var weightedMask fr.Element
			weightedMask.Mul(&digitMask.digit, &power)
			evaluationMask.Add(&evaluationMask, &weightedMask)
			power.Mul(&power, &baseScalar)
		}
		maskLane.blinding, err = apvssRandomFrV1()
		if err != nil {
			return nil, err
		}
		maskLane.blindingCoin, err = apvssRandomFrV1()
		if err != nil {
			return nil, err
		}
		proofLane.tEvaluation = cvPointSum(
			pointPtr(cvPointTimes(&genG1, &evaluationMask)),
			pointPtr(cvPointTimes(&h, &maskLane.blinding)),
		)
		proofLane.tBlindingCoin = cvPointTimes(&genG1, &maskLane.blindingCoin)
		proofLane.tBlinding = cvPointSum(
			pointPtr(cvPointTimes(&h, &maskLane.blinding)),
			pointPtr(cvPointTimes(&lane.receiverPublicKey, &maskLane.blindingCoin)),
		)
	}

	challenge, err := apvssCompactLinkChallengeV1(leaf, proof)
	if err != nil {
		return nil, err
	}
	for laneIndex, receiverIndex := range receiverIndices {
		witnessIndex := receiverIndex - 1
		proofLane := &proof.lanes[laneIndex]
		maskLane := &masks[laneIndex]
		for chunk := range proofLane.digits {
			digitProof := &proofLane.digits[chunk]
			digitMask := &maskLane.digits[chunk]
			digitProof.zDigit.Mul(&challenge, &maskLane.digitValues[chunk]).Add(
				&digitProof.zDigit,
				&digitMask.digit,
			)
			digitProof.zCommitment.Mul(&challenge, &maskLane.commitmentRhos[chunk]).Add(
				&digitProof.zCommitment,
				&digitMask.commitment,
			)
			digitProof.zCoin.Mul(&challenge, &witness.scalarCoins[witnessIndex][chunk]).Add(
				&digitProof.zCoin,
				&digitMask.coin,
			)
		}
		proofLane.zBlinding.Mul(&challenge, &witness.blindings[witnessIndex]).Add(
			&proofLane.zBlinding,
			&maskLane.blinding,
		)
		proofLane.zBlindingCoin.Mul(&challenge, &witness.blindingCoins[witnessIndex]).Add(
			&proofLane.zBlindingCoin,
			&maskLane.blindingCoin,
		)
	}
	return proof, nil
}

func apvssVerifyCompactLinkV1(leaf *cvLeafV1, proof *apvssCompactLinkProofV1) error {
	if err := apvssValidateCompactLinkShapeV1(leaf, proof); err != nil {
		return err
	}
	challenge, err := apvssCompactLinkChallengeV1(leaf, proof)
	if err != nil {
		return err
	}
	base, _, _, err := cvProfile(leaf.context.profile)
	if err != nil {
		return err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return err
	}
	for laneIndex := range proof.lanes {
		proofLane := &proof.lanes[laneIndex]
		lane, err := apvssLaneV1(leaf, proofLane.receiverIndex)
		if err != nil {
			return err
		}
		var evaluationResponse, baseScalar fr.Element
		baseScalar.SetUint64(base)
		var power fr.Element
		power.SetOne()
		for chunk := range proofLane.digits {
			digit := &proofLane.digits[chunk]
			ciphertext := &lane.encryptedShare.scalarChunks[chunk]
			lhsCommitment := cvPointSum(
				&digit.tCommitment,
				pointPtr(cvPointTimes(&digit.commitment, &challenge)),
			)
			rhsCommitment := cvPointSum(
				pointPtr(cvPointTimes(&genG1, &digit.zDigit)),
				pointPtr(cvPointTimes(&h, &digit.zCommitment)),
			)
			if !lhsCommitment.Equal(&rhsCommitment) {
				return fmt.Errorf("invalid APVSS compact-link digit commitment %d/%d", laneIndex, chunk)
			}
			lhsCoin := cvPointSum(
				&digit.tCoin,
				pointPtr(cvPointTimes(&ciphertext.r, &challenge)),
			)
			rhsCoin := cvPointTimes(&genG1, &digit.zCoin)
			if !lhsCoin.Equal(&rhsCoin) {
				return fmt.Errorf("invalid APVSS compact-link digit coin %d/%d", laneIndex, chunk)
			}
			lhsCiphertext := cvPointSum(
				&digit.tCiphertext,
				pointPtr(cvPointTimes(&ciphertext.c, &challenge)),
			)
			rhsCiphertext := cvPointSum(
				pointPtr(cvPointTimes(&genG1, &digit.zDigit)),
				pointPtr(cvPointTimes(&lane.receiverPublicKey, &digit.zCoin)),
			)
			if !lhsCiphertext.Equal(&rhsCiphertext) {
				return fmt.Errorf("invalid APVSS compact-link digit ciphertext %d/%d", laneIndex, chunk)
			}
			var weightedResponse fr.Element
			weightedResponse.Mul(&digit.zDigit, &power)
			evaluationResponse.Add(&evaluationResponse, &weightedResponse)
			power.Mul(&power, &baseScalar)
		}
		lhsEvaluation := cvPointSum(
			&proofLane.tEvaluation,
			pointPtr(cvPointTimes(&lane.encryptedShare.commitment, &challenge)),
		)
		rhsEvaluation := cvPointSum(
			pointPtr(cvPointTimes(&genG1, &evaluationResponse)),
			pointPtr(cvPointTimes(&h, &proofLane.zBlinding)),
		)
		if !lhsEvaluation.Equal(&rhsEvaluation) {
			return fmt.Errorf("invalid APVSS compact-link Pedersen evaluation %d", laneIndex)
		}
		lhsBlindingCoin := cvPointSum(
			&proofLane.tBlindingCoin,
			pointPtr(cvPointTimes(&lane.encryptedShare.blinding.r, &challenge)),
		)
		rhsBlindingCoin := cvPointTimes(&genG1, &proofLane.zBlindingCoin)
		if !lhsBlindingCoin.Equal(&rhsBlindingCoin) {
			return fmt.Errorf("invalid APVSS compact-link blinding coin %d", laneIndex)
		}
		lhsBlinding := cvPointSum(
			&proofLane.tBlinding,
			pointPtr(cvPointTimes(&lane.encryptedShare.blinding.c, &challenge)),
		)
		rhsBlinding := cvPointSum(
			pointPtr(cvPointTimes(&h, &proofLane.zBlinding)),
			pointPtr(cvPointTimes(&lane.receiverPublicKey, &proofLane.zBlindingCoin)),
		)
		if !lhsBlinding.Equal(&rhsBlinding) {
			return fmt.Errorf("invalid APVSS compact-link blinding ciphertext %d", laneIndex)
		}
	}
	return nil
}

func apvssCompactLinkProofBytesV1(leaf *cvLeafV1, proof *apvssCompactLinkProofV1) (int, error) {
	wire, err := apvssCompactLinkProofV1CanonicalBytes(leaf, proof)
	if err != nil {
		return 0, err
	}
	return len(wire), nil
}

func apvssDecodeCompactLinkProofV1(
	wire []byte,
	leaf *cvLeafV1,
) (*apvssCompactLinkProofV1, error) {
	if leaf == nil || len(wire) == 0 || len(wire) > cvMaxLeafWireBytesV1 {
		return nil, fmt.Errorf("invalid APVSS compact-link wire")
	}
	_, _, chunks, err := cvProfile(leaf.context.profile)
	if err != nil {
		return nil, err
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(apvssCompactLinkProofDomainV1))
	if err != nil || !bytes.Equal(domain, []byte(apvssCompactLinkProofDomainV1)) {
		return nil, fmt.Errorf("invalid APVSS compact-link domain")
	}
	statementDigest, err := r.bytes(32)
	if err != nil || len(statementDigest) != 32 {
		return nil, fmt.Errorf("invalid APVSS compact-link statement digest")
	}
	laneCount, err := r.uint32()
	if err != nil || laneCount <= 0 || laneCount > leaf.context.sharingDegree {
		return nil, fmt.Errorf("invalid APVSS compact-link lane count")
	}
	proof := &apvssCompactLinkProofV1{lanes: make([]apvssCompactLinkLaneProofV1, laneCount)}
	for laneIndex := range proof.lanes {
		lane := &proof.lanes[laneIndex]
		lane.receiverIndex, err = r.uint32()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS compact-link receiver %d: %w", laneIndex, err)
		}
		digitCount, err := r.uint32()
		if err != nil || digitCount != chunks {
			return nil, fmt.Errorf("invalid APVSS compact-link digit count %d", laneIndex)
		}
		lane.digits = make([]apvssCompactLinkDigitProofV1, digitCount)
		for digitIndex := range lane.digits {
			digit := &lane.digits[digitIndex]
			for _, point := range []*bls12381.G1Affine{
				&digit.commitment, &digit.tCommitment, &digit.tCoin, &digit.tCiphertext,
			} {
				*point, err = r.point()
				if err != nil {
					return nil, fmt.Errorf("decode APVSS compact-link digit point %d/%d: %w", laneIndex, digitIndex, err)
				}
			}
		}
		for _, point := range []*bls12381.G1Affine{
			&lane.tEvaluation, &lane.tBlindingCoin, &lane.tBlinding,
		} {
			*point, err = r.point()
			if err != nil {
				return nil, fmt.Errorf("decode APVSS compact-link lane point %d: %w", laneIndex, err)
			}
		}
	}
	for laneIndex := range proof.lanes {
		lane := &proof.lanes[laneIndex]
		for digitIndex := range lane.digits {
			digit := &lane.digits[digitIndex]
			for _, scalar := range []*fr.Element{&digit.zDigit, &digit.zCommitment, &digit.zCoin} {
				*scalar, err = r.scalar()
				if err != nil {
					return nil, fmt.Errorf("decode APVSS compact-link digit scalar %d/%d: %w", laneIndex, digitIndex, err)
				}
			}
		}
		lane.zBlinding, err = r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS compact-link blinding %d: %w", laneIndex, err)
		}
		lane.zBlindingCoin, err = r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS compact-link blinding coin %d: %w", laneIndex, err)
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing APVSS compact-link bytes")
	}
	expectedStatement, err := apvssFallbackSetStatementDigestV1(
		leaf,
		apvssCompactLinkReceiverIndicesV1(proof),
		apvssFallbackCompactBatchProfileV1,
	)
	if err != nil || !bytes.Equal(statementDigest, expectedStatement) {
		return nil, fmt.Errorf("APVSS compact-link statement mismatch")
	}
	canonical, err := apvssCompactLinkProofV1CanonicalBytes(leaf, proof)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical APVSS compact-link proof")
	}
	if err := apvssVerifyCompactLinkV1(leaf, proof); err != nil {
		return nil, err
	}
	return proof, nil
}
