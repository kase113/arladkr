package core

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvFallbackLinkWireDomainV2      = "ARL-CV-sAPVSS/v2/fallback-link"
	cvFallbackLinkChallengeDomainV2 = "ARL-CV-sAPVSS/v2/fallback-link/challenge"
)

type cvFallbackLinkProofV2 struct {
	DigitCommitments        []bls12381.G1Affine
	DigitOpeningCommitments []bls12381.G1Affine
	CoinCommitments         []bls12381.G1Affine
	CipherCommitments       []bls12381.G1Affine
	EvaluationCommitments   []bls12381.G1Affine
	DigitResponses          []fr.Element
	BlindingResponses       []fr.Element
	CoinResponses           []fr.Element
}

// cvFallbackDigitWitnessV2 stays local. A future range prover consumes these
// blindings together with the dealer digits to prove the public commitments.
type cvFallbackDigitWitnessV2 struct {
	Blindings []fr.Element
}

func cvProveFallbackLinkV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, witnesses []*cvDealerReceiverWitnessV2,
) (*cvFallbackLinkProofV2, *cvFallbackDigitWitnessV2, error) {
	chunks, total, err := cvValidateFallbackLinkStatementV2(context, dealerID, offers, receiverPublicKeys)
	if err != nil || len(witnesses) != len(offers) {
		return nil, nil, fmt.Errorf("invalid CV V2 fallback-link witness")
	}
	proof := &cvFallbackLinkProofV2{
		DigitCommitments: make([]bls12381.G1Affine, total), DigitOpeningCommitments: make([]bls12381.G1Affine, total),
		CoinCommitments: make([]bls12381.G1Affine, total), CipherCommitments: make([]bls12381.G1Affine, total),
		EvaluationCommitments: make([]bls12381.G1Affine, len(offers)), DigitResponses: make([]fr.Element, total),
		BlindingResponses: make([]fr.Element, total), CoinResponses: make([]fr.Element, total),
	}
	local := &cvFallbackDigitWitnessV2{Blindings: make([]fr.Element, total)}
	digitNonces := make([]fr.Element, total)
	blindingNonces := make([]fr.Element, total)
	coinNonces := make([]fr.Element, total)
	h, err := cvPedersenBase()
	if err != nil {
		return nil, nil, err
	}
	bases := [2]bls12381.G1Affine{genG1, h}
	base, _, _, err := cvProfile(context.Profile)
	if err != nil {
		return nil, nil, err
	}
	for receiver := range offers {
		witness := witnesses[receiver]
		if witness == nil {
			return nil, nil, fmt.Errorf("nil CV V2 fallback-link witness")
		}
		for lane := 0; lane < 2; lane++ {
			if len(witness.Digits[lane]) != chunks || len(witness.Coins[lane]) != chunks {
				return nil, nil, fmt.Errorf("invalid CV V2 fallback-link witness dimensions")
			}
			for chunk := 0; chunk < chunks; chunk++ {
				position := cvFallbackLinkPositionV2(receiver, lane, chunk, chunks)
				if _, err := local.Blindings[position].SetRandom(); err != nil {
					return nil, nil, err
				}
				if _, err := digitNonces[position].SetRandom(); err != nil {
					return nil, nil, err
				}
				if _, err := blindingNonces[position].SetRandom(); err != nil {
					return nil, nil, err
				}
				if _, err := coinNonces[position].SetRandom(); err != nil {
					return nil, nil, err
				}
				var digit fr.Element
				digit.SetUint64(witness.Digits[lane][chunk])
				proof.DigitCommitments[position] = cvPointSum(
					pointPtr(cvPointTimes(&genG1, &digit)), pointPtr(cvPointTimes(&h, &local.Blindings[position])),
				)
				proof.DigitOpeningCommitments[position] = cvPointSum(
					pointPtr(cvPointTimes(&genG1, &digitNonces[position])),
					pointPtr(cvPointTimes(&h, &blindingNonces[position])),
				)
				proof.CoinCommitments[position] = cvPointTimes(&genG1, &coinNonces[position])
				proof.CipherCommitments[position] = cvPointSum(
					pointPtr(cvPointTimes(&receiverPublicKeys[receiver], &coinNonces[position])),
					pointPtr(cvPointTimes(&bases[lane], &digitNonces[position])),
				)
			}
		}
		proof.EvaluationCommitments[receiver] = cvFallbackEvaluationNonceV2(
			receiver, chunks, base, digitNonces, &h,
		)
	}
	challenge, err := cvFallbackLinkChallengeV2(context, dealerID, offers, receiverPublicKeys, proof)
	if err != nil {
		return nil, nil, err
	}
	for receiver := range offers {
		for lane := 0; lane < 2; lane++ {
			for chunk := 0; chunk < chunks; chunk++ {
				position := cvFallbackLinkPositionV2(receiver, lane, chunk, chunks)
				var digit fr.Element
				digit.SetUint64(witnesses[receiver].Digits[lane][chunk])
				proof.DigitResponses[position].Mul(&challenge, &digit).Add(&proof.DigitResponses[position], &digitNonces[position])
				proof.BlindingResponses[position].Mul(&challenge, &local.Blindings[position]).Add(&proof.BlindingResponses[position], &blindingNonces[position])
				proof.CoinResponses[position].Mul(&challenge, &witnesses[receiver].Coins[lane][chunk]).Add(&proof.CoinResponses[position], &coinNonces[position])
			}
		}
	}
	if err := cvVerifyFallbackLinkV2(context, dealerID, offers, receiverPublicKeys, proof); err != nil {
		return nil, nil, err
	}
	return proof, local, nil
}

func cvVerifyFallbackLinkV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, proof *cvFallbackLinkProofV2,
) error {
	chunks, total, err := cvValidateFallbackLinkStatementV2(context, dealerID, offers, receiverPublicKeys)
	if err != nil || !cvValidFallbackLinkProofShapeV2(proof, total, len(offers)) {
		return fmt.Errorf("invalid CV V2 fallback-link proof")
	}
	challenge, err := cvFallbackLinkChallengeV2(context, dealerID, offers, receiverPublicKeys, proof)
	if err != nil {
		return err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return err
	}
	bases := [2]bls12381.G1Affine{genG1, h}
	base, _, _, err := cvProfile(context.Profile)
	if err != nil {
		return err
	}
	var baseScalar fr.Element
	baseScalar.SetUint64(base)
	powers := cvFrPowers(baseScalar, chunks)
	for receiver := range offers {
		var evaluationLeft bls12381.G1Affine
		for lane := 0; lane < 2; lane++ {
			for chunk := 0; chunk < chunks; chunk++ {
				position := cvFallbackLinkPositionV2(receiver, lane, chunk, chunks)
				ciphertext := &offers[receiver].Lanes[lane].Chunks[chunk]
				left := cvPointSum(
					pointPtr(cvPointTimes(&genG1, &proof.DigitResponses[position])),
					pointPtr(cvPointTimes(&h, &proof.BlindingResponses[position])),
				)
				right := cvPointSum(&proof.DigitOpeningCommitments[position],
					pointPtr(cvPointTimes(&proof.DigitCommitments[position], &challenge)))
				if !left.Equal(&right) {
					return fmt.Errorf("invalid CV V2 fallback digit-commitment equation")
				}
				left = cvPointTimes(&genG1, &proof.CoinResponses[position])
				right = cvPointSum(&proof.CoinCommitments[position], pointPtr(cvPointTimes(&ciphertext.r, &challenge)))
				if !left.Equal(&right) {
					return fmt.Errorf("invalid CV V2 fallback coin equation")
				}
				left = cvPointSum(
					pointPtr(cvPointTimes(&receiverPublicKeys[receiver], &proof.CoinResponses[position])),
					pointPtr(cvPointTimes(&bases[lane], &proof.DigitResponses[position])),
				)
				right = cvPointSum(&proof.CipherCommitments[position], pointPtr(cvPointTimes(&ciphertext.c, &challenge)))
				if !left.Equal(&right) {
					return fmt.Errorf("invalid CV V2 fallback ciphertext equation")
				}
				weightedResponse := proof.DigitResponses[position]
				weightedResponse.Mul(&weightedResponse, &powers[chunk])
				evaluationLeft.Add(&evaluationLeft, pointPtr(cvPointTimes(&bases[lane], &weightedResponse)))
			}
		}
		evaluationRight := cvPointSum(&proof.EvaluationCommitments[receiver],
			pointPtr(cvPointTimes(&offers[receiver].Evaluation, &challenge)))
		if !evaluationLeft.Equal(&evaluationRight) {
			return fmt.Errorf("invalid CV V2 fallback evaluation equation")
		}
	}
	return nil
}

func cvFallbackLinkChallengeV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, proof *cvFallbackLinkProofV2,
) (fr.Element, error) {
	_, total, err := cvValidateFallbackLinkStatementV2(context, dealerID, offers, receiverPublicKeys)
	if err != nil || !cvValidFallbackLinkProofShapeV2(proof, total, len(offers)) {
		return fr.Element{}, fmt.Errorf("invalid CV V2 fallback-link challenge")
	}
	contextWire, err := cvLeafContextV2CanonicalBytes(context)
	if err != nil {
		return fr.Element{}, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, contextWire)
	cvWriteUint64(&wire, uint64(dealerID))
	_ = cvWriteUint32(&wire, len(offers))
	for i, offer := range offers {
		cvWriteUint64(&wire, uint64(offer.ReceiverID))
		cvWriteUint64(&wire, uint64(offer.ReceiverIndex))
		cvWritePoint(&wire, &receiverPublicKeys[i])
		cvWritePoint(&wire, &offer.Evaluation)
		for lane := 0; lane < 2; lane++ {
			for chunk := range offer.Lanes[lane].Chunks {
				cvWriteCiphertext(&wire, &offer.Lanes[lane].Chunks[chunk])
			}
		}
	}
	for _, points := range [][]bls12381.G1Affine{
		proof.DigitCommitments, proof.DigitOpeningCommitments, proof.CoinCommitments,
		proof.CipherCommitments, proof.EvaluationCommitments,
	} {
		if err := cvWritePointVector(&wire, points); err != nil {
			return fr.Element{}, err
		}
	}
	return cvHashToFr(cvFallbackLinkChallengeDomainV2, wire.Bytes())
}

func cvValidateFallbackLinkStatementV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine,
) (int, int, error) {
	if err := cvValidateLeafContextV2(context); err != nil || dealerID < 0 ||
		!cvMemberInRosterV2(dealerID, context.OldRoster) ||
		len(offers) == 0 || len(offers) != len(receiverPublicKeys) ||
		len(offers) > cvNewFaultBoundFromContextV2(context) {
		return 0, 0, fmt.Errorf("invalid CV V2 fallback-link statement")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return 0, 0, err
	}
	previous := 0
	for i, offer := range offers {
		if offer == nil || offer.ReceiverIndex <= previous ||
			cvValidateLaneOfferShapeV2(context, offer, &receiverPublicKeys[i]) != nil {
			return 0, 0, fmt.Errorf("invalid CV V2 fallback-link receiver order")
		}
		previous = offer.ReceiverIndex
	}
	return chunks, len(offers) * 2 * chunks, nil
}

func cvFallbackEvaluationNonceV2(
	receiver, chunks int, base uint64, digitNonces []fr.Element, h *bls12381.G1Affine,
) bls12381.G1Affine {
	var baseScalar fr.Element
	baseScalar.SetUint64(base)
	powers := cvFrPowers(baseScalar, chunks)
	bases := [2]*bls12381.G1Affine{&genG1, h}
	var result bls12381.G1Affine
	for lane := 0; lane < 2; lane++ {
		for chunk := 0; chunk < chunks; chunk++ {
			position := cvFallbackLinkPositionV2(receiver, lane, chunk, chunks)
			weighted := digitNonces[position]
			weighted.Mul(&weighted, &powers[chunk])
			result.Add(&result, pointPtr(cvPointTimes(bases[lane], &weighted)))
		}
	}
	return result
}

func cvFallbackLinkPositionV2(receiver, lane, chunk, chunks int) int {
	return receiver*2*chunks + lane*chunks + chunk
}

func cvValidFallbackLinkProofShapeV2(proof *cvFallbackLinkProofV2, total, receivers int) bool {
	if proof == nil || total <= 0 || len(proof.DigitCommitments) != total ||
		len(proof.DigitOpeningCommitments) != total || len(proof.CoinCommitments) != total ||
		len(proof.CipherCommitments) != total || len(proof.EvaluationCommitments) != receivers ||
		len(proof.DigitResponses) != total || len(proof.BlindingResponses) != total || len(proof.CoinResponses) != total {
		return false
	}
	for _, points := range [][]bls12381.G1Affine{
		proof.DigitCommitments, proof.DigitOpeningCommitments, proof.CoinCommitments,
		proof.CipherCommitments, proof.EvaluationCommitments,
	} {
		for i := range points {
			if !cvValidG1(&points[i], true) {
				return false
			}
		}
	}
	return true
}

func cvFallbackLinkProofV2CanonicalBytes(proof *cvFallbackLinkProofV2, context *cvLeafContextV2, fallbackCount int) ([]byte, error) {
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	total := fallbackCount * 2 * chunks
	if fallbackCount <= 0 || !cvValidFallbackLinkProofShapeV2(proof, total, fallbackCount) {
		return nil, fmt.Errorf("invalid CV V2 fallback-link wire")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvFallbackLinkWireDomainV2))
	for _, points := range [][]bls12381.G1Affine{
		proof.DigitCommitments, proof.DigitOpeningCommitments, proof.CoinCommitments,
		proof.CipherCommitments, proof.EvaluationCommitments,
	} {
		if err := cvWritePointVector(&wire, points); err != nil {
			return nil, err
		}
	}
	for _, scalars := range [][]fr.Element{proof.DigitResponses, proof.BlindingResponses, proof.CoinResponses} {
		if err := cvWriteScalarVector(&wire, scalars); err != nil {
			return nil, err
		}
	}
	return wire.Bytes(), nil
}

func cvDecodeFallbackLinkProofV2(wire []byte, context *cvLeafContextV2, fallbackCount int) (*cvFallbackLinkProofV2, error) {
	chunks, err := cvChunkCount(context.Profile)
	if err != nil || fallbackCount <= 0 || fallbackCount > cvNewFaultBoundFromContextV2(context) {
		return nil, fmt.Errorf("invalid CV V2 fallback-link decode parameters")
	}
	total := fallbackCount * 2 * chunks
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvFallbackLinkWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvFallbackLinkWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 fallback-link domain")
	}
	pointCounts := []int{total, total, total, total, fallbackCount}
	pointVectors := make([][]bls12381.G1Affine, len(pointCounts))
	for i, count := range pointCounts {
		pointVectors[i], err = cvReadExactPointVector(r, count, "V2 fallback-link points")
		if err != nil {
			return nil, err
		}
	}
	scalarVectors := make([][]fr.Element, 3)
	for i := range scalarVectors {
		scalarVectors[i], err = cvReadExactScalarVectorV2(r, total)
		if err != nil {
			return nil, err
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV V2 fallback-link bytes")
	}
	proof := &cvFallbackLinkProofV2{
		DigitCommitments: pointVectors[0], DigitOpeningCommitments: pointVectors[1], CoinCommitments: pointVectors[2],
		CipherCommitments: pointVectors[3], EvaluationCommitments: pointVectors[4], DigitResponses: scalarVectors[0],
		BlindingResponses: scalarVectors[1], CoinResponses: scalarVectors[2],
	}
	canonical, err := cvFallbackLinkProofV2CanonicalBytes(proof, context, fallbackCount)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 fallback-link proof")
	}
	return proof, nil
}
