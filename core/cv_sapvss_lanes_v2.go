package core

import (
	"bytes"
	"fmt"
	"math"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const cvOwnershipProofChallengeV2 = "ARL-CV-sAPVSS/v2-scalar-group/ownership-proof/challenge"

type cvOwnershipProofV2 struct {
	ScalarCoinCommitments    []bls12381.G1Affine
	ScalarCipherCommitments  []bls12381.G1Affine
	BlindingCoinCommitment   bls12381.G1Affine
	BlindingCipherCommitment bls12381.G1Affine
	EvaluationCommitment     bls12381.G1Affine
	ScalarCoinResponses      []fr.Element
	ScalarDigitResponses     []fr.Element
	BlindingCoinResponse     fr.Element
	BlindingShareResponse    fr.Element
}

type cvReceiverLaneOfferV2 struct {
	ReceiverID    int
	ReceiverIndex int
	Evaluation    bls12381.G1Affine
	ScalarChunks  []cvElGamalCiphertext
	Blinding      cvElGamalCiphertext
	Ownership     cvOwnershipProofV2
}

type cvDealerReceiverWitnessV2 struct {
	ScalarDigits []uint64
	ScalarCoins  []fr.Element
	Blinding     fr.Element
	BlindingCoin fr.Element
}

func cvEncryptReceiverLanesV2(
	context *cvLeafContextV2, dealerID, receiverID, receiverIndex int,
	receiverPublicKey *bls12381.G1Affine, scalar, blinding fr.Element,
) (*cvReceiverLaneOfferV2, *cvDealerReceiverWitnessV2, error) {
	if err := cvValidateReceiverBindingV2(context, receiverID, receiverIndex, receiverPublicKey); err != nil ||
		dealerID < 0 {
		return nil, nil, fmt.Errorf("invalid CV V2 receiver lane input")
	}
	scalarDigits, err := cvScalarDigits(scalar, context.Profile)
	if err != nil {
		return nil, nil, err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return nil, nil, err
	}
	offer := &cvReceiverLaneOfferV2{
		ReceiverID: receiverID, ReceiverIndex: receiverIndex,
		ScalarChunks: make([]cvElGamalCiphertext, len(scalarDigits)),
	}
	witness := &cvDealerReceiverWitnessV2{
		ScalarDigits: scalarDigits, ScalarCoins: make([]fr.Element, len(scalarDigits)), Blinding: blinding,
	}
	for chunk, digit := range witness.ScalarDigits {
		if _, err := witness.ScalarCoins[chunk].SetRandom(); err != nil {
			return nil, nil, err
		}
		var digitPoint bls12381.G1Affine
		digitPoint.ScalarMultiplication(&genG1, new(big.Int).SetUint64(digit))
		offer.ScalarChunks[chunk] = cvEncryptPointAfterValidationV2(
			receiverPublicKey, &digitPoint, witness.ScalarCoins[chunk],
		)
	}
	if _, err := witness.BlindingCoin.SetRandom(); err != nil {
		return nil, nil, err
	}
	blindingPoint := cvPointTimes(&h, &blinding)
	offer.Blinding = cvEncryptPointAfterValidationV2(receiverPublicKey, &blindingPoint, witness.BlindingCoin)
	offer.Evaluation = cvPointBaseAndTimes(&scalar, &h, &blinding)
	ownership, err := cvProveOwnershipAfterEncryptionV2(context, dealerID, offer, receiverPublicKey, witness)
	if err != nil {
		return nil, nil, err
	}
	offer.Ownership = *ownership
	return offer, witness, nil
}

func cvProveOwnershipV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, witness *cvDealerReceiverWitnessV2,
) (*cvOwnershipProofV2, error) {
	return cvProveOwnershipModeV2(context, dealerID, offer, receiverPublicKey, witness, true)
}

func cvProveOwnershipAfterEncryptionV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, witness *cvDealerReceiverWitnessV2,
) (*cvOwnershipProofV2, error) {
	return cvProveOwnershipModeV2(context, dealerID, offer, receiverPublicKey, witness, false)
}

func cvProveOwnershipModeV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, witness *cvDealerReceiverWitnessV2, validateLane bool,
) (*cvOwnershipProofV2, error) {
	var shapeErr error
	if validateLane {
		shapeErr = cvValidateLaneOfferShapeV2(context, offer, receiverPublicKey)
	} else {
		shapeErr = cvValidateLaneOfferShapeAfterPointDecodingV2(context, offer, receiverPublicKey)
	}
	if context == nil || shapeErr != nil || witness == nil {
		return nil, fmt.Errorf("invalid CV V2 ownership witness")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	proof := &cvOwnershipProofV2{
		ScalarCoinCommitments:   make([]bls12381.G1Affine, chunks),
		ScalarCipherCommitments: make([]bls12381.G1Affine, chunks),
		ScalarCoinResponses:     make([]fr.Element, chunks), ScalarDigitResponses: make([]fr.Element, chunks),
	}
	coinNonces := make([]fr.Element, chunks)
	digitNonces := make([]fr.Element, chunks)
	var blindingCoinNonce, blindingShareNonce fr.Element
	h, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	if len(witness.ScalarDigits) != chunks || len(witness.ScalarCoins) != chunks {
		return nil, fmt.Errorf("invalid CV V2 ownership witness dimensions")
	}
	for chunk := 0; chunk < chunks; chunk++ {
		if _, err := coinNonces[chunk].SetRandom(); err != nil {
			return nil, err
		}
		if _, err := digitNonces[chunk].SetRandom(); err != nil {
			return nil, err
		}
		proof.ScalarCoinCommitments[chunk] = cvPointTimes(&genG1, &coinNonces[chunk])
		proof.ScalarCipherCommitments[chunk] = cvPointBaseAndTimes(
			&digitNonces[chunk], receiverPublicKey, &coinNonces[chunk],
		)
	}
	if _, err := blindingCoinNonce.SetRandom(); err != nil {
		return nil, err
	}
	if _, err := blindingShareNonce.SetRandom(); err != nil {
		return nil, err
	}
	proof.BlindingCoinCommitment = cvPointTimes(&genG1, &blindingCoinNonce)
	proof.BlindingCipherCommitment = cvPointJointTimes(
		receiverPublicKey, &blindingCoinNonce, &h, &blindingShareNonce,
	)
	weightedDigitNonce, err := cvWeightedScalarV2(digitNonces, context.Profile.chunkBits)
	if err != nil {
		return nil, err
	}
	proof.EvaluationCommitment = cvPointBaseAndTimes(&weightedDigitNonce, &h, &blindingShareNonce)
	challenge, err := cvOwnershipChallengeScalarAfterValidationV2(
		context, dealerID, offer, receiverPublicKey, proof,
	)
	if err != nil {
		return nil, err
	}
	for chunk := 0; chunk < chunks; chunk++ {
		var digit fr.Element
		digit.SetUint64(witness.ScalarDigits[chunk])
		proof.ScalarCoinResponses[chunk].Mul(&challenge, &witness.ScalarCoins[chunk]).
			Add(&proof.ScalarCoinResponses[chunk], &coinNonces[chunk])
		proof.ScalarDigitResponses[chunk].Mul(&challenge, &digit).
			Add(&proof.ScalarDigitResponses[chunk], &digitNonces[chunk])
	}
	proof.BlindingCoinResponse.Mul(&challenge, &witness.BlindingCoin).
		Add(&proof.BlindingCoinResponse, &blindingCoinNonce)
	proof.BlindingShareResponse.Mul(&challenge, &witness.Blinding).
		Add(&proof.BlindingShareResponse, &blindingShareNonce)
	return proof, nil
}

func cvEncryptPointAfterValidationV2(
	receiverPublicKey, message *bls12381.G1Affine, coin fr.Element,
) cvElGamalCiphertext {
	var coinInt big.Int
	coin.BigInt(&coinInt)
	var ciphertext cvElGamalCiphertext
	ciphertext.r.ScalarMultiplication(&genG1, &coinInt)
	var shared bls12381.G1Affine
	shared.ScalarMultiplication(receiverPublicKey, &coinInt)
	ciphertext.c.Add(&shared, message)
	return ciphertext
}

func cvVerifyOwnershipV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine,
) error {
	return cvVerifyOwnershipModeV2(context, dealerID, offer, receiverPublicKey, true)
}

func cvVerifyOwnershipAfterPointDecodingV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine,
) error {
	return cvVerifyOwnershipModeV2(context, dealerID, offer, receiverPublicKey, false)
}

func cvVerifyOwnershipModeV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, validatePoints bool,
) error {
	if dealerID < 0 {
		return fmt.Errorf("invalid CV V2 ownership dealer")
	}
	var shapeErr error
	if validatePoints {
		shapeErr = cvValidateLaneOfferShapeV2(context, offer, receiverPublicKey)
	} else {
		shapeErr = cvValidateLaneOfferShapeAfterPointDecodingV2(context, offer, receiverPublicKey)
	}
	if context == nil || shapeErr != nil {
		return fmt.Errorf("invalid CV V2 ownership statement")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return err
	}
	proof := &offer.Ownership
	if len(proof.ScalarCoinCommitments) != chunks || len(proof.ScalarCipherCommitments) != chunks ||
		len(proof.ScalarCoinResponses) != chunks || len(proof.ScalarDigitResponses) != chunks {
		return fmt.Errorf("invalid CV V2 ownership proof dimensions")
	}
	if validatePoints {
		for i := 0; i < chunks; i++ {
			if !cvValidG1(&proof.ScalarCoinCommitments[i], true) ||
				!cvValidG1(&proof.ScalarCipherCommitments[i], true) {
				return fmt.Errorf("invalid CV V2 ownership proof point")
			}
		}
		if !cvValidG1(&proof.BlindingCoinCommitment, true) ||
			!cvValidG1(&proof.BlindingCipherCommitment, true) ||
			!cvValidG1(&proof.EvaluationCommitment, true) {
			return fmt.Errorf("invalid CV V2 ownership proof point")
		}
	}
	challenge, err := cvOwnershipChallengeScalarAfterValidationV2(
		context, dealerID, offer, receiverPublicKey, proof,
	)
	if err != nil {
		return err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return err
	}
	for chunk := 0; chunk < chunks; chunk++ {
		ciphertext := &offer.ScalarChunks[chunk]
		leftCoin := cvPointTimes(&genG1, &proof.ScalarCoinResponses[chunk])
		rightCoin := cvPointSum(&proof.ScalarCoinCommitments[chunk],
			pointPtr(cvPointTimes(&ciphertext.r, &challenge)))
		if !leftCoin.Equal(&rightCoin) {
			return fmt.Errorf("invalid CV V2 ownership scalar coin equation")
		}
		leftCipher := cvPointBaseAndTimes(
			&proof.ScalarDigitResponses[chunk], receiverPublicKey, &proof.ScalarCoinResponses[chunk],
		)
		rightCipher := cvPointSum(&proof.ScalarCipherCommitments[chunk],
			pointPtr(cvPointTimes(&ciphertext.c, &challenge)))
		if !leftCipher.Equal(&rightCipher) {
			return fmt.Errorf("invalid CV V2 ownership scalar ciphertext equation")
		}
	}
	leftBlindingCoin := cvPointTimes(&genG1, &proof.BlindingCoinResponse)
	rightBlindingCoin := cvPointSum(&proof.BlindingCoinCommitment,
		pointPtr(cvPointTimes(&offer.Blinding.r, &challenge)))
	if !leftBlindingCoin.Equal(&rightBlindingCoin) {
		return fmt.Errorf("invalid CV V2 ownership blinding coin equation")
	}
	leftBlindingCipher := cvPointJointTimes(
		receiverPublicKey, &proof.BlindingCoinResponse, &h, &proof.BlindingShareResponse,
	)
	rightBlindingCipher := cvPointSum(&proof.BlindingCipherCommitment,
		pointPtr(cvPointTimes(&offer.Blinding.c, &challenge)))
	if !leftBlindingCipher.Equal(&rightBlindingCipher) {
		return fmt.Errorf("invalid CV V2 ownership blinding ciphertext equation")
	}
	weightedResponse, err := cvWeightedScalarV2(proof.ScalarDigitResponses, context.Profile.chunkBits)
	if err != nil {
		return err
	}
	leftEvaluation := cvPointBaseAndTimes(&weightedResponse, &h, &proof.BlindingShareResponse)
	rightEvaluation := cvPointSum(&proof.EvaluationCommitment,
		pointPtr(cvPointTimes(&offer.Evaluation, &challenge)))
	if !leftEvaluation.Equal(&rightEvaluation) {
		return fmt.Errorf("invalid CV V2 ownership evaluation equation")
	}
	return nil
}

func cvVerifyAndDecryptReceiverLanesV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element,
) (fr.Element, bls12381.G1Affine, error) {
	return cvVerifyAndDecryptReceiverLanesModeV2(
		context, dealerID, offer, receiverPublicKey, receiverSecret, true,
	)
}

func cvVerifyAndDecryptReceiverLanesAfterPointDecodingV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element,
) (fr.Element, bls12381.G1Affine, error) {
	return cvVerifyAndDecryptReceiverLanesModeV2(
		context, dealerID, offer, receiverPublicKey, receiverSecret, false,
	)
}

func cvVerifyAndDecryptReceiverLanesModeV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element, validatePoints bool,
) (fr.Element, bls12381.G1Affine, error) {
	// Ownership is intentionally verified before the receiver secret is used.
	var ownershipErr error
	if validatePoints {
		ownershipErr = cvVerifyOwnershipV2(context, dealerID, offer, receiverPublicKey)
	} else {
		ownershipErr = cvVerifyOwnershipAfterPointDecodingV2(context, dealerID, offer, receiverPublicKey)
	}
	if ownershipErr != nil {
		return fr.Element{}, bls12381.G1Affine{}, ownershipErr
	}
	expectedPublic, err := cvReceiverPublicKey(receiverSecret)
	if err != nil || !expectedPublic.Equal(receiverPublicKey) {
		return fr.Element{}, bls12381.G1Affine{}, fmt.Errorf("CV V2 receiver secret does not match registry key")
	}
	base, _, chunks, err := cvProfile(context.Profile)
	if err != nil {
		return fr.Element{}, bls12381.G1Affine{}, err
	}
	digits := make([]uint64, chunks)
	solver := cvNewBoundedDLogSolverForBaseV2(&genG1, base-1)
	for chunk := 0; chunk < chunks; chunk++ {
		plaintext := cvDecryptGroupCiphertextV2(&offer.ScalarChunks[chunk], receiverSecret)
		digit, ok := solver.solve(&plaintext)
		if !ok {
			return fr.Element{}, bls12381.G1Affine{}, fmt.Errorf("CV V2 scalar chunk %d digit is out of range", chunk)
		}
		digits[chunk] = digit
	}
	scalar, err := cvDigitsToScalarV2(digits, context.Profile.chunkBits)
	if err != nil {
		return fr.Element{}, bls12381.G1Affine{}, err
	}
	blindingOpening := cvDecryptGroupCiphertextV2(&offer.Blinding, receiverSecret)
	evaluation := cvPointSum(pointPtr(cvPointTimes(&genG1, &scalar)), &blindingOpening)
	if !evaluation.Equal(&offer.Evaluation) {
		return fr.Element{}, bls12381.G1Affine{}, fmt.Errorf("CV V2 decrypted ciphertexts do not open receiver evaluation")
	}
	return scalar, blindingOpening, nil
}

func cvDecryptGroupCiphertextV2(ciphertext *cvElGamalCiphertext, secret fr.Element) bls12381.G1Affine {
	var shared, plaintext bls12381.G1Affine
	shared.ScalarMultiplication(&ciphertext.r, secret.BigInt(new(big.Int)))
	plaintext.Sub(&ciphertext.c, &shared)
	return plaintext
}

func cvValidateReceiverBindingV2(
	context *cvLeafContextV2, receiverID, receiverIndex int, receiverPublicKey *bls12381.G1Affine,
) error {
	if err := cvValidateLeafContextV2(context); err != nil || receiverIndex <= 0 ||
		receiverIndex > len(context.NewRoster) || context.NewRoster[receiverIndex-1] != receiverID ||
		!cvValidG1(receiverPublicKey, false) {
		return fmt.Errorf("invalid CV V2 receiver binding")
	}
	return nil
}

func cvValidateLaneOfferShapeV2(
	context *cvLeafContextV2, offer *cvReceiverLaneOfferV2, receiverPublicKey *bls12381.G1Affine,
) error {
	if offer == nil || cvValidateReceiverBindingV2(context, offer.ReceiverID, offer.ReceiverIndex, receiverPublicKey) != nil ||
		!cvValidG1(&offer.Evaluation, true) {
		return fmt.Errorf("invalid CV V2 receiver lane offer")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return err
	}
	if len(offer.ScalarChunks) != chunks || !cvValidCiphertext(&offer.Blinding) {
		return fmt.Errorf("invalid CV V2 receiver ciphertext shape")
	}
	for chunk := range offer.ScalarChunks {
		if !cvValidCiphertext(&offer.ScalarChunks[chunk]) {
			return fmt.Errorf("invalid CV V2 receiver scalar ciphertext")
		}
	}
	return nil
}

func cvValidateLaneOfferShapeAfterPointDecodingV2(
	context *cvLeafContextV2, offer *cvReceiverLaneOfferV2, receiverPublicKey *bls12381.G1Affine,
) error {
	if err := cvValidateLeafContextV2(context); err != nil || offer == nil || receiverPublicKey == nil ||
		offer.ReceiverIndex <= 0 || offer.ReceiverIndex > len(context.NewRoster) ||
		context.NewRoster[offer.ReceiverIndex-1] != offer.ReceiverID {
		return fmt.Errorf("invalid decoded CV V2 receiver lane offer")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil || len(offer.ScalarChunks) != chunks {
		return fmt.Errorf("invalid decoded CV V2 receiver ciphertext dimensions")
	}
	return nil
}

func cvOwnershipChallengeScalarV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, proof *cvOwnershipProofV2,
) (fr.Element, error) {
	if dealerID < 0 || proof == nil || cvValidateLaneOfferShapeV2(context, offer, receiverPublicKey) != nil {
		return fr.Element{}, fmt.Errorf("invalid CV V2 ownership challenge")
	}
	return cvOwnershipChallengeScalarModeV2(context, dealerID, offer, receiverPublicKey, proof, true)
}

func cvOwnershipChallengeScalarAfterValidationV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, proof *cvOwnershipProofV2,
) (fr.Element, error) {
	if context == nil || dealerID < 0 || offer == nil || receiverPublicKey == nil || proof == nil {
		return fr.Element{}, fmt.Errorf("invalid verified CV V2 ownership challenge")
	}
	return cvOwnershipChallengeScalarModeV2(context, dealerID, offer, receiverPublicKey, proof, false)
}

func cvOwnershipChallengeScalarModeV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, proof *cvOwnershipProofV2, validateProofPoints bool,
) (fr.Element, error) {
	contextDigest, err := cvLeafContextDigestV2(context)
	if err != nil {
		return fr.Element{}, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, contextDigest)
	cvWriteUint64(&wire, uint64(dealerID))
	cvWriteUint64(&wire, uint64(offer.ReceiverID))
	cvWriteUint64(&wire, uint64(offer.ReceiverIndex))
	_ = cvWriteBytes(&wire, context.ReceiverRegistryDigest)
	cvWritePoint(&wire, receiverPublicKey)
	cvWritePoint(&wire, &offer.Evaluation)
	if err := cvWriteUint32(&wire, len(offer.ScalarChunks)); err != nil {
		return fr.Element{}, err
	}
	for chunk := range offer.ScalarChunks {
		cvWriteCiphertext(&wire, &offer.ScalarChunks[chunk])
	}
	cvWriteCiphertext(&wire, &offer.Blinding)
	if err := cvWritePointVectorMode(&wire, proof.ScalarCoinCommitments, validateProofPoints); err != nil {
		return fr.Element{}, err
	}
	if err := cvWritePointVectorMode(&wire, proof.ScalarCipherCommitments, validateProofPoints); err != nil {
		return fr.Element{}, err
	}
	cvWritePoint(&wire, &proof.BlindingCoinCommitment)
	cvWritePoint(&wire, &proof.BlindingCipherCommitment)
	cvWritePoint(&wire, &proof.EvaluationCommitment)
	return cvHashToFr(cvOwnershipProofChallengeV2, wire.Bytes())
}

func cvWeightedScalarV2(values []fr.Element, chunkBits uint) (fr.Element, error) {
	if len(values) == 0 || chunkBits == 0 || chunkBits > cvMaxChunkBits {
		return fr.Element{}, fmt.Errorf("invalid CV V2 weighted scalar input")
	}
	var base fr.Element
	base.SetUint64(uint64(1) << chunkBits)
	powers := cvFrPowers(base, len(values))
	var result fr.Element
	for i := range values {
		var term fr.Element
		term.Mul(&values[i], &powers[i])
		result.Add(&result, &term)
	}
	return result, nil
}

type cvBoundedDLogSolverV2 struct {
	bound         uint64
	width         uint64
	babies        map[[bls12381.SizeOfG1AffineCompressed]byte]uint64
	negativeGiant bls12381.G1Affine
}

func cvNewBoundedDLogSolverForBaseV2(base *bls12381.G1Affine, bound uint64) *cvBoundedDLogSolverV2 {
	rangeSize := bound + 1
	width := uint64(math.Ceil(math.Sqrt(float64(rangeSize))))
	for width*width < rangeSize {
		width++
	}
	solver := &cvBoundedDLogSolverV2{
		bound: bound, width: width,
		babies: make(map[[bls12381.SizeOfG1AffineCompressed]byte]uint64, width),
	}
	var current bls12381.G1Affine
	current.ScalarMultiplication(base, big.NewInt(0))
	for j := uint64(0); j < width; j++ {
		solver.babies[cvPointKey(&current)] = j
		current.Add(&current, base)
	}
	var giantStep bls12381.G1Affine
	giantStep.ScalarMultiplication(base, new(big.Int).SetUint64(width))
	solver.negativeGiant.Neg(&giantStep)
	return solver
}

func (solver *cvBoundedDLogSolverV2) solve(target *bls12381.G1Affine) (uint64, bool) {
	if solver == nil || !cvValidG1(target, true) {
		return 0, false
	}
	var candidate bls12381.G1Affine
	candidate.Set(target)
	for i := uint64(0); i <= solver.width; i++ {
		if j, ok := solver.babies[cvPointKey(&candidate)]; ok {
			value := i*solver.width + j
			if value <= solver.bound {
				return value, true
			}
		}
		candidate.Add(&candidate, &solver.negativeGiant)
	}
	return 0, false
}

func cvDigitsToScalarV2(digits []uint64, chunkBits uint) (fr.Element, error) {
	if len(digits) == 0 || chunkBits == 0 || chunkBits > cvMaxChunkBits {
		return fr.Element{}, fmt.Errorf("invalid CV V2 digit reconstruction")
	}
	value := new(big.Int)
	for index, digit := range digits {
		if digit >= uint64(1)<<chunkBits {
			return fr.Element{}, fmt.Errorf("CV V2 digit exceeds chunk base")
		}
		term := new(big.Int).SetUint64(digit)
		term.Lsh(term, uint(index)*chunkBits)
		value.Add(value, term)
	}
	if value.Cmp(fr.Modulus()) >= 0 {
		return fr.Element{}, fmt.Errorf("CV V2 reconstructed scalar is non-canonical")
	}
	var scalar fr.Element
	scalar.SetBigInt(value)
	return scalar, nil
}
