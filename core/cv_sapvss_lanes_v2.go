package core

import (
	"bytes"
	"fmt"
	"math"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const cvOwnershipProofChallengeV2 = "ARL-CV-sAPVSS/v2/ownership-proof/challenge"

type cvCipherLaneV2 struct {
	Chunks []cvElGamalCiphertext
}

type cvOwnershipProofV2 struct {
	CoinCommitments   []bls12381.G1Affine
	CipherCommitments []bls12381.G1Affine
	CoinResponses     []fr.Element
	DigitResponses    []fr.Element
}

type cvReceiverLaneOfferV2 struct {
	ReceiverID    int
	ReceiverIndex int
	Evaluation    bls12381.G1Affine
	Lanes         [2]cvCipherLaneV2
	Ownership     cvOwnershipProofV2
}

type cvDealerReceiverWitnessV2 struct {
	Digits [2][]uint64
	Coins  [2][]fr.Element
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
	blindingDigits, err := cvScalarDigits(blinding, context.Profile)
	if err != nil {
		return nil, nil, err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return nil, nil, err
	}
	bases := [2]bls12381.G1Affine{genG1, h}
	offer := &cvReceiverLaneOfferV2{ReceiverID: receiverID, ReceiverIndex: receiverIndex}
	witness := &cvDealerReceiverWitnessV2{}
	witness.Digits[0] = scalarDigits
	witness.Digits[1] = blindingDigits
	for lane := 0; lane < 2; lane++ {
		witness.Coins[lane] = make([]fr.Element, len(witness.Digits[lane]))
		offer.Lanes[lane].Chunks = make([]cvElGamalCiphertext, len(witness.Digits[lane]))
		for chunk, digit := range witness.Digits[lane] {
			if _, err := witness.Coins[lane][chunk].SetRandom(); err != nil {
				return nil, nil, err
			}
			var digitPoint bls12381.G1Affine
			digitPoint.ScalarMultiplication(&bases[lane], new(big.Int).SetUint64(digit))
			ciphertext, err := cvEncryptPoint(receiverPublicKey, &digitPoint, witness.Coins[lane][chunk])
			if err != nil {
				return nil, nil, err
			}
			offer.Lanes[lane].Chunks[chunk] = ciphertext
		}
	}
	offer.Evaluation = cvPointSum(
		pointPtr(cvPointTimes(&genG1, &scalar)),
		pointPtr(cvPointTimes(&h, &blinding)),
	)
	ownership, err := cvProveOwnershipV2(context, dealerID, offer, receiverPublicKey, witness)
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
	if context == nil || cvValidateLaneOfferShapeV2(context, offer, receiverPublicKey) != nil || witness == nil {
		return nil, fmt.Errorf("invalid CV V2 ownership witness")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	total := 2 * chunks
	proof := &cvOwnershipProofV2{
		CoinCommitments: make([]bls12381.G1Affine, total), CipherCommitments: make([]bls12381.G1Affine, total),
		CoinResponses: make([]fr.Element, total), DigitResponses: make([]fr.Element, total),
	}
	coinNonces := make([]fr.Element, total)
	digitNonces := make([]fr.Element, total)
	h, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	bases := [2]bls12381.G1Affine{genG1, h}
	for lane := 0; lane < 2; lane++ {
		if len(witness.Digits[lane]) != chunks || len(witness.Coins[lane]) != chunks {
			return nil, fmt.Errorf("invalid CV V2 ownership witness dimensions")
		}
		for chunk := 0; chunk < chunks; chunk++ {
			position := lane*chunks + chunk
			if _, err := coinNonces[position].SetRandom(); err != nil {
				return nil, err
			}
			if _, err := digitNonces[position].SetRandom(); err != nil {
				return nil, err
			}
			proof.CoinCommitments[position] = cvPointTimes(&genG1, &coinNonces[position])
			proof.CipherCommitments[position] = cvPointSum(
				pointPtr(cvPointTimes(receiverPublicKey, &coinNonces[position])),
				pointPtr(cvPointTimes(&bases[lane], &digitNonces[position])),
			)
		}
	}
	challenge, err := cvOwnershipChallengeScalarV2(context, dealerID, offer, receiverPublicKey, proof)
	if err != nil {
		return nil, err
	}
	for lane := 0; lane < 2; lane++ {
		for chunk := 0; chunk < chunks; chunk++ {
			position := lane*chunks + chunk
			var digit fr.Element
			digit.SetUint64(witness.Digits[lane][chunk])
			proof.CoinResponses[position].Mul(&challenge, &witness.Coins[lane][chunk]).
				Add(&proof.CoinResponses[position], &coinNonces[position])
			proof.DigitResponses[position].Mul(&challenge, &digit).
				Add(&proof.DigitResponses[position], &digitNonces[position])
		}
	}
	return proof, nil
}

func cvVerifyOwnershipV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine,
) error {
	if dealerID < 0 {
		return fmt.Errorf("invalid CV V2 ownership dealer")
	}
	if context == nil || cvValidateLaneOfferShapeV2(context, offer, receiverPublicKey) != nil {
		return fmt.Errorf("invalid CV V2 ownership statement")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return err
	}
	proof := &offer.Ownership
	total := 2 * chunks
	if len(proof.CoinCommitments) != total || len(proof.CipherCommitments) != total ||
		len(proof.CoinResponses) != total || len(proof.DigitResponses) != total {
		return fmt.Errorf("invalid CV V2 ownership proof dimensions")
	}
	for i := 0; i < total; i++ {
		if !cvValidG1(&proof.CoinCommitments[i], true) || !cvValidG1(&proof.CipherCommitments[i], true) {
			return fmt.Errorf("invalid CV V2 ownership proof point")
		}
	}
	challenge, err := cvOwnershipChallengeScalarV2(context, dealerID, offer, receiverPublicKey, proof)
	if err != nil {
		return err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return err
	}
	bases := [2]bls12381.G1Affine{genG1, h}
	for lane := 0; lane < 2; lane++ {
		for chunk := 0; chunk < chunks; chunk++ {
			position := lane*chunks + chunk
			ciphertext := &offer.Lanes[lane].Chunks[chunk]
			leftCoin := cvPointTimes(&genG1, &proof.CoinResponses[position])
			rightCoin := cvPointSum(&proof.CoinCommitments[position],
				pointPtr(cvPointTimes(&ciphertext.r, &challenge)))
			if !leftCoin.Equal(&rightCoin) {
				return fmt.Errorf("invalid CV V2 ownership coin equation")
			}
			leftCipher := cvPointSum(
				pointPtr(cvPointTimes(receiverPublicKey, &proof.CoinResponses[position])),
				pointPtr(cvPointTimes(&bases[lane], &proof.DigitResponses[position])),
			)
			rightCipher := cvPointSum(&proof.CipherCommitments[position],
				pointPtr(cvPointTimes(&ciphertext.c, &challenge)))
			if !leftCipher.Equal(&rightCipher) {
				return fmt.Errorf("invalid CV V2 ownership ciphertext equation")
			}
		}
	}
	return nil
}

func cvVerifyAndDecryptReceiverLanesV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element,
) (fr.Element, fr.Element, error) {
	// Ownership is intentionally verified before the receiver secret is used.
	if err := cvVerifyOwnershipV2(context, dealerID, offer, receiverPublicKey); err != nil {
		return fr.Element{}, fr.Element{}, err
	}
	expectedPublic, err := cvReceiverPublicKey(receiverSecret)
	if err != nil || !expectedPublic.Equal(receiverPublicKey) {
		return fr.Element{}, fr.Element{}, fmt.Errorf("CV V2 receiver secret does not match registry key")
	}
	base, _, chunks, err := cvProfile(context.Profile)
	if err != nil {
		return fr.Element{}, fr.Element{}, err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return fr.Element{}, fr.Element{}, err
	}
	bases := [2]bls12381.G1Affine{genG1, h}
	var recovered [2]fr.Element
	for lane := 0; lane < 2; lane++ {
		digits := make([]uint64, chunks)
		solver := cvNewBoundedDLogSolverForBaseV2(&bases[lane], base-1)
		for chunk := 0; chunk < chunks; chunk++ {
			ciphertext := &offer.Lanes[lane].Chunks[chunk]
			var shared, plaintext bls12381.G1Affine
			shared.ScalarMultiplication(&ciphertext.r, receiverSecret.BigInt(new(big.Int)))
			plaintext.Sub(&ciphertext.c, &shared)
			digit, ok := solver.solve(&plaintext)
			if !ok {
				return fr.Element{}, fr.Element{}, fmt.Errorf("CV V2 lane %d chunk %d digit is out of range", lane, chunk)
			}
			digits[chunk] = digit
		}
		recovered[lane], err = cvDigitsToScalarV2(digits, context.Profile.chunkBits)
		if err != nil {
			return fr.Element{}, fr.Element{}, err
		}
	}
	evaluation := cvPointSum(
		pointPtr(cvPointTimes(&genG1, &recovered[0])),
		pointPtr(cvPointTimes(&h, &recovered[1])),
	)
	if !evaluation.Equal(&offer.Evaluation) {
		return fr.Element{}, fr.Element{}, fmt.Errorf("CV V2 decrypted lanes do not open receiver evaluation")
	}
	return recovered[0], recovered[1], nil
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
	for lane := 0; lane < 2; lane++ {
		if len(offer.Lanes[lane].Chunks) != chunks {
			return fmt.Errorf("invalid CV V2 receiver lane chunk count")
		}
		for chunk := range offer.Lanes[lane].Chunks {
			if !cvValidCiphertext(&offer.Lanes[lane].Chunks[chunk]) {
				return fmt.Errorf("invalid CV V2 receiver ciphertext")
			}
		}
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
	for lane := 0; lane < 2; lane++ {
		for chunk := range offer.Lanes[lane].Chunks {
			cvWriteCiphertext(&wire, &offer.Lanes[lane].Chunks[chunk])
		}
	}
	if err := cvWritePointVector(&wire, proof.CoinCommitments); err != nil {
		return fr.Element{}, err
	}
	if err := cvWritePointVector(&wire, proof.CipherCommitments); err != nil {
		return fr.Element{}, err
	}
	return cvHashToFr(cvOwnershipProofChallengeV2, wire.Bytes())
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
