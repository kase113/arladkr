package core

import (
	"bytes"
	"fmt"
	"math/big"
	"sort"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvAggregateShareWireDomainV2      = "ARL-CV-sAPVSS/v2/aggregate-share"
	cvAggregateShareChallengeDomainV2 = "ARL-CV-sAPVSS/v2/aggregate-share/challenge"
)

type cvAggregateShareProofV2 struct {
	KeyCommitment     bls12381.G1Affine
	CipherCommitments [2]bls12381.G1Affine
	ShareCommitments  [2]bls12381.G1Affine
	KeyResponse       fr.Element
	ShareResponses    [2]fr.Element
}

type cvScalarShareOutputV2 struct {
	AggregateDigest []byte
	ReceiverID      int
	ReceiverIndex   int
	Y               bls12381.G1Affine
	YBlind          bls12381.G1Affine
	Proof           cvAggregateShareProofV2
}

func cvDecryptAggregateShareV2(
	aggregate *cvAggregateV2, context *cvLeafContextV2, params cvV2Params,
	receiverID, receiverIndex int, receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element,
) (*cvScalarShareOutputV2, error) {
	if err := cvValidateAggregateShareInputsV2(aggregate, context, params, receiverID, receiverIndex, receiverPublicKey); err != nil {
		return nil, err
	}
	wantPublic, err := cvReceiverPublicKey(receiverSecret)
	if err != nil || !wantPublic.Equal(receiverPublicKey) {
		return nil, fmt.Errorf("CV V2 aggregate-share secret does not match receiver key")
	}
	base, digitBound, chunks, err := cvProfile(context.Profile)
	if err != nil {
		return nil, err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	bases := [2]bls12381.G1Affine{genG1, h}
	receiver := &aggregate.Receivers[receiverIndex-1]
	var shares [2]fr.Element
	for lane := 0; lane < 2; lane++ {
		digits := make([]uint64, chunks)
		solver := cvNewBoundedDLogSolverForBaseV2(&bases[lane], digitBound)
		for chunk := 0; chunk < chunks; chunk++ {
			ciphertext := &receiver.Lanes[lane].Chunks[chunk]
			shared := cvPointTimes(&ciphertext.r, &receiverSecret)
			var plaintext bls12381.G1Affine
			plaintext.Sub(&ciphertext.c, &shared)
			digit, ok := solver.solve(&plaintext)
			if !ok {
				return nil, fmt.Errorf("CV V2 aggregate lane %d chunk %d is outside [0,K(B-1)]", lane, chunk)
			}
			digits[chunk] = digit
		}
		shares[lane], err = cvAggregateDigitsToScalarV2(digits, context.Profile.chunkBits, base, digitBound)
		if err != nil {
			return nil, err
		}
	}
	output := &cvScalarShareOutputV2{
		AggregateDigest: append([]byte(nil), aggregate.Digest...), ReceiverID: receiverID, ReceiverIndex: receiverIndex,
		Y: cvPointTimes(&genG1, &shares[0]), YBlind: cvPointTimes(&h, &shares[1]),
	}
	var opened bls12381.G1Affine
	opened.Add(&output.Y, &output.YBlind)
	if !opened.Equal(&receiver.Evaluation) {
		return nil, fmt.Errorf("CV V2 aggregate decrypted shares do not open receiver evaluation")
	}
	proof, err := cvProveAggregateShareV2(aggregate, context, receiverPublicKey, receiverSecret, shares, output)
	if err != nil {
		return nil, err
	}
	output.Proof = *proof
	if err := cvVerifyAggregateShareV2(output, aggregate, context, params, receiverPublicKey); err != nil {
		return nil, err
	}
	return output, nil
}

func cvProveAggregateShareV2(
	aggregate *cvAggregateV2, context *cvLeafContextV2, receiverPublicKey *bls12381.G1Affine,
	receiverSecret fr.Element, shares [2]fr.Element, output *cvScalarShareOutputV2,
) (*cvAggregateShareProofV2, error) {
	weighted, err := cvWeightedAggregateLanesV2(aggregate, context, output.ReceiverIndex)
	if err != nil {
		return nil, err
	}
	h, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	bases := [2]bls12381.G1Affine{genG1, h}
	var keyNonce fr.Element
	if _, err := keyNonce.SetRandom(); err != nil {
		return nil, err
	}
	var shareNonces [2]fr.Element
	proof := &cvAggregateShareProofV2{KeyCommitment: cvPointTimes(&genG1, &keyNonce)}
	for lane := 0; lane < 2; lane++ {
		if _, err := shareNonces[lane].SetRandom(); err != nil {
			return nil, err
		}
		proof.CipherCommitments[lane] = cvPointSum(
			pointPtr(cvPointTimes(&weighted[lane].r, &keyNonce)),
			pointPtr(cvPointTimes(&bases[lane], &shareNonces[lane])),
		)
		proof.ShareCommitments[lane] = cvPointTimes(&bases[lane], &shareNonces[lane])
	}
	challenge, err := cvAggregateShareChallengeV2(aggregate, context, receiverPublicKey, output, proof)
	if err != nil {
		return nil, err
	}
	proof.KeyResponse.Mul(&challenge, &receiverSecret).Add(&proof.KeyResponse, &keyNonce)
	for lane := 0; lane < 2; lane++ {
		proof.ShareResponses[lane].Mul(&challenge, &shares[lane]).Add(&proof.ShareResponses[lane], &shareNonces[lane])
	}
	return proof, nil
}

func cvVerifyAggregateShareV2(
	output *cvScalarShareOutputV2, aggregate *cvAggregateV2, context *cvLeafContextV2,
	params cvV2Params, receiverPublicKey *bls12381.G1Affine,
) error {
	if output == nil || output.ReceiverID < 0 || output.ReceiverIndex <= 0 || len(output.AggregateDigest) != 32 ||
		!bytes.Equal(output.AggregateDigest, aggregate.Digest) ||
		cvValidateAggregateShareInputsV2(aggregate, context, params, output.ReceiverID, output.ReceiverIndex, receiverPublicKey) != nil ||
		!cvValidG1(&output.Y, true) || !cvValidG1(&output.YBlind, true) ||
		!cvValidAggregateShareProofV2(&output.Proof) {
		return fmt.Errorf("invalid CV V2 aggregate-share output")
	}
	receiver := &aggregate.Receivers[output.ReceiverIndex-1]
	var opened bls12381.G1Affine
	opened.Add(&output.Y, &output.YBlind)
	if !opened.Equal(&receiver.Evaluation) {
		return fmt.Errorf("CV V2 aggregate-share opening mismatch")
	}
	weighted, err := cvWeightedAggregateLanesV2(aggregate, context, output.ReceiverIndex)
	if err != nil {
		return err
	}
	challenge, err := cvAggregateShareChallengeV2(aggregate, context, receiverPublicKey, output, &output.Proof)
	if err != nil {
		return err
	}
	left := cvPointTimes(&genG1, &output.Proof.KeyResponse)
	right := cvPointSum(&output.Proof.KeyCommitment, pointPtr(cvPointTimes(receiverPublicKey, &challenge)))
	if !left.Equal(&right) {
		return fmt.Errorf("invalid CV V2 aggregate-share key equation")
	}
	h, err := cvPedersenBase()
	if err != nil {
		return err
	}
	bases := [2]bls12381.G1Affine{genG1, h}
	shares := [2]*bls12381.G1Affine{&output.Y, &output.YBlind}
	for lane := 0; lane < 2; lane++ {
		left = cvPointSum(
			pointPtr(cvPointTimes(&weighted[lane].r, &output.Proof.KeyResponse)),
			pointPtr(cvPointTimes(&bases[lane], &output.Proof.ShareResponses[lane])),
		)
		right = cvPointSum(&output.Proof.CipherCommitments[lane], pointPtr(cvPointTimes(&weighted[lane].c, &challenge)))
		if !left.Equal(&right) {
			return fmt.Errorf("invalid CV V2 aggregate-share ciphertext equation")
		}
		left = cvPointTimes(&bases[lane], &output.Proof.ShareResponses[lane])
		right = cvPointSum(&output.Proof.ShareCommitments[lane], pointPtr(cvPointTimes(shares[lane], &challenge)))
		if !left.Equal(&right) {
			return fmt.Errorf("invalid CV V2 aggregate-share opening equation")
		}
	}
	return nil
}

func cvAggregateShareChallengeV2(
	aggregate *cvAggregateV2, context *cvLeafContextV2, receiverPublicKey *bls12381.G1Affine,
	output *cvScalarShareOutputV2, proof *cvAggregateShareProofV2,
) (fr.Element, error) {
	if aggregate == nil || context == nil || output == nil || proof == nil ||
		output.ReceiverIndex <= 0 || output.ReceiverIndex > len(aggregate.Receivers) ||
		!cvValidG1(receiverPublicKey, false) {
		return fr.Element{}, fmt.Errorf("invalid CV V2 aggregate-share challenge")
	}
	contextWire, err := cvLeafContextV2CanonicalBytes(context)
	if err != nil {
		return fr.Element{}, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, contextWire)
	_ = cvWriteBytes(&wire, aggregate.Digest)
	cvWriteUint64(&wire, uint64(output.ReceiverID))
	cvWriteUint64(&wire, uint64(output.ReceiverIndex))
	cvWritePoint(&wire, receiverPublicKey)
	receiver := &aggregate.Receivers[output.ReceiverIndex-1]
	for lane := 0; lane < 2; lane++ {
		for chunk := range receiver.Lanes[lane].Chunks {
			cvWriteCiphertext(&wire, &receiver.Lanes[lane].Chunks[chunk])
		}
	}
	cvWritePoint(&wire, &output.Y)
	cvWritePoint(&wire, &output.YBlind)
	cvWritePoint(&wire, &proof.KeyCommitment)
	for lane := 0; lane < 2; lane++ {
		cvWritePoint(&wire, &proof.CipherCommitments[lane])
		cvWritePoint(&wire, &proof.ShareCommitments[lane])
	}
	return cvHashToFr(cvAggregateShareChallengeDomainV2, wire.Bytes())
}

func cvWeightedAggregateLanesV2(
	aggregate *cvAggregateV2, context *cvLeafContextV2, receiverIndex int,
) ([2]cvElGamalCiphertext, error) {
	var weighted [2]cvElGamalCiphertext
	if aggregate == nil || context == nil || receiverIndex <= 0 || receiverIndex > len(aggregate.Receivers) {
		return weighted, fmt.Errorf("invalid CV V2 weighted aggregate lane")
	}
	base, _, chunks, err := cvProfile(context.Profile)
	if err != nil {
		return weighted, err
	}
	var baseScalar fr.Element
	baseScalar.SetUint64(base)
	powers := cvFrPowers(baseScalar, chunks)
	receiver := &aggregate.Receivers[receiverIndex-1]
	for lane := 0; lane < 2; lane++ {
		if len(receiver.Lanes[lane].Chunks) != chunks {
			return weighted, fmt.Errorf("invalid CV V2 weighted aggregate lane length")
		}
		for chunk := 0; chunk < chunks; chunk++ {
			weighted[lane].r.Add(&weighted[lane].r,
				pointPtr(cvPointTimes(&receiver.Lanes[lane].Chunks[chunk].r, &powers[chunk])))
			weighted[lane].c.Add(&weighted[lane].c,
				pointPtr(cvPointTimes(&receiver.Lanes[lane].Chunks[chunk].c, &powers[chunk])))
		}
	}
	return weighted, nil
}

func cvAggregateDigitsToScalarV2(digits []uint64, chunkBits uint, base, bound uint64) (fr.Element, error) {
	if len(digits) == 0 || chunkBits == 0 || chunkBits > cvMaxChunkBits || base != uint64(1)<<chunkBits {
		return fr.Element{}, fmt.Errorf("invalid CV V2 aggregate digit reconstruction")
	}
	value := new(big.Int)
	for index, digit := range digits {
		if digit > bound {
			return fr.Element{}, fmt.Errorf("CV V2 aggregate digit exceeds K(B-1)")
		}
		term := new(big.Int).SetUint64(digit)
		term.Lsh(term, uint(index)*chunkBits)
		value.Add(value, term)
	}
	value.Mod(value, fr.Modulus())
	var scalar fr.Element
	scalar.SetBigInt(value)
	return scalar, nil
}

func cvValidateAggregateShareInputsV2(
	aggregate *cvAggregateV2, context *cvLeafContextV2, params cvV2Params,
	receiverID, receiverIndex int, receiverPublicKey *bls12381.G1Affine,
) error {
	if context == nil || params.componentCount <= 0 || context.Profile.maxComponents != params.componentCount ||
		context.SharingDegree != params.newShareDegree || params.newShareThreshold != context.SharingDegree+1 ||
		cvValidateReceiverBindingV2(context, receiverID, receiverIndex, receiverPublicKey) != nil {
		return fmt.Errorf("invalid CV V2 aggregate-share parameters")
	}
	if _, err := cvAggregateV2CanonicalBytes(aggregate, context, params); err != nil {
		return err
	}
	receiver := &aggregate.Receivers[receiverIndex-1]
	if receiver.ReceiverID != receiverID || receiver.ReceiverIndex != receiverIndex {
		return fmt.Errorf("CV V2 aggregate-share receiver mismatch")
	}
	return nil
}

func cvValidAggregateShareProofV2(proof *cvAggregateShareProofV2) bool {
	if proof == nil || !cvValidG1(&proof.KeyCommitment, true) {
		return false
	}
	for lane := 0; lane < 2; lane++ {
		if !cvValidG1(&proof.CipherCommitments[lane], true) || !cvValidG1(&proof.ShareCommitments[lane], true) {
			return false
		}
	}
	return true
}

func cvScalarShareOutputV2CanonicalBytes(output *cvScalarShareOutputV2) ([]byte, error) {
	if output == nil || len(output.AggregateDigest) != 32 || output.ReceiverID < 0 || output.ReceiverIndex <= 0 ||
		!cvValidG1(&output.Y, true) || !cvValidG1(&output.YBlind, true) || !cvValidAggregateShareProofV2(&output.Proof) {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share wire")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAggregateShareWireDomainV2))
	_ = cvWriteBytes(&wire, output.AggregateDigest)
	cvWriteUint64(&wire, uint64(output.ReceiverID))
	cvWriteUint64(&wire, uint64(output.ReceiverIndex))
	cvWritePoint(&wire, &output.Y)
	cvWritePoint(&wire, &output.YBlind)
	cvWritePoint(&wire, &output.Proof.KeyCommitment)
	for lane := 0; lane < 2; lane++ {
		cvWritePoint(&wire, &output.Proof.CipherCommitments[lane])
		cvWritePoint(&wire, &output.Proof.ShareCommitments[lane])
	}
	cvWriteScalar(&wire, &output.Proof.KeyResponse)
	for lane := 0; lane < 2; lane++ {
		cvWriteScalar(&wire, &output.Proof.ShareResponses[lane])
	}
	return wire.Bytes(), nil
}

func cvDecodeScalarShareOutputV2(
	wire []byte, aggregate *cvAggregateV2, context *cvLeafContextV2, params cvV2Params,
	receivers *cvReceiverKeyMaterialV2,
) (*cvScalarShareOutputV2, error) {
	if cvValidateReceiverMaterialForLeafV2(context, receivers) != nil {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share receiver registry")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregateShareWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateShareWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share domain")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share digest")
	}
	receiverID, err := r.uint64()
	if err != nil || receiverID > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share receiver ID")
	}
	receiverIndex, err := r.uint64()
	if err != nil || receiverIndex == 0 || receiverIndex > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV V2 aggregate-share receiver index")
	}
	points := make([]bls12381.G1Affine, 7)
	for i := range points {
		points[i], err = r.point()
		if err != nil {
			return nil, fmt.Errorf("invalid CV V2 aggregate-share point")
		}
	}
	responses := make([]fr.Element, 3)
	for i := range responses {
		responses[i], err = r.scalar()
		if err != nil {
			return nil, fmt.Errorf("invalid CV V2 aggregate-share response")
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV V2 aggregate-share bytes")
	}
	output := &cvScalarShareOutputV2{
		AggregateDigest: digest, ReceiverID: int(receiverID), ReceiverIndex: int(receiverIndex), Y: points[0], YBlind: points[1],
		Proof: cvAggregateShareProofV2{
			KeyCommitment: points[2], CipherCommitments: [2]bls12381.G1Affine{points[3], points[5]},
			ShareCommitments: [2]bls12381.G1Affine{points[4], points[6]}, KeyResponse: responses[0],
			ShareResponses: [2]fr.Element{responses[1], responses[2]},
		},
	}
	canonical, err := cvScalarShareOutputV2CanonicalBytes(output)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 aggregate-share output")
	}
	index := output.ReceiverIndex - 1
	if index < 0 || index >= len(receivers.encryptionPublicKeys) {
		return nil, fmt.Errorf("CV V2 aggregate-share receiver is outside registry")
	}
	if err := cvVerifyAggregateShareV2(output, aggregate, context, params, &receivers.encryptionPublicKeys[index]); err != nil {
		return nil, err
	}
	return output, nil
}

func cvRecoverThresholdPublicKeyV2(
	outputs []*cvScalarShareOutputV2, aggregate *cvAggregateV2, context *cvLeafContextV2,
	params cvV2Params, receivers *cvReceiverKeyMaterialV2,
) (bls12381.G1Affine, error) {
	if cvValidateReceiverMaterialForLeafV2(context, receivers) != nil || len(outputs) < params.newShareThreshold {
		return bls12381.G1Affine{}, fmt.Errorf("insufficient CV V2 aggregate-share outputs")
	}
	ordered := append([]*cvScalarShareOutputV2(nil), outputs...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ReceiverIndex < ordered[j].ReceiverIndex })
	indices := make([]int, len(ordered))
	shares := make([]bls12381.G1Affine, len(ordered))
	blindShares := make([]bls12381.G1Affine, len(ordered))
	for i, output := range ordered {
		if output == nil || output.ReceiverIndex <= 0 || output.ReceiverIndex > len(receivers.encryptionPublicKeys) ||
			(i > 0 && output.ReceiverIndex == ordered[i-1].ReceiverIndex) {
			return bls12381.G1Affine{}, fmt.Errorf("invalid CV V2 aggregate-share output set")
		}
		if err := cvVerifyAggregateShareV2(
			output, aggregate, context, params, &receivers.encryptionPublicKeys[output.ReceiverIndex-1],
		); err != nil {
			return bls12381.G1Affine{}, err
		}
		indices[i], shares[i], blindShares[i] = output.ReceiverIndex, output.Y, output.YBlind
	}
	publicKey, err := cvInterpolateG1AtZero(indices, shares)
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	blindConstant, err := cvInterpolateG1AtZero(indices, blindShares)
	if err != nil {
		return bls12381.G1Affine{}, err
	}
	var commitment bls12381.G1Affine
	commitment.Add(&publicKey, &blindConstant)
	if len(aggregate.CoefficientCommitments) == 0 || !commitment.Equal(&aggregate.CoefficientCommitments[0]) {
		return bls12381.G1Affine{}, fmt.Errorf("CV V2 aggregate-share interpolation mismatch")
	}
	if publicKey.IsInfinity() {
		return bls12381.G1Affine{}, fmt.Errorf("CV V2 threshold public key is identity")
	}
	return publicKey, nil
}
