package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvMaxChunkBits                 = 20
	cvMaxDLogBound                 = uint64(1) << 32
	cvLeafV1StructuralProofProfile = "m1a-structural-no-nizk"
	cvLeafV1GrothProofProfile      = "m1b-groth-32x8-exact-range-v2"
	cvLeafV1ContextDigestDomain    = "ARL-CV-sAPVSS-v1/context"
	cvLeafV1StatementDigestDomain  = "ARL-CV-sAPVSS-v1/statement"
	cvLeafV1DigestDomain           = "ARL-CV-sAPVSS-v1/leaf"
	cvLeafV1ReceiverRegistryDomain = "ARL-CV-sAPVSS-v1/registry"
	cvLeafV1GroupID                = "BLS12-381-G1/fr"
)

type cvChunkProfile struct {
	chunkBits     uint
	maxComponents int
}

type cvElGamalCiphertext struct {
	r bls12381.G1Affine
	c bls12381.G1Affine
}

type cvEncryptedShare struct {
	receiverPublicKey bls12381.G1Affine
	scalarChunks      []cvElGamalCiphertext
	blinding          cvElGamalCiphertext
	commitment        bls12381.G1Affine
}

type cvDecryptedShare struct {
	scalar          fr.Element
	publicScalar    bls12381.G1Affine
	blindingOpening bls12381.G1Affine
}

type cvLeafContextV1 struct {
	sessionID          []byte
	epoch              uint64
	sharingDegree      int
	profile            cvChunkProfile
	receiverPublicKeys []bls12381.G1Affine
	dealerSetPolicy    []byte
	proofProfile       string
}

type cvLeafReceiverV1 struct {
	receiverIndex     int
	receiverPublicKey bls12381.G1Affine
	encryptedShare    *cvEncryptedShare
}

type cvLeafV1 struct {
	context                cvLeafContextV1
	dealerID               uint64
	coefficientCommitments []bls12381.G1Affine
	receivers              []cvLeafReceiverV1
	hasLeafNIZK            bool
	proof                  *cvLeafProofV1
	digest                 []byte
}

func cvProfile(profile cvChunkProfile) (uint64, uint64, int, error) {
	if profile.chunkBits == 0 || profile.chunkBits > cvMaxChunkBits || profile.maxComponents <= 0 {
		return 0, 0, 0, fmt.Errorf("invalid CV-sAPVSS chunk profile")
	}
	base := uint64(1) << profile.chunkBits
	maxDigit := base - 1
	if uint64(profile.maxComponents) > ^uint64(0)/maxDigit {
		return 0, 0, 0, fmt.Errorf("CV-sAPVSS digit bound overflows")
	}
	bound := uint64(profile.maxComponents) * maxDigit
	if new(big.Int).SetUint64(bound).Cmp(fr.Modulus()) >= 0 {
		return 0, 0, 0, fmt.Errorf("CV-sAPVSS digit bound wraps scalar field")
	}
	if bound > cvMaxDLogBound {
		return 0, 0, 0, fmt.Errorf("CV-sAPVSS bounded-DLog range is infeasible")
	}
	chunks := (fr.Modulus().BitLen() + int(profile.chunkBits) - 1) / int(profile.chunkBits)
	return base, bound, chunks, nil
}

func cvChunkCount(profile cvChunkProfile) (int, error) {
	_, _, chunks, err := cvProfile(profile)
	return chunks, err
}

func cvValidG1(point *bls12381.G1Affine, allowInfinity bool) bool {
	return point != nil && point.IsOnCurve() && point.IsInSubGroup() &&
		(allowInfinity || !point.IsInfinity())
}

func cvReceiverPublicKey(secret fr.Element) (bls12381.G1Affine, error) {
	if secret.IsZero() {
		return bls12381.G1Affine{}, fmt.Errorf("CV-sAPVSS receiver secret must be nonzero")
	}
	var publicKey bls12381.G1Affine
	publicKey.ScalarMultiplication(&genG1, secret.BigInt(new(big.Int)))
	return publicKey, nil
}

func cvPedersenBase() (bls12381.G1Affine, error) {
	h, err := bls12381.HashToG1(
		[]byte("ARL-CV-sAPVSS-v1-Pedersen-H"),
		[]byte("ARL-CV-sAPVSS-v1-H2C"),
	)
	if err != nil {
		return bls12381.G1Affine{}, fmt.Errorf("derive CV-sAPVSS Pedersen base: %w", err)
	}
	if !cvValidG1(&h, false) || h.Equal(&genG1) {
		return bls12381.G1Affine{}, fmt.Errorf("invalid CV-sAPVSS Pedersen base")
	}
	return h, nil
}

func cvEncryptPoint(receiverPK, message *bls12381.G1Affine, coin fr.Element) (cvElGamalCiphertext, error) {
	if !cvValidG1(receiverPK, false) || !cvValidG1(message, true) {
		return cvElGamalCiphertext{}, fmt.Errorf("invalid CV-sAPVSS ElGamal point")
	}
	coinInt := coin.BigInt(new(big.Int))
	var r, shared, c bls12381.G1Affine
	r.ScalarMultiplication(&genG1, coinInt)
	shared.ScalarMultiplication(receiverPK, coinInt)
	c.Add(&shared, message)
	return cvElGamalCiphertext{r: r, c: c}, nil
}

func cvScalarDigits(scalar fr.Element, profile cvChunkProfile) ([]uint64, error) {
	base, _, chunks, err := cvProfile(profile)
	if err != nil {
		return nil, err
	}
	remaining := scalar.BigInt(new(big.Int))
	mask := new(big.Int).SetUint64(base - 1)
	digits := make([]uint64, chunks)
	for i := range digits {
		digits[i] = new(big.Int).And(remaining, mask).Uint64()
		remaining.Rsh(remaining, profile.chunkBits)
	}
	if remaining.Sign() != 0 {
		return nil, fmt.Errorf("CV-sAPVSS chunk count did not cover scalar")
	}
	return digits, nil
}

func cvReferenceEncryptShare(
	profile cvChunkProfile,
	receiverPK bls12381.G1Affine,
	scalar, blinding fr.Element,
	scalarCoins []fr.Element,
	blindingCoin fr.Element,
) (*cvEncryptedShare, error) {
	if !cvValidG1(&receiverPK, false) {
		return nil, fmt.Errorf("invalid CV-sAPVSS receiver public key")
	}
	digits, err := cvScalarDigits(scalar, profile)
	if err != nil {
		return nil, err
	}
	if len(scalarCoins) != len(digits) {
		return nil, fmt.Errorf("CV-sAPVSS scalar coin count mismatch")
	}

	chunks := make([]cvElGamalCiphertext, len(digits))
	for i, digit := range digits {
		var digitPoint bls12381.G1Affine
		digitPoint.ScalarMultiplication(&genG1, new(big.Int).SetUint64(digit))
		chunks[i], err = cvEncryptPoint(&receiverPK, &digitPoint, scalarCoins[i])
		if err != nil {
			return nil, err
		}
	}

	h, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	var blindingPoint bls12381.G1Affine
	blindingPoint.ScalarMultiplication(&h, blinding.BigInt(new(big.Int)))
	blindingCiphertext, err := cvEncryptPoint(&receiverPK, &blindingPoint, blindingCoin)
	if err != nil {
		return nil, err
	}
	var scalarPoint, commitment bls12381.G1Affine
	scalarPoint.ScalarMultiplication(&genG1, scalar.BigInt(new(big.Int)))
	commitment.Add(&scalarPoint, &blindingPoint)

	return &cvEncryptedShare{
		receiverPublicKey: receiverPK,
		scalarChunks:      chunks,
		blinding:          blindingCiphertext,
		commitment:        commitment,
	}, nil
}

func cvValidCiphertext(ciphertext *cvElGamalCiphertext) bool {
	return ciphertext != nil && cvValidG1(&ciphertext.r, true) && cvValidG1(&ciphertext.c, true)
}

func cvValidateShare(share *cvEncryptedShare, chunks int) error {
	if share == nil || !cvValidG1(&share.receiverPublicKey, false) ||
		!cvValidG1(&share.commitment, true) || !cvValidCiphertext(&share.blinding) {
		return fmt.Errorf("invalid CV-sAPVSS encrypted share")
	}
	if len(share.scalarChunks) != chunks {
		return fmt.Errorf("CV-sAPVSS scalar chunk count mismatch")
	}
	for i := range share.scalarChunks {
		if !cvValidCiphertext(&share.scalarChunks[i]) {
			return fmt.Errorf("invalid CV-sAPVSS scalar chunk %d", i)
		}
	}
	return nil
}

func cvAggregate(profile cvChunkProfile, shares []*cvEncryptedShare) (*cvEncryptedShare, error) {
	_, _, chunks, err := cvProfile(profile)
	if err != nil {
		return nil, err
	}
	if len(shares) == 0 || len(shares) > profile.maxComponents {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate component count")
	}
	if err := cvValidateShare(shares[0], chunks); err != nil {
		return nil, err
	}
	result := &cvEncryptedShare{
		receiverPublicKey: shares[0].receiverPublicKey,
		scalarChunks:      append([]cvElGamalCiphertext(nil), shares[0].scalarChunks...),
		blinding:          shares[0].blinding,
		commitment:        shares[0].commitment,
	}
	for shareIndex := 1; shareIndex < len(shares); shareIndex++ {
		share := shares[shareIndex]
		if err := cvValidateShare(share, chunks); err != nil {
			return nil, err
		}
		if !share.receiverPublicKey.Equal(&result.receiverPublicKey) {
			return nil, fmt.Errorf("CV-sAPVSS aggregate mixes receiver keys")
		}
		for i := range result.scalarChunks {
			result.scalarChunks[i].r.Add(&result.scalarChunks[i].r, &share.scalarChunks[i].r)
			result.scalarChunks[i].c.Add(&result.scalarChunks[i].c, &share.scalarChunks[i].c)
		}
		result.blinding.r.Add(&result.blinding.r, &share.blinding.r)
		result.blinding.c.Add(&result.blinding.c, &share.blinding.c)
		result.commitment.Add(&result.commitment, &share.commitment)
	}
	return result, nil
}

func cvPointKey(point *bls12381.G1Affine) [bls12381.SizeOfG1AffineCompressed]byte {
	return point.Bytes()
}

type cvBoundedDLogSolver struct {
	bound         uint64
	width         uint64
	babies        map[[bls12381.SizeOfG1AffineCompressed]byte]uint64
	negativeGiant bls12381.G1Affine
}

func cvNewBoundedDLogSolver(bound uint64) *cvBoundedDLogSolver {
	rangeSize := bound + 1
	width := uint64(math.Ceil(math.Sqrt(float64(rangeSize))))
	for width*width < rangeSize {
		width++
	}

	solver := &cvBoundedDLogSolver{
		bound:  bound,
		width:  width,
		babies: make(map[[bls12381.SizeOfG1AffineCompressed]byte]uint64, width),
	}
	var current bls12381.G1Affine
	current.ScalarMultiplication(&genG1, big.NewInt(0))
	for j := uint64(0); j < width; j++ {
		solver.babies[cvPointKey(&current)] = j
		current.Add(&current, &genG1)
	}

	var giantStep bls12381.G1Affine
	giantStep.ScalarMultiplication(&genG1, new(big.Int).SetUint64(width))
	solver.negativeGiant.Neg(&giantStep)
	return solver
}

func (solver *cvBoundedDLogSolver) solve(target *bls12381.G1Affine) (uint64, bool) {
	if !cvValidG1(target, true) {
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

func cvBoundedDLog(target *bls12381.G1Affine, bound uint64) (uint64, bool) {
	return cvNewBoundedDLogSolver(bound).solve(target)
}

func cvDecryptShare(
	profile cvChunkProfile,
	receiverSecret fr.Element,
	aggregate *cvEncryptedShare,
	componentCount int,
) (*cvDecryptedShare, error) {
	base, _, chunks, err := cvProfile(profile)
	if err != nil {
		return nil, err
	}
	if componentCount <= 0 || componentCount > profile.maxComponents {
		return nil, fmt.Errorf("invalid CV-sAPVSS decrypt component count")
	}
	if err := cvValidateShare(aggregate, chunks); err != nil {
		return nil, err
	}
	receiverPK, err := cvReceiverPublicKey(receiverSecret)
	if err != nil {
		return nil, err
	}
	if !receiverPK.Equal(&aggregate.receiverPublicKey) {
		return nil, fmt.Errorf("CV-sAPVSS receiver secret does not match key")
	}

	bound := uint64(componentCount) * (base - 1)
	solver := cvNewBoundedDLogSolver(bound)
	integerSum := new(big.Int)
	for i := range aggregate.scalarChunks {
		chunk := &aggregate.scalarChunks[i]
		var shared, message bls12381.G1Affine
		shared.ScalarMultiplication(&chunk.r, receiverSecret.BigInt(new(big.Int)))
		message.Sub(&chunk.c, &shared)
		digit, ok := solver.solve(&message)
		if !ok {
			return nil, fmt.Errorf("CV-sAPVSS bounded DLog failed for chunk %d", i)
		}
		term := new(big.Int).SetUint64(digit)
		term.Lsh(term, uint(i)*profile.chunkBits)
		integerSum.Add(integerSum, term)
	}
	integerSum.Mod(integerSum, fr.Modulus())
	var scalar fr.Element
	scalar.SetBigInt(integerSum)

	var blindingShared, blindingOpening, publicScalar bls12381.G1Affine
	blindingShared.ScalarMultiplication(&aggregate.blinding.r, receiverSecret.BigInt(new(big.Int)))
	blindingOpening.Sub(&aggregate.blinding.c, &blindingShared)
	publicScalar.ScalarMultiplication(&genG1, scalar.BigInt(new(big.Int)))
	return &cvDecryptedShare{
		scalar:          scalar,
		publicScalar:    publicScalar,
		blindingOpening: blindingOpening,
	}, nil
}

func cvVerifyRelation(aggregate *cvEncryptedShare, decrypted *cvDecryptedShare) bool {
	if aggregate == nil || decrypted == nil || !cvValidG1(&aggregate.commitment, true) ||
		!cvValidG1(&decrypted.publicScalar, true) || !cvValidG1(&decrypted.blindingOpening, true) {
		return false
	}
	var expectedPublic, expectedCommitment bls12381.G1Affine
	expectedPublic.ScalarMultiplication(&genG1, decrypted.scalar.BigInt(new(big.Int)))
	expectedCommitment.Add(&decrypted.publicScalar, &decrypted.blindingOpening)
	return expectedPublic.Equal(&decrypted.publicScalar) && expectedCommitment.Equal(&aggregate.commitment)
}

func cvValidateLeafContextV1(context *cvLeafContextV1) error {
	if context == nil || len(context.sessionID) == 0 || len(context.dealerSetPolicy) == 0 ||
		(context.proofProfile != cvLeafV1StructuralProofProfile &&
			context.proofProfile != cvLeafV1GrothProofProfile) {
		return fmt.Errorf("invalid CV-sAPVSS LeafV1 context")
	}
	if _, _, _, err := cvProfile(context.profile); err != nil {
		return err
	}
	if len(context.receiverPublicKeys) == 0 || context.sharingDegree < 0 ||
		context.sharingDegree >= len(context.receiverPublicKeys) {
		return fmt.Errorf("invalid CV-sAPVSS LeafV1 sharing degree")
	}
	seen := make(map[[bls12381.SizeOfG1AffineCompressed]byte]struct{}, len(context.receiverPublicKeys))
	for i := range context.receiverPublicKeys {
		key := &context.receiverPublicKeys[i]
		if !cvValidG1(key, false) {
			return fmt.Errorf("invalid CV-sAPVSS receiver key at index %d", i+1)
		}
		encoded := cvPointKey(key)
		if _, ok := seen[encoded]; ok {
			return fmt.Errorf("duplicate CV-sAPVSS receiver key at index %d", i+1)
		}
		seen[encoded] = struct{}{}
	}
	return nil
}

func cvWriteUint32(buffer *bytes.Buffer, value int) error {
	if value < 0 || uint64(value) > uint64(^uint32(0)) {
		return fmt.Errorf("CV-sAPVSS canonical length exceeds uint32")
	}
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(value))
	_, _ = buffer.Write(encoded[:])
	return nil
}

func cvWriteUint64(buffer *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = buffer.Write(encoded[:])
}

func cvWriteBytes(buffer *bytes.Buffer, value []byte) error {
	if err := cvWriteUint32(buffer, len(value)); err != nil {
		return err
	}
	_, _ = buffer.Write(value)
	return nil
}

func cvWritePoint(buffer *bytes.Buffer, point *bls12381.G1Affine) {
	encoded := point.Bytes()
	_, _ = buffer.Write(encoded[:])
}

func cvReceiverRegistryDigestV1(keys []bls12381.G1Affine) ([]byte, error) {
	var wire bytes.Buffer
	if err := cvWriteUint32(&wire, len(keys)); err != nil {
		return nil, err
	}
	for i := range keys {
		if !cvValidG1(&keys[i], false) {
			return nil, fmt.Errorf("invalid CV-sAPVSS receiver key at index %d", i+1)
		}
		if err := cvWriteUint32(&wire, i+1); err != nil {
			return nil, err
		}
		cvWritePoint(&wire, &keys[i])
	}
	return hashBytes([]byte(cvLeafV1ReceiverRegistryDomain), wire.Bytes()), nil
}

func cvLeafContextV1CanonicalBytes(context *cvLeafContextV1) ([]byte, error) {
	if err := cvValidateLeafContextV1(context); err != nil {
		return nil, err
	}
	base, _, chunks, _ := cvProfile(context.profile)
	h, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	registryDigest, err := cvReceiverRegistryDigestV1(context.receiverPublicKeys)
	if err != nil {
		return nil, err
	}

	var wire bytes.Buffer
	for _, value := range [][]byte{
		[]byte("ARL-CV-sAPVSS-v1"),
		[]byte(cvLeafV1GroupID),
		fr.Modulus().Bytes(),
	} {
		if err := cvWriteBytes(&wire, value); err != nil {
			return nil, err
		}
	}
	cvWritePoint(&wire, &genG1)
	cvWritePoint(&wire, &h)
	if err := cvWriteBytes(&wire, context.sessionID); err != nil {
		return nil, err
	}
	cvWriteUint64(&wire, context.epoch)
	for _, value := range []int{
		len(context.receiverPublicKeys),
		context.sharingDegree,
		context.profile.maxComponents,
		int(context.profile.chunkBits),
		int(base),
		chunks,
	} {
		if err := cvWriteUint32(&wire, value); err != nil {
			return nil, err
		}
	}
	if err := cvWriteBytes(&wire, registryDigest); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(context.receiverPublicKeys)); err != nil {
		return nil, err
	}
	for i := range context.receiverPublicKeys {
		if err := cvWriteUint32(&wire, i+1); err != nil {
			return nil, err
		}
		cvWritePoint(&wire, &context.receiverPublicKeys[i])
	}
	if err := cvWriteBytes(&wire, context.dealerSetPolicy); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, []byte(context.proofProfile)); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

func cvLeafContextV1Digest(context *cvLeafContextV1) []byte {
	wire, err := cvLeafContextV1CanonicalBytes(context)
	if err != nil {
		return nil
	}
	return hashBytes([]byte(cvLeafV1ContextDigestDomain), wire)
}

func cvCloneLeafContextV1(context cvLeafContextV1) cvLeafContextV1 {
	context.sessionID = append([]byte(nil), context.sessionID...)
	context.receiverPublicKeys = append([]bls12381.G1Affine(nil), context.receiverPublicKeys...)
	context.dealerSetPolicy = append([]byte(nil), context.dealerSetPolicy...)
	return context
}

func cvReferenceDealV1(
	context cvLeafContextV1,
	dealerID uint64,
	scalarCoefficients, blindingCoefficients []fr.Element,
	scalarCoins [][]fr.Element,
	blindingCoins []fr.Element,
) (*cvLeafV1, error) {
	if err := cvValidateLeafContextV1(&context); err != nil {
		return nil, err
	}
	coefficientCount := context.sharingDegree + 1
	if len(scalarCoefficients) != coefficientCount || len(blindingCoefficients) != coefficientCount {
		return nil, fmt.Errorf("CV-sAPVSS polynomial coefficient count mismatch")
	}
	if len(scalarCoins) != len(context.receiverPublicKeys) ||
		len(blindingCoins) != len(context.receiverPublicKeys) {
		return nil, fmt.Errorf("CV-sAPVSS receiver coin count mismatch")
	}
	if context.proofProfile == cvLeafV1GrothProofProfile {
		for receiver := 1; receiver < len(context.receiverPublicKeys); receiver++ {
			if len(scalarCoins[receiver]) != len(scalarCoins[0]) {
				return nil, fmt.Errorf("CV-sAPVSS Groth scalar coin count mismatch")
			}
			for chunk := range scalarCoins[0] {
				if !scalarCoins[receiver][chunk].Equal(&scalarCoins[0][chunk]) {
					return nil, fmt.Errorf("CV-sAPVSS Groth profile requires shared chunk coins")
				}
			}
			if !blindingCoins[receiver].Equal(&blindingCoins[0]) {
				return nil, fmt.Errorf("CV-sAPVSS Groth profile requires a shared blinding coin")
			}
		}
	}

	h, err := cvPedersenBase()
	if err != nil {
		return nil, err
	}
	commitments := make([]bls12381.G1Affine, coefficientCount)
	for i := range commitments {
		var scalarTerm, blindingTerm bls12381.G1Affine
		scalarTerm.ScalarMultiplication(&genG1, scalarCoefficients[i].BigInt(new(big.Int)))
		blindingTerm.ScalarMultiplication(&h, blindingCoefficients[i].BigInt(new(big.Int)))
		commitments[i].Add(&scalarTerm, &blindingTerm)
	}

	receivers := make([]cvLeafReceiverV1, len(context.receiverPublicKeys))
	scalarEvaluations := make([]fr.Element, len(receivers))
	blindingEvaluations := make([]fr.Element, len(receivers))
	for i := range receivers {
		scalar := evalPolyInt(scalarCoefficients, int64(i+1))
		blinding := evalPolyInt(blindingCoefficients, int64(i+1))
		scalarEvaluations[i] = scalar
		blindingEvaluations[i] = blinding
		encrypted, encryptErr := cvReferenceEncryptShare(
			context.profile,
			context.receiverPublicKeys[i],
			scalar,
			blinding,
			scalarCoins[i],
			blindingCoins[i],
		)
		if encryptErr != nil {
			return nil, fmt.Errorf("encrypt CV-sAPVSS receiver %d: %w", i+1, encryptErr)
		}
		receivers[i] = cvLeafReceiverV1{
			receiverIndex:     i + 1,
			receiverPublicKey: context.receiverPublicKeys[i],
			encryptedShare:    encrypted,
		}
	}

	leaf := &cvLeafV1{
		context:                cvCloneLeafContextV1(context),
		dealerID:               dealerID,
		coefficientCommitments: commitments,
		receivers:              receivers,
		hasLeafNIZK:            context.proofProfile == cvLeafV1GrothProofProfile,
	}
	if leaf.hasLeafNIZK {
		leaf.proof, err = cvProveLeafV1(
			leaf,
			scalarEvaluations,
			blindingEvaluations,
			scalarCoins[0],
			blindingCoins[0],
		)
		if err != nil {
			return nil, err
		}
	}
	leaf.digest = cvLeafV1Digest(leaf)
	if leaf.digest == nil {
		return nil, fmt.Errorf("encode CV-sAPVSS LeafV1")
	}
	return leaf, nil
}

func cvWriteCiphertext(buffer *bytes.Buffer, ciphertext *cvElGamalCiphertext) {
	cvWritePoint(buffer, &ciphertext.r)
	cvWritePoint(buffer, &ciphertext.c)
}

func cvLeafV1StatementBytes(leaf *cvLeafV1) ([]byte, error) {
	if leaf == nil {
		return nil, fmt.Errorf("invalid CV-sAPVSS LeafV1")
	}
	contextWire, err := cvLeafContextV1CanonicalBytes(&leaf.context)
	if err != nil {
		return nil, err
	}
	_, _, chunks, _ := cvProfile(leaf.context.profile)

	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, contextWire); err != nil {
		return nil, err
	}
	cvWriteUint64(&wire, leaf.dealerID)
	if err := cvWriteUint32(&wire, len(leaf.coefficientCommitments)); err != nil {
		return nil, err
	}
	for i := range leaf.coefficientCommitments {
		if !cvValidG1(&leaf.coefficientCommitments[i], true) {
			return nil, fmt.Errorf("invalid CV-sAPVSS coefficient commitment %d", i)
		}
		cvWritePoint(&wire, &leaf.coefficientCommitments[i])
	}
	if err := cvWriteUint32(&wire, len(leaf.receivers)); err != nil {
		return nil, err
	}
	for i := range leaf.receivers {
		receiver := &leaf.receivers[i]
		if receiver.receiverIndex <= 0 || !cvValidG1(&receiver.receiverPublicKey, false) ||
			receiver.encryptedShare == nil {
			return nil, fmt.Errorf("invalid CV-sAPVSS LeafV1 receiver item %d", i)
		}
		if err := cvValidateShare(receiver.encryptedShare, chunks); err != nil {
			return nil, err
		}
		if err := cvWriteUint32(&wire, receiver.receiverIndex); err != nil {
			return nil, err
		}
		cvWritePoint(&wire, &receiver.receiverPublicKey)
		cvWritePoint(&wire, &receiver.encryptedShare.receiverPublicKey)
		cvWritePoint(&wire, &receiver.encryptedShare.commitment)
		if err := cvWriteUint32(&wire, len(receiver.encryptedShare.scalarChunks)); err != nil {
			return nil, err
		}
		for chunkIndex := range receiver.encryptedShare.scalarChunks {
			cvWriteCiphertext(&wire, &receiver.encryptedShare.scalarChunks[chunkIndex])
		}
		cvWriteCiphertext(&wire, &receiver.encryptedShare.blinding)
	}
	return wire.Bytes(), nil
}

func cvLeafV1CanonicalBytes(leaf *cvLeafV1) ([]byte, error) {
	statement, err := cvLeafV1StatementBytes(leaf)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_, _ = wire.Write(statement)
	switch leaf.context.proofProfile {
	case cvLeafV1StructuralProofProfile:
		if leaf.hasLeafNIZK || leaf.proof != nil {
			return nil, fmt.Errorf("invalid CV-sAPVSS structural LeafV1 capability")
		}
		_ = wire.WriteByte(0)
	case cvLeafV1GrothProofProfile:
		if !leaf.hasLeafNIZK || leaf.proof == nil {
			return nil, fmt.Errorf("missing CV-sAPVSS LeafV1 proof")
		}
		_ = wire.WriteByte(1)
		proofWire, err := cvLeafProofV1CanonicalBytes(leaf.proof)
		if err != nil {
			return nil, err
		}
		if err := cvWriteBytes(&wire, proofWire); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported CV-sAPVSS LeafV1 proof profile")
	}
	return wire.Bytes(), nil
}

func cvLeafV1Digest(leaf *cvLeafV1) []byte {
	wire, err := cvLeafV1CanonicalBytes(leaf)
	if err != nil {
		return nil
	}
	return hashBytes([]byte(cvLeafV1DigestDomain), wire)
}

func cvEvaluateCommitmentsV1(commitments []bls12381.G1Affine, receiverIndex int) bls12381.G1Affine {
	var x, power fr.Element
	x.SetInt64(int64(receiverIndex))
	power.SetOne()
	var result bls12381.G1Affine
	result.ScalarMultiplication(&genG1, big.NewInt(0))
	for i := range commitments {
		var term bls12381.G1Affine
		term.ScalarMultiplication(&commitments[i], power.BigInt(new(big.Int)))
		result.Add(&result, &term)
		power.Mul(&power, &x)
	}
	return result
}

func cvVerifyLeafV1(expectedContext *cvLeafContextV1, leaf *cvLeafV1) error {
	if cvPerfCountersEnabled {
		cvPerfCounters.leafVerifyCalls.Add(1)
	}
	if err := cvValidateLeafContextV1(expectedContext); err != nil {
		return err
	}
	if leaf == nil {
		return fmt.Errorf("invalid CV-sAPVSS LeafV1")
	}
	switch expectedContext.proofProfile {
	case cvLeafV1StructuralProofProfile:
		if leaf.hasLeafNIZK || leaf.proof != nil {
			return fmt.Errorf("invalid CV-sAPVSS structural LeafV1 capability")
		}
	case cvLeafV1GrothProofProfile:
		if !leaf.hasLeafNIZK || leaf.proof == nil {
			return fmt.Errorf("missing CV-sAPVSS LeafV1 proof")
		}
	default:
		return fmt.Errorf("unsupported CV-sAPVSS LeafV1 proof profile")
	}
	expectedContextWire, err := cvLeafContextV1CanonicalBytes(expectedContext)
	if err != nil {
		return err
	}
	leafContextWire, err := cvLeafContextV1CanonicalBytes(&leaf.context)
	if err != nil || !bytes.Equal(expectedContextWire, leafContextWire) {
		return fmt.Errorf("CV-sAPVSS LeafV1 context mismatch")
	}
	if len(leaf.coefficientCommitments) != expectedContext.sharingDegree+1 ||
		len(leaf.receivers) != len(expectedContext.receiverPublicKeys) {
		return fmt.Errorf("CV-sAPVSS LeafV1 statement size mismatch")
	}
	_, _, chunks, _ := cvProfile(expectedContext.profile)
	for i := range leaf.coefficientCommitments {
		if !cvValidG1(&leaf.coefficientCommitments[i], true) {
			return fmt.Errorf("invalid CV-sAPVSS coefficient commitment %d", i)
		}
	}
	for i := range leaf.receivers {
		receiver := &leaf.receivers[i]
		expectedKey := &expectedContext.receiverPublicKeys[i]
		if receiver.receiverIndex != i+1 || !receiver.receiverPublicKey.Equal(expectedKey) ||
			receiver.encryptedShare == nil || !receiver.encryptedShare.receiverPublicKey.Equal(expectedKey) {
			return fmt.Errorf("CV-sAPVSS LeafV1 receiver binding mismatch at index %d", i+1)
		}
		if err := cvValidateShare(receiver.encryptedShare, chunks); err != nil {
			return err
		}
		expectedCommitment := cvEvaluateCommitmentsV1(leaf.coefficientCommitments, i+1)
		if !receiver.encryptedShare.commitment.Equal(&expectedCommitment) {
			return fmt.Errorf("CV-sAPVSS LeafV1 evaluation commitment mismatch at index %d", i+1)
		}
	}
	wire, err := cvLeafV1CanonicalBytes(leaf)
	if err != nil {
		return err
	}
	expectedDigest := hashBytes([]byte(cvLeafV1DigestDomain), wire)
	if len(leaf.digest) != sha256.Size || !bytes.Equal(leaf.digest, expectedDigest) {
		return fmt.Errorf("CV-sAPVSS LeafV1 digest mismatch")
	}
	if expectedContext.proofProfile == cvLeafV1GrothProofProfile {
		if err := cvVerifyLeafProofV1(leaf); err != nil {
			return err
		}
	}
	if cvPerfCountersEnabled {
		cvPerfCounters.leafVerifySuccesses.Add(1)
	}
	return nil
}
