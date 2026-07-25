package core

import (
	"bytes"
	"fmt"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvMaxLeafProofWireBytesV1 = 64 << 20
	cvMaxLeafWireBytesV1      = 64 << 20
)

func (r *cvWireReader) scalar() (fr.Element, error) {
	var encoded [fr.Bytes]byte
	if _, err := io.ReadFull(r.reader, encoded[:]); err != nil {
		return fr.Element{}, err
	}
	var scalar fr.Element
	if err := scalar.SetBytesCanonical(encoded[:]); err != nil {
		return fr.Element{}, fmt.Errorf("invalid CV-sAPVSS canonical scalar: %w", err)
	}
	return scalar, nil
}

func cvCheckedProductV1(left, right int, field string) (int, error) {
	if left < 0 || right < 0 || (left != 0 && right > int(^uint(0)>>1)/left) {
		return 0, fmt.Errorf("invalid CV-sAPVSS %s size", field)
	}
	return left * right, nil
}

func cvCheckedAddV1(left, right int, field string) (int, error) {
	if left < 0 || right < 0 || right > int(^uint(0)>>1)-left {
		return 0, fmt.Errorf("invalid CV-sAPVSS %s size", field)
	}
	return left + right, nil
}

func cvCountedVectorWireSizeV1(count, width int, field string) (int, error) {
	payload, err := cvCheckedProductV1(count, width, field)
	if err != nil {
		return 0, err
	}
	return cvCheckedAddV1(4, payload, field)
}

func cvLeafProofWireSizeV1(context *cvLeafContextV1) (int, error) {
	if err := cvValidateLeafContextV1(context); err != nil {
		return 0, err
	}
	if context.proofProfile != cvLeafV1GrothProofProfile {
		return 0, fmt.Errorf("CV-sAPVSS LeafV1 proof is not enabled by the context")
	}
	receivers := len(context.receiverPublicKeys)
	chunks, err := cvChunkCount(context.profile)
	if err != nil {
		return 0, err
	}
	receiversPlusOne, err := cvCheckedAddV1(receivers, 1, "chunk D")
	if err != nil {
		return 0, err
	}
	wantBits, err := cvCheckedProductV1(receivers, chunks, "exact range proof")
	if err != nil {
		return 0, err
	}
	wantBits, err = cvCheckedProductV1(wantBits, int(context.profile.chunkBits), "exact range proof")
	if err != nil {
		return 0, err
	}

	pointVector := func(count int, field string) (int, error) {
		return cvCountedVectorWireSizeV1(count, bls12381.SizeOfG1AffineCompressed, field)
	}
	scalarVector := func(count int, field string) (int, error) {
		return cvCountedVectorWireSizeV1(count, fr.Bytes, field)
	}
	total := 0
	add := func(size int, field string) error {
		var addErr error
		total, addErr = cvCheckedAddV1(total, size, field)
		return addErr
	}
	addProduct := func(count, width int, field string) error {
		size, productErr := cvCheckedProductV1(count, width, field)
		if productErr != nil {
			return productErr
		}
		return add(size, field)
	}
	addVector := func(count, width int, field string) error {
		size, vectorErr := cvCountedVectorWireSizeV1(count, width, field)
		if vectorErr != nil {
			return vectorErr
		}
		return add(size, field)
	}

	if err := addProduct(6, bls12381.SizeOfG1AffineCompressed, "LeafV1 proof points"); err != nil {
		return 0, err
	}
	if err := addProduct(4, fr.Bytes, "LeafV1 sharing scalars"); err != nil {
		return 0, err
	}
	for _, vector := range []struct {
		count int
		width int
		field string
	}{
		{cvChunkProofRepetitions, bls12381.SizeOfG1AffineCompressed, "chunk B"},
		{cvChunkProofRepetitions, bls12381.SizeOfG1AffineCompressed, "chunk C"},
		{receiversPlusOne, bls12381.SizeOfG1AffineCompressed, "chunk D"},
	} {
		if err := addVector(vector.count, vector.width, vector.field); err != nil {
			return 0, err
		}
	}
	if err := add(bls12381.SizeOfG1AffineCompressed, "chunk Y"); err != nil {
		return 0, err
	}
	if err := addVector(receivers, fr.Bytes, "chunk coin responses"); err != nil {
		return 0, err
	}
	if err := addVector(cvChunkProofRepetitions, fr.Bytes, "chunk digit responses"); err != nil {
		return 0, err
	}
	if err := add(fr.Bytes, "chunk beta response"); err != nil {
		return 0, err
	}
	if err := addVector(wantBits, bls12381.SizeOfG1AffineCompressed, "exact range commitments"); err != nil {
		return 0, err
	}
	const bitProofWireBytes = 2*bls12381.SizeOfG1AffineCompressed + 3*fr.Bytes
	if err := addVector(wantBits, bitProofWireBytes, "exact range bit proofs"); err != nil {
		return 0, err
	}

	pointResponses, err := pointVector(receivers, "exact range link points")
	if err != nil {
		return 0, err
	}
	scalarResponses, err := scalarVector(receivers, "exact range link scalars")
	if err != nil {
		return 0, err
	}
	linkSize := 0
	for _, size := range []int{
		bls12381.SizeOfG1AffineCompressed,
		pointResponses,
		pointResponses,
		fr.Bytes,
		scalarResponses,
		scalarResponses,
	} {
		linkSize, err = cvCheckedAddV1(linkSize, size, "exact range link")
		if err != nil {
			return 0, err
		}
	}
	linksPayload, err := cvCheckedProductV1(chunks, linkSize, "exact range links")
	if err != nil {
		return 0, err
	}
	linksSize, err := cvCheckedAddV1(4, linksPayload, "exact range links")
	if err != nil {
		return 0, err
	}
	if err := add(linksSize, "exact range links"); err != nil {
		return 0, err
	}
	return total, nil
}

func cvLeafWireSizeV1(context *cvLeafContextV1) (int, error) {
	if err := cvValidateLeafContextV1(context); err != nil {
		return 0, err
	}
	contextWire, err := cvLeafContextV1CanonicalBytes(context)
	if err != nil {
		return 0, err
	}
	receivers := len(context.receiverPublicKeys)
	chunks, err := cvChunkCount(context.profile)
	if err != nil {
		return 0, err
	}
	commitments, err := cvCheckedAddV1(context.sharingDegree, 1, "LeafV1 coefficient commitments")
	if err != nil {
		return 0, err
	}
	ciphertexts, err := cvCheckedAddV1(chunks, 1, "LeafV1 receiver ciphertexts")
	if err != nil {
		return 0, err
	}
	ciphertextBytes, err := cvCheckedProductV1(ciphertexts, 2*bls12381.SizeOfG1AffineCompressed, "LeafV1 receiver ciphertexts")
	if err != nil {
		return 0, err
	}
	receiverSize, err := cvCheckedAddV1(4+3*bls12381.SizeOfG1AffineCompressed+4, ciphertextBytes, "LeafV1 receiver")
	if err != nil {
		return 0, err
	}
	receiverPayload, err := cvCheckedProductV1(receivers, receiverSize, "LeafV1 receivers")
	if err != nil {
		return 0, err
	}
	receiverVector, err := cvCheckedAddV1(4, receiverPayload, "LeafV1 receivers")
	if err != nil {
		return 0, err
	}
	commitmentVector, err := cvCountedVectorWireSizeV1(commitments, bls12381.SizeOfG1AffineCompressed, "LeafV1 coefficient commitments")
	if err != nil {
		return 0, err
	}
	contextField, err := cvCheckedAddV1(4, len(contextWire), "LeafV1 context")
	if err != nil {
		return 0, err
	}
	total := 0
	for _, size := range []int{contextField, 8, commitmentVector, receiverVector, 1} {
		total, err = cvCheckedAddV1(total, size, "LeafV1")
		if err != nil {
			return 0, err
		}
	}
	if context.proofProfile == cvLeafV1GrothProofProfile {
		proofSize, proofErr := cvLeafProofWireSizeV1(context)
		if proofErr != nil {
			return 0, proofErr
		}
		proofField, proofErr := cvCheckedAddV1(4, proofSize, "LeafV1 proof")
		if proofErr != nil {
			return 0, proofErr
		}
		total, err = cvCheckedAddV1(total, proofField, "LeafV1")
		if err != nil {
			return 0, err
		}
	}
	return total, nil
}

func cvReadExactBytesV1(r *cvWireReader, expected int, field string) ([]byte, error) {
	value, err := r.bytes(expected)
	if err != nil {
		return nil, fmt.Errorf("decode CV-sAPVSS %s: %w", field, err)
	}
	if len(value) != expected {
		return nil, fmt.Errorf("invalid CV-sAPVSS %s length: got %d, want %d", field, len(value), expected)
	}
	return value, nil
}

func cvRequireRemainingV1(r *cvWireReader, count, width int, field string) error {
	required, err := cvCheckedProductV1(count, width, field)
	if err != nil {
		return err
	}
	if required > r.reader.Len() {
		return fmt.Errorf("CV-sAPVSS %s exceeds remaining wire", field)
	}
	return nil
}

func cvReadExactCountV1(r *cvWireReader, expected int, field string) error {
	count, err := r.uint32()
	if err != nil {
		return fmt.Errorf("decode CV-sAPVSS %s count: %w", field, err)
	}
	if expected < 0 || count != expected {
		return fmt.Errorf("invalid CV-sAPVSS %s count: got %d, want %d", field, count, expected)
	}
	return nil
}

func cvReadExactPointVectorV1(r *cvWireReader, expected int, field string) ([]bls12381.G1Affine, error) {
	if err := cvReadExactCountV1(r, expected, field); err != nil {
		return nil, err
	}
	if err := cvRequireRemainingV1(r, expected, bls12381.SizeOfG1AffineCompressed, field); err != nil {
		return nil, err
	}
	points := make([]bls12381.G1Affine, expected)
	for i := range points {
		point, err := r.point()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS %s point %d: %w", field, i, err)
		}
		points[i] = point
	}
	return points, nil
}

func cvReadExactScalarVectorV1(r *cvWireReader, expected int, field string) ([]fr.Element, error) {
	if err := cvReadExactCountV1(r, expected, field); err != nil {
		return nil, err
	}
	if err := cvRequireRemainingV1(r, expected, fr.Bytes, field); err != nil {
		return nil, err
	}
	scalars := make([]fr.Element, expected)
	for i := range scalars {
		scalar, err := r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS %s scalar %d: %w", field, i, err)
		}
		scalars[i] = scalar
	}
	return scalars, nil
}

func cvDecodeLeafProofV1(wire []byte, expectedContext *cvLeafContextV1) (*cvLeafProofV1, error) {
	if err := cvValidateLeafContextV1(expectedContext); err != nil {
		return nil, err
	}
	if expectedContext.proofProfile != cvLeafV1GrothProofProfile {
		return nil, fmt.Errorf("CV-sAPVSS LeafV1 proof is not enabled by the expected context")
	}
	expectedWireSize, err := cvLeafProofWireSizeV1(expectedContext)
	if err != nil {
		return nil, err
	}
	if expectedWireSize > cvMaxLeafProofWireBytesV1 {
		return nil, fmt.Errorf("CV-sAPVSS LeafV1 proof exceeds the wire safety limit")
	}
	if len(wire) != expectedWireSize {
		return nil, fmt.Errorf("invalid CV-sAPVSS LeafV1 proof length: got %d, want %d", len(wire), expectedWireSize)
	}
	receivers := len(expectedContext.receiverPublicKeys)
	chunks, err := cvChunkCount(expectedContext.profile)
	if err != nil {
		return nil, err
	}
	wantBits, err := cvCheckedProductV1(receivers, chunks, "exact range proof")
	if err != nil {
		return nil, err
	}
	wantBits, err = cvCheckedProductV1(wantBits, int(expectedContext.profile.chunkBits), "exact range proof")
	if err != nil {
		return nil, err
	}

	r := newCVWireReader(wire)
	proof := &cvLeafProofV1{}
	for i, point := range []*bls12381.G1Affine{
		&proof.sharing.fScalar,
		&proof.sharing.fBlinding,
		&proof.sharing.a,
		&proof.sharing.yScalar,
		&proof.sharing.yBlinding,
		&proof.chunking.y0,
	} {
		decoded, pointErr := r.point()
		if pointErr != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS LeafV1 proof point %d: %w", i, pointErr)
		}
		*point = decoded
	}
	for i, scalar := range []*fr.Element{
		&proof.sharing.zScalar,
		&proof.sharing.zBlinding,
		&proof.sharing.zScalarCoin,
		&proof.sharing.zBlindingCoin,
	} {
		decoded, scalarErr := r.scalar()
		if scalarErr != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS LeafV1 sharing scalar %d: %w", i, scalarErr)
		}
		*scalar = decoded
	}
	proof.chunking.b, err = cvReadExactPointVectorV1(r, cvChunkProofRepetitions, "chunk B")
	if err != nil {
		return nil, err
	}
	proof.chunking.c, err = cvReadExactPointVectorV1(r, cvChunkProofRepetitions, "chunk C")
	if err != nil {
		return nil, err
	}
	proof.chunking.d, err = cvReadExactPointVectorV1(r, receivers+1, "chunk D")
	if err != nil {
		return nil, err
	}
	proof.chunking.y, err = r.point()
	if err != nil {
		return nil, fmt.Errorf("decode CV-sAPVSS chunk Y: %w", err)
	}
	proof.chunking.zCoins, err = cvReadExactScalarVectorV1(r, receivers, "chunk coin responses")
	if err != nil {
		return nil, err
	}
	proof.chunking.zDigits, err = cvReadExactScalarVectorV1(r, cvChunkProofRepetitions, "chunk digit responses")
	if err != nil {
		return nil, err
	}
	proof.chunking.zBeta, err = r.scalar()
	if err != nil {
		return nil, fmt.Errorf("decode CV-sAPVSS chunk beta response: %w", err)
	}

	rangeProof := &proof.chunking.exactRange
	rangeProof.commitments, err = cvReadExactPointVectorV1(r, wantBits, "exact range commitments")
	if err != nil {
		return nil, err
	}
	if err := cvReadExactCountV1(r, wantBits, "exact range bit proofs"); err != nil {
		return nil, err
	}
	const bitProofWireBytes = 2*bls12381.SizeOfG1AffineCompressed + 3*fr.Bytes
	if err := cvRequireRemainingV1(r, wantBits, bitProofWireBytes, "exact range bit proofs"); err != nil {
		return nil, err
	}
	rangeProof.bits = make([]cvBitProofV1, wantBits)
	for i := range rangeProof.bits {
		bit := &rangeProof.bits[i]
		bit.t0, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS exact range T0 %d: %w", i, err)
		}
		bit.t1, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS exact range T1 %d: %w", i, err)
		}
		bit.e0, err = r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS exact range E0 %d: %w", i, err)
		}
		bit.z0, err = r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS exact range Z0 %d: %w", i, err)
		}
		bit.z1, err = r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS exact range Z1 %d: %w", i, err)
		}
	}
	if err := cvReadExactCountV1(r, chunks, "exact range links"); err != nil {
		return nil, err
	}
	rangeProof.links = make([]cvRangeLinkProofV1, chunks)
	for i := range rangeProof.links {
		link := &rangeProof.links[i]
		link.tCoin, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS exact range coin link %d: %w", i, err)
		}
		link.tCommitments, err = cvReadExactPointVectorV1(r, receivers, "exact range link commitments")
		if err != nil {
			return nil, err
		}
		link.tCiphertexts, err = cvReadExactPointVectorV1(r, receivers, "exact range link ciphertexts")
		if err != nil {
			return nil, err
		}
		link.zCoin, err = r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS exact range coin response %d: %w", i, err)
		}
		link.zDigits, err = cvReadExactScalarVectorV1(r, receivers, "exact range link digit responses")
		if err != nil {
			return nil, err
		}
		link.zRhos, err = cvReadExactScalarVectorV1(r, receivers, "exact range link rho responses")
		if err != nil {
			return nil, err
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV-sAPVSS LeafV1 proof bytes")
	}
	canonical, err := cvLeafProofV1CanonicalBytes(proof)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS LeafV1 proof encoding")
	}
	return proof, nil
}

func cvDecodeLeafV1(wire []byte, expectedContext *cvLeafContextV1) (*cvLeafV1, error) {
	expectedWireSize, err := cvLeafWireSizeV1(expectedContext)
	if err != nil {
		return nil, err
	}
	if expectedWireSize > cvMaxLeafWireBytesV1 {
		return nil, fmt.Errorf("CV-sAPVSS LeafV1 exceeds the wire safety limit")
	}
	if len(wire) != expectedWireSize {
		return nil, fmt.Errorf("invalid CV-sAPVSS LeafV1 length: got %d, want %d", len(wire), expectedWireSize)
	}
	expectedContextWire, err := cvLeafContextV1CanonicalBytes(expectedContext)
	if err != nil {
		return nil, err
	}
	r := newCVWireReader(wire)
	contextWire, err := cvReadExactBytesV1(r, len(expectedContextWire), "LeafV1 context")
	if err != nil || !bytes.Equal(contextWire, expectedContextWire) {
		return nil, fmt.Errorf("CV-sAPVSS LeafV1 context mismatch")
	}
	context, err := cvDecodeLeafContextV1(contextWire)
	if err != nil {
		return nil, err
	}
	leaf := &cvLeafV1{context: context}
	leaf.dealerID, err = r.uint64()
	if err != nil {
		return nil, fmt.Errorf("decode CV-sAPVSS LeafV1 dealer: %w", err)
	}
	leaf.coefficientCommitments, err = cvReadExactPointVectorV1(
		r,
		expectedContext.sharingDegree+1,
		"LeafV1 coefficient commitments",
	)
	if err != nil {
		return nil, err
	}
	receivers := len(expectedContext.receiverPublicKeys)
	if err := cvReadExactCountV1(r, receivers, "LeafV1 receivers"); err != nil {
		return nil, err
	}
	chunks, err := cvChunkCount(expectedContext.profile)
	if err != nil {
		return nil, err
	}
	ciphertextBytes, err := cvCheckedProductV1(chunks+1, 2*bls12381.SizeOfG1AffineCompressed, "LeafV1 receiver ciphertexts")
	if err != nil {
		return nil, err
	}
	receiverBytes := 4 + 3*bls12381.SizeOfG1AffineCompressed + 4 + ciphertextBytes
	if err := cvRequireRemainingV1(r, receivers, receiverBytes, "LeafV1 receivers"); err != nil {
		return nil, err
	}
	leaf.receivers = make([]cvLeafReceiverV1, receivers)
	for i := range leaf.receivers {
		receiver := &leaf.receivers[i]
		receiver.receiverIndex, err = r.uint32()
		if err != nil || receiver.receiverIndex != i+1 {
			return nil, fmt.Errorf("invalid CV-sAPVSS LeafV1 receiver index %d", i+1)
		}
		receiver.receiverPublicKey, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS LeafV1 receiver key %d: %w", i+1, err)
		}
		share := &cvEncryptedShare{}
		share.receiverPublicKey, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS LeafV1 encrypted key %d: %w", i+1, err)
		}
		share.commitment, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS LeafV1 commitment %d: %w", i+1, err)
		}
		if err := cvReadExactCountV1(r, chunks, "LeafV1 scalar chunks"); err != nil {
			return nil, err
		}
		if err := cvRequireRemainingV1(r, chunks+1, 2*bls12381.SizeOfG1AffineCompressed, "LeafV1 ciphertexts"); err != nil {
			return nil, err
		}
		share.scalarChunks = make([]cvElGamalCiphertext, chunks)
		for j := range share.scalarChunks {
			share.scalarChunks[j], err = r.ciphertext()
			if err != nil {
				return nil, fmt.Errorf("decode CV-sAPVSS LeafV1 ciphertext %d/%d: %w", i+1, j, err)
			}
		}
		share.blinding, err = r.ciphertext()
		if err != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS LeafV1 blinding ciphertext %d: %w", i+1, err)
		}
		receiver.encryptedShare = share
	}
	capability, err := r.reader.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("decode CV-sAPVSS LeafV1 proof capability: %w", err)
	}
	switch expectedContext.proofProfile {
	case cvLeafV1StructuralProofProfile:
		if capability != 0 {
			return nil, fmt.Errorf("invalid CV-sAPVSS structural LeafV1 capability")
		}
	case cvLeafV1GrothProofProfile:
		if capability != 1 {
			return nil, fmt.Errorf("missing CV-sAPVSS LeafV1 proof")
		}
		proofSize, proofErr := cvLeafProofWireSizeV1(expectedContext)
		if proofErr != nil {
			return nil, proofErr
		}
		proofWire, proofErr := cvReadExactBytesV1(r, proofSize, "LeafV1 proof")
		if proofErr != nil {
			return nil, proofErr
		}
		leaf.proof, proofErr = cvDecodeLeafProofV1(proofWire, expectedContext)
		if proofErr != nil {
			return nil, proofErr
		}
		leaf.hasLeafNIZK = true
	default:
		return nil, fmt.Errorf("unsupported CV-sAPVSS LeafV1 proof profile")
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV-sAPVSS LeafV1 bytes")
	}
	leaf.digest = hashBytes([]byte(cvLeafV1DigestDomain), wire)
	canonical, err := cvLeafV1CanonicalBytes(leaf)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS LeafV1 encoding")
	}
	if err := cvVerifyLeafV1(expectedContext, leaf); err != nil {
		return nil, err
	}
	return leaf, nil
}

func cvDecodeReceiptV1(
	wire []byte,
	expectedContext *cvLeafContextV1,
	agg *cvAggregateV1,
	expectedReceiverIndex int,
) (*cvReceiptV1, error) {
	if len(wire) == 0 || len(wire) > cvMaxCanonicalFieldBytes {
		return nil, fmt.Errorf("invalid CV-sAPVSS receipt length")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvReceiptV1Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvReceiptV1Domain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS receipt domain")
	}
	receipt := &cvReceiptV1{}
	receipt.aggregateDigest, err = r.bytes(32)
	if err != nil || len(receipt.aggregateDigest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS receipt aggregate digest")
	}
	receipt.receiverIndex, err = r.uint32()
	if err != nil {
		return nil, fmt.Errorf("decode CV-sAPVSS receipt receiver index: %w", err)
	}
	for i, point := range []*bls12381.G1Affine{
		&receipt.publicScalar,
		&receipt.blindingOpening,
		&receipt.proof.tKey,
		&receipt.proof.tScalar,
		&receipt.proof.tBlinding,
	} {
		decoded, pointErr := r.point()
		if pointErr != nil {
			return nil, fmt.Errorf("decode CV-sAPVSS receipt point %d: %w", i, pointErr)
		}
		*point = decoded
	}
	receipt.proof.z, err = r.scalar()
	if err != nil {
		return nil, fmt.Errorf("decode CV-sAPVSS receipt response: %w", err)
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV-sAPVSS receipt bytes")
	}
	canonical, err := cvReceiptV1CanonicalBytes(receipt)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS receipt encoding")
	}
	receipt.digestWire = append([]byte(nil), wire...)
	receipt.digest = hashBytes([]byte(cvReceiptV1Domain), wire)
	if err := cvVerifyShareV1(expectedContext, agg, expectedReceiverIndex, receipt); err != nil {
		return nil, err
	}
	return receipt, nil
}
