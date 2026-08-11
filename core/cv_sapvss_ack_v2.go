package core

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvLaneOfferWireDomainV2      = "ARL-CV-sAPVSS/v2/lane-offer"
	cvFallbackLaneWireDomainV2   = "ARL-CV-sAPVSS/v2/fallback-lane"
	cvOwnershipProofWireDomainV2 = "ARL-CV-sAPVSS/v2/ownership-proof"
	cvACKWireDomainV2            = "ARL-CV-sAPVSS/v2/ack"
	cvACKStatementDomainV2       = "ARL-CV-sAPVSS/v2/ack-statement"
	cvCiphertextDigestDomainV2   = "ARL-CV-sAPVSS/v2/ciphertexts"
)

type cvACKEvidenceV2 struct {
	Ownership cvOwnershipProofV2
	Signature []byte
}

func cvFallbackLaneOfferV2CanonicalBytes(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine,
) ([]byte, error) {
	if dealerID < 0 || cvValidateLaneOfferShapeV2(context, offer, receiverPublicKey) != nil {
		return nil, fmt.Errorf("invalid CV V2 fallback lane")
	}
	contextDigest, err := cvLeafContextDigestV2(context)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvFallbackLaneWireDomainV2))
	_ = cvWriteBytes(&wire, contextDigest)
	cvWriteUint64(&wire, uint64(dealerID))
	cvWriteUint64(&wire, uint64(offer.ReceiverID))
	if err := cvWriteUint32(&wire, offer.ReceiverIndex); err != nil {
		return nil, err
	}
	cvWritePoint(&wire, &offer.Evaluation)
	for lane := 0; lane < 2; lane++ {
		if err := cvWriteUint32(&wire, len(offer.Lanes[lane].Chunks)); err != nil {
			return nil, err
		}
		for chunk := range offer.Lanes[lane].Chunks {
			cvWriteCiphertext(&wire, &offer.Lanes[lane].Chunks[chunk])
		}
	}
	return wire.Bytes(), nil
}

func cvDecodeFallbackLaneOfferV2(
	wire []byte, context *cvLeafContextV2, expectedDealer, expectedReceiverID, expectedReceiverIndex int,
	receiverPublicKey *bls12381.G1Affine,
) (*cvReceiverLaneOfferV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvFallbackLaneWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvFallbackLaneWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 fallback lane domain")
	}
	contextDigest, err := r.bytes(32)
	wantContext, contextErr := cvLeafContextDigestV2(context)
	if err != nil || contextErr != nil || !bytes.Equal(contextDigest, wantContext) {
		return nil, fmt.Errorf("invalid CV V2 fallback lane context")
	}
	dealer, err := r.uint64()
	if err != nil || dealer != uint64(expectedDealer) {
		return nil, fmt.Errorf("invalid CV V2 fallback lane dealer")
	}
	receiverID, err := r.uint64()
	if err != nil || receiverID != uint64(expectedReceiverID) {
		return nil, fmt.Errorf("invalid CV V2 fallback lane receiver")
	}
	receiverIndex, err := r.uint32()
	if err != nil || receiverIndex != expectedReceiverIndex {
		return nil, fmt.Errorf("invalid CV V2 fallback lane receiver index")
	}
	evaluation, err := r.point()
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 fallback lane evaluation")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	offer := &cvReceiverLaneOfferV2{ReceiverID: expectedReceiverID, ReceiverIndex: expectedReceiverIndex, Evaluation: evaluation}
	for lane := 0; lane < 2; lane++ {
		count, readErr := r.uint32()
		if readErr != nil || count != chunks {
			return nil, fmt.Errorf("invalid CV V2 fallback lane chunk count")
		}
		offer.Lanes[lane].Chunks = make([]cvElGamalCiphertext, chunks)
		for chunk := 0; chunk < chunks; chunk++ {
			offer.Lanes[lane].Chunks[chunk], err = r.ciphertext()
			if err != nil {
				return nil, fmt.Errorf("invalid CV V2 fallback lane ciphertext")
			}
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV V2 fallback lane bytes")
	}
	canonical, err := cvFallbackLaneOfferV2CanonicalBytes(context, expectedDealer, offer, receiverPublicKey)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 fallback lane")
	}
	return offer, nil
}

func cvVerifyDecryptAndSignACKV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, receiverSecret fr.Element,
	identityPublicKey ed25519.PublicKey, identitySecret ed25519.PrivateKey,
) (*cvACKEvidenceV2, fr.Element, fr.Element, error) {
	if len(identityPublicKey) != ed25519.PublicKeySize || len(identitySecret) != ed25519.PrivateKeySize ||
		!bytes.Equal(identitySecret.Public().(ed25519.PublicKey), identityPublicKey) {
		return nil, fr.Element{}, fr.Element{}, fmt.Errorf("invalid CV V2 receiver identity secret")
	}
	scalar, blinding, err := cvVerifyAndDecryptReceiverLanesV2(
		context, dealerID, offer, receiverPublicKey, receiverSecret,
	)
	if err != nil {
		return nil, fr.Element{}, fr.Element{}, err
	}
	statement, err := cvACKStatementV2(context, dealerID, offer)
	if err != nil {
		return nil, fr.Element{}, fr.Element{}, err
	}
	evidence := &cvACKEvidenceV2{
		Ownership: cvCloneOwnershipProofV2(&offer.Ownership),
		Signature: ed25519.Sign(identitySecret, statement),
	}
	return evidence, scalar, blinding, nil
}

func cvVerifyACKV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine, identityPublicKey ed25519.PublicKey,
	evidence *cvACKEvidenceV2,
) error {
	if offer == nil || evidence == nil || len(identityPublicKey) != ed25519.PublicKeySize ||
		len(evidence.Signature) != ed25519.SignatureSize ||
		!cvEqualOwnershipProofV2(&offer.Ownership, &evidence.Ownership) {
		return fmt.Errorf("invalid CV V2 ACK evidence")
	}
	if err := cvVerifyOwnershipV2(context, dealerID, offer, receiverPublicKey); err != nil {
		return err
	}
	statement, err := cvACKStatementV2(context, dealerID, offer)
	if err != nil || !ed25519.Verify(identityPublicKey, statement, evidence.Signature) {
		return fmt.Errorf("invalid CV V2 ACK signature")
	}
	return nil
}

func cvACKStatementV2(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
) ([]byte, error) {
	if dealerID < 0 || context == nil || offer == nil || len(context.ReceiverRegistryDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 ACK statement")
	}
	contextDigest, err := cvLeafContextDigestV2(context)
	if err != nil {
		return nil, err
	}
	ciphertextDigest, err := cvCiphertextDigestV2(context, offer)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvACKStatementDomainV2))
	_ = cvWriteBytes(&wire, contextDigest)
	cvWriteUint64(&wire, uint64(dealerID))
	cvWriteUint64(&wire, uint64(offer.ReceiverID))
	cvWriteUint64(&wire, uint64(offer.ReceiverIndex))
	_ = cvWriteBytes(&wire, context.ReceiverRegistryDigest)
	cvWritePoint(&wire, &offer.Evaluation)
	_ = cvWriteBytes(&wire, ciphertextDigest)
	return hashBytes([]byte(cvACKStatementDomainV2), wire.Bytes()), nil
}

func cvCiphertextDigestV2(context *cvLeafContextV2, offer *cvReceiverLaneOfferV2) ([]byte, error) {
	if context == nil || offer == nil {
		return nil, fmt.Errorf("invalid CV V2 ciphertext digest")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvCiphertextDigestDomainV2))
	for lane := 0; lane < 2; lane++ {
		if len(offer.Lanes[lane].Chunks) != chunks {
			return nil, fmt.Errorf("invalid CV V2 ciphertext digest dimensions")
		}
		for chunk := range offer.Lanes[lane].Chunks {
			if !cvValidCiphertext(&offer.Lanes[lane].Chunks[chunk]) {
				return nil, fmt.Errorf("invalid CV V2 ciphertext")
			}
			cvWriteCiphertext(&wire, &offer.Lanes[lane].Chunks[chunk])
		}
	}
	return hashBytes([]byte(cvCiphertextDigestDomainV2), wire.Bytes()), nil
}

func cvReceiverLaneOfferV2CanonicalBytes(
	context *cvLeafContextV2, dealerID int, offer *cvReceiverLaneOfferV2,
	receiverPublicKey *bls12381.G1Affine,
) ([]byte, error) {
	if dealerID < 0 || cvVerifyOwnershipV2(context, dealerID, offer, receiverPublicKey) != nil {
		return nil, fmt.Errorf("invalid CV V2 lane offer")
	}
	contextDigest, err := cvLeafContextDigestV2(context)
	if err != nil {
		return nil, err
	}
	proofWire, err := cvOwnershipProofV2CanonicalBytes(&offer.Ownership, context)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvLaneOfferWireDomainV2))
	_ = cvWriteBytes(&wire, contextDigest)
	cvWriteUint64(&wire, uint64(dealerID))
	cvWriteUint64(&wire, uint64(offer.ReceiverID))
	if err := cvWriteUint32(&wire, offer.ReceiverIndex); err != nil {
		return nil, err
	}
	cvWritePoint(&wire, &offer.Evaluation)
	if err := cvWriteUint32(&wire, 2); err != nil {
		return nil, err
	}
	for lane := 0; lane < 2; lane++ {
		if err := cvWriteUint32(&wire, len(offer.Lanes[lane].Chunks)); err != nil {
			return nil, err
		}
		for chunk := range offer.Lanes[lane].Chunks {
			cvWriteCiphertext(&wire, &offer.Lanes[lane].Chunks[chunk])
		}
	}
	_ = cvWriteBytes(&wire, proofWire)
	return wire.Bytes(), nil
}

func cvDecodeReceiverLaneOfferV2(
	wire []byte, context *cvLeafContextV2, expectedDealer, expectedReceiverID, expectedReceiverIndex int,
	receiverPublicKey *bls12381.G1Affine,
) (*cvReceiverLaneOfferV2, error) {
	if expectedDealer < 0 || cvValidateReceiverBindingV2(
		context, expectedReceiverID, expectedReceiverIndex, receiverPublicKey,
	) != nil {
		return nil, fmt.Errorf("invalid expected CV V2 lane offer binding")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvLaneOfferWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvLaneOfferWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 lane offer domain")
	}
	contextDigest, err := r.bytes(32)
	expectedContextDigest, digestErr := cvLeafContextDigestV2(context)
	if err != nil || digestErr != nil || !bytes.Equal(contextDigest, expectedContextDigest) {
		return nil, fmt.Errorf("invalid CV V2 lane offer context")
	}
	dealer, err := r.uint64()
	if err != nil || dealer != uint64(expectedDealer) {
		return nil, fmt.Errorf("invalid CV V2 lane offer dealer")
	}
	receiverID, err := r.uint64()
	if err != nil || receiverID != uint64(expectedReceiverID) {
		return nil, fmt.Errorf("invalid CV V2 lane offer receiver")
	}
	receiverIndex, err := r.uint32()
	if err != nil || receiverIndex != expectedReceiverIndex {
		return nil, fmt.Errorf("invalid CV V2 lane offer receiver index")
	}
	evaluation, err := r.point()
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 lane offer evaluation")
	}
	laneCount, err := r.uint32()
	if err != nil || laneCount != 2 {
		return nil, fmt.Errorf("invalid CV V2 lane count")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	offer := &cvReceiverLaneOfferV2{
		ReceiverID: expectedReceiverID, ReceiverIndex: expectedReceiverIndex, Evaluation: evaluation,
	}
	for lane := 0; lane < 2; lane++ {
		count, err := r.uint32()
		if err != nil || count != chunks {
			return nil, fmt.Errorf("invalid CV V2 lane chunk count")
		}
		offer.Lanes[lane].Chunks = make([]cvElGamalCiphertext, chunks)
		for chunk := 0; chunk < chunks; chunk++ {
			offer.Lanes[lane].Chunks[chunk], err = r.ciphertext()
			if err != nil {
				return nil, fmt.Errorf("invalid CV V2 lane ciphertext")
			}
		}
	}
	proofWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 lane offer proof framing")
	}
	proof, err := cvDecodeOwnershipProofV2(proofWire, context)
	if err != nil {
		return nil, err
	}
	offer.Ownership = *proof
	canonical, err := cvReceiverLaneOfferV2CanonicalBytes(context, expectedDealer, offer, receiverPublicKey)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 lane offer")
	}
	return offer, nil
}

func cvOwnershipProofV2CanonicalBytes(proof *cvOwnershipProofV2, context *cvLeafContextV2) ([]byte, error) {
	if context == nil || proof == nil {
		return nil, fmt.Errorf("invalid CV V2 ownership proof")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	total := 2 * chunks
	if len(proof.CoinCommitments) != total || len(proof.CipherCommitments) != total ||
		len(proof.CoinResponses) != total || len(proof.DigitResponses) != total {
		return nil, fmt.Errorf("invalid CV V2 ownership proof dimensions")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvOwnershipProofWireDomainV2))
	if err := cvWritePointVector(&wire, proof.CoinCommitments); err != nil {
		return nil, err
	}
	if err := cvWritePointVector(&wire, proof.CipherCommitments); err != nil {
		return nil, err
	}
	if err := cvWriteScalarVector(&wire, proof.CoinResponses); err != nil {
		return nil, err
	}
	if err := cvWriteScalarVector(&wire, proof.DigitResponses); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

func cvDecodeOwnershipProofV2(wire []byte, context *cvLeafContextV2) (*cvOwnershipProofV2, error) {
	if context == nil {
		return nil, fmt.Errorf("nil CV V2 ownership context")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return nil, err
	}
	total := 2 * chunks
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvOwnershipProofWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvOwnershipProofWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 ownership proof domain")
	}
	coinCommitments, err := cvReadExactPointVector(r, total, "V2 ownership coin commitments")
	if err != nil {
		return nil, err
	}
	cipherCommitments, err := cvReadExactPointVector(r, total, "V2 ownership ciphertext commitments")
	if err != nil {
		return nil, err
	}
	coinResponses, err := cvReadExactScalarVectorV2(r, total)
	if err != nil {
		return nil, err
	}
	digitResponses, err := cvReadExactScalarVectorV2(r, total)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 ownership proof response framing")
	}
	proof := &cvOwnershipProofV2{
		CoinCommitments: coinCommitments, CipherCommitments: cipherCommitments,
		CoinResponses: coinResponses, DigitResponses: digitResponses,
	}
	canonical, err := cvOwnershipProofV2CanonicalBytes(proof, context)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 ownership proof")
	}
	return proof, nil
}

func cvACKEvidenceV2CanonicalBytes(evidence *cvACKEvidenceV2, context *cvLeafContextV2) ([]byte, error) {
	if evidence == nil || len(evidence.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid CV V2 ACK evidence")
	}
	ownershipWire, err := cvOwnershipProofV2CanonicalBytes(&evidence.Ownership, context)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvACKWireDomainV2))
	_ = cvWriteBytes(&wire, ownershipWire)
	_ = cvWriteBytes(&wire, evidence.Signature)
	return wire.Bytes(), nil
}

func cvDecodeACKEvidenceV2(wire []byte, context *cvLeafContextV2) (*cvACKEvidenceV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvACKWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvACKWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 ACK domain")
	}
	ownershipWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 ACK ownership proof")
	}
	ownership, err := cvDecodeOwnershipProofV2(ownershipWire, context)
	if err != nil {
		return nil, err
	}
	signature, err := r.bytes(ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 ACK signature framing")
	}
	evidence := &cvACKEvidenceV2{Ownership: *ownership, Signature: signature}
	canonical, err := cvACKEvidenceV2CanonicalBytes(evidence, context)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 ACK evidence")
	}
	return evidence, nil
}

func cvCloneOwnershipProofV2(proof *cvOwnershipProofV2) cvOwnershipProofV2 {
	if proof == nil {
		return cvOwnershipProofV2{}
	}
	return cvOwnershipProofV2{
		CoinCommitments:   append([]bls12381.G1Affine(nil), proof.CoinCommitments...),
		CipherCommitments: append([]bls12381.G1Affine(nil), proof.CipherCommitments...),
		CoinResponses:     append([]fr.Element(nil), proof.CoinResponses...),
		DigitResponses:    append([]fr.Element(nil), proof.DigitResponses...),
	}
}

func cvEqualOwnershipProofV2(left, right *cvOwnershipProofV2) bool {
	if left == nil || right == nil || len(left.CoinCommitments) != len(right.CoinCommitments) ||
		len(left.CipherCommitments) != len(right.CipherCommitments) ||
		len(left.CoinResponses) != len(right.CoinResponses) ||
		len(left.DigitResponses) != len(right.DigitResponses) {
		return false
	}
	for i := range left.CoinCommitments {
		if !left.CoinCommitments[i].Equal(&right.CoinCommitments[i]) {
			return false
		}
	}
	for i := range left.CipherCommitments {
		if !left.CipherCommitments[i].Equal(&right.CipherCommitments[i]) {
			return false
		}
	}
	for i := range left.CoinResponses {
		if !left.CoinResponses[i].Equal(&right.CoinResponses[i]) {
			return false
		}
	}
	for i := range left.DigitResponses {
		if !left.DigitResponses[i].Equal(&right.DigitResponses[i]) {
			return false
		}
	}
	return true
}
