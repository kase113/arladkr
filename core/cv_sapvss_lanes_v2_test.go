package core

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func cvReceiverLanesV2Fixture(
	t *testing.T,
) (*cvLeafContextV2, int, int, int, fr.Element, bls12381.G1Affine, fr.Element, fr.Element) {
	t.Helper()
	context, coefficients, blindings := cvCoreProofV2Fixture(t)
	dealer := context.OldRoster[0]
	receiverID := context.NewRoster[1]
	receiverIndex := 2
	var receiverSecret fr.Element
	if _, err := receiverSecret.SetRandom(); err != nil {
		t.Fatal(err)
	}
	receiverPublic, err := cvReceiverPublicKey(receiverSecret)
	if err != nil {
		t.Fatal(err)
	}
	return context, dealer, receiverID, receiverIndex, receiverSecret, receiverPublic, coefficients[0], blindings[0]
}

func TestCVReceiverLanesV2UseScalarChunksAndGroupBlinding(t *testing.T) {
	context, dealer, receiverID, receiverIndex, secret, publicKey, scalar, blinding := cvReceiverLanesV2Fixture(t)
	offer, witness, err := cvEncryptReceiverLanesV2(
		context, dealer, receiverID, receiverIndex, &publicKey, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvVerifyOwnershipV2(context, dealer, offer, &publicKey); err != nil {
		t.Fatalf("verify V2 ownership proof: %v", err)
	}
	recoveredScalar, recoveredBlinding, err := cvVerifyAndDecryptReceiverLanesV2(
		context, dealer, offer, &publicKey, secret,
	)
	if err != nil {
		t.Fatal(err)
	}
	h, err := cvPedersenBase()
	if err != nil {
		t.Fatal(err)
	}
	wantBlinding := cvPointTimes(&h, &blinding)
	if !recoveredScalar.Equal(&scalar) || !recoveredBlinding.Equal(&wantBlinding) {
		t.Fatal("scalar/group decryption did not recover the Pedersen opening")
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(offer.ScalarChunks) != chunks || len(witness.ScalarCoins) != chunks ||
		!cvValidCiphertext(&offer.Blinding) {
		t.Fatal("V2 offer is not exactly scalar chunks plus one blinding ciphertext")
	}
	seenCoins := make(map[[bls12381.SizeOfG1AffineCompressed]byte]struct{})
	for chunk := range offer.ScalarChunks {
		key := cvPointKey(&offer.ScalarChunks[chunk].r)
		if _, duplicate := seenCoins[key]; duplicate {
			t.Fatal("V2 scalar chunks reused an encryption coin")
		}
		seenCoins[key] = struct{}{}
	}
	if _, duplicate := seenCoins[cvPointKey(&offer.Blinding.r)]; duplicate {
		t.Fatal("V2 blinding ciphertext reused a scalar encryption coin")
	}
}

func TestCVReceiverLanesV2DecodedPathStillVerifiesOwnershipEquations(t *testing.T) {
	context, dealer, receiverID, receiverIndex, secret, publicKey, scalar, blinding := cvReceiverLanesV2Fixture(t)
	offer, _, err := cvEncryptReceiverLanesV2(
		context, dealer, receiverID, receiverIndex, &publicKey, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvReceiverLaneOfferV2CanonicalBytesAfterValidation(context, dealer, offer)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeReceiverLaneOfferBeforeVerificationV2(
		wire, context, dealer, receiverID, receiverIndex, &publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cvVerifyAndDecryptReceiverLanesAfterPointDecodingV2(
		context, dealer, decoded, &publicKey, secret,
	); err != nil {
		t.Fatalf("decoded receiver lane verification failed: %v", err)
	}

	badProof := *decoded
	badProof.Ownership = cvCloneOwnershipProofV2(&decoded.Ownership)
	one := fr.One()
	badProof.Ownership.BlindingShareResponse.Add(&badProof.Ownership.BlindingShareResponse, &one)
	if _, _, err := cvVerifyAndDecryptReceiverLanesAfterPointDecodingV2(
		context, dealer, &badProof, &publicKey, secret,
	); err == nil {
		t.Fatal("decoded receiver path accepted a mutated ownership response")
	}

	badCiphertext := *decoded
	badCiphertext.ScalarChunks = append([]cvElGamalCiphertext(nil), decoded.ScalarChunks...)
	badCiphertext.ScalarChunks[0].c.Add(&badCiphertext.ScalarChunks[0].c, &genG1)
	if _, _, err := cvVerifyAndDecryptReceiverLanesAfterPointDecodingV2(
		context, dealer, &badCiphertext, &publicKey, secret,
	); err == nil {
		t.Fatal("decoded receiver path accepted a ciphertext mutation")
	}
}

func TestCVOwnershipProofV2RejectsCiphertextEvaluationAndBindingMutations(t *testing.T) {
	context, dealer, receiverID, receiverIndex, _, publicKey, scalar, blinding := cvReceiverLanesV2Fixture(t)
	offer, _, err := cvEncryptReceiverLanesV2(
		context, dealer, receiverID, receiverIndex, &publicKey, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}

	badCiphertext := *offer
	badCiphertext.ScalarChunks = append([]cvElGamalCiphertext(nil), offer.ScalarChunks...)
	badCiphertext.ScalarChunks[0].c.Add(&badCiphertext.ScalarChunks[0].c, &genG1)
	if err := cvVerifyOwnershipV2(context, dealer, &badCiphertext, &publicKey); err == nil {
		t.Fatal("accepted ownership proof after ciphertext mutation")
	}
	badBlinding := *offer
	badBlinding.Blinding.c.Add(&badBlinding.Blinding.c, &genG1)
	if err := cvVerifyOwnershipV2(context, dealer, &badBlinding, &publicKey); err == nil {
		t.Fatal("accepted ownership proof after blinding ciphertext mutation")
	}

	badEvaluation := *offer
	badEvaluation.Evaluation.Add(&badEvaluation.Evaluation, &genG1)
	if err := cvVerifyOwnershipV2(context, dealer, &badEvaluation, &publicKey); err == nil {
		t.Fatal("accepted ownership proof after evaluation mutation")
	}
	if err := cvVerifyOwnershipV2(context, dealer+1, offer, &publicKey); err == nil {
		t.Fatal("accepted ownership proof under another dealer")
	}
	badReceiver := *offer
	badReceiver.ReceiverID = context.NewRoster[0]
	if err := cvVerifyOwnershipV2(context, dealer, &badReceiver, &publicKey); err == nil {
		t.Fatal("accepted ownership proof under a mismatched receiver binding")
	}
	badIndex := *offer
	badIndex.ReceiverIndex = 1
	if err := cvVerifyOwnershipV2(context, dealer, &badIndex, &publicKey); err == nil {
		t.Fatal("accepted ownership proof under another receiver index")
	}
	badContext := *context
	badContext.ReceiverRegistryDigest = append([]byte(nil), context.ReceiverRegistryDigest...)
	badContext.ReceiverRegistryDigest[0] ^= 1
	if err := cvVerifyOwnershipV2(&badContext, dealer, offer, &publicKey); err == nil {
		t.Fatal("accepted ownership proof under another receiver registry")
	}
	badProof := *offer
	badProof.Ownership = cvCloneOwnershipProofV2(&offer.Ownership)
	var one fr.Element
	one.SetOne()
	badProof.Ownership.BlindingShareResponse.Add(&badProof.Ownership.BlindingShareResponse, &one)
	if err := cvVerifyOwnershipV2(context, dealer, &badProof, &publicKey); err == nil {
		t.Fatal("accepted mutated blinding-share ownership response")
	}

	var wrongSecret fr.Element
	if _, err := wrongSecret.SetRandom(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cvVerifyAndDecryptReceiverLanesV2(context, dealer, offer, &publicKey, wrongSecret); err == nil {
		t.Fatal("decrypted V2 lanes with a secret outside the receiver registry")
	}
}

func TestCVReceiverLanesV2RejectOutOfRangeDigitAfterValidOwnershipProof(t *testing.T) {
	context, dealer, receiverID, receiverIndex, secret, publicKey, scalar, blinding := cvReceiverLanesV2Fixture(t)
	offer, witness, err := cvEncryptReceiverLanesV2(
		context, dealer, receiverID, receiverIndex, &publicKey, scalar, blinding,
	)
	if err != nil {
		t.Fatal(err)
	}
	base, _, _, err := cvProfile(context.Profile)
	if err != nil {
		t.Fatal(err)
	}
	oldDigit := witness.ScalarDigits[0]
	witness.ScalarDigits[0] = base
	var outOfRangePoint bls12381.G1Affine
	outOfRangePoint.ScalarMultiplication(&genG1, new(big.Int).SetUint64(base))
	offer.ScalarChunks[0], err = cvEncryptPoint(&publicKey, &outOfRangePoint, witness.ScalarCoins[0])
	if err != nil {
		t.Fatal(err)
	}
	delta := new(big.Int).SetUint64(base - oldDigit)
	var deltaPoint bls12381.G1Affine
	deltaPoint.ScalarMultiplication(&genG1, delta)
	offer.Evaluation.Add(&offer.Evaluation, &deltaPoint)
	proof, err := cvProveOwnershipV2(context, dealer, offer, &publicKey, witness)
	if err != nil {
		t.Fatal(err)
	}
	offer.Ownership = *proof
	if err := cvVerifyOwnershipV2(context, dealer, offer, &publicKey); err != nil {
		t.Fatalf("ownership proof should not claim a range relation: %v", err)
	}
	if _, _, err := cvVerifyAndDecryptReceiverLanesV2(context, dealer, offer, &publicKey, secret); err == nil {
		t.Fatal("accepted out-of-range V2 digit after valid ownership proof")
	}
}
