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

func TestCVReceiverLanesV2UseIndependentCoinsAndDecryptBothOpenings(t *testing.T) {
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
	if !recoveredScalar.Equal(&scalar) || !recoveredBlinding.Equal(&blinding) {
		t.Fatal("two-lane decryption did not recover both Pedersen openings")
	}

	seenCoins := make(map[[bls12381.SizeOfG1AffineCompressed]byte]struct{})
	for lane := 0; lane < 2; lane++ {
		if len(witness.Coins[lane]) != len(offer.Lanes[lane].Chunks) {
			t.Fatal("V2 lane coin count mismatch")
		}
		for chunk := range offer.Lanes[lane].Chunks {
			key := cvPointKey(&offer.Lanes[lane].Chunks[chunk].r)
			if _, duplicate := seenCoins[key]; duplicate {
				t.Fatal("V2 lanes reused an encryption coin across lane or chunk")
			}
			seenCoins[key] = struct{}{}
		}
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
	badCiphertext.Lanes = offer.Lanes
	badCiphertext.Lanes[0].Chunks = append([]cvElGamalCiphertext(nil), offer.Lanes[0].Chunks...)
	badCiphertext.Lanes[0].Chunks[0].c.Add(&badCiphertext.Lanes[0].Chunks[0].c, &genG1)
	if err := cvVerifyOwnershipV2(context, dealer, &badCiphertext, &publicKey); err == nil {
		t.Fatal("accepted ownership proof after ciphertext mutation")
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
	witness.Digits[0][0] = base
	var outOfRangePoint bls12381.G1Affine
	outOfRangePoint.ScalarMultiplication(&genG1, new(big.Int).SetUint64(base))
	offer.Lanes[0].Chunks[0], err = cvEncryptPoint(&publicKey, &outOfRangePoint, witness.Coins[0][0])
	if err != nil {
		t.Fatal(err)
	}
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
