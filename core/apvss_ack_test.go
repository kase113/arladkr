package core

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type apvssTestFixtureV1 struct {
	context         cvLeafContextV1
	leaf            *cvLeafV1
	receiverSecrets []fr.Element
	witness         apvssDealerWitnessV1
}

func apvssFixtureV1(tb testing.TB, receivers, f int) apvssTestFixtureV1 {
	tb.Helper()
	if receivers <= 0 || f < 0 || f >= receivers {
		tb.Fatal("invalid APVSS fixture topology")
	}
	profile := cvChunkProfile{chunkBits: 8, maxComponents: f + 1}
	chunks, err := cvChunkCount(profile)
	if err != nil {
		tb.Fatal(err)
	}
	secrets := make([]fr.Element, receivers)
	keys := make([]bls12381.G1Affine, receivers)
	for i := range secrets {
		secrets[i] = cvTestScalar(uint64(101 + i))
		keys[i], err = cvReceiverPublicKey(secrets[i])
		if err != nil {
			tb.Fatal(err)
		}
	}
	context := cvLeafContextV1{
		sessionID:          []byte("apvss-ack-test-session"),
		epoch:              17,
		sharingDegree:      f,
		profile:            profile,
		receiverPublicKeys: keys,
		dealerSetPolicy:    []byte("availability-then-local-valid-k"),
		proofProfile:       cvLeafV1StructuralProofProfile,
	}
	scalarCoefficients := make([]fr.Element, f+1)
	blindingCoefficients := make([]fr.Element, f+1)
	for i := 0; i <= f; i++ {
		scalarCoefficients[i] = cvTestScalar(uint64(11 + i*3))
		blindingCoefficients[i] = cvTestScalar(uint64(701 + i*5))
	}
	scalarCoins := make([][]fr.Element, receivers)
	blindingCoins := make([]fr.Element, receivers)
	for i := 0; i < receivers; i++ {
		scalarCoins[i] = cvTestCoins(chunks, uint64(2001+i*(chunks+1)))
		blindingCoins[i] = cvTestScalar(uint64(9001 + i))
	}
	leaf, err := cvReferenceDealV1(
		context,
		41,
		scalarCoefficients,
		blindingCoefficients,
		scalarCoins,
		blindingCoins,
	)
	if err != nil {
		tb.Fatal(err)
	}
	witness := apvssDealerWitnessV1{
		scalars:       make([]fr.Element, receivers),
		blindings:     make([]fr.Element, receivers),
		scalarCoins:   scalarCoins,
		blindingCoins: blindingCoins,
	}
	for i := 0; i < receivers; i++ {
		witness.scalars[i] = evalPolyInt(scalarCoefficients, int64(i+1))
		witness.blindings[i] = evalPolyInt(blindingCoefficients, int64(i+1))
	}
	return apvssTestFixtureV1{
		context:         context,
		leaf:            leaf,
		receiverSecrets: secrets,
		witness:         witness,
	}
}

func apvssClonePrototypeV1ForTest(in *apvssLeafPrototypeV1) *apvssLeafPrototypeV1 {
	out := *in
	out.acks = append([]apvssLaneACKV1(nil), in.acks...)
	out.fallbackProofs = append([]apvssFallbackProofV1(nil), in.fallbackProofs...)
	return &out
}

func TestAPVSSPrototypeACKFallbackProfilesV1(t *testing.T) {
	fixture := apvssFixtureV1(t, 7, 2)
	profiles := []struct {
		name     string
		fallback []int
	}{
		{name: "I_empty"},
		{name: "I_1", fallback: []int{1}},
		{name: "I_f", fallback: []int{1, 2}},
	}
	previousBytes := 0
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			prototype, err := apvssBuildPrototypeV1(
				&fixture.context,
				fixture.leaf,
				fixture.receiverSecrets,
				&fixture.witness,
				profile.fallback,
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(prototype.acks) != 7-len(profile.fallback) ||
				len(prototype.fallbackProofs) != len(profile.fallback) {
				t.Fatalf("ACK/fallback counts = %d/%d", len(prototype.acks), len(prototype.fallbackProofs))
			}
			if err := apvssVerifyPrototypeV1(&fixture.context, prototype); err != nil {
				t.Fatalf("valid APVSS prototype rejected: %v", err)
			}
			proofBytes, err := apvssProofMaterialBytesV1(prototype)
			if err != nil {
				t.Fatal(err)
			}
			if proofBytes <= previousBytes {
				t.Fatalf("proof bytes did not grow with |I|: previous=%d current=%d", previousBytes, proofBytes)
			}
			previousBytes = proofBytes
		})
	}
}

func TestAPVSSACKStrictDecryptionAndStatementBindingV1(t *testing.T) {
	fixture := apvssFixtureV1(t, 4, 1)
	ack, err := apvssIssueLaneACKV1(&fixture.context, fixture.leaf, 1, fixture.receiverSecrets[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := apvssVerifyLaneACKV1(fixture.leaf, &ack); err != nil {
		t.Fatalf("valid ACK rejected: %v", err)
	}

	t.Run("ciphertext replacement after ACK", func(t *testing.T) {
		bad := cvCloneLeafV1ForTest(fixture.leaf)
		bad.receivers[0].encryptedShare.scalarChunks[0].c.Add(
			&bad.receivers[0].encryptedShare.scalarChunks[0].c,
			&genG1,
		)
		bad.digest = cvLeafV1Digest(bad)
		if err := apvssVerifyLaneACKV1(bad, &ack); err == nil {
			t.Fatal("ACK accepted a replaced ciphertext")
		}
	})
	t.Run("epoch replay", func(t *testing.T) {
		bad := cvCloneLeafV1ForTest(fixture.leaf)
		bad.context.epoch++
		bad.digest = cvLeafV1Digest(bad)
		if err := apvssVerifyLaneACKV1(bad, &ack); err == nil {
			t.Fatal("ACK replayed across epochs")
		}
	})
	t.Run("dealer replay", func(t *testing.T) {
		bad := cvCloneLeafV1ForTest(fixture.leaf)
		bad.dealerID++
		bad.digest = cvLeafV1Digest(bad)
		if err := apvssVerifyLaneACKV1(bad, &ack); err == nil {
			t.Fatal("ACK replayed across dealers")
		}
	})
	t.Run("receiver replay", func(t *testing.T) {
		badACK := ack
		badACK.receiverIndex = 2
		if err := apvssVerifyLaneACKV1(fixture.leaf, &badACK); err == nil {
			t.Fatal("ACK replayed for another receiver")
		}
	})
	t.Run("wrong receiver secret", func(t *testing.T) {
		if _, err := apvssIssueLaneACKV1(
			&fixture.context,
			fixture.leaf,
			1,
			fixture.receiverSecrets[1],
		); err == nil {
			t.Fatal("issued ACK using another receiver's secret")
		}
	})
	t.Run("wrong scalar opening", func(t *testing.T) {
		bad := cvCloneLeafV1ForTest(fixture.leaf)
		bad.receivers[0].encryptedShare.scalarChunks[0].c.Add(
			&bad.receivers[0].encryptedShare.scalarChunks[0].c,
			&genG1,
		)
		bad.digest = cvLeafV1Digest(bad)
		if _, err := apvssIssueLaneACKV1(
			&fixture.context,
			bad,
			1,
			fixture.receiverSecrets[0],
		); err == nil {
			t.Fatal("issued ACK for a scalar that does not open V_i,j")
		}
	})
	t.Run("mutated blinding ciphertext", func(t *testing.T) {
		bad := cvCloneLeafV1ForTest(fixture.leaf)
		bad.receivers[0].encryptedShare.blinding.c.Add(
			&bad.receivers[0].encryptedShare.blinding.c,
			&genG1,
		)
		bad.digest = cvLeafV1Digest(bad)
		if _, err := apvssIssueLaneACKV1(
			&fixture.context,
			bad,
			1,
			fixture.receiverSecrets[0],
		); err == nil {
			t.Fatal("issued ACK for a mutated blinding lane")
		}
	})
	t.Run("noncanonical s plus q digits", func(t *testing.T) {
		bad := cvCloneLeafV1ForTest(fixture.leaf)
		lifted := new(big.Int).Add(
			fr.Modulus(),
			fixture.witness.scalars[0].BigInt(new(big.Int)),
		)
		base := new(big.Int).Lsh(big.NewInt(1), fixture.context.profile.chunkBits)
		for chunk := range bad.receivers[0].encryptedShare.scalarChunks {
			digit := new(big.Int).Mod(lifted, base)
			lifted.Div(lifted, base)
			var message bls12381.G1Affine
			message.ScalarMultiplication(&genG1, digit)
			ciphertext, err := cvEncryptPoint(
				&bad.receivers[0].receiverPublicKey,
				&message,
				fixture.witness.scalarCoins[0][chunk],
			)
			if err != nil {
				t.Fatal(err)
			}
			bad.receivers[0].encryptedShare.scalarChunks[chunk] = ciphertext
		}
		if lifted.Sign() != 0 {
			t.Fatal("fixture chunk width did not cover s+q")
		}
		bad.digest = cvLeafV1Digest(bad)
		if _, err := apvssIssueLaneACKV1(
			&fixture.context,
			bad,
			1,
			fixture.receiverSecrets[0],
		); err == nil {
			t.Fatal("issued ACK for a noncanonical s+q digit encoding")
		}
	})
}

func TestAPVSSACKFallbackPartitionRejectsMalformedSetsV1(t *testing.T) {
	fixture := apvssFixtureV1(t, 7, 2)
	allACK, err := apvssBuildPrototypeV1(
		&fixture.context, fixture.leaf, fixture.receiverSecrets, &fixture.witness, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	withFallback, err := apvssBuildPrototypeV1(
		&fixture.context, fixture.leaf, fixture.receiverSecrets, &fixture.witness, []int{1},
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("I empty carries proof", func(t *testing.T) {
		bad := apvssClonePrototypeV1ForTest(allACK)
		bad.fallbackProofs = append(bad.fallbackProofs, withFallback.fallbackProofs[0])
		if err := apvssVerifyPrototypeV1(&fixture.context, bad); err == nil {
			t.Fatal("all-ACK leaf accepted a fallback proof")
		}
	})
	t.Run("I nonempty missing proof", func(t *testing.T) {
		bad := apvssClonePrototypeV1ForTest(withFallback)
		bad.fallbackProofs = nil
		if err := apvssVerifyPrototypeV1(&fixture.context, bad); err == nil {
			t.Fatal("accepted an uncovered receiver")
		}
	})
	t.Run("ACK and I overlap", func(t *testing.T) {
		bad := apvssClonePrototypeV1ForTest(withFallback)
		bad.acks = append([]apvssLaneACKV1{allACK.acks[0]}, bad.acks...)
		bad.acks = bad.acks[:len(bad.acks)-1]
		if err := apvssVerifyPrototypeV1(&fixture.context, bad); err == nil {
			t.Fatal("accepted overlapping ACK and fallback sets")
		}
	})
	t.Run("duplicate ACK", func(t *testing.T) {
		bad := apvssClonePrototypeV1ForTest(allACK)
		bad.acks[1] = bad.acks[0]
		if err := apvssVerifyPrototypeV1(&fixture.context, bad); err == nil {
			t.Fatal("accepted duplicate ACK receiver indices")
		}
	})
	t.Run("out of order ACK", func(t *testing.T) {
		bad := apvssClonePrototypeV1ForTest(allACK)
		bad.acks[0], bad.acks[1] = bad.acks[1], bad.acks[0]
		if err := apvssVerifyPrototypeV1(&fixture.context, bad); err == nil {
			t.Fatal("accepted out-of-order ACK receiver indices")
		}
	})
	t.Run("duplicate fallback", func(t *testing.T) {
		bad := apvssClonePrototypeV1ForTest(withFallback)
		bad.acks = bad.acks[:len(bad.acks)-1]
		bad.fallbackProofs = append(bad.fallbackProofs, bad.fallbackProofs[0])
		if err := apvssVerifyPrototypeV1(&fixture.context, bad); err == nil {
			t.Fatal("accepted duplicate fallback receiver indices")
		}
	})
	t.Run("I exceeds f", func(t *testing.T) {
		if _, err := apvssBuildPrototypeV1(
			&fixture.context,
			fixture.leaf,
			fixture.receiverSecrets,
			&fixture.witness,
			[]int{1, 2, 3},
		); err == nil {
			t.Fatal("built an APVSS leaf with |I| > f")
		}
	})
	t.Run("fallback proof mutation", func(t *testing.T) {
		bad := apvssClonePrototypeV1ForTest(withFallback)
		proxy := &cvLeafV1{proof: bad.fallbackProofs[0].proof}
		clonedProof := cvCloneLeafV1ForTest(proxy).proof
		one := fr.One()
		clonedProof.sharing.zScalar.Add(&clonedProof.sharing.zScalar, &one)
		bad.fallbackProofs[0].proof = clonedProof
		if err := apvssVerifyPrototypeV1(&fixture.context, bad); err == nil {
			t.Fatal("accepted a mutated exact fallback proof")
		}
	})
	t.Run("ciphertext replacement after fallback proof", func(t *testing.T) {
		bad := apvssClonePrototypeV1ForTest(withFallback)
		bad.leaf = cvCloneLeafV1ForTest(withFallback.leaf)
		bad.leaf.receivers[0].encryptedShare.scalarChunks[0].c.Add(
			&bad.leaf.receivers[0].encryptedShare.scalarChunks[0].c,
			&genG1,
		)
		bad.leaf.digest = cvLeafV1Digest(bad.leaf)
		if err := apvssVerifyPrototypeV1(&fixture.context, bad); err == nil {
			t.Fatal("fallback proof accepted a replaced ciphertext")
		}
	})
}
