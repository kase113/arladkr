package core

import (
	"bytes"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type apvssTestFixture struct {
	context         cvLeafContext
	leaf            *cvLeaf
	receiverSecrets []fr.Element
	witness         apvssDealerWitness
}

func apvssFixture(tb testing.TB, receivers, f int) apvssTestFixture {
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
	context := cvLeafContext{
		sessionID:          []byte("apvss-ack-test-session"),
		epoch:              17,
		sharingDegree:      f,
		profile:            profile,
		receiverPublicKeys: keys,
		dealerSetPolicy:    []byte("availability-then-local-valid-k"),
		proofProfile:       cvLeafStructuralProofProfile,
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
	leaf, err := cvReferenceDeal(
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
	witness := apvssDealerWitness{
		scalars:       make([]fr.Element, receivers),
		blindings:     make([]fr.Element, receivers),
		scalarCoins:   scalarCoins,
		blindingCoins: blindingCoins,
	}
	for i := 0; i < receivers; i++ {
		witness.scalars[i] = evalPolyInt(scalarCoefficients, int64(i+1))
		witness.blindings[i] = evalPolyInt(blindingCoefficients, int64(i+1))
	}
	return apvssTestFixture{
		context:         context,
		leaf:            leaf,
		receiverSecrets: secrets,
		witness:         witness,
	}
}

func apvssClonePrototypeForTest(in *apvssLeafPrototype) *apvssLeafPrototype {
	out := *in
	out.acks = append([]apvssLaneACK(nil), in.acks...)
	out.fallbackProofs = append([]apvssFallbackProof(nil), in.fallbackProofs...)
	out.fallbackIndices = append([]int(nil), in.fallbackIndices...)
	out.compactFallback = apvssCloneCompactFallbackProofForTest(in.compactFallback)
	return &out
}

func TestAPVSSPrototypeACKFallbackProfilesV1(t *testing.T) {
	fixture := apvssFixture(t, 7, 2)
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
			prototype, err := apvssBuildPrototype(
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
			if err := apvssVerifyPrototype(&fixture.context, prototype); err != nil {
				t.Fatalf("valid APVSS prototype rejected: %v", err)
			}
			proofBytes, err := apvssProofMaterialBytes(prototype)
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

func TestAPVSSFallbackBackendSelectionFailsClosedV1(t *testing.T) {
	fixture := apvssFixture(t, 7, 2)
	compact, err := apvssBuildPrototypeWithFallbackProfile(
		&fixture.context,
		fixture.leaf,
		fixture.receiverSecrets,
		&fixture.witness,
		[]int{1, 2},
		apvssFallbackCompactBatchProfile,
	)
	if err != nil {
		t.Fatalf("build experimental compact APVSS fallback: %v", err)
	}
	if err := apvssVerifyPrototype(&fixture.context, compact); err != nil {
		t.Fatalf("verify experimental compact APVSS fallback: %v", err)
	}
	if _, err := apvssBuildPrototypeWithFallbackProfile(
		&fixture.context,
		fixture.leaf,
		fixture.receiverSecrets,
		&fixture.witness,
		[]int{1, 2},
		"unknown-fallback",
	); err == nil {
		t.Fatal("built APVSS fallback using an unknown profile")
	}

	prototype, err := apvssBuildPrototype(
		&fixture.context,
		fixture.leaf,
		fixture.receiverSecrets,
		&fixture.witness,
		[]int{1, 2},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{apvssFallbackCompactBatchProfile, "unknown-fallback"} {
		bad := apvssClonePrototypeForTest(prototype)
		bad.fallbackProfile = profile
		if err := apvssVerifyPrototype(&fixture.context, bad); err == nil {
			t.Fatalf("verified APVSS fallback after profile replay to %q", profile)
		}
	}
	for _, profile := range []string{
		apvssFallbackExactLaneProfile,
		apvssFallbackCompactBatchProfile,
		"unknown-fallback",
	} {
		if err := apvssRequireProductionFallbackBackend(profile); err == nil {
			t.Fatalf("admitted incomplete APVSS production fallback profile %q", profile)
		}
	}
}

func TestAPVSSFallbackSetStatementBindingV1(t *testing.T) {
	fixture := apvssFixture(t, 7, 2)
	digest, err := apvssFallbackSetStatementDigest(
		fixture.leaf,
		[]int{1, 2},
		apvssFallbackExactLaneProfile,
	)
	if err != nil {
		t.Fatal(err)
	}
	compactDigest, err := apvssFallbackSetStatementDigest(
		fixture.leaf,
		[]int{1, 2},
		apvssFallbackCompactBatchProfile,
	)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(digest, compactDigest) {
		t.Fatal("fallback statement digest did not bind proof profile")
	}
	otherSetDigest, err := apvssFallbackSetStatementDigest(
		fixture.leaf,
		[]int{1},
		apvssFallbackExactLaneProfile,
	)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(digest, otherSetDigest) {
		t.Fatal("fallback statement digest did not bind ordered I")
	}
	if _, err := apvssFallbackSetStatementDigest(
		fixture.leaf,
		[]int{2, 1},
		apvssFallbackExactLaneProfile,
	); err == nil {
		t.Fatal("fallback statement accepted a reordered I")
	}

	mutated := cvCloneLeafForTest(fixture.leaf)
	mutated.receivers[0].encryptedShare.scalarChunks[0].c.Add(
		&mutated.receivers[0].encryptedShare.scalarChunks[0].c,
		&genG1,
	)
	mutatedDigest, err := apvssFallbackSetStatementDigest(
		mutated,
		[]int{1, 2},
		apvssFallbackExactLaneProfile,
	)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(digest, mutatedDigest) {
		t.Fatal("fallback statement digest did not bind complete ciphertexts")
	}
}

func TestAPVSSFallbackWitnessRelationGateV1(t *testing.T) {
	fixture := apvssFixture(t, 4, 1)
	if err := apvssValidateFallbackLaneWitness(
		fixture.leaf,
		1,
		fixture.witness.scalars[0],
		fixture.witness.blindings[0],
		fixture.witness.scalarCoins[0],
		fixture.witness.blindingCoins[0],
	); err != nil {
		t.Fatalf("valid APVSS fallback witness rejected: %v", err)
	}

	badScalar := fixture.witness.scalars[0]
	one := fr.One()
	badScalar.Add(&badScalar, &one)
	if err := apvssValidateFallbackLaneWitness(
		fixture.leaf,
		1,
		badScalar,
		fixture.witness.blindings[0],
		fixture.witness.scalarCoins[0],
		fixture.witness.blindingCoins[0],
	); err == nil {
		t.Fatal("fallback relation accepted a different scalar/radix witness")
	}

	badBlinding := fixture.witness.blindings[0]
	badBlinding.Add(&badBlinding, &one)
	if err := apvssValidateFallbackLaneWitness(
		fixture.leaf,
		1,
		fixture.witness.scalars[0],
		badBlinding,
		fixture.witness.scalarCoins[0],
		fixture.witness.blindingCoins[0],
	); err == nil {
		t.Fatal("fallback relation accepted a different Pedersen blinding witness")
	}

	badCoin := fixture.witness.scalarCoins[0][0]
	badCoin.Add(&badCoin, &one)
	badCoins := append([]fr.Element(nil), fixture.witness.scalarCoins[0]...)
	badCoins[0] = badCoin
	if err := apvssValidateFallbackLaneWitness(
		fixture.leaf,
		1,
		fixture.witness.scalars[0],
		fixture.witness.blindings[0],
		badCoins,
		fixture.witness.blindingCoins[0],
	); err == nil {
		t.Fatal("fallback relation accepted a different ciphertext randomness witness")
	}
}

func TestAPVSSACKStrictDecryptionAndStatementBindingV1(t *testing.T) {
	fixture := apvssFixture(t, 4, 1)
	ack, err := apvssIssueLaneACK(&fixture.context, fixture.leaf, 1, fixture.receiverSecrets[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := apvssVerifyLaneACK(fixture.leaf, &ack); err != nil {
		t.Fatalf("valid ACK rejected: %v", err)
	}

	t.Run("ciphertext replacement after ACK", func(t *testing.T) {
		bad := cvCloneLeafForTest(fixture.leaf)
		bad.receivers[0].encryptedShare.scalarChunks[0].c.Add(
			&bad.receivers[0].encryptedShare.scalarChunks[0].c,
			&genG1,
		)
		bad.digest = cvLeafDigest(bad)
		if err := apvssVerifyLaneACK(bad, &ack); err == nil {
			t.Fatal("ACK accepted a replaced ciphertext")
		}
	})
	t.Run("epoch replay", func(t *testing.T) {
		bad := cvCloneLeafForTest(fixture.leaf)
		bad.context.epoch++
		bad.digest = cvLeafDigest(bad)
		if err := apvssVerifyLaneACK(bad, &ack); err == nil {
			t.Fatal("ACK replayed across epochs")
		}
	})
	t.Run("dealer replay", func(t *testing.T) {
		bad := cvCloneLeafForTest(fixture.leaf)
		bad.dealerID++
		bad.digest = cvLeafDigest(bad)
		if err := apvssVerifyLaneACK(bad, &ack); err == nil {
			t.Fatal("ACK replayed across dealers")
		}
	})
	t.Run("receiver replay", func(t *testing.T) {
		badACK := ack
		badACK.receiverIndex = 2
		if err := apvssVerifyLaneACK(fixture.leaf, &badACK); err == nil {
			t.Fatal("ACK replayed for another receiver")
		}
	})
	t.Run("wrong receiver secret", func(t *testing.T) {
		if _, err := apvssIssueLaneACK(
			&fixture.context,
			fixture.leaf,
			1,
			fixture.receiverSecrets[1],
		); err == nil {
			t.Fatal("issued ACK using another receiver's secret")
		}
	})
	t.Run("wrong scalar opening", func(t *testing.T) {
		bad := cvCloneLeafForTest(fixture.leaf)
		bad.receivers[0].encryptedShare.scalarChunks[0].c.Add(
			&bad.receivers[0].encryptedShare.scalarChunks[0].c,
			&genG1,
		)
		bad.digest = cvLeafDigest(bad)
		if _, err := apvssIssueLaneACK(
			&fixture.context,
			bad,
			1,
			fixture.receiverSecrets[0],
		); err == nil {
			t.Fatal("issued ACK for a scalar that does not open V_i,j")
		}
	})
	t.Run("mutated blinding ciphertext", func(t *testing.T) {
		bad := cvCloneLeafForTest(fixture.leaf)
		bad.receivers[0].encryptedShare.blinding.c.Add(
			&bad.receivers[0].encryptedShare.blinding.c,
			&genG1,
		)
		bad.digest = cvLeafDigest(bad)
		if _, err := apvssIssueLaneACK(
			&fixture.context,
			bad,
			1,
			fixture.receiverSecrets[0],
		); err == nil {
			t.Fatal("issued ACK for a mutated blinding lane")
		}
	})
	t.Run("noncanonical s plus q digits", func(t *testing.T) {
		bad := cvCloneLeafForTest(fixture.leaf)
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
		bad.digest = cvLeafDigest(bad)
		if _, err := apvssIssueLaneACK(
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
	fixture := apvssFixture(t, 7, 2)
	allACK, err := apvssBuildPrototype(
		&fixture.context, fixture.leaf, fixture.receiverSecrets, &fixture.witness, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	withFallback, err := apvssBuildPrototype(
		&fixture.context, fixture.leaf, fixture.receiverSecrets, &fixture.witness, []int{1},
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("I empty carries proof", func(t *testing.T) {
		bad := apvssClonePrototypeForTest(allACK)
		bad.fallbackProofs = append(bad.fallbackProofs, withFallback.fallbackProofs[0])
		if err := apvssVerifyPrototype(&fixture.context, bad); err == nil {
			t.Fatal("all-ACK leaf accepted a fallback proof")
		}
	})
	t.Run("I nonempty missing proof", func(t *testing.T) {
		bad := apvssClonePrototypeForTest(withFallback)
		bad.fallbackProofs = nil
		if err := apvssVerifyPrototype(&fixture.context, bad); err == nil {
			t.Fatal("accepted an uncovered receiver")
		}
	})
	t.Run("ACK and I overlap", func(t *testing.T) {
		bad := apvssClonePrototypeForTest(withFallback)
		bad.acks = append([]apvssLaneACK{allACK.acks[0]}, bad.acks...)
		bad.acks = bad.acks[:len(bad.acks)-1]
		if err := apvssVerifyPrototype(&fixture.context, bad); err == nil {
			t.Fatal("accepted overlapping ACK and fallback sets")
		}
	})
	t.Run("duplicate ACK", func(t *testing.T) {
		bad := apvssClonePrototypeForTest(allACK)
		bad.acks[1] = bad.acks[0]
		if err := apvssVerifyPrototype(&fixture.context, bad); err == nil {
			t.Fatal("accepted duplicate ACK receiver indices")
		}
	})
	t.Run("out of order ACK", func(t *testing.T) {
		bad := apvssClonePrototypeForTest(allACK)
		bad.acks[0], bad.acks[1] = bad.acks[1], bad.acks[0]
		if err := apvssVerifyPrototype(&fixture.context, bad); err == nil {
			t.Fatal("accepted out-of-order ACK receiver indices")
		}
	})
	t.Run("duplicate fallback", func(t *testing.T) {
		bad := apvssClonePrototypeForTest(withFallback)
		bad.acks = bad.acks[:len(bad.acks)-1]
		bad.fallbackProofs = append(bad.fallbackProofs, bad.fallbackProofs[0])
		if err := apvssVerifyPrototype(&fixture.context, bad); err == nil {
			t.Fatal("accepted duplicate fallback receiver indices")
		}
	})
	t.Run("I exceeds f", func(t *testing.T) {
		if _, err := apvssBuildPrototype(
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
		bad := apvssClonePrototypeForTest(withFallback)
		proxy := &cvLeaf{proof: bad.fallbackProofs[0].proof}
		clonedProof := cvCloneLeafForTest(proxy).proof
		one := fr.One()
		clonedProof.sharing.zScalar.Add(&clonedProof.sharing.zScalar, &one)
		bad.fallbackProofs[0].proof = clonedProof
		if err := apvssVerifyPrototype(&fixture.context, bad); err == nil {
			t.Fatal("accepted a mutated exact fallback proof")
		}
	})
	t.Run("ciphertext replacement after fallback proof", func(t *testing.T) {
		bad := apvssClonePrototypeForTest(withFallback)
		bad.leaf = cvCloneLeafForTest(withFallback.leaf)
		bad.leaf.receivers[0].encryptedShare.scalarChunks[0].c.Add(
			&bad.leaf.receivers[0].encryptedShare.scalarChunks[0].c,
			&genG1,
		)
		bad.leaf.digest = cvLeafDigest(bad.leaf)
		if err := apvssVerifyPrototype(&fixture.context, bad); err == nil {
			t.Fatal("fallback proof accepted a replaced ciphertext")
		}
	})
}
