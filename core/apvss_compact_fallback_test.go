package core

import (
	"bytes"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func apvssCloneCompactFallbackProofV1ForTest(in *apvssCompactFallbackProofV1) *apvssCompactFallbackProofV1 {
	if in == nil {
		return nil
	}
	out := *in
	out.link = apvssCloneCompactLinkProofV1ForTest(in.link)
	out.digitRange = apvssCloneCompactRangeProofV1ForTest(in.digitRange)
	if in.comparator != nil {
		comparator := *in.comparator
		comparator.complementCommitments = append(
			[]bls12381.G1Affine(nil), in.comparator.complementCommitments...,
		)
		comparator.borrowCommitments = append(
			[]bls12381.G1Affine(nil), in.comparator.borrowCommitments...,
		)
		comparator.complementRange = apvssCloneCompactRangeProofV1ForTest(in.comparator.complementRange)
		comparator.borrowRange = apvssCloneCompactRangeProofV1ForTest(in.comparator.borrowRange)
		out.comparator = &comparator
	}
	return &out
}

func TestAPVSSCompactFallbackRangeLinkComparatorV1(t *testing.T) {
	fixture := apvssFixtureV1(t, 7, 2)
	proof, err := apvssProveCompactFallbackV1(fixture.leaf, &fixture.witness, []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := apvssVerifyCompactFallbackV1(fixture.leaf, proof); err != nil {
		t.Fatalf("valid compact fallback proof rejected: %v", err)
	}
	wire, err := apvssCompactFallbackProofV1CanonicalBytes(fixture.leaf, proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) == 0 {
		t.Fatal("empty compact fallback proof wire")
	}
	decoded, err := apvssDecodeCompactFallbackProofV1(wire, fixture.leaf)
	if err != nil {
		t.Fatalf("decode compact fallback proof: %v", err)
	}
	decodedWire, err := apvssCompactFallbackProofV1CanonicalBytes(fixture.leaf, decoded)
	if err != nil || !bytes.Equal(wire, decodedWire) {
		t.Fatal("compact fallback proof changed across wire round-trip")
	}
	if _, err := apvssDecodeCompactFallbackProofV1(append(wire, 0), fixture.leaf); err == nil {
		t.Fatal("accepted compact fallback proof with trailing bytes")
	}
}

func TestAPVSSCompactPrototypeRuntimeAndWireV1(t *testing.T) {
	fixture := apvssFixtureV1(t, 7, 2)
	testCases := []struct {
		name    string
		indices []int
	}{
		{name: "I_empty"},
		{name: "I_1", indices: []int{1}},
		{name: "I_f", indices: []int{1, 2}},
	}
	previousProofBytes := 0
	var withTwoFallbacks *apvssLeafPrototypeV1
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			prototype, err := apvssBuildPrototypeWithFallbackProfileV1(
				&fixture.context,
				fixture.leaf,
				fixture.receiverSecrets,
				&fixture.witness,
				testCase.indices,
				apvssFallbackCompactBatchProfileV1,
			)
			if err != nil {
				t.Fatal(err)
			}
			if got := apvssPrototypeFallbackCountV1(prototype); got != len(testCase.indices) {
				t.Fatalf("compact fallback count = %d, want %d", got, len(testCase.indices))
			}
			if len(prototype.acks) != 7-len(testCase.indices) {
				t.Fatalf("compact ACK count = %d", len(prototype.acks))
			}
			if err := apvssVerifyPrototypeV1(&fixture.context, prototype); err != nil {
				t.Fatalf("verify compact prototype: %v", err)
			}
			proofBytes, err := apvssProofMaterialBytesV1(prototype)
			if err != nil {
				t.Fatal(err)
			}
			if proofBytes <= previousProofBytes {
				t.Fatalf("compact proof bytes did not grow with |I|: previous=%d current=%d", previousProofBytes, proofBytes)
			}
			previousProofBytes = proofBytes
			wire, err := apvssLeafPrototypeV1CanonicalBytes(prototype)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("acks=%d fallback=%d proof_bytes=%d leaf_wire_bytes=%d",
				len(prototype.acks), len(testCase.indices), proofBytes, len(wire))
			decoded, err := apvssDecodeLeafPrototypeV1(wire, &fixture.context)
			if err != nil {
				t.Fatalf("decode compact prototype: %v", err)
			}
			encodedAgain, err := apvssLeafPrototypeV1CanonicalBytes(decoded)
			if err != nil || !bytes.Equal(encodedAgain, wire) {
				t.Fatal("compact APVSS prototype changed across wire round-trip")
			}
			if len(testCase.indices) == 2 {
				withTwoFallbacks = prototype
			}
		})
	}
	if withTwoFallbacks == nil {
		t.Fatal("missing compact mutation fixture")
	}
	one := fr.One()
	t.Run("cross profile replay", func(t *testing.T) {
		bad := apvssClonePrototypeV1ForTest(withTwoFallbacks)
		bad.fallbackProfile = apvssFallbackExactLaneProfileV1
		if err := apvssVerifyPrototypeV1(&fixture.context, bad); err == nil {
			t.Fatal("accepted compact proof under exact profile")
		}
	})
	t.Run("ordered I", func(t *testing.T) {
		bad := apvssClonePrototypeV1ForTest(withTwoFallbacks)
		bad.fallbackIndices[0], bad.fallbackIndices[1] = bad.fallbackIndices[1], bad.fallbackIndices[0]
		if err := apvssVerifyPrototypeV1(&fixture.context, bad); err == nil {
			t.Fatal("accepted compact proof with reordered outer I")
		}
	})
	t.Run("missing I member", func(t *testing.T) {
		bad := apvssClonePrototypeV1ForTest(withTwoFallbacks)
		bad.fallbackIndices = bad.fallbackIndices[:1]
		if err := apvssVerifyPrototypeV1(&fixture.context, bad); err == nil {
			t.Fatal("accepted compact proof with a missing outer I member")
		}
	})
	t.Run("extra I member", func(t *testing.T) {
		bad := apvssClonePrototypeV1ForTest(withTwoFallbacks)
		bad.fallbackIndices = append(bad.fallbackIndices, 3)
		if err := apvssVerifyPrototypeV1(&fixture.context, bad); err == nil {
			t.Fatal("accepted compact proof with an extra outer I member")
		}
	})
	t.Run("proof mutation", func(t *testing.T) {
		bad := apvssClonePrototypeV1ForTest(withTwoFallbacks)
		bad.compactFallback.digitRange.tHat.Add(&bad.compactFallback.digitRange.tHat, &one)
		badWire, err := apvssLeafPrototypeV1CanonicalBytes(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := apvssDecodeLeafPrototypeV1(badWire, &fixture.context); err == nil {
			t.Fatal("decoded compact APVSS prototype with a mutated proof")
		}
	})
	t.Run("trailing leaf bytes", func(t *testing.T) {
		wire, err := apvssLeafPrototypeV1CanonicalBytes(withTwoFallbacks)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := apvssDecodeLeafPrototypeV1(append(wire, 0), &fixture.context); err == nil {
			t.Fatal("decoded compact APVSS prototype with trailing bytes")
		}
	})
}

func BenchmarkAPVSSCompactFallbackProveN7F2V1(b *testing.B) {
	fixture := apvssFixtureV1(b, 7, 2)
	proof, err := apvssProveCompactFallbackV1(fixture.leaf, &fixture.witness, []int{1, 2})
	if err != nil {
		b.Fatal(err)
	}
	wire, err := apvssCompactFallbackProofV1CanonicalBytes(fixture.leaf, proof)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := apvssProveCompactFallbackV1(fixture.leaf, &fixture.witness, []int{1, 2}); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(len(wire)), "proof_bytes")
}

func BenchmarkAPVSSCompactFallbackVerifyN7F2V1(b *testing.B) {
	fixture := apvssFixtureV1(b, 7, 2)
	proof, err := apvssProveCompactFallbackV1(fixture.leaf, &fixture.witness, []int{1, 2})
	if err != nil {
		b.Fatal(err)
	}
	wire, err := apvssCompactFallbackProofV1CanonicalBytes(fixture.leaf, proof)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := apvssVerifyCompactFallbackV1(fixture.leaf, proof); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(len(wire)), "proof_bytes")
}

func TestAPVSSCompactFallbackRejectsMutationV1(t *testing.T) {
	fixture := apvssFixtureV1(t, 7, 2)
	proof, err := apvssProveCompactFallbackV1(fixture.leaf, &fixture.witness, []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	one := fr.One()

	t.Run("scalar digit range", func(t *testing.T) {
		bad := apvssCloneCompactFallbackProofV1ForTest(proof)
		bad.digitRange.tHat.Add(&bad.digitRange.tHat, &one)
		if err := apvssVerifyCompactFallbackV1(fixture.leaf, bad); err == nil {
			t.Fatal("accepted mutated scalar digit range")
		}
	})
	t.Run("complement range", func(t *testing.T) {
		bad := apvssCloneCompactFallbackProofV1ForTest(proof)
		bad.comparator.complementRange.tHat.Add(&bad.comparator.complementRange.tHat, &one)
		if err := apvssVerifyCompactFallbackV1(fixture.leaf, bad); err == nil {
			t.Fatal("accepted mutated complement range")
		}
	})
	t.Run("borrow range", func(t *testing.T) {
		bad := apvssCloneCompactFallbackProofV1ForTest(proof)
		bad.comparator.borrowRange.tHat.Add(&bad.comparator.borrowRange.tHat, &one)
		if err := apvssVerifyCompactFallbackV1(fixture.leaf, bad); err == nil {
			t.Fatal("accepted mutated borrow range")
		}
	})
	t.Run("subtraction relation", func(t *testing.T) {
		bad := apvssCloneCompactFallbackProofV1ForTest(proof)
		bad.comparator.zRelation.Add(&bad.comparator.zRelation, &one)
		if err := apvssVerifyCompactFallbackV1(fixture.leaf, bad); err == nil {
			t.Fatal("accepted mutated canonical subtraction relation")
		}
	})
	t.Run("complement commitment", func(t *testing.T) {
		bad := apvssCloneCompactFallbackProofV1ForTest(proof)
		bad.comparator.complementCommitments[0].Add(
			&bad.comparator.complementCommitments[0], &genG1,
		)
		if err := apvssVerifyCompactFallbackV1(fixture.leaf, bad); err == nil {
			t.Fatal("accepted mutated complement commitment")
		}
	})
	t.Run("borrow commitment", func(t *testing.T) {
		bad := apvssCloneCompactFallbackProofV1ForTest(proof)
		bad.comparator.borrowCommitments[0].Add(
			&bad.comparator.borrowCommitments[0], &genG1,
		)
		if err := apvssVerifyCompactFallbackV1(fixture.leaf, bad); err == nil {
			t.Fatal("accepted mutated borrow commitment")
		}
	})
}

func TestAPVSSCompactComparatorRejectsSPlusQDigitsV1(t *testing.T) {
	fixture := apvssFixtureV1(t, 7, 2)
	_, _, chunks, err := cvProfile(fixture.context.profile)
	if err != nil {
		t.Fatal(err)
	}
	modulusDigits, err := apvssCompactModulusDigitsV1(chunks)
	if err != nil {
		t.Fatal(err)
	}
	lifted := new(big.Int).Add(
		fr.Modulus(), fixture.witness.scalars[0].BigInt(new(big.Int)),
	)
	encoded := lifted.FillBytes(make([]byte, chunks))
	scalarDigits := make([]uint64, chunks)
	for i := range scalarDigits {
		scalarDigits[i] = uint64(encoded[chunks-1-i])
	}
	wrappedComplement, err := apvssCompactComplementDigitsV1(fixture.witness.scalars[0], chunks)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := apvssCompactComparatorBorrowsV1(modulusDigits, scalarDigits, wrappedComplement); err == nil {
		t.Fatal("canonical comparator accepted the radix encoding q+s")
	}
}
