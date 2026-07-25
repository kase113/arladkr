package core

import (
	"bytes"
	"encoding/binary"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestCVLeafCodecRoundTripAndRejectsTrailingBytes(t *testing.T) {
	profile := cvChunkProfile{chunkBits: 8, maxComponents: 1}
	chunks, err := cvChunkCount(profile)
	if err != nil {
		t.Fatal(err)
	}
	receiverSecret := cvTestScalar(13)
	receiverKey, err := cvReceiverPublicKey(receiverSecret)
	if err != nil {
		t.Fatal(err)
	}
	context := cvLeafContextV1{
		sessionID:          []byte("codec-leaf-session"),
		epoch:              23,
		sharingDegree:      0,
		profile:            profile,
		receiverPublicKeys: []bls12381.G1Affine{receiverKey},
		dealerSetPolicy:    []byte("first-f_o-plus-one"),
		proofProfile:       cvLeafV1GrothProofProfile,
	}
	leaf, err := cvReferenceDealV1(
		context,
		41,
		[]fr.Element{cvTestScalar(5)},
		[]fr.Element{cvTestScalar(7)},
		[][]fr.Element{cvTestCoins(chunks, 101)},
		[]fr.Element{cvTestScalar(401)},
	)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvLeafV1CanonicalBytes(leaf)
	if err != nil {
		t.Fatal(err)
	}
	proofWire, err := cvLeafProofV1CanonicalBytes(leaf.proof)
	if err != nil {
		t.Fatal(err)
	}
	proofSize, err := cvLeafProofWireSizeV1(&context)
	if err != nil {
		t.Fatal(err)
	}
	if len(proofWire) != proofSize {
		t.Fatalf("LeafV1 proof wire size = %d, want %d", len(proofWire), proofSize)
	}
	leafSize, err := cvLeafWireSizeV1(&context)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != leafSize {
		t.Fatalf("LeafV1 wire size = %d, want %d", len(wire), leafSize)
	}

	decoded, err := cvDecodeLeafV1(wire, &context)
	if err != nil {
		t.Fatalf("decode canonical leaf: %v", err)
	}
	decodedWire, err := cvLeafV1CanonicalBytes(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedWire, wire) || !bytes.Equal(decoded.digest, leaf.digest) {
		t.Fatal("decoded LeafV1 did not preserve its canonical wire or digest")
	}

	trailing := append(append([]byte(nil), wire...), 0)
	if _, err := cvDecodeLeafV1(trailing, &context); err == nil {
		t.Fatal("accepted trailing LeafV1 bytes")
	}

	if _, err := cvDecodeLeafProofV1(proofWire, &context); err != nil {
		t.Fatalf("decode canonical LeafV1 proof: %v", err)
	}
	firstVectorCountOffset := 6*bls12381.SizeOfG1AffineCompressed + 4*fr.Bytes
	for _, test := range []struct {
		name  string
		count uint32
	}{
		{name: "undersized vector", count: cvChunkProofRepetitions - 1},
		{name: "oversized vector", count: cvChunkProofRepetitions + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := append([]byte(nil), proofWire...)
			binary.BigEndian.PutUint32(bad[firstVectorCountOffset:firstVectorCountOffset+4], test.count)
			if _, err := cvDecodeLeafProofV1(bad, &context); err == nil {
				t.Fatalf("accepted LeafV1 proof with vector count %d", test.count)
			}
		})
	}
	t.Run("proof trailing bytes", func(t *testing.T) {
		bad := append(append([]byte(nil), proofWire...), 0)
		if _, err := cvDecodeLeafProofV1(bad, &context); err == nil {
			t.Fatal("accepted trailing LeafV1 proof bytes")
		}
	})
	t.Run("noncanonical scalar", func(t *testing.T) {
		bad := append([]byte(nil), proofWire...)
		firstScalarOffset := 6 * bls12381.SizeOfG1AffineCompressed
		copy(bad[firstScalarOffset:firstScalarOffset+fr.Bytes], fr.Modulus().FillBytes(make([]byte, fr.Bytes)))
		if _, err := cvDecodeLeafProofV1(bad, &context); err == nil {
			t.Fatal("accepted noncanonical LeafV1 proof scalar")
		}
	})
	t.Run("noncanonical point", func(t *testing.T) {
		bad := append([]byte(nil), proofWire...)
		bad[0] &^= 0x80
		if _, err := cvDecodeLeafProofV1(bad, &context); err == nil {
			t.Fatal("accepted noncanonical LeafV1 proof point")
		}
	})
}

func TestCVLeafCodecSizesAllowLargeValidContext(t *testing.T) {
	const receiverCount = 256
	keys := make([]bls12381.G1Affine, receiverCount)
	for i := range keys {
		var err error
		keys[i], err = cvReceiverPublicKey(cvTestScalar(uint64(i + 1)))
		if err != nil {
			t.Fatal(err)
		}
	}
	context := cvLeafContextV1{
		sessionID:          []byte("codec-large-leaf-session"),
		epoch:              24,
		sharingDegree:      85,
		profile:            cvChunkProfile{chunkBits: 8, maxComponents: 86},
		receiverPublicKeys: keys,
		dealerSetPolicy:    []byte("first-f_o-plus-one"),
		proofProfile:       cvLeafV1GrothProofProfile,
	}
	if err := cvValidateLeafContextV1(&context); err != nil {
		t.Fatalf("large context is not valid: %v", err)
	}
	proofSize, err := cvLeafProofWireSizeV1(&context)
	if err != nil {
		t.Fatal(err)
	}
	leafSize, err := cvLeafWireSizeV1(&context)
	if err != nil {
		t.Fatal(err)
	}
	for name, size := range map[string]int{"proof": proofSize, "leaf": leafSize} {
		if size <= cvMaxCanonicalFieldBytes {
			t.Fatalf("large %s size = %d, want greater than legacy 16 MiB cap", name, size)
		}
		if size > 64<<20 {
			t.Fatalf("large %s size = %d, exceeds independent 64 MiB safety cap", name, size)
		}
	}
}

func TestCVLeafCodecRoundTripWithMultipleReceiversAndDegree(t *testing.T) {
	context, _, leaves := cvM2Fixture(t)
	wire, err := cvLeafV1CanonicalBytes(leaves[0])
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeLeafV1(wire, &context)
	if err != nil {
		t.Fatalf("decode multi-receiver degree-%d LeafV1: %v", context.sharingDegree, err)
	}
	decodedWire, err := cvLeafV1CanonicalBytes(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedWire, wire) {
		t.Fatal("multi-receiver LeafV1 roundtrip changed canonical wire")
	}
}

func TestCVReceiptCodecRoundTripAndRejectsTampering(t *testing.T) {
	context, secrets, leaves := cvM2Fixture(t)
	agg, err := cvAggV1(&context, leaves)
	if err != nil {
		t.Fatal(err)
	}
	_, receipt, err := cvDecShareV1(agg, secrets[0], 1)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvReceiptV1CanonicalBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := cvDecodeReceiptV1(wire, &context, agg, 1)
	if err != nil {
		t.Fatalf("decode canonical receipt: %v", err)
	}
	decodedWire, err := cvReceiptV1CanonicalBytes(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedWire, wire) || !bytes.Equal(decoded.digest, receipt.digest) {
		t.Fatal("decoded receipt did not preserve its canonical wire or digest")
	}

	t.Run("aggregate binding", func(t *testing.T) {
		bad := append([]byte(nil), wire...)
		aggregateOffset := 4 + len(cvReceiptV1Domain) + 4
		bad[aggregateOffset] ^= 1
		if _, err := cvDecodeReceiptV1(bad, &context, agg, 1); err == nil {
			t.Fatal("accepted receipt bound to another aggregate")
		}
	})
	t.Run("receiver binding", func(t *testing.T) {
		if _, err := cvDecodeReceiptV1(wire, &context, agg, 2); err == nil {
			t.Fatal("accepted receipt under another receiver index")
		}
	})
	t.Run("proof mutation", func(t *testing.T) {
		bad := append([]byte(nil), wire...)
		bad[len(bad)-1] ^= 1
		if _, err := cvDecodeReceiptV1(bad, &context, agg, 1); err == nil {
			t.Fatal("accepted receipt with a mutated DLEQ response")
		}
	})
	t.Run("trailing bytes", func(t *testing.T) {
		bad := append(append([]byte(nil), wire...), 0)
		if _, err := cvDecodeReceiptV1(bad, &context, agg, 1); err == nil {
			t.Fatal("accepted trailing receipt bytes")
		}
	})
}
