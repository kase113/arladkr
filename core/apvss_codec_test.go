package core

import (
	"bytes"
	"testing"
)

func TestAPVSSLeafPrototypeCodecRoundTripV1(t *testing.T) {
	fixture := apvssFixtureV1(t, 7, 2)
	for _, profile := range []struct {
		name     string
		fallback []int
	}{
		{name: "I_empty"},
		{name: "I_1", fallback: []int{1}},
		{name: "I_f", fallback: []int{1, 2}},
	} {
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
			wire, err := apvssLeafPrototypeV1CanonicalBytes(prototype)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := apvssDecodeLeafPrototypeV1(wire, &fixture.context)
			if err != nil {
				t.Fatalf("decode APVSS leaf: %v", err)
			}
			encodedAgain, err := apvssLeafPrototypeV1CanonicalBytes(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encodedAgain, wire) {
				t.Fatal("APVSS leaf codec changed canonical bytes")
			}
			wantDigest := hashBytes([]byte(apvssLeafDigestDomain), wire)
			if !bytes.Equal(decoded.digest, wantDigest) || !bytes.Equal(prototype.digest, wantDigest) {
				t.Fatal("APVSS leaf digest did not bind canonical wire")
			}
		})
	}
}

func TestAPVSSLeafPrototypeCodecRejectsMutationV1(t *testing.T) {
	fixture := apvssFixtureV1(t, 7, 2)
	prototype, err := apvssBuildPrototypeV1(
		&fixture.context,
		fixture.leaf,
		fixture.receiverSecrets,
		&fixture.witness,
		[]int{1},
	)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := apvssLeafPrototypeV1CanonicalBytes(prototype)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("trailing bytes", func(t *testing.T) {
		bad := append(append([]byte(nil), wire...), 0)
		if _, err := apvssDecodeLeafPrototypeV1(bad, &fixture.context); err == nil {
			t.Fatal("accepted APVSS leaf with trailing bytes")
		}
	})
	t.Run("signature response", func(t *testing.T) {
		bad := apvssClonePrototypeV1ForTest(prototype)
		one := cvTestScalar(1)
		bad.acks[0].signature.z.Add(&bad.acks[0].signature.z, &one)
		badWire, err := apvssLeafPrototypeV1CanonicalBytes(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := apvssDecodeLeafPrototypeV1(badWire, &fixture.context); err == nil {
			t.Fatal("accepted APVSS leaf with a mutated ACK response")
		}
	})
	t.Run("wrong context", func(t *testing.T) {
		other := cvCloneLeafContextV1(fixture.context)
		other.epoch++
		if _, err := apvssDecodeLeafPrototypeV1(wire, &other); err == nil {
			t.Fatal("accepted APVSS leaf in another epoch")
		}
	})
	t.Run("fallback response", func(t *testing.T) {
		bad := apvssClonePrototypeV1ForTest(prototype)
		proxy := &cvLeafV1{proof: bad.fallbackProofs[0].proof}
		bad.fallbackProofs[0].proof = cvCloneLeafV1ForTest(proxy).proof
		one := cvTestScalar(1)
		bad.fallbackProofs[0].proof.sharing.zScalar.Add(
			&bad.fallbackProofs[0].proof.sharing.zScalar,
			&one,
		)
		badWire, err := apvssLeafPrototypeV1CanonicalBytes(bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := apvssDecodeLeafPrototypeV1(badWire, &fixture.context); err == nil {
			t.Fatal("accepted APVSS leaf with a mutated fallback proof")
		}
	})
}

func TestAPVSSLaneACKMessageCodecV1(t *testing.T) {
	fixture := apvssFixtureV1(t, 4, 1)
	ack, err := apvssIssueLaneACKV1(
		&fixture.context,
		fixture.leaf,
		1,
		fixture.receiverSecrets[0],
	)
	if err != nil {
		t.Fatal(err)
	}
	message := &apvssLaneACKMessageV1{
		dealerID:   fixture.leaf.dealerID,
		leafDigest: append([]byte(nil), fixture.leaf.digest...),
		ack:        ack,
	}
	wire, err := apvssLaneACKMessageV1CanonicalBytes(message)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := apvssDecodeLaneACKMessageV1(wire, fixture.leaf)
	if err != nil {
		t.Fatalf("decode ACK message: %v", err)
	}
	encodedAgain, err := apvssLaneACKMessageV1CanonicalBytes(decoded)
	if err != nil || !bytes.Equal(encodedAgain, wire) {
		t.Fatal("ACK message codec changed canonical bytes")
	}

	badLeaf := cvCloneLeafV1ForTest(fixture.leaf)
	badLeaf.dealerID++
	badLeaf.digest = cvLeafV1Digest(badLeaf)
	if _, err := apvssDecodeLaneACKMessageV1(wire, badLeaf); err == nil {
		t.Fatal("ACK message replayed for another dealer leaf")
	}
}
