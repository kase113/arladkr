package core

import (
	"bytes"
	"fmt"
)

const apvssMaxLeafWireBytesV1 = cvMaxLeafWireBytesV1

func apvssHasLeafWireDomainV1(wire []byte) bool {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(apvssLeafWireDomain))
	return err == nil && bytes.Equal(domain, []byte(apvssLeafWireDomain))
}

func apvssValidatePartitionShapeV1(prototype *apvssLeafPrototypeV1) error {
	if prototype == nil || prototype.leaf == nil {
		return fmt.Errorf("invalid APVSS prototype leaf")
	}
	n := len(prototype.leaf.receivers)
	if len(prototype.fallbackProofs) > prototype.leaf.context.sharingDegree ||
		len(prototype.acks)+len(prototype.fallbackProofs) != n {
		return fmt.Errorf("APVSS ACK and fallback sets do not cover receivers exactly")
	}
	covered := make([]bool, n)
	previous := 0
	for i := range prototype.acks {
		ack := &prototype.acks[i]
		if ack.receiverIndex <= previous || ack.receiverIndex <= 0 || ack.receiverIndex > n ||
			covered[ack.receiverIndex-1] || !cvValidG1(&ack.signature.r, false) {
			return fmt.Errorf("APVSS ACK indices or signature points are not canonical")
		}
		covered[ack.receiverIndex-1] = true
		previous = ack.receiverIndex
	}
	previous = 0
	for i := range prototype.fallbackProofs {
		fallback := &prototype.fallbackProofs[i]
		if fallback.receiverIndex <= previous || fallback.receiverIndex <= 0 || fallback.receiverIndex > n ||
			covered[fallback.receiverIndex-1] || fallback.proof == nil {
			return fmt.Errorf("APVSS fallback indices are not the ACK complement")
		}
		covered[fallback.receiverIndex-1] = true
		previous = fallback.receiverIndex
	}
	for receiver, ok := range covered {
		if !ok {
			return fmt.Errorf("APVSS receiver %d is absent from ACK and fallback sets", receiver+1)
		}
	}
	return nil
}

func apvssLeafPrototypeV1CanonicalBytes(prototype *apvssLeafPrototypeV1) ([]byte, error) {
	if prototype == nil || prototype.leaf == nil {
		return nil, fmt.Errorf("invalid APVSS prototype leaf")
	}
	if err := apvssValidatePartitionShapeV1(prototype); err != nil {
		return nil, err
	}
	leafWire, err := cvLeafV1CanonicalBytes(prototype.leaf)
	if err != nil {
		return nil, err
	}

	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(apvssLeafWireDomain)); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, leafWire); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, len(prototype.acks)); err != nil {
		return nil, err
	}
	for i := range prototype.acks {
		ack := &prototype.acks[i]
		if err := cvWriteUint32(&wire, ack.receiverIndex); err != nil {
			return nil, err
		}
		cvWritePoint(&wire, &ack.signature.r)
		cvWriteScalar(&wire, &ack.signature.z)
	}
	if err := cvWriteUint32(&wire, len(prototype.fallbackProofs)); err != nil {
		return nil, err
	}
	for i := range prototype.fallbackProofs {
		fallback := &prototype.fallbackProofs[i]
		if err := cvWriteUint32(&wire, fallback.receiverIndex); err != nil {
			return nil, err
		}
		proofWire, err := cvLeafProofV1CanonicalBytes(fallback.proof)
		if err != nil {
			return nil, err
		}
		if err := cvWriteBytes(&wire, proofWire); err != nil {
			return nil, err
		}
	}
	if wire.Len() > apvssMaxLeafWireBytesV1 {
		return nil, fmt.Errorf("APVSS leaf exceeds the wire safety limit")
	}
	return wire.Bytes(), nil
}

func apvssLeafPrototypeV1Digest(prototype *apvssLeafPrototypeV1) []byte {
	wire, err := apvssLeafPrototypeV1CanonicalBytes(prototype)
	if err != nil {
		return nil
	}
	return hashBytes([]byte(apvssLeafDigestDomain), wire)
}

func apvssDecodeLeafPrototypeV1(
	wire []byte,
	expectedContext *cvLeafContextV1,
) (*apvssLeafPrototypeV1, error) {
	if expectedContext == nil || expectedContext.proofProfile != cvLeafV1StructuralProofProfile ||
		len(wire) == 0 || len(wire) > apvssMaxLeafWireBytesV1 {
		return nil, fmt.Errorf("invalid expected APVSS leaf context or wire")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(apvssLeafWireDomain))
	if err != nil || !bytes.Equal(domain, []byte(apvssLeafWireDomain)) {
		return nil, fmt.Errorf("invalid APVSS leaf wire domain")
	}
	baseWire, err := r.bytes(cvMaxLeafWireBytesV1)
	if err != nil || len(baseWire) == 0 {
		return nil, fmt.Errorf("invalid APVSS structural leaf field")
	}
	leaf, err := cvDecodeLeafV1(baseWire, expectedContext)
	if err != nil {
		return nil, err
	}
	n := len(leaf.receivers)
	ackCount, err := r.uint32()
	if err != nil || ackCount < 0 || ackCount > n {
		return nil, fmt.Errorf("invalid APVSS ACK count")
	}
	prototype := &apvssLeafPrototypeV1{leaf: leaf, acks: make([]apvssLaneACKV1, ackCount)}
	for i := range prototype.acks {
		ack := &prototype.acks[i]
		ack.receiverIndex, err = r.uint32()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS ACK receiver index: %w", err)
		}
		ack.signature.r, err = r.point()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS ACK nonce: %w", err)
		}
		ack.signature.z, err = r.scalar()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS ACK response: %w", err)
		}
	}
	fallbackCount, err := r.uint32()
	if err != nil || fallbackCount < 0 || fallbackCount > expectedContext.sharingDegree {
		return nil, fmt.Errorf("invalid APVSS fallback proof count")
	}
	prototype.fallbackProofs = make([]apvssFallbackProofV1, fallbackCount)
	for i := range prototype.fallbackProofs {
		fallback := &prototype.fallbackProofs[i]
		fallback.receiverIndex, err = r.uint32()
		if err != nil {
			return nil, fmt.Errorf("decode APVSS fallback receiver index: %w", err)
		}
		fallbackContext, _, deriveErr := apvssFallbackLeafV1(leaf, fallback.receiverIndex)
		if deriveErr != nil {
			return nil, deriveErr
		}
		proofSize, sizeErr := cvLeafProofWireSizeV1(fallbackContext)
		if sizeErr != nil {
			return nil, sizeErr
		}
		proofWire, readErr := cvReadExactBytesV1(r, proofSize, "APVSS fallback proof")
		if readErr != nil {
			return nil, readErr
		}
		fallback.proof, err = cvDecodeLeafProofV1(proofWire, fallbackContext)
		if err != nil {
			return nil, err
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing APVSS leaf bytes")
	}
	if err := apvssValidatePartitionShapeV1(prototype); err != nil {
		return nil, err
	}
	canonical, err := apvssLeafPrototypeV1CanonicalBytes(prototype)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical APVSS leaf encoding")
	}
	// cvDecodeLeafV1 already performed the complete structural-leaf check.
	// Verify only the APVSS authentication partition here so an untrusted wire
	// is checked once, rather than repeating all commitment evaluations.
	if err := apvssVerifyPrototypePartitionV1(prototype); err != nil {
		return nil, err
	}
	prototype.digest = hashBytes([]byte(apvssLeafDigestDomain), wire)
	return prototype, nil
}

func apvssLaneACKMessageV1CanonicalBytes(message *apvssLaneACKMessageV1) ([]byte, error) {
	if message == nil || len(message.leafDigest) != 32 || message.ack.receiverIndex <= 0 ||
		!cvValidG1(&message.ack.signature.r, false) {
		return nil, fmt.Errorf("invalid APVSS ACK message")
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(apvssACKMessageDomain)); err != nil {
		return nil, err
	}
	cvWriteUint64(&wire, message.dealerID)
	if err := cvWriteBytes(&wire, message.leafDigest); err != nil {
		return nil, err
	}
	if err := cvWriteUint32(&wire, message.ack.receiverIndex); err != nil {
		return nil, err
	}
	cvWritePoint(&wire, &message.ack.signature.r)
	cvWriteScalar(&wire, &message.ack.signature.z)
	return wire.Bytes(), nil
}

func apvssDecodeLaneACKMessageV1(
	wire []byte,
	leaf *cvLeafV1,
) (*apvssLaneACKMessageV1, error) {
	if leaf == nil || len(leaf.digest) != 32 {
		return nil, fmt.Errorf("invalid APVSS ACK message leaf")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(apvssACKMessageDomain))
	if err != nil || !bytes.Equal(domain, []byte(apvssACKMessageDomain)) {
		return nil, fmt.Errorf("invalid APVSS ACK message domain")
	}
	message := &apvssLaneACKMessageV1{}
	message.dealerID, err = r.uint64()
	if err != nil || message.dealerID != leaf.dealerID {
		return nil, fmt.Errorf("APVSS ACK message dealer mismatch")
	}
	message.leafDigest, err = r.bytes(32)
	if err != nil || !bytes.Equal(message.leafDigest, leaf.digest) {
		return nil, fmt.Errorf("APVSS ACK message leaf digest mismatch")
	}
	message.ack.receiverIndex, err = r.uint32()
	if err != nil {
		return nil, fmt.Errorf("decode APVSS ACK message receiver index: %w", err)
	}
	message.ack.signature.r, err = r.point()
	if err != nil {
		return nil, fmt.Errorf("decode APVSS ACK message nonce: %w", err)
	}
	message.ack.signature.z, err = r.scalar()
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid APVSS ACK message response or framing")
	}
	canonical, err := apvssLaneACKMessageV1CanonicalBytes(message)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical APVSS ACK message")
	}
	if err := apvssVerifyLaneACKV1(leaf, &message.ack); err != nil {
		return nil, err
	}
	return message, nil
}
