package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const cvLaneACKMessageV2Domain = "ARL-CV-sAPVSS/v2-scalar-group/lane-ack-message"

type cvLaneACKMessageV2 struct {
	DealerID      int
	ReceiverID    int
	ReceiverIndex int
	OfferDigest   []byte
	Evidence      cvACKEvidenceV2
}

type cvPendingLaneACKsV2 struct {
	offers    []*cvReceiverLaneOfferV2
	witnesses []*cvDealerReceiverWitnessV2
	acks      map[int]*cvACKEvidenceV2
	ready     chan struct{}
}

func cvLaneACKMessageV2CanonicalBytes(message *cvLaneACKMessageV2, context *cvLeafContextV2) ([]byte, error) {
	if message == nil || message.DealerID < 0 || message.ReceiverID < 0 || message.ReceiverIndex <= 0 ||
		len(message.OfferDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 lane ACK message")
	}
	evidence, err := cvACKEvidenceV2CanonicalBytes(&message.Evidence, context)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvLaneACKMessageV2Domain))
	cvWriteUint64(&wire, uint64(message.DealerID))
	cvWriteUint64(&wire, uint64(message.ReceiverID))
	_ = cvWriteUint32(&wire, message.ReceiverIndex)
	_ = cvWriteBytes(&wire, message.OfferDigest)
	_ = cvWriteBytes(&wire, evidence)
	return wire.Bytes(), nil
}

func cvDecodeLaneACKMessageV2(wire []byte, context *cvLeafContextV2) (*cvLaneACKMessageV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvLaneACKMessageV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvLaneACKMessageV2Domain)) {
		return nil, fmt.Errorf("invalid CV V2 lane ACK message domain")
	}
	dealer, err := r.uint64()
	if err != nil || dealer > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV V2 lane ACK dealer")
	}
	receiver, err := r.uint64()
	if err != nil || receiver > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV V2 lane ACK receiver")
	}
	index, err := r.uint32()
	if err != nil || index <= 0 {
		return nil, fmt.Errorf("invalid CV V2 lane ACK receiver index")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 lane ACK offer digest")
	}
	evidenceWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 lane ACK evidence framing")
	}
	evidence, err := cvDecodeACKEvidenceV2(evidenceWire, context)
	if err != nil {
		return nil, err
	}
	message := &cvLaneACKMessageV2{DealerID: int(dealer), ReceiverID: int(receiver), ReceiverIndex: index,
		OfferDigest: digest, Evidence: *evidence}
	canonical, err := cvLaneACKMessageV2CanonicalBytes(message, context)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 lane ACK message")
	}
	return message, nil
}

func cvLaneOfferDigestV2(wire []byte) []byte {
	return hashBytes([]byte("ARL-CV-sAPVSS/v2-scalar-group/lane-offer-digest"), wire)
}

func (s *cvAPDBNetworkServiceV2) BuildAllACKLeafV2(ctx context.Context) (*cvLeafV2, error) {
	if s == nil || ctx == nil || s.cfg.LeafContext == nil || s.cfg.Receivers == nil || s.cfg.Validators == nil ||
		!cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) {
		return nil, fmt.Errorf("invalid CV V2 network leaf builder")
	}
	coefficientCount := s.cfg.LeafContext.SharingDegree + 1
	scalarCoefficients := make([]fr.Element, coefficientCount)
	blindingCoefficients := make([]fr.Element, coefficientCount)
	for i := 0; i < coefficientCount; i++ {
		if _, err := scalarCoefficients[i].SetRandom(); err != nil {
			return nil, err
		}
		if _, err := blindingCoefficients[i].SetRandom(); err != nil {
			return nil, err
		}
	}
	commitments, coreProof, err := cvProveCoreV2(
		s.cfg.LeafContext, s.cfg.LocalNode, scalarCoefficients, blindingCoefficients,
	)
	if err != nil {
		return nil, err
	}
	pending := &cvPendingLaneACKsV2{
		offers:    make([]*cvReceiverLaneOfferV2, len(s.cfg.NewRoster)),
		witnesses: make([]*cvDealerReceiverWitnessV2, len(s.cfg.NewRoster)),
		acks:      make(map[int]*cvACKEvidenceV2, len(s.cfg.NewRoster)), ready: make(chan struct{}, 1),
	}
	offerWires := make([][]byte, len(s.cfg.NewRoster))
	for i, receiverID := range s.cfg.NewRoster {
		index := i + 1
		scalar := cvEvaluateScalarPolynomialV2(scalarCoefficients, index)
		blinding := cvEvaluateScalarPolynomialV2(blindingCoefficients, index)
		pending.offers[i], pending.witnesses[i], err = cvEncryptReceiverLanesV2(
			s.cfg.LeafContext, s.cfg.LocalNode, receiverID, index,
			&s.cfg.Receivers.encryptionPublicKeys[i], scalar, blinding,
		)
		if err != nil {
			return nil, err
		}
		offerWires[i], err = cvReceiverLaneOfferV2CanonicalBytes(
			s.cfg.LeafContext, s.cfg.LocalNode, pending.offers[i], &s.cfg.Receivers.encryptionPublicKeys[i],
		)
		if err != nil {
			return nil, err
		}
	}
	wireBytes, err := cvAllACKLeafWireSizeV2(
		s.cfg.LeafContext, s.cfg.LocalNode, commitments, coreProof, pending.offers,
		s.cfg.Receivers, s.cfg.Validators,
	)
	if err != nil {
		return nil, err
	}
	shardBytes := (8 + wireBytes + s.cfg.DataShards - 1) / s.cfg.DataShards
	s.mu.Lock()
	if s.cfg.ShardBytes != 0 && s.cfg.ShardBytes != shardBytes {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV V2 all-ACK leaf shard size mismatch")
	}
	s.cfg.ShardBytes = shardBytes
	s.mu.Unlock()
	s.mu.Lock()
	if s.pendingLaneACKsV2 != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV V2 lane ACK collection already active")
	}
	s.pendingLaneACKsV2 = pending
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingLaneACKsV2 == pending {
			s.pendingLaneACKsV2 = nil
		}
		s.mu.Unlock()
	}()
	for i, receiver := range s.cfg.NewRoster {
		if err := s.send(receiver, cvTagLaneOfferV2, offerWires[i]); err != nil {
			return nil, err
		}
	}
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("CV V2 all-ACK leaf incomplete: %w", ctx.Err())
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case <-pending.ready:
	}
	acks := make([]*cvACKEvidenceV2, len(s.cfg.NewRoster))
	s.mu.Lock()
	for index, ack := range pending.acks {
		acks[index-1] = ack
	}
	s.mu.Unlock()
	return cvBuildAllACKLeafV2(
		s.cfg.LeafContext, s.cfg.LocalNode, commitments, coreProof, pending.offers, acks,
		s.cfg.Receivers, s.cfg.Validators,
	)
}

func cvAllACKLeafWireSizeV2(
	context *cvLeafContextV2, dealer int, commitments []bls12381.G1Affine, coreProof *cvCoreProofV2,
	offers []*cvReceiverLaneOfferV2, receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) (int, error) {
	if context == nil || len(offers) != len(context.NewRoster) {
		return 0, fmt.Errorf("invalid CV V2 all-ACK leaf sizing input")
	}
	leaf := &cvLeafV2{Context: *cvCloneLeafContextV2(context), DealerID: dealer,
		CoefficientCommitments: append([]bls12381.G1Affine(nil), commitments...), CoreProof: cvCloneCoreProofV2(coreProof),
		Receivers:       make([]cvLeafReceiverV2, len(offers)),
		Partition:       cvEvidencePartitionV2{ACKReceiverIndices: make([]int, len(offers))},
		DealerSignature: make([]byte, bls12381.SizeOfG1AffineCompressed),
	}
	for i, offer := range offers {
		if offer == nil {
			return 0, fmt.Errorf("missing CV V2 all-ACK sizing offer")
		}
		leaf.Partition.ACKReceiverIndices[i] = i + 1
		leaf.Receivers[i].Offer = *cvCloneReceiverLaneOfferV2(offer)
		leaf.Receivers[i].ACK = &cvACKEvidenceV2{
			Ownership: cvCloneOwnershipProofV2(&offer.Ownership), Signature: make([]byte, ed25519.SignatureSize),
		}
	}
	wire, err := cvLeafV2CanonicalBytes(leaf, receivers, validators)
	if err != nil {
		return 0, err
	}
	return len(wire), nil
}

func cvAllACKLeafShardBytesV2(
	context *cvLeafContextV2, receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
	dataShards int,
) (int, error) {
	if context == nil || receivers == nil || validators == nil || dataShards <= 0 || len(context.OldRoster) == 0 {
		return 0, fmt.Errorf("invalid CV V2 all-ACK shard sizing input")
	}
	count := context.SharingDegree + 1
	scalarCoefficients := make([]fr.Element, count)
	blindingCoefficients := make([]fr.Element, count)
	for i := 0; i < count; i++ {
		scalarCoefficients[i].SetUint64(uint64(i + 1))
		blindingCoefficients[i].SetUint64(uint64(i + count + 1))
	}
	dealer := context.OldRoster[0]
	commitments, coreProof, err := cvProveCoreV2(context, dealer, scalarCoefficients, blindingCoefficients)
	if err != nil {
		return 0, err
	}
	offers := make([]*cvReceiverLaneOfferV2, len(context.NewRoster))
	for i, receiverID := range context.NewRoster {
		index := i + 1
		scalar := cvEvaluateScalarPolynomialV2(scalarCoefficients, index)
		blinding := cvEvaluateScalarPolynomialV2(blindingCoefficients, index)
		offers[i], _, err = cvEncryptReceiverLanesV2(
			context, dealer, receiverID, index, &receivers.encryptionPublicKeys[i], scalar, blinding,
		)
		if err != nil {
			return 0, err
		}
	}
	wireBytes, err := cvAllACKLeafWireSizeV2(context, dealer, commitments, coreProof, offers, receivers, validators)
	if err != nil {
		return 0, err
	}
	return (8 + wireBytes + dataShards - 1) / dataShards, nil
}
