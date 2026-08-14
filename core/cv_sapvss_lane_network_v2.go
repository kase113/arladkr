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
	quorum    int
	frozen    bool
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

func (s *cvAPDBNetworkServiceV2) BuildLeafV2(ctx context.Context) (*cvLeafV2, error) {
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
	quorum := len(s.cfg.NewRoster) - cvNewFaultBoundFromContextV2(s.cfg.LeafContext)
	if quorum <= 0 || quorum > len(s.cfg.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 lane ACK quorum")
	}
	pending := &cvPendingLaneACKsV2{
		offers:    make([]*cvReceiverLaneOfferV2, len(s.cfg.NewRoster)),
		witnesses: make([]*cvDealerReceiverWitnessV2, len(s.cfg.NewRoster)),
		acks:      make(map[int]*cvACKEvidenceV2, quorum), quorum: quorum, ready: make(chan struct{}, 1),
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
	s.mu.Lock()
	shardBytes := s.cfg.ShardBytes
	s.mu.Unlock()
	if shardBytes == 0 {
		shardBytes, err = cvEpochShardBytesUpperBoundV2(
			s.cfg.LeafContext, s.cfg.Params, s.cfg.Receivers, s.cfg.Validators, s.cfg.DataShards,
		)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		if s.cfg.ShardBytes == 0 {
			s.cfg.ShardBytes = shardBytes
		} else if s.cfg.ShardBytes != shardBytes {
			s.mu.Unlock()
			return nil, fmt.Errorf("CV V2 epoch shard size mismatch")
		}
		s.mu.Unlock()
	}
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
		return nil, fmt.Errorf("CV V2 lane ACK quorum incomplete: %w", ctx.Err())
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case <-pending.ready:
	}
	acks := make([]*cvACKEvidenceV2, len(s.cfg.NewRoster))
	partition := &cvEvidencePartitionV2{}
	fallbackOffers := make([]*cvReceiverLaneOfferV2, 0, len(s.cfg.NewRoster)-quorum)
	fallbackKeys := make([]bls12381.G1Affine, 0, len(s.cfg.NewRoster)-quorum)
	fallbackWitnesses := make([]*cvDealerReceiverWitnessV2, 0, len(s.cfg.NewRoster)-quorum)
	s.mu.Lock()
	for index := 1; index <= len(s.cfg.NewRoster); index++ {
		if ack, ok := pending.acks[index]; ok {
			acks[index-1] = ack
			partition.ACKReceiverIndices = append(partition.ACKReceiverIndices, index)
			continue
		}
		partition.FallbackReceiverIndices = append(partition.FallbackReceiverIndices, index)
		fallbackOffers = append(fallbackOffers, pending.offers[index-1])
		fallbackKeys = append(fallbackKeys, s.cfg.Receivers.encryptionPublicKeys[index-1])
		fallbackWitnesses = append(fallbackWitnesses, pending.witnesses[index-1])
	}
	s.mu.Unlock()
	var fallback *cvFallbackEvidenceV2
	if len(fallbackOffers) > 0 {
		fallback, err = cvBuildFallbackEvidenceV2(
			s.cfg.LeafContext, s.cfg.LocalNode, fallbackOffers, fallbackKeys, fallbackWitnesses,
		)
		if err != nil {
			return nil, err
		}
	}
	leaf, err := cvBuildLeafV2(
		s.cfg.LeafContext, s.cfg.LocalNode, commitments, coreProof, pending.offers, acks, partition, fallback,
		s.cfg.Receivers, s.cfg.Validators,
	)
	if err != nil {
		return nil, err
	}
	if err := cvVerifyAPVSSV2(leaf, s.cfg.LeafContext, s.cfg.Receivers, s.cfg.Validators); err != nil {
		return nil, fmt.Errorf("verify locally built CV V2 leaf: %w", err)
	}
	return leaf, nil
}

func cvEpochShardBytesUpperBoundV2(
	context *cvLeafContextV2, params cvV2Params, receivers *cvReceiverKeyMaterialV2,
	validators *cvValidatorKeyMaterialV2, dataShards int,
) (int, error) {
	if context == nil || receivers == nil || validators == nil || dataShards <= 0 || len(context.OldRoster) == 0 ||
		params.componentCount <= 0 || params.componentCount > len(context.OldRoster) ||
		params.newFaults != cvNewFaultBoundFromContextV2(context) || params.newShareDegree != context.SharingDegree {
		return 0, fmt.Errorf("invalid CV V2 epoch shard sizing input")
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
	witnesses := make([]*cvDealerReceiverWitnessV2, len(context.NewRoster))
	for i, receiverID := range context.NewRoster {
		index := i + 1
		scalar := cvEvaluateScalarPolynomialV2(scalarCoefficients, index)
		blinding := cvEvaluateScalarPolynomialV2(blindingCoefficients, index)
		offers[i], witnesses[i], err = cvEncryptReceiverLanesV2(
			context, dealer, receiverID, index, &receivers.encryptionPublicKeys[i], scalar, blinding,
		)
		if err != nil {
			return 0, err
		}
	}
	maxWireBytes := 0
	newFaults := cvNewFaultBoundFromContextV2(context)
	for fallbackCount := 0; fallbackCount <= newFaults; fallbackCount++ {
		acks := make([]*cvACKEvidenceV2, len(offers))
		partition := cvEvidencePartitionV2{}
		fallbackOffers := make([]*cvReceiverLaneOfferV2, 0, fallbackCount)
		fallbackKeys := make([]bls12381.G1Affine, 0, fallbackCount)
		fallbackWitnesses := make([]*cvDealerReceiverWitnessV2, 0, fallbackCount)
		for i, offer := range offers {
			if i < fallbackCount {
				partition.FallbackReceiverIndices = append(partition.FallbackReceiverIndices, i+1)
				fallbackOffers = append(fallbackOffers, offer)
				fallbackKeys = append(fallbackKeys, receivers.encryptionPublicKeys[i])
				fallbackWitnesses = append(fallbackWitnesses, witnesses[i])
				continue
			}
			partition.ACKReceiverIndices = append(partition.ACKReceiverIndices, i+1)
			acks[i] = &cvACKEvidenceV2{
				Ownership: cvCloneOwnershipProofV2(&offer.Ownership), Signature: make([]byte, ed25519.SignatureSize),
			}
		}
		var fallback *cvFallbackEvidenceV2
		if fallbackCount > 0 {
			fallback, err = cvBuildFallbackEvidenceV2(
				context, dealer, fallbackOffers, fallbackKeys, fallbackWitnesses,
			)
			if err != nil {
				return 0, err
			}
		}
		leaf := &cvLeafV2{
			Context: *cvCloneLeafContextV2(context), DealerID: dealer,
			CoefficientCommitments: append([]bls12381.G1Affine(nil), commitments...),
			CoreProof:              cvCloneCoreProofV2(coreProof), Partition: partition, Fallback: fallback,
			Receivers:       make([]cvLeafReceiverV2, len(offers)),
			DealerSignature: make([]byte, bls12381.SizeOfG1AffineCompressed),
		}
		for i := range offers {
			leaf.Receivers[i] = cvLeafReceiverV2{Offer: *cvCloneReceiverLaneOfferV2(offers[i]), ACK: acks[i]}
		}
		wire, err := cvLeafV2CanonicalBytes(leaf, receivers, validators)
		if err != nil {
			return 0, err
		}
		if len(wire) > maxWireBytes {
			maxWireBytes = len(wire)
		}
	}

	contextDigest, err := cvLeafContextDigestV2(context)
	if err != nil {
		return 0, err
	}
	aggregate := &cvAggregateV2{
		ContextDigest:          append([]byte(nil), contextDigest...),
		Components:             make([]cvAggregateComponentV2, params.componentCount),
		CoefficientCommitments: append([]bls12381.G1Affine(nil), commitments...),
		Receivers:              make([]cvAggregateReceiverV2, len(offers)),
	}
	for i := range aggregate.Components {
		aggregate.Components[i] = cvAggregateComponentV2{
			DealerID: context.OldRoster[i], LeafDigest: make([]byte, 32),
		}
	}
	for i, offer := range offers {
		aggregate.Receivers[i] = cvAggregateReceiverV2{
			ReceiverID: offer.ReceiverID, ReceiverIndex: offer.ReceiverIndex, Evaluation: offer.Evaluation,
			ScalarChunks: append([]cvElGamalCiphertext(nil), offer.ScalarChunks...), Blinding: offer.Blinding,
		}
	}
	unsigned, err := cvAggregateV2UnsignedCanonicalBytes(aggregate, context, params)
	if err != nil {
		return 0, err
	}
	aggregate.Digest = hashBytes([]byte(cvAggregateDigestV2Domain), unsigned)
	aggregateWire, err := cvAggregateV2CanonicalBytes(aggregate, context, params)
	if err != nil {
		return 0, err
	}
	if len(aggregateWire) > maxWireBytes {
		maxWireBytes = len(aggregateWire)
	}
	return (8 + maxWireBytes + dataShards - 1) / dataShards, nil
}
