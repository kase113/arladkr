package core

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvLeafUnsignedWireDomainV2 = "ARL-CV-sAPVSS/v2-scalar-group/leaf-unsigned"
	cvLeafWireDomainV2         = "ARL-CV-sAPVSS/v2-scalar-group/leaf"
	cvLeafDigestDomainV2       = "ARL-CV-sAPVSS/v2-scalar-group/leaf-digest"
	cvDealerSignatureDomainV2  = "ARL-CV-sAPVSS/v2-scalar-group/dealer-signature"
)

type cvLeafReceiverV2 struct {
	Offer cvReceiverLaneOfferV2
	ACK   *cvACKEvidenceV2
}

type cvLeafV2 struct {
	Context                cvLeafContextV2
	DealerID               int
	CoefficientCommitments []bls12381.G1Affine
	CoreProof              cvCoreProofV2
	Receivers              []cvLeafReceiverV2
	Partition              cvEvidencePartitionV2
	Fallback               *cvFallbackEvidenceV2
	DealerSignature        []byte
	Digest                 []byte
}

func cvBuildAllACKLeafV2(
	context *cvLeafContextV2, dealerID int, commitments []bls12381.G1Affine, coreProof *cvCoreProofV2,
	offers []*cvReceiverLaneOfferV2, acks []*cvACKEvidenceV2,
	receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) (*cvLeafV2, error) {
	if context == nil || len(offers) != len(context.NewRoster) || len(acks) != len(offers) || coreProof == nil {
		return nil, fmt.Errorf("invalid CV V2 all-ACK leaf input")
	}
	partition := cvEvidencePartitionV2{ACKReceiverIndices: make([]int, len(offers))}
	for i := range offers {
		if offers[i] == nil || acks[i] == nil {
			return nil, fmt.Errorf("all-ACK leaf is missing receiver evidence")
		}
		partition.ACKReceiverIndices[i] = i + 1
	}
	return cvBuildLeafV2(context, dealerID, commitments, coreProof, offers, acks, &partition, nil, receivers, validators)
}

func cvBuildLeafV2(
	context *cvLeafContextV2, dealerID int, commitments []bls12381.G1Affine, coreProof *cvCoreProofV2,
	offers []*cvReceiverLaneOfferV2, acks []*cvACKEvidenceV2, partition *cvEvidencePartitionV2,
	fallback *cvFallbackEvidenceV2, receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) (*cvLeafV2, error) {
	if context == nil || coreProof == nil || partition == nil || len(offers) != len(context.NewRoster) || len(acks) != len(offers) {
		return nil, fmt.Errorf("invalid CV V2 leaf input")
	}
	leaf := &cvLeafV2{
		Context: *cvCloneLeafContextV2(context), DealerID: dealerID,
		CoefficientCommitments: append([]bls12381.G1Affine(nil), commitments...), CoreProof: cvCloneCoreProofV2(coreProof),
		Receivers: make([]cvLeafReceiverV2, len(offers)),
		Partition: cvEvidencePartitionV2{
			ACKReceiverIndices:      append([]int(nil), partition.ACKReceiverIndices...),
			FallbackReceiverIndices: append([]int(nil), partition.FallbackReceiverIndices...),
		},
	}
	for i := range offers {
		if offers[i] == nil {
			return nil, fmt.Errorf("CV V2 leaf is missing receiver offer")
		}
		leaf.Receivers[i].Offer = *cvCloneReceiverLaneOfferV2(offers[i])
		if acks[i] != nil {
			leaf.Receivers[i].ACK = &cvACKEvidenceV2{
				Ownership: cvCloneOwnershipProofV2(&acks[i].Ownership), Signature: append([]byte(nil), acks[i].Signature...),
			}
		}
	}
	if fallback != nil {
		fallbackWire, err := cvFallbackEvidenceV2CanonicalBytes(fallback, context)
		if err != nil {
			return nil, err
		}
		leaf.Fallback, err = cvDecodeFallbackEvidenceV2(fallbackWire, context)
		if err != nil {
			return nil, err
		}
	}
	if err := cvVerifyLeafStatementV2(leaf, context, receivers); err != nil {
		return nil, err
	}
	if err := cvValidateValidatorMaterialForLeafV2(context, validators); err != nil {
		return nil, err
	}
	secret, ok := validators.localSecrets[dealerID]
	if !ok {
		return nil, fmt.Errorf("missing local CV V2 dealer signing secret")
	}
	unsigned, err := cvLeafV2UnsignedCanonicalBytes(leaf, receivers)
	if err != nil {
		return nil, err
	}
	statement := hashBytes([]byte(cvDealerSignatureDomainV2), unsigned)
	leaf.DealerSignature, err = cvSignValidatorV2(secret, cvDealerSignatureDomainV2, statement)
	if err != nil {
		return nil, err
	}
	wire, err := cvLeafV2CanonicalBytes(leaf, receivers, validators)
	if err != nil {
		return nil, err
	}
	leaf.Digest = hashBytes([]byte(cvLeafDigestDomainV2), wire)
	return leaf, nil
}

// cvVerifyAPVSSV2 is the unique verifier for both ACK and fallback evidence.
func cvVerifyAPVSSV2(
	leaf *cvLeafV2, expectedContext *cvLeafContextV2,
	receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) error {
	if leaf == nil {
		return fmt.Errorf("nil CV V2 leaf")
	}
	if err := cvVerifyLeafStatementV2(leaf, expectedContext, receivers); err != nil {
		return err
	}
	if err := cvValidateValidatorMaterialForLeafV2(expectedContext, validators); err != nil {
		return err
	}
	dealerIndex, ok := validators.memberIndex[leaf.DealerID]
	if !ok {
		return fmt.Errorf("CV V2 dealer is outside validator registry")
	}
	unsigned, err := cvLeafV2UnsignedCanonicalBytes(leaf, receivers)
	if err != nil {
		return err
	}
	statement := hashBytes([]byte(cvDealerSignatureDomainV2), unsigned)
	if !cvVerifyValidatorSignatureV2(
		&validators.publicKeys[dealerIndex], cvDealerSignatureDomainV2, statement, leaf.DealerSignature,
	) {
		return fmt.Errorf("invalid CV V2 dealer signature")
	}
	wire, err := cvLeafV2CanonicalBytes(leaf, receivers, validators)
	if err != nil {
		return err
	}
	expectedDigest := hashBytes([]byte(cvLeafDigestDomainV2), wire)
	if len(leaf.Digest) != 32 || !bytes.Equal(leaf.Digest, expectedDigest) {
		return fmt.Errorf("invalid CV V2 leaf digest")
	}
	return nil
}

func cvVerifyLeafStatementV2(
	leaf *cvLeafV2, expectedContext *cvLeafContextV2, receivers *cvReceiverKeyMaterialV2,
) error {
	if leaf == nil || expectedContext == nil || leaf.DealerID < 0 ||
		len(leaf.CoefficientCommitments) != expectedContext.SharingDegree+1 ||
		len(leaf.Receivers) != len(expectedContext.NewRoster) ||
		cvValidateReceiverMaterialForLeafV2(expectedContext, receivers) != nil {
		return fmt.Errorf("invalid CV V2 leaf statement")
	}
	expectedContextWire, err := cvLeafContextV2CanonicalBytes(expectedContext)
	if err != nil {
		return err
	}
	actualContextWire, err := cvLeafContextV2CanonicalBytes(&leaf.Context)
	if err != nil || !bytes.Equal(actualContextWire, expectedContextWire) {
		return fmt.Errorf("CV V2 leaf context mismatch")
	}
	if !cvMemberInRosterV2(leaf.DealerID, expectedContext.OldRoster) {
		return fmt.Errorf("CV V2 leaf dealer is outside old roster")
	}
	if err := cvVerifyCoreV2(expectedContext, leaf.DealerID, leaf.CoefficientCommitments, &leaf.CoreProof); err != nil {
		return err
	}
	if err := cvValidateEvidencePartitionV2(expectedContext, &leaf.Partition); err != nil {
		return err
	}
	fallbackSet := make(map[int]struct{}, len(leaf.Partition.FallbackReceiverIndices))
	for _, index := range leaf.Partition.FallbackReceiverIndices {
		fallbackSet[index] = struct{}{}
	}
	fallbackOffers := make([]*cvReceiverLaneOfferV2, 0, len(fallbackSet))
	fallbackKeys := make([]bls12381.G1Affine, 0, len(fallbackSet))
	for i := range leaf.Receivers {
		receiver := &leaf.Receivers[i]
		expectedID := expectedContext.NewRoster[i]
		if receiver.Offer.ReceiverID != expectedID || receiver.Offer.ReceiverIndex != i+1 {
			return fmt.Errorf("invalid CV V2 leaf receiver ordering")
		}
		expectedEvaluation := cvEvaluateCommitments(leaf.CoefficientCommitments, i+1)
		if !receiver.Offer.Evaluation.Equal(&expectedEvaluation) {
			return fmt.Errorf("CV V2 receiver evaluation does not match coefficient polynomial")
		}
		if _, isFallback := fallbackSet[i+1]; isFallback {
			if receiver.ACK != nil {
				return fmt.Errorf("CV V2 fallback receiver also carries ACK evidence")
			}
			fallbackOffers = append(fallbackOffers, &receiver.Offer)
			fallbackKeys = append(fallbackKeys, receivers.encryptionPublicKeys[i])
		} else {
			if receiver.ACK == nil {
				return fmt.Errorf("CV V2 ACK receiver is missing evidence")
			}
			if err := cvVerifyACKV2(
				expectedContext, leaf.DealerID, &receiver.Offer, &receivers.encryptionPublicKeys[i],
				receivers.identityPublicKeys[i], receiver.ACK,
			); err != nil {
				return fmt.Errorf("invalid CV V2 receiver %d ACK: %w", i+1, err)
			}
		}
	}
	if len(fallbackOffers) == 0 {
		if leaf.Fallback != nil {
			return fmt.Errorf("all-ACK CV V2 leaf carries fallback evidence")
		}
	} else if err := cvVerifyFallbackEvidenceV2(
		expectedContext, leaf.DealerID, fallbackOffers, fallbackKeys, leaf.Fallback,
	); err != nil {
		return fmt.Errorf("invalid CV V2 fallback evidence: %w", err)
	}
	return nil
}

func cvLeafV2UnsignedCanonicalBytes(
	leaf *cvLeafV2, receivers *cvReceiverKeyMaterialV2,
) ([]byte, error) {
	if leaf == nil || cvValidateReceiverMaterialForLeafV2(&leaf.Context, receivers) != nil ||
		cvValidateEvidencePartitionV2(&leaf.Context, &leaf.Partition) != nil ||
		len(leaf.Receivers) != len(leaf.Context.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 unsigned leaf")
	}
	contextWire, err := cvLeafContextV2CanonicalBytes(&leaf.Context)
	if err != nil {
		return nil, err
	}
	coreWire, err := cvCoreProofV2CanonicalBytes(&leaf.CoreProof, len(leaf.CoefficientCommitments))
	if err != nil {
		return nil, err
	}
	partitionWire, err := cvEvidencePartitionV2CanonicalBytes(&leaf.Context, &leaf.Partition)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvLeafUnsignedWireDomainV2))
	_ = cvWriteBytes(&wire, contextWire)
	cvWriteUint64(&wire, uint64(leaf.DealerID))
	if err := cvWritePointVector(&wire, leaf.CoefficientCommitments); err != nil {
		return nil, err
	}
	_ = cvWriteBytes(&wire, coreWire)
	_ = cvWriteBytes(&wire, partitionWire)
	if err := cvWriteUint32(&wire, len(leaf.Receivers)); err != nil {
		return nil, err
	}
	fallbackSet := make(map[int]struct{}, len(leaf.Partition.FallbackReceiverIndices))
	for _, index := range leaf.Partition.FallbackReceiverIndices {
		fallbackSet[index] = struct{}{}
	}
	for i := range leaf.Receivers {
		receiver := &leaf.Receivers[i]
		if _, isFallback := fallbackSet[i+1]; isFallback {
			if receiver.ACK != nil || cvWriteUint32(&wire, 1) != nil {
				return nil, fmt.Errorf("invalid CV V2 fallback receiver wire")
			}
			offerWire, err := cvFallbackLaneOfferV2CanonicalBytes(
				&leaf.Context, leaf.DealerID, &receiver.Offer, &receivers.encryptionPublicKeys[i],
			)
			if err != nil {
				return nil, err
			}
			_ = cvWriteBytes(&wire, offerWire)
		} else {
			if receiver.ACK == nil || cvWriteUint32(&wire, 0) != nil {
				return nil, fmt.Errorf("invalid CV V2 ACK receiver wire")
			}
			offerWire, err := cvReceiverLaneOfferV2CanonicalBytes(
				&leaf.Context, leaf.DealerID, &receiver.Offer, &receivers.encryptionPublicKeys[i],
			)
			if err != nil {
				return nil, err
			}
			ackWire, err := cvACKEvidenceV2CanonicalBytes(receiver.ACK, &leaf.Context)
			if err != nil {
				return nil, err
			}
			_ = cvWriteBytes(&wire, offerWire)
			_ = cvWriteBytes(&wire, ackWire)
		}
	}
	if len(fallbackSet) == 0 {
		if leaf.Fallback != nil {
			return nil, fmt.Errorf("unexpected CV V2 fallback evidence")
		}
		_ = cvWriteBytes(&wire, nil)
	} else {
		fallbackWire, err := cvFallbackEvidenceV2CanonicalBytes(leaf.Fallback, &leaf.Context)
		if err != nil {
			return nil, err
		}
		_ = cvWriteBytes(&wire, fallbackWire)
	}
	return wire.Bytes(), nil
}

func cvLeafV2CanonicalBytes(
	leaf *cvLeafV2, receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) ([]byte, error) {
	if leaf == nil || len(leaf.DealerSignature) != bls12381.SizeOfG1AffineCompressed ||
		cvValidateValidatorMaterialForLeafV2(&leaf.Context, validators) != nil {
		return nil, fmt.Errorf("invalid CV V2 leaf wire")
	}
	unsigned, err := cvLeafV2UnsignedCanonicalBytes(leaf, receivers)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvLeafWireDomainV2))
	_ = cvWriteBytes(&wire, unsigned)
	_ = cvWriteBytes(&wire, leaf.DealerSignature)
	return wire.Bytes(), nil
}

func cvDecodeLeafV2(
	wire []byte, expectedContext *cvLeafContextV2,
	receivers *cvReceiverKeyMaterialV2, validators *cvValidatorKeyMaterialV2,
) (*cvLeafV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvLeafWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvLeafWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 leaf domain")
	}
	unsigned, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 unsigned leaf framing")
	}
	signature, err := r.bytes(bls12381.SizeOfG1AffineCompressed)
	if err != nil || len(signature) != bls12381.SizeOfG1AffineCompressed || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 dealer signature framing")
	}
	leaf, err := cvDecodeLeafV2Unsigned(unsigned, expectedContext, receivers)
	if err != nil {
		return nil, err
	}
	leaf.DealerSignature = signature
	leaf.Digest = hashBytes([]byte(cvLeafDigestDomainV2), wire)
	canonical, err := cvLeafV2CanonicalBytes(leaf, receivers, validators)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 leaf")
	}
	if err := cvVerifyAPVSSV2(leaf, expectedContext, receivers, validators); err != nil {
		return nil, err
	}
	return leaf, nil
}

func cvDecodeLeafV2Unsigned(
	wire []byte, expectedContext *cvLeafContextV2, receivers *cvReceiverKeyMaterialV2,
) (*cvLeafV2, error) {
	if cvValidateReceiverMaterialForLeafV2(expectedContext, receivers) != nil {
		return nil, fmt.Errorf("invalid CV V2 leaf receiver registry")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvLeafUnsignedWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvLeafUnsignedWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 unsigned leaf domain")
	}
	contextWire, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil {
		return nil, err
	}
	context, err := cvDecodeLeafContextV2(contextWire)
	if err != nil {
		return nil, err
	}
	expectedWire, err := cvLeafContextV2CanonicalBytes(expectedContext)
	if err != nil || !bytes.Equal(contextWire, expectedWire) {
		return nil, fmt.Errorf("CV V2 unsigned leaf context mismatch")
	}
	dealer, err := r.uint64()
	if err != nil || dealer > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV V2 leaf dealer")
	}
	commitments, err := cvReadExactPointVector(r, expectedContext.SharingDegree+1, "V2 coefficient commitments")
	if err != nil {
		return nil, err
	}
	coreWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil {
		return nil, err
	}
	coreProof, err := cvDecodeCoreProofV2(coreWire, len(commitments))
	if err != nil {
		return nil, err
	}
	partitionWire, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil {
		return nil, err
	}
	partition, err := cvDecodeEvidencePartitionV2(partitionWire, expectedContext)
	if err != nil {
		return nil, err
	}
	count, err := r.uint32()
	if err != nil || count != len(expectedContext.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 receiver transcript count")
	}
	leaf := &cvLeafV2{
		Context: *context, DealerID: int(dealer), CoefficientCommitments: commitments,
		CoreProof: *coreProof, Partition: *partition, Receivers: make([]cvLeafReceiverV2, count),
	}
	fallbackSet := make(map[int]struct{}, len(partition.FallbackReceiverIndices))
	for _, index := range partition.FallbackReceiverIndices {
		fallbackSet[index] = struct{}{}
	}
	for i := 0; i < count; i++ {
		mode, err := r.uint32()
		_, isFallback := fallbackSet[i+1]
		wantMode := 0
		if isFallback {
			wantMode = 1
		}
		if err != nil || mode != wantMode {
			return nil, fmt.Errorf("invalid CV V2 receiver evidence mode")
		}
		offerWire, err := r.bytes(cvMaxLeafWireBytes)
		if err != nil {
			return nil, err
		}
		var offer *cvReceiverLaneOfferV2
		if isFallback {
			offer, err = cvDecodeFallbackLaneOfferV2(
				offerWire, expectedContext, leaf.DealerID, expectedContext.NewRoster[i], i+1,
				&receivers.encryptionPublicKeys[i],
			)
		} else {
			offer, err = cvDecodeReceiverLaneOfferV2(
				offerWire, expectedContext, leaf.DealerID, expectedContext.NewRoster[i], i+1,
				&receivers.encryptionPublicKeys[i],
			)
		}
		if err != nil {
			return nil, err
		}
		leaf.Receivers[i] = cvLeafReceiverV2{Offer: *offer}
		if !isFallback {
			ackWire, readErr := r.bytes(cvMaxLeafProofWireBytes)
			if readErr != nil {
				return nil, readErr
			}
			ack, readErr := cvDecodeACKEvidenceV2(ackWire, expectedContext)
			if readErr != nil {
				return nil, readErr
			}
			leaf.Receivers[i].ACK = ack
		}
	}
	fallbackWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 fallback evidence framing")
	}
	if len(fallbackSet) == 0 {
		if len(fallbackWire) != 0 {
			return nil, fmt.Errorf("all-ACK CV V2 leaf carries fallback evidence")
		}
	} else {
		leaf.Fallback, err = cvDecodeFallbackEvidenceV2(fallbackWire, expectedContext)
		if err != nil {
			return nil, err
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV V2 unsigned leaf bytes")
	}
	canonical, err := cvLeafV2UnsignedCanonicalBytes(leaf, receivers)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 unsigned leaf")
	}
	return leaf, nil
}

func cvValidateReceiverMaterialForLeafV2(
	context *cvLeafContextV2, material *cvReceiverKeyMaterialV2,
) error {
	if context == nil || material == nil || material.sid != context.SID || material.epoch != context.Epoch ||
		!equalInts(material.receiverOrder, context.NewRoster) ||
		len(material.encryptionPublicKeys) != len(context.NewRoster) ||
		len(material.identityPublicKeys) != len(context.NewRoster) ||
		!bytes.Equal(material.registryDigest, context.ReceiverRegistryDigest) {
		return fmt.Errorf("CV V2 receiver registry does not match leaf context")
	}
	return nil
}

func cvValidateValidatorMaterialForLeafV2(
	context *cvLeafContextV2, material *cvValidatorKeyMaterialV2,
) error {
	if context == nil || material == nil || material.sid != context.SID || material.epoch != context.Epoch ||
		!equalInts(material.memberOrder, context.OldRoster) ||
		len(material.publicKeys) != len(context.OldRoster) {
		return fmt.Errorf("CV V2 validator registry does not match leaf context")
	}
	return nil
}

func cvCloneLeafContextV2(context *cvLeafContextV2) *cvLeafContextV2 {
	if context == nil {
		return nil
	}
	cloned := *context
	cloned.OldRoster = append([]int(nil), context.OldRoster...)
	cloned.NewRoster = append([]int(nil), context.NewRoster...)
	cloned.ReceiverRegistryDigest = append([]byte(nil), context.ReceiverRegistryDigest...)
	return &cloned
}

func cvCloneCoreProofV2(proof *cvCoreProofV2) cvCoreProofV2 {
	if proof == nil {
		return cvCoreProofV2{}
	}
	return cvCoreProofV2{
		NonceCommitments:  append([]bls12381.G1Affine(nil), proof.NonceCommitments...),
		ScalarResponses:   append([]fr.Element(nil), proof.ScalarResponses...),
		BlindingResponses: append([]fr.Element(nil), proof.BlindingResponses...),
	}
}

func cvCloneReceiverLaneOfferV2(offer *cvReceiverLaneOfferV2) *cvReceiverLaneOfferV2 {
	if offer == nil {
		return nil
	}
	cloned := *offer
	cloned.ScalarChunks = append([]cvElGamalCiphertext(nil), offer.ScalarChunks...)
	cloned.Blinding = offer.Blinding
	cloned.Ownership = cvCloneOwnershipProofV2(&offer.Ownership)
	return &cloned
}
