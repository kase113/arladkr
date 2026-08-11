package core

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const cvFallbackEvidenceWireDomainV2 = "ARL-CV-sAPVSS/v2/fallback-evidence"

type cvFallbackEvidenceV2 struct {
	ReceiverIndices []int
	Link            cvFallbackLinkProofV2
	Range           cvFallbackRangeProofV2
}

func cvBuildFallbackEvidenceV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, witnesses []*cvDealerReceiverWitnessV2,
) (*cvFallbackEvidenceV2, error) {
	link, linkWitness, err := cvProveFallbackLinkV2(context, dealerID, offers, receiverPublicKeys, witnesses)
	if err != nil {
		return nil, err
	}
	rangeProof, err := cvProveFallbackRangeV2(
		context, dealerID, offers, receiverPublicKeys, witnesses, link, linkWitness,
	)
	if err != nil {
		return nil, err
	}
	indices := make([]int, len(offers))
	for i := range offers {
		indices[i] = offers[i].ReceiverIndex
	}
	return &cvFallbackEvidenceV2{ReceiverIndices: indices, Link: *link, Range: *rangeProof}, nil
}

func cvVerifyFallbackEvidenceV2(
	context *cvLeafContextV2, dealerID int, offers []*cvReceiverLaneOfferV2,
	receiverPublicKeys []bls12381.G1Affine, evidence *cvFallbackEvidenceV2,
) error {
	if evidence == nil || len(evidence.ReceiverIndices) != len(offers) {
		return fmt.Errorf("invalid CV V2 fallback evidence")
	}
	for i := range offers {
		if offers[i] == nil || evidence.ReceiverIndices[i] != offers[i].ReceiverIndex {
			return fmt.Errorf("CV V2 fallback evidence receiver mismatch")
		}
	}
	if err := cvVerifyFallbackLinkV2(context, dealerID, offers, receiverPublicKeys, &evidence.Link); err != nil {
		return err
	}
	return cvVerifyFallbackRangeV2(context, dealerID, offers, receiverPublicKeys, &evidence.Link, &evidence.Range)
}

func cvFallbackEvidenceV2CanonicalBytes(evidence *cvFallbackEvidenceV2, context *cvLeafContextV2) ([]byte, error) {
	if evidence == nil || len(evidence.ReceiverIndices) == 0 ||
		len(evidence.ReceiverIndices) > cvNewFaultBoundFromContextV2(context) {
		return nil, fmt.Errorf("invalid CV V2 fallback evidence wire")
	}
	previous := 0
	for _, index := range evidence.ReceiverIndices {
		if index <= previous || index > len(context.NewRoster) {
			return nil, fmt.Errorf("invalid CV V2 fallback evidence indices")
		}
		previous = index
	}
	linkWire, err := cvFallbackLinkProofV2CanonicalBytes(&evidence.Link, context, len(evidence.ReceiverIndices))
	if err != nil {
		return nil, err
	}
	rangeWire, err := cvFallbackRangeProofV2CanonicalBytes(&evidence.Range)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvFallbackEvidenceWireDomainV2))
	if err := cvWriteIndexVectorV2(&wire, evidence.ReceiverIndices); err != nil {
		return nil, err
	}
	_ = cvWriteBytes(&wire, linkWire)
	_ = cvWriteBytes(&wire, rangeWire)
	return wire.Bytes(), nil
}

func cvDecodeFallbackEvidenceV2(wire []byte, context *cvLeafContextV2) (*cvFallbackEvidenceV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvFallbackEvidenceWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvFallbackEvidenceWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 fallback evidence domain")
	}
	indices, err := cvReadIndexVectorV2(r, cvNewFaultBoundFromContextV2(context))
	if err != nil || len(indices) == 0 {
		return nil, fmt.Errorf("invalid CV V2 fallback evidence indices")
	}
	linkWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 fallback link framing")
	}
	rangeWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 fallback range framing")
	}
	link, err := cvDecodeFallbackLinkProofV2(linkWire, context, len(indices))
	if err != nil {
		return nil, err
	}
	rangeProof, err := cvDecodeFallbackRangeProofV2(rangeWire, context, len(indices))
	if err != nil {
		return nil, err
	}
	evidence := &cvFallbackEvidenceV2{ReceiverIndices: indices, Link: *link, Range: *rangeProof}
	canonical, err := cvFallbackEvidenceV2CanonicalBytes(evidence, context)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 fallback evidence")
	}
	return evidence, nil
}
