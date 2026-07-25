package core

import "fmt"

// OptrandAPVSS is the protocol emulator provider. It exercises the ARL-ADKR
// control flow but does not claim scalar PVSS or threshold-key output.
type OptrandAPVSS struct{}

func NewOptrandAPVSS() *OptrandAPVSS {
	return &OptrandAPVSS{}
}

func (o *OptrandAPVSS) ADist(cfg Config, art *DealerArtifact) (*APVSSTranscript, error) {
	if art == nil {
		return nil, fmt.Errorf("nil dealer artifact")
	}
	if err := OptrandShareVerify(cfg, art); err != nil {
		return nil, err
	}
	out := &APVSSTranscript{
		Dealer:       art.Dealer,
		Payload:      append([]byte(nil), art.Payload...),
		Ciphertexts:  make(map[int][]byte, len(art.Ciphertexts)),
		DescriptorID: append([]byte(nil), art.Descriptor.Digest...),
	}
	for receiver, ct := range art.Ciphertexts {
		out.Ciphertexts[receiver] = append([]byte(nil), ct...)
	}
	return out, nil
}

func (o *OptrandAPVSS) Ver(cfg Config, tx *APVSSTranscript, art *DealerArtifact) error {
	if tx == nil {
		return fmt.Errorf("nil APVSS transcript")
	}
	if art == nil {
		return fmt.Errorf("nil dealer artifact")
	}
	if tx.Dealer != art.Dealer {
		return fmt.Errorf("transcript dealer mismatch: tx=%d art=%d", tx.Dealer, art.Dealer)
	}
	if !bytesEq(tx.Payload, art.Payload) {
		return fmt.Errorf("transcript payload mismatch for dealer=%d", tx.Dealer)
	}
	if !bytesEq(tx.DescriptorID, art.Descriptor.Digest) {
		return fmt.Errorf("transcript descriptor mismatch for dealer=%d", tx.Dealer)
	}
	return OptrandShareVerify(cfg, art)
}

func (o *OptrandAPVSS) Agg(
	cfg Config,
	dealers []int,
	artifacts map[int]*DealerArtifact,
) (*APVSSAggregate, error) {
	agg, err := BuildOptrandAggregatedTranscript(cfg, dealers, artifacts)
	if err != nil {
		return nil, err
	}
	return &APVSSAggregate{
		Provider:        "optrand",
		Dealers:         append([]int(nil), agg.Dealers...),
		AggregateDigest: append([]byte(nil), agg.AggregateDigest...),
		ListTranscript:  agg,
	}, nil
}

func (o *OptrandAPVSS) AVer(cfg Config, agg *APVSSAggregate, artifacts map[int]*DealerArtifact) error {
	if agg == nil {
		return fmt.Errorf("nil APVSS aggregate")
	}
	if agg.Provider != "optrand" {
		return fmt.Errorf("unexpected APVSS provider: %s", agg.Provider)
	}
	if agg.ListTranscript == nil {
		return fmt.Errorf("missing optrand aggregate transcript")
	}
	if err := VerifyOptrandAggregatedTranscript(cfg, agg.ListTranscript, artifacts); err != nil {
		return err
	}
	if !bytesEq(agg.AggregateDigest, agg.ListTranscript.AggregateDigest) {
		return fmt.Errorf("aggregate digest mismatch")
	}
	if len(agg.Dealers) != len(agg.ListTranscript.Dealers) {
		return fmt.Errorf("aggregate dealer count mismatch")
	}
	for i := range agg.Dealers {
		if agg.Dealers[i] != agg.ListTranscript.Dealers[i] {
			return fmt.Errorf("aggregate dealer order mismatch")
		}
	}
	return nil
}

func (o *OptrandAPVSS) Rec(
	cfg Config,
	agg *APVSSAggregate,
	artifacts map[int]*DealerArtifact,
) (*APVSSRecovered, error) {
	if err := o.AVer(cfg, agg, artifacts); err != nil {
		return nil, err
	}
	contrib := make(map[int][]byte, len(agg.ListTranscript.ContributionDigests))
	digestParts := make([][]byte, 0, 2+2*len(agg.Dealers))
	digestParts = append(digestParts, []byte("optrand-rec"), agg.AggregateDigest)
	for _, dealer := range agg.Dealers {
		dig := agg.ListTranscript.ContributionDigests[dealer]
		contrib[dealer] = append([]byte(nil), dig...)
		digestParts = append(digestParts, encodeInts([]int{dealer}), dig)
	}
	return &APVSSRecovered{
		OutputKind:          APVSSOutputEmulated,
		AggregateDigest:     append([]byte(nil), agg.AggregateDigest...),
		RecoveredMaterial:   hashBytes(digestParts...),
		ContributionDigests: contrib,
	}, nil
}
