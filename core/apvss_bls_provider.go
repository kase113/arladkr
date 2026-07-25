package core

import "fmt"

// BlsPVSSProvider is the BLS12-381 group-element prototype provider. Its
// recovered object is not a scalar threshold-key output.
type BlsPVSSProvider struct{}

func NewBlsPVSS() *BlsPVSSProvider {
	return &BlsPVSSProvider{}
}

func (p *BlsPVSSProvider) ADist(cfg Config, art *DealerArtifact) (*APVSSTranscript, error) {
	if _, err := decodeAndVerifyBlsArtifact(cfg, art); err != nil {
		return nil, err
	}
	return &APVSSTranscript{
		Dealer:       art.Dealer,
		Payload:      append([]byte(nil), art.Payload...),
		Ciphertexts:  cloneBytesMap(art.Ciphertexts),
		DescriptorID: append([]byte(nil), art.Descriptor.Digest...),
	}, nil
}

func (p *BlsPVSSProvider) Ver(cfg Config, tx *APVSSTranscript, art *DealerArtifact) error {
	if tx == nil {
		return fmt.Errorf("nil APVSS transcript")
	}
	if art == nil {
		return fmt.Errorf("nil dealer artifact")
	}
	if tx.Dealer != art.Dealer {
		return fmt.Errorf("transcript dealer mismatch: tx=%d art=%d", tx.Dealer, art.Dealer)
	}
	if !bytesEq(tx.DescriptorID, art.Descriptor.Digest) {
		return fmt.Errorf("transcript descriptor mismatch for dealer=%d", tx.Dealer)
	}
	if !bytesEq(tx.Payload, art.Payload) {
		return fmt.Errorf("transcript payload mismatch for dealer=%d", tx.Dealer)
	}
	if len(tx.Ciphertexts) != len(art.Ciphertexts) {
		return fmt.Errorf("transcript ciphertext count mismatch for dealer=%d", tx.Dealer)
	}
	for receiver, expected := range art.Ciphertexts {
		if !bytesEq(tx.Ciphertexts[receiver], expected) {
			return fmt.Errorf("transcript ciphertext mismatch for dealer=%d receiver=%d", tx.Dealer, receiver)
		}
	}
	_, err := decodeAndVerifyBlsArtifact(cfg, art)
	return err
}

func (p *BlsPVSSProvider) Agg(
	cfg Config,
	dealers []int,
	artifacts map[int]*DealerArtifact,
) (*APVSSAggregate, error) {
	canonDealers := sortedUnique(dealers)
	if len(canonDealers) != len(dealers) {
		return nil, fmt.Errorf("BLS PVSS aggregate dealers must be distinct")
	}
	transcripts := make(map[int]*BlsPVSSDealerTranscript, len(canonDealers))
	for _, d := range canonDealers {
		art, ok := artifacts[d]
		if !ok || art == nil {
			return nil, fmt.Errorf("missing artifact for dealer=%d", d)
		}
		tx, err := decodeAndVerifyBlsArtifact(cfg, art)
		if err != nil {
			return nil, fmt.Errorf("dealer %d artifact: %w", d, err)
		}
		transcripts[d] = tx
	}

	agg, err := blsPVSSAggregate(cfg, canonDealers, transcripts)
	if err != nil {
		return nil, err
	}
	digest, err := digestBlsPVSSAggregate(agg)
	if err != nil {
		return nil, err
	}

	return &APVSSAggregate{
		Provider:          "bls-pvss",
		Dealers:           append([]int(nil), canonDealers...),
		AggregateDigest:   digest,
		BlsPVSSTranscript: agg,
	}, nil
}

func (p *BlsPVSSProvider) AVer(cfg Config, agg *APVSSAggregate, artifacts map[int]*DealerArtifact) error {
	if agg == nil {
		return fmt.Errorf("nil aggregate")
	}
	if agg.Provider != "bls-pvss" {
		return fmt.Errorf("unexpected provider: %s", agg.Provider)
	}
	if agg.BlsPVSSTranscript == nil {
		return fmt.Errorf("missing BLS PVSS transcript")
	}
	if len(agg.Dealers) != len(agg.BlsPVSSTranscript.Dealers) {
		return fmt.Errorf("BLS aggregate dealer count mismatch")
	}
	for i := range agg.Dealers {
		if agg.Dealers[i] != agg.BlsPVSSTranscript.Dealers[i] {
			return fmt.Errorf("BLS aggregate dealer order mismatch at index=%d", i)
		}
	}
	if err := blsPVSSAggregateVerify(cfg, agg.BlsPVSSTranscript); err != nil {
		return err
	}
	expected, err := digestBlsPVSSAggregate(agg.BlsPVSSTranscript)
	if err != nil {
		return err
	}
	if !bytesEq(agg.AggregateDigest, expected) {
		return fmt.Errorf("BLS aggregate digest mismatch")
	}
	return nil
}

func (p *BlsPVSSProvider) Rec(
	cfg Config,
	agg *APVSSAggregate,
	artifacts map[int]*DealerArtifact,
) (*APVSSRecovered, error) {
	if err := p.AVer(cfg, agg, artifacts); err != nil {
		return nil, err
	}
	decrypted, err := blsPVSSRecover(cfg, agg.BlsPVSSTranscript)
	if err != nil {
		return nil, err
	}

	contrib := make(map[int][]byte, len(agg.BlsPVSSTranscript.PerDealer))
	for dealerID, tx := range agg.BlsPVSSTranscript.PerDealer {
		payload, encodeErr := encodeBlsPVSSDealerTranscript(tx)
		if encodeErr != nil {
			return nil, encodeErr
		}
		contrib[dealerID] = hashBytes([]byte("bls-pvss-contribution"), payload)
	}

	parts := make([][]byte, 0, 2+len(decrypted))
	parts = append(parts, []byte("blspvss-rec"), agg.AggregateDigest)
	receiverOrder := cfg.runtime.receiverOrder
	for _, receiver := range receiverOrder {
		if dec, ok := decrypted[receiver]; ok {
			parts = append(parts, g2Bytes(&dec))
		}
	}

	return &APVSSRecovered{
		OutputKind:          APVSSOutputGroup,
		AggregateDigest:     append([]byte(nil), agg.AggregateDigest...),
		RecoveredMaterial:   hashBytes(parts...),
		ContributionDigests: contrib,
	}, nil
}

func decodeAndVerifyBlsArtifact(cfg Config, art *DealerArtifact) (*BlsPVSSDealerTranscript, error) {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	if art == nil {
		return nil, fmt.Errorf("nil BLS dealer artifact")
	}
	if art.Dealer != art.Descriptor.Dealer {
		return nil, fmt.Errorf("BLS artifact dealer mismatch: artifact=%d descriptor=%d", art.Dealer, art.Descriptor.Dealer)
	}
	if !bytesEq(art.Descriptor.Digest, digestDescriptor(art.Descriptor)) {
		return nil, fmt.Errorf("BLS artifact descriptor digest mismatch for dealer=%d", art.Dealer)
	}
	if !ValidateDescriptor(c, art.Descriptor) {
		return nil, fmt.Errorf("BLS artifact descriptor validation failed for dealer=%d", art.Dealer)
	}
	if !bytesEq(hashBytes([]byte("rladkr-root"), art.Payload), art.Descriptor.Header.Root) {
		return nil, fmt.Errorf("BLS artifact payload root mismatch for dealer=%d", art.Dealer)
	}
	tx, err := decodeBlsPVSSDealerTranscript(art.Payload)
	if err != nil {
		return nil, fmt.Errorf("BLS artifact decode failed for dealer=%d: %w", art.Dealer, err)
	}
	if tx.Dealer != art.Dealer {
		return nil, fmt.Errorf("BLS decoded dealer mismatch: transcript=%d artifact=%d", tx.Dealer, art.Dealer)
	}
	if err := blsPVSSVerify(c, tx); err != nil {
		return nil, fmt.Errorf("BLS artifact verification failed for dealer=%d: %w", art.Dealer, err)
	}
	if len(art.Ciphertexts) != len(tx.ReceiverOrder) {
		return nil, fmt.Errorf("BLS artifact ciphertext count mismatch for dealer=%d", art.Dealer)
	}
	for i, receiver := range tx.ReceiverOrder {
		if !bytesEq(art.Ciphertexts[receiver], g2Bytes(&tx.EncryptedShares[i])) {
			return nil, fmt.Errorf("BLS artifact ciphertext mismatch for dealer=%d receiver=%d", art.Dealer, receiver)
		}
	}
	return tx, nil
}
