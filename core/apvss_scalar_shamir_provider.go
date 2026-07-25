package core

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

// ScalarShamirProvider currently declares only the capability contract of the
// functional scalar-output Shamir prototype. Later tasks will implement its
// APVSS operations.
type ScalarShamirProvider struct{}

func scalarShamirHash(domain string, parts ...[]byte) []byte {
	h := sha256.New()
	var length [8]byte
	writePart := func(part []byte) {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(part)
	}
	writePart([]byte(domain))
	for _, part := range parts {
		writePart(part)
	}
	return h.Sum(nil)
}

func NewScalarShamirAPVSS() *ScalarShamirProvider {
	return &ScalarShamirProvider{}
}

func (p *ScalarShamirProvider) Capabilities() APVSSCapabilities {
	return APVSSCapabilities{
		OutputKind:                 APVSSOutputScalar,
		VerifiesReceivedTranscript: true,
		AggregatesReceivedInputs:   true,
		ProducesVerifiableShares:   true,
		SupportsThresholdKeyOutput: true,
		SecurityProfile:            "functional-scalar-prototype",
	}
}

func (p *ScalarShamirProvider) ADist(cfg Config, art *DealerArtifact) (*APVSSTranscript, error) {
	if _, err := verifyScalarShamirArtifact(cfg, art); err != nil {
		return nil, err
	}
	return &APVSSTranscript{
		Dealer:       art.Dealer,
		Payload:      append([]byte(nil), art.Payload...),
		Ciphertexts:  cloneBytesMap(art.Ciphertexts),
		DescriptorID: append([]byte(nil), art.Descriptor.Digest...),
	}, nil
}

func (p *ScalarShamirProvider) Ver(cfg Config, tx *APVSSTranscript, art *DealerArtifact) error {
	if tx == nil {
		return fmt.Errorf("nil scalar-shamir transcript")
	}
	if _, err := verifyScalarShamirArtifact(cfg, art); err != nil {
		return err
	}
	if tx.Dealer != art.Dealer {
		return fmt.Errorf("scalar-shamir transcript dealer mismatch: tx=%d artifact=%d", tx.Dealer, art.Dealer)
	}
	if !bytesEq(tx.Payload, art.Payload) {
		return fmt.Errorf("scalar-shamir transcript payload mismatch for dealer=%d", art.Dealer)
	}
	if !bytesEq(tx.DescriptorID, art.Descriptor.Digest) {
		return fmt.Errorf("scalar-shamir transcript descriptor mismatch for dealer=%d", art.Dealer)
	}
	if len(tx.Ciphertexts) != len(art.Ciphertexts) {
		return fmt.Errorf("scalar-shamir transcript ciphertext count mismatch for dealer=%d", art.Dealer)
	}
	for receiver, expected := range art.Ciphertexts {
		got, ok := tx.Ciphertexts[receiver]
		if !ok || !bytesEq(got, expected) {
			return fmt.Errorf("scalar-shamir transcript ciphertext mismatch for dealer=%d receiver=%d", art.Dealer, receiver)
		}
	}
	return nil
}

func (p *ScalarShamirProvider) Agg(
	cfg Config,
	dealers []int,
	artifacts map[int]*DealerArtifact,
) (*APVSSAggregate, error) {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	if len(dealers) == 0 {
		return nil, fmt.Errorf("empty scalar-shamir dealer set")
	}
	canonDealers := sortedUnique(dealers)
	if len(canonDealers) != len(dealers) {
		return nil, fmt.Errorf("scalar-shamir aggregate dealers must be distinct")
	}
	threshold := c.F + 1
	if threshold < 1 {
		threshold = 1
	}
	if len(canonDealers) < threshold {
		return nil, fmt.Errorf("insufficient scalar-shamir dealers: have=%d need=%d", len(canonDealers), threshold)
	}

	contributions := make(map[int][]byte, len(canonDealers))
	parts := make([][]byte, 0, 1+len(canonDealers))
	parts = append(parts, encodeInts(canonDealers))
	for _, dealer := range canonDealers {
		if _, ok := c.runtime.oldIndex[dealer]; !ok {
			return nil, fmt.Errorf("scalar-shamir dealer is outside old committee: %d", dealer)
		}
		art, ok := artifacts[dealer]
		if !ok || art == nil {
			return nil, fmt.Errorf("missing scalar-shamir artifact for dealer=%d", dealer)
		}
		tx := scalarShamirTranscriptFromArtifact(art)
		if err := p.Ver(c, tx, art); err != nil {
			return nil, fmt.Errorf("scalar-shamir dealer %d artifact: %w", dealer, err)
		}
		if art.Dealer != dealer {
			return nil, fmt.Errorf("scalar-shamir artifact map dealer mismatch: key=%d artifact=%d", dealer, art.Dealer)
		}
		digest := scalarShamirContributionDigest(art)
		contributions[dealer] = append([]byte(nil), digest...)
		parts = append(parts, digest)
	}
	aggregateDigest := scalarShamirHash("scalar-shamir-agg-v1", parts...)
	inner := &ListBackedAggregateTranscript{
		Dealers:             append([]int(nil), canonDealers...),
		ContributionDigests: contributions,
		AggregateDigest:     append([]byte(nil), aggregateDigest...),
		Trusted:             false,
	}
	return &APVSSAggregate{
		Provider:        "scalar-shamir",
		Dealers:         append([]int(nil), canonDealers...),
		AggregateDigest: append([]byte(nil), aggregateDigest...),
		ListTranscript:  inner,
	}, nil
}

func (p *ScalarShamirProvider) AVer(cfg Config, agg *APVSSAggregate, artifacts map[int]*DealerArtifact) error {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return err
	}
	if agg == nil {
		return fmt.Errorf("nil scalar-shamir aggregate")
	}
	if agg.Provider != "scalar-shamir" {
		return fmt.Errorf("unexpected scalar-shamir aggregate provider: %s", agg.Provider)
	}
	inner := agg.ListTranscript
	if inner == nil {
		return fmt.Errorf("missing scalar-shamir contribution container")
	}
	if inner.Trusted {
		return fmt.Errorf("scalar-shamir aggregate cannot use trusted shortcut")
	}
	canonDealers := sortedUnique(agg.Dealers)
	if len(canonDealers) != len(agg.Dealers) || !scalarShamirIntSlicesEqual(canonDealers, agg.Dealers) {
		return fmt.Errorf("scalar-shamir outer dealers must be canonical and distinct")
	}
	threshold := c.F + 1
	if threshold < 1 {
		threshold = 1
	}
	if len(canonDealers) < threshold {
		return fmt.Errorf("insufficient scalar-shamir aggregate dealers: have=%d need=%d", len(canonDealers), threshold)
	}
	if len(inner.Dealers) != len(canonDealers) || !scalarShamirIntSlicesEqual(inner.Dealers, canonDealers) {
		return fmt.Errorf("scalar-shamir inner dealer list mismatch")
	}
	if len(inner.ContributionDigests) != len(canonDealers) {
		return fmt.Errorf("scalar-shamir contribution count mismatch")
	}
	if !bytesEq(agg.AggregateDigest, inner.AggregateDigest) {
		return fmt.Errorf("scalar-shamir inner/outer aggregate digest mismatch")
	}

	parts := make([][]byte, 0, 1+len(canonDealers))
	parts = append(parts, encodeInts(canonDealers))
	for _, dealer := range canonDealers {
		if _, ok := c.runtime.oldIndex[dealer]; !ok {
			return fmt.Errorf("scalar-shamir dealer is outside old committee: %d", dealer)
		}
		art, ok := artifacts[dealer]
		if !ok || art == nil {
			return fmt.Errorf("missing scalar-shamir artifact for dealer=%d", dealer)
		}
		if art.Dealer != dealer {
			return fmt.Errorf("scalar-shamir artifact map dealer mismatch: key=%d artifact=%d", dealer, art.Dealer)
		}
		if err := p.Ver(c, scalarShamirTranscriptFromArtifact(art), art); err != nil {
			return fmt.Errorf("scalar-shamir dealer %d artifact: %w", dealer, err)
		}
		expected := scalarShamirContributionDigest(art)
		got, ok := inner.ContributionDigests[dealer]
		if !ok || !bytesEq(got, expected) {
			return fmt.Errorf("scalar-shamir contribution digest mismatch for dealer=%d", dealer)
		}
		parts = append(parts, expected)
	}
	expectedAggregate := scalarShamirHash("scalar-shamir-agg-v1", parts...)
	if !bytesEq(agg.AggregateDigest, expectedAggregate) || !bytesEq(inner.AggregateDigest, expectedAggregate) {
		return fmt.Errorf("scalar-shamir aggregate digest mismatch")
	}
	return nil
}

func (p *ScalarShamirProvider) Rec(
	cfg Config,
	agg *APVSSAggregate,
	artifacts map[int]*DealerArtifact,
) (*APVSSRecovered, error) {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	if err := p.AVer(c, agg, artifacts); err != nil {
		return nil, err
	}

	receiverOrder := c.runtime.receiverOrder
	threshold := dealerShareThreshold(c, len(receiverOrder))
	if threshold == 0 {
		return nil, fmt.Errorf("invalid scalar-shamir recovery threshold")
	}
	suite := edwards25519.NewBlakeSHA256Ed25519()
	receiverShares := make(map[int]kyber.Scalar, len(receiverOrder))
	for _, receiver := range receiverOrder {
		receiverShares[receiver] = suite.Scalar().Zero()
	}
	publicKey := suite.Point().Null()

	for _, dealer := range agg.Dealers {
		result := processDealer(c, dealer, artifacts[dealer], len(receiverOrder))
		if result.err != nil {
			return nil, result.err
		}
		if result.validOpeners != len(receiverOrder) || len(result.shares) != len(receiverOrder) {
			return nil, fmt.Errorf(
				"dealer %d: incomplete scalar-shamir share set: have=%d need=%d",
				dealer,
				len(result.shares),
				len(receiverOrder),
			)
		}
		for _, receiver := range receiverOrder {
			dealerShare, ok := result.shares[receiver]
			if !ok || dealerShare == nil {
				return nil, fmt.Errorf("dealer %d: missing verified share for receiver=%d", dealer, receiver)
			}
			receiverShares[receiver].Add(receiverShares[receiver], dealerShare)
		}
		if result.commit == nil {
			return nil, fmt.Errorf("dealer %d: missing constant commitment", dealer)
		}
		publicKey.Add(publicKey, result.commit)
	}

	scalarShares := make(map[int][]byte, len(receiverOrder))
	for _, receiver := range receiverOrder {
		raw, err := receiverShares[receiver].MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("marshal scalar-shamir share for receiver=%d: %w", receiver, err)
		}
		canonical := suite.Scalar()
		if err := canonical.UnmarshalBinary(raw); err != nil {
			return nil, fmt.Errorf("validate scalar-shamir share for receiver=%d: %w", receiver, err)
		}
		canonicalRaw, err := canonical.MarshalBinary()
		if err != nil || !bytesEq(raw, canonicalRaw) {
			return nil, fmt.Errorf("non-canonical scalar-shamir share for receiver=%d", receiver)
		}
		scalarShares[receiver] = append([]byte(nil), raw...)
	}
	if publicKey.Equal(suite.Point().Null()) {
		return nil, fmt.Errorf("scalar-shamir threshold public key is identity")
	}
	eight := suite.Scalar().SetInt64(8)
	inverseEight := suite.Scalar().Inv(eight)
	projected := suite.Point().Mul(inverseEight, suite.Point().Mul(eight, publicKey))
	if !projected.Equal(publicKey) {
		return nil, fmt.Errorf("scalar-shamir threshold public key is outside prime-order subgroup")
	}
	publicKeyRaw, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal scalar-shamir threshold public key: %w", err)
	}
	canonicalPublicKey := suite.Point()
	if err := canonicalPublicKey.UnmarshalBinary(publicKeyRaw); err != nil {
		return nil, fmt.Errorf("validate scalar-shamir threshold public key: %w", err)
	}
	canonicalPublicKeyRaw, err := canonicalPublicKey.MarshalBinary()
	if err != nil || !bytesEq(publicKeyRaw, canonicalPublicKeyRaw) {
		return nil, fmt.Errorf("non-canonical scalar-shamir threshold public key")
	}

	contributions := cloneBytesMap(agg.ListTranscript.ContributionDigests)
	recoveredMaterial := scalarShamirRecoveredMaterialHash(
		agg.AggregateDigest,
		threshold,
		agg.Dealers,
		contributions,
		receiverOrder,
		scalarShares,
		publicKeyRaw,
	)
	return &APVSSRecovered{
		OutputKind:          APVSSOutputScalar,
		AggregateDigest:     append([]byte(nil), agg.AggregateDigest...),
		RecoveredMaterial:   recoveredMaterial,
		ContributionDigests: contributions,
		ScalarThreshold:     threshold,
		ScalarShares:        scalarShares,
		ThresholdPublicKey:  append([]byte(nil), publicKeyRaw...),
	}, nil
}

func scalarShamirRecoveredMaterialHash(
	aggregateDigest []byte,
	threshold int,
	dealers []int,
	contributions map[int][]byte,
	receiverOrder []int,
	scalarShares map[int][]byte,
	publicKey []byte,
) []byte {
	parts := make([][]byte, 0, 4+2*len(dealers)+2*len(receiverOrder))
	parts = append(parts,
		aggregateDigest,
		encodeInts([]int{threshold}),
		encodeInts(dealers),
	)
	for _, dealer := range dealers {
		parts = append(parts, encodeInts([]int{dealer}), contributions[dealer])
	}
	for _, receiver := range receiverOrder {
		parts = append(parts, encodeInts([]int{receiver}), scalarShares[receiver])
	}
	parts = append(parts, publicKey)
	return scalarShamirHash("scalar-shamir-recovered-v1", parts...)
}

func verifyScalarShamirArtifact(cfg Config, art *DealerArtifact) (*decodedDealerTranscript, error) {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	if c.runtime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}
	if c.APVSSProvider != "scalar-shamir" {
		return nil, fmt.Errorf("scalar-shamir provider required, got %q", c.APVSSProvider)
	}
	if art == nil {
		return nil, fmt.Errorf("nil scalar-shamir dealer artifact")
	}
	if art.Dealer != art.Descriptor.Dealer || art.Dealer != art.Descriptor.Header.Dealer {
		return nil, fmt.Errorf("scalar-shamir dealer mismatch for artifact=%d", art.Dealer)
	}
	if _, ok := c.runtime.oldIndex[art.Dealer]; !ok {
		return nil, fmt.Errorf("scalar-shamir dealer is outside old committee: %d", art.Dealer)
	}
	if !bytesEq(art.Descriptor.Digest, digestDescriptor(art.Descriptor)) {
		return nil, fmt.Errorf("scalar-shamir descriptor digest mismatch for dealer=%d", art.Dealer)
	}
	if !ValidateDescriptor(c, art.Descriptor) {
		return nil, fmt.Errorf("scalar-shamir descriptor validation failed for dealer=%d", art.Dealer)
	}
	if !bytesEq(hashBytes([]byte("rladkr-root"), art.Payload), art.Descriptor.Header.Root) {
		return nil, fmt.Errorf("scalar-shamir payload root mismatch for dealer=%d", art.Dealer)
	}
	transcript, err := decodeDealerTranscript(art.Payload)
	if err != nil {
		return nil, fmt.Errorf("scalar-shamir transcript decode failed for dealer=%d: %w", art.Dealer, err)
	}
	if transcript.Version != 1 {
		return nil, fmt.Errorf("scalar-shamir rejects transcript version=%d", transcript.Version)
	}
	if transcript.Provider != "scalar-shamir" {
		return nil, fmt.Errorf("scalar-shamir transcript provider mismatch: %q", transcript.Provider)
	}
	if transcript.Dealer != art.Dealer {
		return nil, fmt.Errorf("scalar-shamir transcript dealer mismatch: transcript=%d artifact=%d", transcript.Dealer, art.Dealer)
	}
	expectedThreshold := dealerShareThreshold(c, len(c.runtime.receiverOrder))
	if expectedThreshold == 0 || transcript.Threshold != expectedThreshold {
		return nil, fmt.Errorf("scalar-shamir transcript threshold mismatch: have=%d need=%d", transcript.Threshold, expectedThreshold)
	}
	if !scalarShamirIntSlicesEqual(transcript.ReceiverIDs, c.runtime.receiverOrder) {
		return nil, fmt.Errorf("scalar-shamir transcript receiver order mismatch")
	}
	if !bytesEq(transcript.MetadataHash, dealerTranscriptMetadataHash(c)) {
		return nil, fmt.Errorf("scalar-shamir transcript metadata mismatch")
	}
	if len(art.Ciphertexts) != len(c.runtime.receiverOrder) {
		return nil, fmt.Errorf("scalar-shamir ciphertext receiver count mismatch for dealer=%d", art.Dealer)
	}
	for _, receiver := range c.runtime.receiverOrder {
		ciphertext, ok := art.Ciphertexts[receiver]
		if !ok || len(ciphertext) == 0 {
			return nil, fmt.Errorf("missing scalar-shamir ciphertext for dealer=%d receiver=%d", art.Dealer, receiver)
		}
	}
	expectedContribution := scalarShamirContributionDigest(art)
	if len(art.ContributionDigest) == 0 || !bytesEq(art.ContributionDigest, expectedContribution) {
		return nil, fmt.Errorf("scalar-shamir contribution digest mismatch for dealer=%d", art.Dealer)
	}
	return transcript, nil
}

func scalarShamirTranscriptFromArtifact(art *DealerArtifact) *APVSSTranscript {
	if art == nil {
		return nil
	}
	return &APVSSTranscript{
		Dealer:       art.Dealer,
		Payload:      append([]byte(nil), art.Payload...),
		Ciphertexts:  cloneBytesMap(art.Ciphertexts),
		DescriptorID: append([]byte(nil), art.Descriptor.Digest...),
	}
}

func scalarShamirIntSlicesEqual(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
