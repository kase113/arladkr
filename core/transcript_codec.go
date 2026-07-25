package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

type dealerTranscriptWire struct {
	Version      int      `json:"v"`
	Provider     string   `json:"provider,omitempty"`
	Dealer       int      `json:"dealer"`
	Threshold    int      `json:"threshold"`
	ReceiverIDs  []int    `json:"receiver_ids"`
	Commitments  []string `json:"commitments"`
	MetadataHash string   `json:"metadata_hash"`
}

type dealerShareWire struct {
	Version          int    `json:"v"`
	Provider         string `json:"provider,omitempty"`
	Dealer           int    `json:"dealer"`
	Receiver         int    `json:"receiver"`
	ShareIndex       int    `json:"share_index"`
	ShareValue       string `json:"share_value"`
	TranscriptDigest string `json:"transcript_digest"`
}

type decodedDealerTranscript struct {
	Version      int
	Provider     string
	Dealer       int
	Threshold    int
	ReceiverIDs  []int
	MetadataHash []byte
	PubPoly      *share.PubPoly
	Raw          []byte
}

type decodedDealerShare struct {
	Version          int
	Provider         string
	Dealer           int
	Receiver         int
	ShareIndex       int
	ShareValue       kyber.Scalar
	TranscriptDigest []byte
}

func buildDealerTranscript(cfg Config, dealer int) ([]byte, map[int][]byte, error) {
	if cfg.runtime == nil {
		return nil, nil, fmt.Errorf("runtime not initialized")
	}
	suite := edwards25519.NewBlakeSHA256Ed25519()
	shareThreshold := dealerShareThreshold(cfg, len(cfg.runtime.receiverOrder))
	if shareThreshold == 0 {
		return nil, nil, fmt.Errorf("invalid dealer share threshold for receiver count=%d", len(cfg.runtime.receiverOrder))
	}
	transcriptVersion := 1
	shareVersion := 1
	provider := ""
	scalarShamir := strings.EqualFold(strings.TrimSpace(cfg.APVSSProvider), "scalar-shamir")
	if scalarShamir {
		provider = "scalar-shamir"
	}
	// The deterministic stream is prototype-only scaffolding, not a claim of
	// production-secure dealer randomness.
	stream := deterministicStream(
		"rladkr-dealer-shamir",
		[]byte(cfg.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d", cfg.Epoch, dealer)),
		encodeInts(cfg.runtime.receiverOrder),
	)
	if scalarShamir {
		stream = deterministicStream(
			"rladkr-scalar-shamir-dealer-v1",
			[]byte(cfg.SID),
			[]byte("|provider=scalar-shamir|schema_version=1"),
			[]byte(fmt.Sprintf("|epoch=%d|dealer=%d", cfg.Epoch, dealer)),
			encodeInts(cfg.runtime.receiverOrder),
		)
	}
	secret := suite.Scalar().Pick(stream)
	priPoly := share.NewPriPoly(suite, shareThreshold, secret, stream)
	pubPoly := priPoly.Commit(suite.Point().Base())
	_, commits := pubPoly.Info()

	commitHex := make([]string, 0, len(commits))
	for _, p := range commits {
		raw, err := p.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		commitHex = append(commitHex, hex.EncodeToString(raw))
	}
	wire := dealerTranscriptWire{
		Version:      transcriptVersion,
		Provider:     provider,
		Dealer:       dealer,
		Threshold:    shareThreshold,
		ReceiverIDs:  append([]int(nil), cfg.runtime.receiverOrder...),
		Commitments:  commitHex,
		MetadataHash: hex.EncodeToString(dealerTranscriptMetadataHash(cfg)),
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		return nil, nil, err
	}

	transcriptDigest := hashBytes([]byte("rladkr-transcript-digest"), payload)
	packets := make(map[int][]byte, len(cfg.runtime.receiverOrder))
	for _, receiver := range cfg.runtime.receiverOrder {
		idx := cfg.runtime.receiverIndex[receiver]
		shareVal := priPoly.Eval(idx)
		rawShare, err := shareVal.V.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		shareWire := dealerShareWire{
			Version:          shareVersion,
			Provider:         provider,
			Dealer:           dealer,
			Receiver:         receiver,
			ShareIndex:       idx,
			ShareValue:       hex.EncodeToString(rawShare),
			TranscriptDigest: hex.EncodeToString(transcriptDigest),
		}
		shareBlob, mErr := json.Marshal(shareWire)
		if mErr != nil {
			return nil, nil, mErr
		}
		packets[receiver] = shareBlob
	}
	return payload, packets, nil
}

func decodeDealerTranscript(payload []byte) (*decodedDealerTranscript, error) {
	var wire dealerTranscriptWire
	if err := json.Unmarshal(payload, &wire); err != nil {
		return nil, fmt.Errorf("decode dealer transcript: %w", err)
	}
	canonical, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode canonical dealer transcript: %w", err)
	}
	if !bytes.Equal(payload, canonical) {
		return nil, fmt.Errorf("non-canonical dealer transcript encoding")
	}
	if wire.Version != 1 {
		return nil, fmt.Errorf("unsupported dealer transcript version: %d", wire.Version)
	}
	if wire.Provider != "" && wire.Provider != "scalar-shamir" {
		return nil, fmt.Errorf("unsupported dealer transcript provider/schema: provider=%q version=%d", wire.Provider, wire.Version)
	}
	if wire.Threshold <= 0 {
		return nil, fmt.Errorf("invalid transcript threshold: %d", wire.Threshold)
	}
	if wire.Threshold > len(wire.ReceiverIDs) {
		return nil, fmt.Errorf("transcript threshold exceeds receiver count: threshold=%d receivers=%d", wire.Threshold, len(wire.ReceiverIDs))
	}
	seenReceivers := make(map[int]struct{}, len(wire.ReceiverIDs))
	for _, receiver := range wire.ReceiverIDs {
		if _, exists := seenReceivers[receiver]; exists {
			return nil, fmt.Errorf("duplicate transcript receiver ID: %d", receiver)
		}
		seenReceivers[receiver] = struct{}{}
	}
	metadataHash, err := hex.DecodeString(wire.MetadataHash)
	if err != nil {
		return nil, fmt.Errorf("invalid transcript metadata hash encoding: %w", err)
	}
	if len(metadataHash) != sha256.Size {
		return nil, fmt.Errorf("invalid transcript metadata hash length: %d", len(metadataHash))
	}
	suite := edwards25519.NewBlakeSHA256Ed25519()
	identity := suite.Point().Null()
	eight := suite.Scalar().SetInt64(8)
	inverseEight := suite.Scalar().Inv(eight)
	commits := make([]kyber.Point, 0, len(wire.Commitments))
	for _, encoded := range wire.Commitments {
		raw, err := hex.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("invalid commitment encoding: %w", err)
		}
		p := suite.Point()
		if err := p.UnmarshalBinary(raw); err != nil {
			return nil, fmt.Errorf("invalid commitment point: %w", err)
		}
		canonicalPoint, err := p.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("marshal commitment point: %w", err)
		}
		if !bytes.Equal(raw, canonicalPoint) {
			return nil, fmt.Errorf("non-canonical commitment point encoding")
		}
		if p.Equal(identity) {
			return nil, fmt.Errorf("identity commitment point")
		}
		cofactorCleared := suite.Point().Mul(eight, p)
		projected := suite.Point().Mul(inverseEight, cofactorCleared)
		if !projected.Equal(p) {
			return nil, fmt.Errorf("commitment point outside prime-order subgroup")
		}
		commits = append(commits, p)
	}
	if len(commits) != wire.Threshold {
		return nil, fmt.Errorf("commitment count mismatch: have=%d threshold=%d", len(commits), wire.Threshold)
	}
	return &decodedDealerTranscript{
		Version:      wire.Version,
		Provider:     wire.Provider,
		Dealer:       wire.Dealer,
		Threshold:    wire.Threshold,
		ReceiverIDs:  append([]int(nil), wire.ReceiverIDs...),
		MetadataHash: append([]byte(nil), metadataHash...),
		PubPoly:      share.NewPubPoly(suite, suite.Point().Base(), commits),
		Raw:          append([]byte(nil), payload...),
	}, nil
}

func decodeDealerSharePacket(payload []byte) (*decodedDealerShare, error) {
	var wire dealerShareWire
	if err := json.Unmarshal(payload, &wire); err != nil {
		return nil, fmt.Errorf("decode dealer share packet: %w", err)
	}
	canonical, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode canonical dealer share packet: %w", err)
	}
	if !bytes.Equal(payload, canonical) {
		return nil, fmt.Errorf("non-canonical dealer share packet encoding")
	}
	if wire.Version != 1 || (wire.Provider != "" && wire.Provider != "scalar-shamir") {
		return nil, fmt.Errorf("unsupported dealer share provider/schema: provider=%q version=%d", wire.Provider, wire.Version)
	}
	suite := edwards25519.NewBlakeSHA256Ed25519()
	shareRaw, err := hex.DecodeString(wire.ShareValue)
	if err != nil {
		return nil, fmt.Errorf("invalid share encoding: %w", err)
	}
	s := suite.Scalar()
	if err := s.UnmarshalBinary(shareRaw); err != nil {
		return nil, fmt.Errorf("invalid share scalar: %w", err)
	}
	canonicalShare, err := s.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal share scalar: %w", err)
	}
	if !bytes.Equal(shareRaw, canonicalShare) {
		return nil, fmt.Errorf("non-canonical share scalar encoding")
	}
	dig, err := hex.DecodeString(wire.TranscriptDigest)
	if err != nil {
		return nil, fmt.Errorf("invalid transcript digest encoding: %w", err)
	}
	if len(dig) != sha256.Size {
		return nil, fmt.Errorf("invalid transcript digest length: %d", len(dig))
	}
	return &decodedDealerShare{
		Version:          wire.Version,
		Provider:         wire.Provider,
		Dealer:           wire.Dealer,
		Receiver:         wire.Receiver,
		ShareIndex:       wire.ShareIndex,
		ShareValue:       s,
		TranscriptDigest: dig,
	}, nil
}

func dealerShareThreshold(cfg Config, receiverCount int) int {
	if receiverCount <= 0 {
		return 0
	}
	if strings.EqualFold(strings.TrimSpace(cfg.APVSSProvider), "scalar-shamir") {
		threshold := cfg.F + 1
		if threshold < 1 || threshold > receiverCount {
			return 0
		}
		return threshold
	}
	threshold := receiverCount - cfg.F
	if threshold < 1 {
		return 1
	}
	if threshold > receiverCount {
		return receiverCount
	}
	return threshold
}

func expectedDealerShareSchema(cfg Config) (string, int) {
	if strings.EqualFold(strings.TrimSpace(cfg.APVSSProvider), "scalar-shamir") {
		return "scalar-shamir", 1
	}
	return "", 1
}

func dealerTranscriptMetadataHash(cfg Config) []byte {
	return hashBytes(
		[]byte("rladkr-transcript-meta"),
		[]byte(cfg.SID),
		[]byte(fmt.Sprintf("|epoch=%d", cfg.Epoch)),
	)
}
