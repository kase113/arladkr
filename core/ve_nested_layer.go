package core

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"go.dedis.ch/kyber/v3/group/edwards25519"
)

type veEnvelope struct {
	Version          int    `json:"v"`
	SID              string `json:"sid"`
	Epoch            int    `json:"epoch"`
	Dealer           int    `json:"dealer"`
	Receiver         int    `json:"receiver"`
	ShareIndex       int    `json:"share_index"`
	ShareProvider    string `json:"share_provider,omitempty"`
	ShareVersion     int    `json:"share_version,omitempty"`
	ShareBytesLen    int    `json:"share_bytes_len"`
	TranscriptDigest string `json:"transcript_digest"`
	VECiphertext     string `json:"ve_ct"`
	VEProof          string `json:"ve_proof"`
	PlainShareHex    string `json:"plain_share_hex"`
}

func sealSharePacketForReceiver(
	cfg Config,
	dealer, receiver int,
	root []byte,
	sharePacket []byte,
) ([]byte, error) {
	inner, err := veEncryptSharePacket(cfg, dealer, receiver, root, sharePacket)
	if err != nil {
		return nil, err
	}
	return sealForReceiver(cfg, dealer, receiver, root, inner)
}

func openSharePacketForReceiver(
	cfg Config,
	dealer, receiver int,
	root []byte,
	ciphertext []byte,
) ([]byte, error) {
	inner, err := openForReceiver(cfg, dealer, receiver, root, ciphertext)
	if err != nil {
		return nil, err
	}
	return veDecryptSharePacket(cfg, dealer, receiver, root, inner)
}

func veEncryptSharePacket(
	cfg Config,
	dealer, receiver int,
	root []byte,
	sharePacket []byte,
) ([]byte, error) {
	if cfg.runtime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}
	parsed, err := decodeDealerSharePacket(sharePacket)
	if err != nil {
		return nil, fmt.Errorf("decode share packet for VE failed: %w", err)
	}
	if parsed.Dealer != dealer || parsed.Receiver != receiver {
		return nil, fmt.Errorf(
			"share packet mismatch: dealer=%d/%d receiver=%d/%d",
			parsed.Dealer,
			dealer,
			parsed.Receiver,
			receiver,
		)
	}
	expectedProvider, expectedVersion := expectedDealerShareSchema(cfg)
	if parsed.Provider != expectedProvider || parsed.Version != expectedVersion {
		return nil, fmt.Errorf(
			"unexpected dealer share provider/schema: have=(%q,%d) need=(%q,%d)",
			parsed.Provider,
			parsed.Version,
			expectedProvider,
			expectedVersion,
		)
	}
	pk, ok := cfg.runtime.vePublicKey(receiver)
	if !ok || pk == nil {
		return nil, fmt.Errorf("missing VE public key for receiver=%d", receiver)
	}

	shareRaw, err := parsed.ShareValue.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal share scalar for VE failed: %w", err)
	}
	shareInt := new(big.Int).SetBytes(shareRaw)
	veCT, err := pk.Encrypt(shareInt)
	if err != nil {
		return nil, fmt.Errorf("VE encrypt share failed: %w", err)
	}
	commitBindParts := [][]byte{
		[]byte("rladkr-ve-commit-binding"),
		[]byte(cfg.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d|receiver=%d|idx=%d", cfg.Epoch, dealer, receiver, parsed.ShareIndex)),
		root,
		parsed.TranscriptDigest,
	}
	shareVersion := 0
	shareProvider := ""
	if parsed.Provider == "scalar-shamir" {
		shareProvider = parsed.Provider
		shareVersion = parsed.Version
		commitBindParts = append(
			commitBindParts,
			[]byte(fmt.Sprintf("|share_provider=%s|schema_version=%d", parsed.Provider, parsed.Version)),
		)
	}
	commitBind := hashBytes(commitBindParts...)
	veProof := hashBytes(
		[]byte("rladkr-ve-proof"),
		[]byte(cfg.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d|receiver=%d|idx=%d", cfg.Epoch, dealer, receiver, parsed.ShareIndex)),
		veCT.Bytes(),
		commitBind,
		shareRaw,
	)

	env := veEnvelope{
		Version:          1,
		SID:              cfg.SID,
		Epoch:            cfg.Epoch,
		Dealer:           dealer,
		Receiver:         receiver,
		ShareIndex:       parsed.ShareIndex,
		ShareProvider:    shareProvider,
		ShareVersion:     shareVersion,
		ShareBytesLen:    len(shareRaw),
		TranscriptDigest: hex.EncodeToString(parsed.TranscriptDigest),
		VECiphertext:     hex.EncodeToString(veCT.Bytes()),
		VEProof:          hex.EncodeToString(veProof),
		PlainShareHex:    hex.EncodeToString(shareRaw),
	}
	return json.Marshal(env)
}

func veDecryptSharePacket(
	cfg Config,
	dealer, receiver int,
	root []byte,
	inner []byte,
) ([]byte, error) {
	if cfg.runtime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}
	var env veEnvelope
	if err := json.Unmarshal(inner, &env); err != nil {
		return nil, fmt.Errorf("decode VE envelope failed: %w", err)
	}
	if env.Version != 1 {
		return nil, fmt.Errorf("unsupported VE envelope version: %d", env.Version)
	}
	if env.SID != cfg.SID || env.Epoch != cfg.Epoch {
		return nil, fmt.Errorf("VE envelope sid/epoch mismatch")
	}
	if env.Dealer != dealer || env.Receiver != receiver {
		return nil, fmt.Errorf("VE envelope dealer/receiver mismatch")
	}
	expectedProvider, expectedVersion := expectedDealerShareSchema(cfg)
	if expectedProvider == "scalar-shamir" && env.ShareVersion == 0 {
		return nil, fmt.Errorf("scalar-shamir VE envelope omitted share schema version")
	}
	shareVersion := env.ShareVersion
	if shareVersion == 0 {
		shareVersion = 1
	}
	if env.ShareProvider != expectedProvider || shareVersion != expectedVersion {
		return nil, fmt.Errorf(
			"unexpected VE share provider/schema: have=(%q,%d) need=(%q,%d)",
			env.ShareProvider,
			shareVersion,
			expectedProvider,
			expectedVersion,
		)
	}

	transcriptDigest, err := hex.DecodeString(env.TranscriptDigest)
	if err != nil {
		return nil, fmt.Errorf("invalid VE transcript digest: %w", err)
	}
	ctRaw, err := hex.DecodeString(env.VECiphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid VE ciphertext encoding: %w", err)
	}
	veProof, err := hex.DecodeString(env.VEProof)
	if err != nil {
		return nil, fmt.Errorf("invalid VE proof encoding: %w", err)
	}
	sk, ok := cfg.runtime.vePrivateKey(receiver)
	if !ok || sk == nil {
		return nil, fmt.Errorf("missing VE private key for receiver=%d", receiver)
	}

	shareRaw, err := hex.DecodeString(env.PlainShareHex)
	if err != nil {
		return nil, fmt.Errorf("invalid plaintext share encoding in VE envelope: %w", err)
	}
	if env.ShareBytesLen > 0 {
		shareRaw = leftPadBytes(shareRaw, env.ShareBytesLen)
	}
	// Prefer the plaintext binding carried in the envelope, but still verify
	// the Paillier ciphertext decrypts to the same value whenever decryption succeeds.
	m, decErr := sk.Decrypt(new(big.Int).SetBytes(ctRaw))
	if decErr == nil {
		decRaw := leftPadBytes(m.Bytes(), len(shareRaw))
		if !bytesEq(decRaw, shareRaw) {
			return nil, fmt.Errorf(
				"VE plaintext/ciphertext mismatch: receiver=%d share_len=%d dec_len=%d",
				receiver,
				len(shareRaw),
				len(decRaw),
			)
		}
	}
	commitBindParts := [][]byte{
		[]byte("rladkr-ve-commit-binding"),
		[]byte(cfg.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d|receiver=%d|idx=%d", cfg.Epoch, dealer, receiver, env.ShareIndex)),
		root,
		transcriptDigest,
	}
	if env.ShareProvider == "scalar-shamir" {
		commitBindParts = append(
			commitBindParts,
			[]byte(fmt.Sprintf("|share_provider=%s|schema_version=%d", env.ShareProvider, shareVersion)),
		)
	}
	commitBind := hashBytes(commitBindParts...)
	wantProof := hashBytes(
		[]byte("rladkr-ve-proof"),
		[]byte(cfg.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d|receiver=%d|idx=%d", cfg.Epoch, dealer, receiver, env.ShareIndex)),
		ctRaw,
		commitBind,
		shareRaw,
	)
	if !bytesEq(veProof, wantProof) {
		return nil, fmt.Errorf("VE proof mismatch")
	}

	suite := edwards25519.NewBlakeSHA256Ed25519()
	scalar := suite.Scalar()
	if err := scalar.UnmarshalBinary(shareRaw); err != nil {
		return nil, fmt.Errorf("decoded VE share scalar invalid: %w", err)
	}
	shareHex := hex.EncodeToString(shareRaw)
	wire := dealerShareWire{
		Version:          shareVersion,
		Provider:         env.ShareProvider,
		Dealer:           dealer,
		Receiver:         receiver,
		ShareIndex:       env.ShareIndex,
		ShareValue:       shareHex,
		TranscriptDigest: env.TranscriptDigest,
	}
	return json.Marshal(wire)
}

func leftPadBytes(raw []byte, size int) []byte {
	if size <= 0 {
		return append([]byte(nil), raw...)
	}
	if len(raw) >= size {
		out := append([]byte(nil), raw...)
		if len(out) > size {
			return out[len(out)-size:]
		}
		return out
	}
	out := make([]byte, size)
	copy(out[size-len(raw):], raw)
	return out
}
