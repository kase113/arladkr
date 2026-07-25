package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"time"

	dmvba "dumbomvba_go/core"
)

const inProcRecvBuffer = 4096

// ── Shared key derivation ───────────────────────────────────────────────

// deriveMVBAKey generates a deterministic ed25519 key pair for MVBA node i.
// Both in-process and TCP paths use the same derivation so every instance
// independently produces identical keys.
func deriveMVBAKey(sid string, idx int) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	key := sha256.Sum256([]byte(fmt.Sprintf("%s-mvba-%d", sid, idx)))
	block, _ := aes.NewCipher(key[:])
	dr := newDeterministicReader(cipher.NewCTR(block, make([]byte, aes.BlockSize)))
	pub, sk, err := ed25519.GenerateKey(dr)
	if err != nil {
		return nil, nil, err
	}
	return pub, sk, nil
}

// deriveMVBAKeySet generates keys for all n MVBA nodes.
func deriveMVBAKeySet(sid string, n int) (
	map[int]ed25519.PrivateKey, map[int]ed25519.PublicKey, error,
) {
	privKM := make(map[int]ed25519.PrivateKey, n)
	pubKM := make(map[int]ed25519.PublicKey, n)
	for i := 0; i < n; i++ {
		pub, sk, err := deriveMVBAKey(sid, i)
		if err != nil {
			return nil, nil, err
		}
		pubKM[i] = pub
		privKM[i] = sk
	}
	return privKM, pubKM, nil
}

// ── In-process channel network ───────────────────────────────────────────

// inProcNet is a channel-based network connecting co-located MVBA nodes.
// Uses bounded buffers plus a brief blocking fallback so transient
// back-pressure does not silently drop protocol messages.
type inProcNet struct {
	id    int
	peers []chan dmvba.ReceivedMessage
}

func (n *inProcNet) Broadcast(msg dmvba.ProtocolMessage) error {
	rm := dmvba.ReceivedMessage{From: n.id, Msg: msg}
	for _, p := range n.peers {
		select {
		case p <- rm:
		default:
			select {
			case p <- rm:
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return nil
}

func (n *inProcNet) Send(to int, msg dmvba.ProtocolMessage) error {
	if to < 0 || to >= len(n.peers) {
		return nil
	}
	rm := dmvba.ReceivedMessage{From: n.id, Msg: msg}
	select {
	case n.peers[to] <- rm:
	default:
		select {
		case n.peers[to] <- rm:
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil
}

// ── Legacy dealer extraction from ACS (used by TCP fallback path) ──────

// extractDecidedDealersFromACS parses ACS output vectors and returns the
// agreed-upon set of dealer IDs using canonical-ready ordering.
func extractDecidedDealersFromACS(
	acsVecs [][]*dmvba.ProposalValue,
	cfg Config,
	descriptors map[int]Descriptor,
	artifacts map[int]*DealerArtifact,
) []int {
	found := false
	for _, vec := range acsVecs {
		for _, pv := range vec {
			if pv != nil && len(pv.Payload) > 0 {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return nil
	}
	candidates := canonicalReadyCandidates(cfg, descriptors, artifacts)
	if len(candidates) < fastlaneReadyPoolMinimum(cfg) {
		return nil
	}
	required := cfg.F + 1
	if required <= 0 {
		required = 1
	}
	targetSize := cfg.Kappa
	if targetSize < required {
		targetSize = required
	}
	if len(candidates) < targetSize {
		return nil
	}
	dealers := make([]int, 0, targetSize)
	for i := 0; i < targetSize && i < len(candidates); i++ {
		dealers = append(dealers, candidates[i].dealer)
	}
	return normalizeCandidate(dealers, targetSize, cfg.OldCommittee)
}

// ── Legacy descriptor digest map (kept for backward compat) ─────────────

func descriptorDigestMap(descriptors map[int]Descriptor) map[int]string {
	m := make(map[int]string, len(descriptors))
	for id, d := range descriptors {
		h := sha256.Sum256(d.Digest)
		m[id] = fmt.Sprintf("%x", h[:])
	}
	return m
}
