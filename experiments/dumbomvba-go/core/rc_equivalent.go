package core

import (
	"context"
	"fmt"
)

func (m *DumboMVBA) runRCSubprotocol(
	ctx context.Context,
	sid string,
	recv <-chan ReceivedMessage,
	store *rcStoreMsg,
	lock *pdLockMsg,
) ([]byte, error) {
	n := m.cfg.N
	f := m.cfg.F
	threshold := n - f
	// Use the same erasure-code parameters as PD (Provable Dissemination).
	// PD encodes with k = n - 2f. The f+1 threshold previously used is only
	// equal to n-2f when n = 3f+1. For general n ≥ 3f+1, we must match PD.
	k := n - 2*f
	if k <= 0 {
		k = 1
	}

	sendRC := func(to int, body interface{}) {
		_ = m.net.Send(to, ProtocolMessage{
			Tag:    TagMVBARC,
			Round:  0,
			Leader: 0,
			Body:   body,
		})
	}
	broadcastRC := func(body interface{}) {
		for i := 0; i < n; i++ {
			sendRC(i, body)
		}
	}

	if lock != nil {
		broadcastRC(*lock)
	}
	if store != nil {
		broadcastRC(*store)
	}

	commit := make(map[string][][]byte)
	seenStoreBySender := make(map[int]struct{}, n)
	rebroadcastLock := false

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case in := <-recv:
			switch msg := in.Msg.Body.(type) {
			case pdLockMsg:
				if msg.SID != sid {
					continue
				}
				dig := digestDomain("PD_STORED", sid, msg.Root)
				if !verifyShareSet(m.signer, "PD_STORED", dig, msg.Proof, threshold) {
					continue
				}
				if !rebroadcastLock {
					broadcastRC(msg)
					rebroadcastLock = true
				}
				rootKey := fmt.Sprintf("%x", msg.Root)
				shards, ok := commit[rootKey]
				if !ok {
					continue
				}
				if countNonNilShards(shards) >= k {
					val, err := erasureDecodeValue(shards, k, n)
					if err != nil {
						continue
					}
					reencoded, err := erasureEncodeValue(val, k, n)
					if err != nil {
						continue
					}
					root, _ := buildMerkle(reencoded)
					if sameRoot(root, msg.Root) {
						return val, nil
					}
				}
			case rcStoreMsg:
				if msg.SID != sid {
					continue
				}
				if _, seen := seenStoreBySender[msg.From]; seen {
					continue
				}
				if !verifyMerkle(msg.Stripe, msg.Root, msg.Branch) {
					continue
				}
				seenStoreBySender[msg.From] = struct{}{}
				rootKey := fmt.Sprintf("%x", msg.Root)
				shards, ok := commit[rootKey]
				if !ok {
					shards = make([][]byte, n)
				}
				shards[msg.From] = append([]byte(nil), msg.Stripe...)
				commit[rootKey] = shards
			default:
				continue
			}
		}
	}
}

func countNonNilShards(shards [][]byte) int {
	n := 0
	for i := range shards {
		if shards[i] != nil {
			n++
		}
	}
	return n
}
