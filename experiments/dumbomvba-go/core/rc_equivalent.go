package core

import (
	"context"
	"fmt"
	"time"
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

	// RC dissemination is a best-effort fan-out. A peer may have already
	// completed MVBA and closed its listener while this node is still
	// reconstructing a value. Keeping the old sequential Send loop here made
	// one failed peer's retry/backoff stall the only goroutine consuming RC
	// shards. Bound the fan-out wait by the protocol route timeout; certificate
	// and shard validation below remain unchanged.
	sendWait := m.cfg.RouteSendTimeout
	if sendWait <= 0 {
		sendWait = 300 * time.Millisecond
	}
	broadcastRC := func(body interface{}) {
		broadcastEquivalent(ctx, m.net, n, sendWait, ProtocolMessage{
			Tag: TagMVBARC, Round: 0, Leader: 0, Body: body,
		})
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
				dig := pdCertificateDigest("PD_STORED", sid, msg.Leader, msg.Root)
				if msg.Leader < 0 || msg.Leader >= n || !verifyThresholdCertificate(
					m.signer, "PD_STORED", dig, msg.Certificate, threshold,
				) {
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

// broadcastEquivalent fans out one protocol message without allowing a
// stalled peer to stop the caller from processing already delivered messages.
// Send has no context parameter, so timed-out sends finish in their own
// goroutine and are reclaimed when the session transport closes.
func broadcastEquivalent(
	ctx context.Context,
	net Network,
	n int,
	wait time.Duration,
	msg ProtocolMessage,
) {
	if ctx == nil || net == nil || n <= 0 {
		return
	}
	if wait <= 0 {
		wait = 300 * time.Millisecond
	}
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			_ = net.Send(i, msg)
			done <- struct{}{}
		}()
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for completed := 0; completed < n; completed++ {
		select {
		case <-ctx.Done():
			return
		case <-done:
		case <-timer.C:
			return
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
