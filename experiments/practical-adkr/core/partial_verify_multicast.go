package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// partialVerifyResultWire is a compact, signed result multicast.  It carries
// only the verifier's lane bits and a digest of the already dispersed
// transcript; receivers never trust a result for a different transcript.
type partialVerifyResultWire struct {
	Dealer           int          `json:"dealer"`
	Verifier         int          `json:"verifier"`
	TranscriptDigest []byte       `json:"transcript_digest"`
	Lanes            map[int]bool `json:"lanes"`
	Signature        []byte       `json:"signature"`
}

func partialVerifyTranscriptDigest(transcript *DXTTranscript) ([]byte, error) {
	if transcript == nil {
		return nil, errors.New("nil transcript")
	}
	raw, err := json.Marshal(transcript)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte("PRACTICAL-PARTIAL-VERIFY-TRANSCRIPT-v1"))
	h.Write(raw)
	return h.Sum(nil), nil
}

func partialVerifyResultMessage(w *partialVerifyResultWire) []byte {
	h := sha256.New()
	h.Write([]byte("PRACTICAL-PARTIAL-VERIFY-RESULT-v1"))
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(w.Dealer))
	binary.BigEndian.PutUint64(b[8:], uint64(w.Verifier))
	h.Write(b[:])
	h.Write(w.TranscriptDigest)
	ids := make([]int, 0, len(w.Lanes))
	for rid := range w.Lanes {
		ids = append(ids, rid)
	}
	sort.Ints(ids)
	for _, rid := range ids {
		var lane [9]byte
		binary.BigEndian.PutUint64(lane[:8], uint64(rid))
		if w.Lanes[rid] {
			lane[8] = 1
		}
		h.Write(lane[:])
	}
	return h.Sum(nil)
}

func partialVerifyNetworkTimeout(cfg Config) time.Duration {
	timeout := durationFromEnvMsOr("PRACTICAL_PARTIAL_VERIFY_TIMEOUT_MS", 8*time.Second)
	if cfg.RouteSendTimeout > 0 && 8*cfg.RouteSendTimeout > timeout {
		timeout = 8 * cfg.RouteSendTimeout
	}
	if timeout < 2*time.Second {
		timeout = 2 * time.Second
	}
	return timeout
}

// runPartialVerificationMulticast distributes lane-local verification results
// and accepts a transcript only after every lane has f+1 signed positive votes.
// The f+1 threshold is sufficient because each lane is assigned to 2f+1
// verifiers and at least f+1 of those verifiers are honest.
func runPartialVerificationMulticast(
	ctx context.Context,
	cfg Config,
	verifiers []int,
	selectedIDs []int,
	transcripts map[int]*DXTTranscript,
	dxt *DXTBackend,
	tracef func(string, ...any),
) ([]int, map[string]int, error) {
	if len(selectedIDs) == 0 {
		return nil, nil, nil
	}
	addrMap := parseNodeAddrMap(cfg.ProtocolNodeAddrs)
	configuredLocal := parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	localIDs := make([]int, 0, len(configuredLocal))
	verifierSet := make(map[int]struct{}, len(verifiers))
	for _, id := range verifiers {
		verifierSet[id] = struct{}{}
		if _, ok := configuredLocal[id]; ok {
			localIDs = append(localIDs, id)
		}
	}
	sort.Ints(localIDs)
	if len(addrMap) == 0 || len(localIDs) == 0 {
		return nil, nil, errors.New("partial verification multicast requires protocol transport and a local new-committee verifier")
	}
	coverage := make(map[int]int, len(dxt.newCommittee))
	for _, verifier := range verifiers {
		lanes, ok := dxt.partialLaneIDs(verifier)
		if !ok {
			return nil, nil, fmt.Errorf("partial verification verifier %d has no responsibility window", verifier)
		}
		seenLanes := make(map[int]struct{}, len(lanes))
		for _, rid := range lanes {
			if _, duplicate := seenLanes[rid]; duplicate {
				continue
			}
			seenLanes[rid] = struct{}{}
			coverage[rid]++
		}
	}
	for _, rid := range dxt.newCommittee {
		if coverage[rid] < 2*dxt.f+1 {
			return nil, nil, fmt.Errorf("partial verification lane %d coverage=%d need=%d", rid, coverage[rid], 2*dxt.f+1)
		}
	}
	for _, id := range verifiers {
		if strings.TrimSpace(addrMap[id]) == "" {
			return nil, nil, fmt.Errorf("partial verification missing address for verifier %d", id)
		}
	}

	stageCtx, cancel := context.WithTimeout(ctx, partialVerifyNetworkTimeout(cfg))
	defer cancel()
	wireCh := make(chan partialVerifyResultWire, len(verifiers)*len(selectedIDs)*2)
	lnByID := make(map[int]net.Listener, len(localIDs))
	var listenerWG sync.WaitGroup
	cleanupListeners := func() {
		cancel()
		for _, ln := range lnByID {
			_ = ln.Close()
		}
		listenerWG.Wait()
	}
	defer cleanupListeners()

	for _, verifier := range localIDs {
		_, port, err := net.SplitHostPort(addrMap[verifier])
		if err != nil || strings.TrimSpace(port) == "" {
			return nil, nil, fmt.Errorf("invalid partial verification address for verifier %d", verifier)
		}
		ln, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", port))
		if err != nil {
			return nil, nil, fmt.Errorf("partial verification listener %d: %w", verifier, err)
		}
		lnByID[verifier] = ln
		listenerWG.Add(1)
		go func(_ int, listener net.Listener) {
			defer listenerWG.Done()
			for {
				conn, err := listener.Accept()
				if err != nil {
					select {
					case <-stageCtx.Done():
						return
					default:
						continue
					}
				}
				_ = conn.SetReadDeadline(time.Now().Add(partialVerifyNetworkTimeout(cfg)))
				var wire partialVerifyResultWire
				if err := json.NewDecoder(conn).Decode(&wire); err == nil {
					if body, mErr := json.Marshal(wire); mErr == nil {
						recordRecvBytes(len(body))
					}
					select {
					case wireCh <- wire:
					default:
					}
				}
				_ = conn.Close()
			}
		}(verifier, ln)
	}

	transcriptDigests := make(map[int][]byte, len(selectedIDs))
	for _, dealer := range selectedIDs {
		digest, err := partialVerifyTranscriptDigest(transcripts[dealer])
		if err != nil {
			return nil, nil, fmt.Errorf("digest selected transcript %d: %w", dealer, err)
		}
		transcriptDigests[dealer] = digest
	}

	positive := make(map[int]map[int]int, len(selectedIDs))
	seen := make(map[int]map[int]map[int]struct{}, len(selectedIDs))
	for _, dealer := range selectedIDs {
		positive[dealer] = make(map[int]int, len(dxt.newCommittee))
		seen[dealer] = make(map[int]map[int]struct{}, len(verifiers))
	}
	accept := func(wire partialVerifyResultWire) {
		if _, ok := verifierSet[wire.Verifier]; !ok {
			return
		}
		if _, ok := positive[wire.Dealer]; !ok {
			return
		}
		if !bytesEqual(wire.TranscriptDigest, transcriptDigests[wire.Dealer]) {
			return
		}
		pub := dxt.recipientSignPub[wire.Verifier]
		if pub == nil || !ecdsa.VerifyASN1(pub, partialVerifyResultMessage(&wire), wire.Signature) {
			return
		}
		expected, ok := dxt.partialLaneIDs(wire.Verifier)
		if !ok || len(wire.Lanes) != len(expected) {
			return
		}
		expectedSet := make(map[int]struct{}, len(expected))
		for _, rid := range expected {
			expectedSet[rid] = struct{}{}
		}
		for rid := range wire.Lanes {
			if _, ok := expectedSet[rid]; !ok {
				return
			}
		}
		if seen[wire.Dealer][wire.Verifier] == nil {
			seen[wire.Dealer][wire.Verifier] = make(map[int]struct{}, len(expected))
		}
		for _, rid := range expected {
			if _, duplicate := seen[wire.Dealer][wire.Verifier][rid]; duplicate {
				return
			}
			seen[wire.Dealer][wire.Verifier][rid] = struct{}{}
			if wire.Lanes[rid] {
				positive[wire.Dealer][rid]++
			}
		}
	}

	prepared := make(map[int]map[int]struct {
		wire partialVerifyResultWire
		raw  []byte
	}, len(localIDs))
	for _, verifier := range localIDs {
		if dxt.recipientSignPriv[verifier] == nil {
			return nil, nil, fmt.Errorf("partial verification local signer %d key unavailable", verifier)
		}
		prepared[verifier] = make(map[int]struct {
			wire partialVerifyResultWire
			raw  []byte
		}, len(selectedIDs))
		for _, dealer := range selectedIDs {
			lanes, ok := dxt.partialVerifyLanes(verifier, transcripts[dealer])
			if !ok {
				lanes = make(map[int]bool)
				if expected, expectedOK := dxt.partialLaneIDs(verifier); expectedOK {
					for _, rid := range expected {
						lanes[rid] = false
					}
				}
			}
			wire := partialVerifyResultWire{Dealer: dealer, Verifier: verifier, TranscriptDigest: transcriptDigests[dealer], Lanes: lanes}
			var err error
			wire.Signature, err = ecdsa.SignASN1(rand.Reader, dxt.recipientSignPriv[verifier], partialVerifyResultMessage(&wire))
			if err != nil {
				return nil, nil, err
			}
			raw, err := json.Marshal(wire)
			if err != nil {
				return nil, nil, err
			}
			prepared[verifier][dealer] = struct {
				wire partialVerifyResultWire
				raw  []byte
			}{wire: wire, raw: raw}
			// A local verifier's result is trusted only after the same signature
			// and lane-shape checks used for received multicast messages.
			accept(wire)
		}
	}

	var sendWG sync.WaitGroup
	for _, verifier := range localIDs {
		for _, dealer := range selectedIDs {
			preparedResult := prepared[verifier][dealer]
			raw := preparedResult.raw
			for _, target := range verifiers {
				if target == verifier {
					continue
				}
				targetAddr := addrMap[target]
				sendWG.Add(1)
				go func(from, to int, addr string, body []byte) {
					defer sendWG.Done()
					for {
						select {
						case <-stageCtx.Done():
							return
						default:
						}
						conn, dialErr := dialWithOptionalDelay(from, to, "tcp", addr, 500*time.Millisecond)
						if dialErr == nil {
							_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
							recordSentBytes(len(body))
							_, writeErr := conn.Write(body)
							_ = conn.Close()
							if writeErr == nil {
								return
							}
						}
						select {
						case <-stageCtx.Done():
							return
						case <-time.After(40 * time.Millisecond):
						}
					}
				}(verifier, target, targetAddr, raw)
			}
		}
	}

	complete := func() bool {
		need := dxt.f + 1
		for _, dealer := range selectedIDs {
			for _, rid := range dxt.newCommittee {
				if positive[dealer][rid] < need {
					return false
				}
			}
		}
		return true
	}
	for !complete() {
		select {
		case wire := <-wireCh:
			accept(wire)
		case <-stageCtx.Done():
			sendWG.Wait()
			return nil, nil, fmt.Errorf("partial verification result multicast timeout")
		}
	}
	// In local multi-node simulation all old verifiers are hosted by one
	// process, so direct local votes can satisfy the threshold before the
	// multicast writes finish.  Drain those writes to keep communication
	// measurements representative; distributed processes do not take this
	// path and retain the threshold-first latency behavior.
	if len(localIDs) == len(verifiers) {
		sendWG.Wait()
	}
	cancel()
	sendWG.Wait()
	positiveVotes := make(map[string]int, len(selectedIDs)*len(dxt.newCommittee))
	for _, dealer := range selectedIDs {
		for _, rid := range dxt.newCommittee {
			key := fmt.Sprintf("%d/%d", dealer, rid)
			positiveVotes[key] = positive[dealer][rid]
			tracef("phase=partial_verify_lane_votes dealer=%d lane=%d positive=%d", dealer, rid, positive[dealer][rid])
		}
	}
	tracef("phase=partial_verify_multicast_end transcripts=%d threshold=%d", len(selectedIDs), dxt.f+1)
	return append([]int(nil), selectedIDs...), positiveVotes, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
