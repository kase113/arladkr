package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const dxtTranscriptWireKind = "transcript"

type dxtTranscriptWire struct {
	Kind             string         `json:"kind"`
	SID              string         `json:"sid"`
	Epoch            uint64         `json:"epoch"`
	Dealer           int            `json:"dealer"`
	Transcript       *DXTTranscript `json:"transcript"`
	TranscriptDigest []byte         `json:"transcript_digest"`
}

type dxtTranscriptAck struct {
	SID              string `json:"sid"`
	Epoch            uint64 `json:"epoch"`
	Dealer           int    `json:"dealer"`
	Holder           int    `json:"holder"`
	TranscriptDigest []byte `json:"transcript_digest"`
	Accepted         bool   `json:"accepted"`
}

// dxtNetworkService replaces the historical shared-directory readiness and
// transcript exchange. Plaintext ACK auxiliary data remains receiver-local;
// only fully verified public transcripts are exposed to the next phase.
type dxtNetworkService struct {
	cfg       Config
	dxt       *DXTBackend
	old       []int
	addresses map[int]string
	localIDs  map[int]struct{}

	ctx       context.Context
	cancel    context.CancelFunc
	listeners map[int]net.Listener
	closeOnce sync.Once
	acceptWG  sync.WaitGroup
	workerWG  sync.WaitGroup

	mu          sync.RWMutex
	transcripts map[int]*DXTTranscript
	shares      map[int]map[int]SharePair
	changed     chan struct{}
}

func startDXTNetworkService(ctx context.Context, cfg Config, old []int, dxt *DXTBackend) (*dxtNetworkService, error) {
	addresses := parseNodeAddrMap(dxtNodeAddrs(cfg))
	localIDs := parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	if len(addresses) == 0 || len(localIDs) == 0 {
		return nil, errors.New("DXT network service requires protocol addresses and local identities")
	}
	serviceCtx, cancel := context.WithCancel(ctx)
	service := &dxtNetworkService{
		cfg: cfg, dxt: dxt, old: append([]int(nil), old...), addresses: addresses, localIDs: localIDs,
		ctx: serviceCtx, cancel: cancel, listeners: make(map[int]net.Listener),
		transcripts: make(map[int]*DXTTranscript), shares: make(map[int]map[int]SharePair), changed: make(chan struct{}, 1),
	}
	for id := range localIDs {
		addr := strings.TrimSpace(addresses[id])
		if addr == "" {
			service.close()
			return nil, fmt.Errorf("DXT network service missing address for local node %d", id)
		}
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			service.close()
			return nil, fmt.Errorf("DXT network address for node %d: %w", id, err)
		}
		listener, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", port))
		if err != nil {
			service.close()
			return nil, fmt.Errorf("DXT network listen node %d: %w", id, err)
		}
		service.listeners[id] = listener
		service.acceptWG.Add(1)
		go service.serve(id, listener)
	}
	return service, nil
}

func (service *dxtNetworkService) close() {
	if service == nil {
		return
	}
	service.closeOnce.Do(func() {
		service.cancel()
		for _, listener := range service.listeners {
			_ = listener.Close()
		}
		service.acceptWG.Wait()
		service.workerWG.Wait()
	})
}

func (service *dxtNetworkService) serve(localID int, listener net.Listener) {
	defer service.acceptWG.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-service.ctx.Done():
				return
			default:
				continue
			}
		}
		service.workerWG.Add(1)
		go func() {
			defer service.workerWG.Done()
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(dxtNetworkTimeout()))
			var raw json.RawMessage
			if err := json.NewDecoder(conn).Decode(&raw); err != nil {
				return
			}
			recordRecvBytes(len(raw) + 1)
			var header struct {
				Kind string `json:"kind"`
			}
			_ = json.Unmarshal(raw, &header)
			if header.Kind == dxtTranscriptWireKind {
				service.handleTranscript(localID, conn, raw)
				return
			}
			service.handleLane(localID, raw)
		}()
	}
}

func (service *dxtNetworkService) handleLane(localID int, raw []byte) {
	if _, ok := service.dxt.newIndex[localID]; !ok {
		return
	}
	var req dxtDealReq
	if err := json.Unmarshal(raw, &req); err != nil || req.Recipient != localID || len(req.ShareCiphertext) == 0 {
		return
	}
	dealerPub := service.dxt.dealerPub[req.Dealer]
	if dealerPub == nil {
		return
	}
	shareS, shareSR, err := decryptDXTShare(dealerPub, service.dxt.recipientSignPriv[localID], req.Dealer, localID, req.ShareCiphertext)
	if err != nil || !equalCommit(req.Commitment, commitSharePair(service.dxt.curve, shareS, shareSR)) {
		return
	}
	share := SharePair{S: shareS, SR: shareSR}
	if err := service.dxt.storeLocalShare(req.Dealer, localID, share); err != nil {
		return
	}
	service.mu.Lock()
	if service.shares[req.Dealer] == nil {
		service.shares[req.Dealer] = make(map[int]SharePair)
	}
	service.shares[req.Dealer][localID] = cloneSharePair(share)
	service.mu.Unlock()
	sk := service.dxt.recipientSignPriv[localID]
	if sk == nil {
		return
	}
	ack := dxtDealAck{Recipient: localID, Sig: signAck(sk, req.Dealer, localID, req.Commitment)}
	conn, err := dialWithOptionalDelay(localID, req.Dealer, "tcp", req.ReplyAddr, dxtNetworkTimeout())
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(dxtNetworkTimeout()))
	if body, marshalErr := json.Marshal(ack); marshalErr == nil {
		recordSentBytes(len(body) + 1)
	}
	_ = json.NewEncoder(conn).Encode(ack)
}

func (service *dxtNetworkService) handleTranscript(holder int, conn net.Conn, raw []byte) {
	ack := dxtTranscriptAck{SID: service.cfg.SID, Epoch: service.cfg.Epoch, Holder: holder}
	var wire dxtTranscriptWire
	if err := json.Unmarshal(raw, &wire); err == nil {
		ack.Dealer = wire.Dealer
		ack.TranscriptDigest = append([]byte(nil), wire.TranscriptDigest...)
		if wire.SID == service.cfg.SID && wire.Epoch == service.cfg.Epoch && containsNode(service.old, wire.Dealer) &&
			wire.Transcript != nil && wire.Transcript.Dealer == wire.Dealer {
			digest, digestErr := dxtTranscriptDigest(wire.Transcript)
			if digestErr == nil && bytes.Equal(digest, wire.TranscriptDigest) && service.dxt.VerifyTranscript(holder, wire.Transcript) {
				ack.Accepted = service.addTranscript(wire.Dealer, wire.Transcript, digest)
			}
		}
	}
	if body, err := json.Marshal(ack); err == nil {
		recordSentBytes(len(body) + 1)
	}
	_ = json.NewEncoder(conn).Encode(ack)
}

func (service *dxtNetworkService) addTranscript(dealer int, transcript *DXTTranscript, digest []byte) bool {
	service.mu.Lock()
	defer service.mu.Unlock()
	if existing := service.transcripts[dealer]; existing != nil {
		existingDigest, err := dxtTranscriptDigest(existing)
		return err == nil && bytes.Equal(existingDigest, digest)
	}
	service.transcripts[dealer] = transcript
	select {
	case service.changed <- struct{}{}:
	default:
	}
	return true
}

func (service *dxtNetworkService) publishTranscript(ctx context.Context, dealer int, transcript *DXTTranscript) error {
	if transcript == nil || transcript.Dealer != dealer || !service.dxt.VerifyTranscript(dealer, transcript) {
		return fmt.Errorf("dealer %d attempted to publish invalid DXT transcript", dealer)
	}
	digest, err := dxtTranscriptDigest(transcript)
	if err != nil {
		return err
	}
	wire := dxtTranscriptWire{
		Kind: dxtTranscriptWireKind, SID: service.cfg.SID, Epoch: service.cfg.Epoch,
		Dealer: dealer, Transcript: transcript, TranscriptDigest: digest,
	}
	required := len(service.old) - service.cfg.F
	if required <= 0 {
		return errors.New("invalid DXT transcript publication threshold")
	}
	accepted := 0
	results := make(chan bool, len(service.old))
	for _, holder := range service.old {
		holder := holder
		if _, local := service.localIDs[holder]; local {
			results <- service.addTranscript(dealer, transcript, digest)
			continue
		}
		go func() {
			results <- sendDXTTranscript(ctx, service.cfg, dealer, holder, service.addresses[holder], wire)
		}()
	}
	for range service.old {
		select {
		case ok := <-results:
			if ok {
				accepted++
				if accepted >= required {
					return nil
				}
			}
		case <-ctx.Done():
			return fmt.Errorf("publish DXT transcript %d: accepted=%d need=%d: %w", dealer, accepted, required, ctx.Err())
		}
	}
	return fmt.Errorf("publish DXT transcript %d: accepted=%d need=%d", dealer, accepted, required)
}

func sendDXTTranscript(ctx context.Context, cfg Config, dealer, holder int, addr string, wire dxtTranscriptWire) bool {
	if strings.TrimSpace(addr) == "" {
		return false
	}
	deadline := time.Now().Add(dxtNetworkTimeout())
	for {
		if err := ctx.Err(); err != nil || time.Now().After(deadline) {
			return false
		}
		conn, err := dialWithOptionalDelay(dealer, holder, "tcp", addr, 300*time.Millisecond)
		if err != nil {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(dxtNetworkTimeout()))
		body, marshalErr := json.Marshal(wire)
		if marshalErr == nil {
			recordSentBytes(len(body) + 1)
		}
		writeErr := json.NewEncoder(conn).Encode(wire)
		var ack dxtTranscriptAck
		readErr := json.NewDecoder(conn).Decode(&ack)
		if readErr == nil {
			if ackBody, ackErr := json.Marshal(ack); ackErr == nil {
				recordRecvBytes(len(ackBody) + 1)
			}
		}
		_ = conn.Close()
		if writeErr == nil && readErr == nil && ack.Accepted && ack.SID == cfg.SID && ack.Epoch == cfg.Epoch &&
			ack.Dealer == dealer && ack.Holder == holder && bytes.Equal(ack.TranscriptDigest, wire.TranscriptDigest) {
			return true
		}
		return false
	}
}

func (service *dxtNetworkService) waitForTranscripts(ctx context.Context, threshold int) (map[int]*DXTTranscript, error) {
	grace := dxtTranscriptPropagationGrace()
	var quietTimer *time.Timer
	var quiet <-chan time.Time
	for {
		service.mu.RLock()
		count := len(service.transcripts)
		service.mu.RUnlock()
		if count == len(service.old) {
			if quietTimer != nil {
				quietTimer.Stop()
			}
			return service.transcriptSnapshot(), nil
		}
		if count >= threshold && quietTimer == nil {
			quietTimer = time.NewTimer(grace)
			quiet = quietTimer.C
		}
		select {
		case <-ctx.Done():
			if quietTimer != nil {
				quietTimer.Stop()
			}
			return nil, fmt.Errorf("waiting for network DXT transcripts: have=%d need=%d: %w", count, threshold, ctx.Err())
		case <-service.changed:
			if quietTimer != nil {
				if !quietTimer.Stop() {
					select {
					case <-quietTimer.C:
					default:
					}
				}
				quietTimer.Reset(grace)
			}
		case <-quiet:
			return service.transcriptSnapshot(), nil
		}
	}
}

// dxtTranscriptPropagationGrace gives concurrent local processes a bounded
// window to finish in-flight authenticated transcript publications after the
// 2f+1 availability threshold is reached. It is not an acceptance condition:
// a missing dealer remains admissible after the grace expires.
func dxtTranscriptPropagationGrace() time.Duration {
	const defaultGrace = time.Second
	raw := strings.TrimSpace(os.Getenv("PRACTICAL_DXT_TRANSCRIPT_GRACE_MS"))
	if raw == "" {
		return defaultGrace
	}
	ms, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || ms < 0 {
		return defaultGrace
	}
	return time.Duration(ms) * time.Millisecond
}

func (service *dxtNetworkService) transcriptSnapshot() map[int]*DXTTranscript {
	service.mu.RLock()
	defer service.mu.RUnlock()
	dealers := make([]int, 0, len(service.transcripts))
	for dealer := range service.transcripts {
		dealers = append(dealers, dealer)
	}
	sort.Ints(dealers)
	out := make(map[int]*DXTTranscript, len(dealers))
	for _, dealer := range dealers {
		out[dealer] = service.transcripts[dealer]
	}
	return out
}

func (service *dxtNetworkService) shareSnapshot() map[int]map[int]SharePair {
	service.mu.RLock()
	defer service.mu.RUnlock()
	out := make(map[int]map[int]SharePair, len(service.shares))
	for dealer, lanes := range service.shares {
		out[dealer] = make(map[int]SharePair, len(lanes))
		for recipient, share := range lanes {
			out[dealer][recipient] = cloneSharePair(share)
		}
	}
	return out
}

func dxtTranscriptDigest(transcript *DXTTranscript) ([]byte, error) {
	raw, err := json.Marshal(transcript)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	return digest[:], nil
}

func cloneSharePair(share SharePair) SharePair {
	out := SharePair{}
	if share.S != nil {
		out.S = new(big.Int).Set(share.S)
	}
	if share.SR != nil {
		out.SR = new(big.Int).Set(share.SR)
	}
	return out
}

func containsNode(nodes []int, target int) bool {
	for _, node := range nodes {
		if node == target {
			return true
		}
	}
	return false
}

func dxtNodeAddrs(cfg Config) string {
	if configured := strings.TrimSpace(cfg.DXTNodeAddrs); configured != "" {
		return configured
	}
	base := parseNodeAddrMap(cfg.ProtocolNodeAddrs)
	ids := make([]int, 0, len(base))
	for id := range base {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		host, portText, err := net.SplitHostPort(base[id])
		if err != nil {
			return ""
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port <= 0 || port+2000 > 65535 {
			return ""
		}
		parts = append(parts, fmt.Sprintf("%d=%s", id, net.JoinHostPort(host, strconv.Itoa(port+2000))))
	}
	return strings.Join(parts, ",")
}
