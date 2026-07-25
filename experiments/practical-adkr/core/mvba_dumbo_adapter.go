package core

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	dmvba "dumbomvba_go/core"
)

type mvbaSetPayload struct {
	Proposer int   `json:"proposer"`
	Set      []int `json:"set"`
}

type mvbaTCPWire struct {
	From int
	Msg  dmvba.ProtocolMessage
}

type spbcSigMsg struct {
	Signer int    `json:"signer"`
	SigHex string `json:"sig_hex"`
}

type spbcFinalMsg struct {
	Proposal dmvba.ProposalValue `json:"proposal"`
	Proof    []spbcSigMsg        `json:"proof"`
}

type pracPoolConn struct {
	conn net.Conn
	mu   sync.Mutex
}

type practicalMVBANetStat struct {
	id              int
	tag             string
	sends           int64
	failures        int64
	totalSendMicros int64
	maxSendMicros   int64
	lockWaitMicros  int64
	poolHits        int64
	reconnects      int64
	localSends      int64
	buckets         []int64
}

var practicalMVBANetTimingBucketsMicros = []int64{
	1000,
	2000,
	5000,
	10000,
	20000,
	50000,
	100000,
	200000,
	500000,
	1000000,
	2000000,
	5000000,
	10000000,
	30000000,
}

type mvbaTCPHub struct {
	sid        string
	mu         sync.RWMutex
	addrByID   map[int]string
	recv       []chan dmvba.ReceivedMessage
	listeners  map[int]net.Listener
	closed     chan struct{}
	wg         sync.WaitGroup
	dialTO     time.Duration
	writeTO    time.Duration
	readTO     time.Duration
	retries    int
	backoff    time.Duration
	enqueueTO  time.Duration
	pool       map[string]*pracPoolConn
	poolMu     sync.Mutex
	poolLanes  int
	netTiming  bool
	netStatsMu sync.Mutex
	netStats   map[string]*practicalMVBANetStat
}

type simpleSigner struct {
	id      int
	privKey ed25519.PrivateKey
	pubKeys map[int]ed25519.PublicKey
}

func init() {
	gob.Register(dmvba.ProtocolMessage{})
	gob.Register(dmvba.ProposalValue{})
	gob.Register(mvbaTCPWire{})
	gob.Register(spbcSigMsg{})
	gob.Register(spbcFinalMsg{})
}

func (s *simpleSigner) ID() int {
	return s.id
}

func (s *simpleSigner) Sign(domain string, digest []byte) ([]byte, error) {
	msg := digestSignerMsg(domain, digest)
	sig := ed25519.Sign(s.privKey, msg)
	return append([]byte(nil), sig...), nil
}

func (s *simpleSigner) Verify(from int, domain string, digest, sig []byte) bool {
	pk, ok := s.pubKeys[from]
	if !ok {
		return false
	}
	return ed25519.Verify(pk, digestSignerMsg(domain, digest), sig)
}

func digestSignerMsg(domain string, digest []byte) []byte {
	out := make([]byte, 0, len(domain)+1+len(digest))
	out = append(out, []byte(domain)...)
	out = append(out, 0)
	out = append(out, digest...)
	return out
}

type mvbaTCPNet struct {
	id  int
	hub *mvbaTCPHub
}

func traceMVBATCP(format string, args ...any) {
	if os.Getenv("PRACTICAL_MVBA_TCP_TRACE") == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "PRACTICAL_MVBA_TCP "+format+"\n", args...)
}

func (n *mvbaTCPNet) Broadcast(msg dmvba.ProtocolMessage) error {
	traceMVBATCP("broadcast from=%d tag=%d round=%d leader=%d peers=%d", n.id, msg.Tag, msg.Round, msg.Leader, len(n.hub.recv))
	var wg sync.WaitGroup
	errCh := make(chan error, len(n.hub.recv))
	for to := range n.hub.recv {
		to := to
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := n.Send(to, msg); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err
	}
	return nil
}

func (n *mvbaTCPNet) Send(to int, msg dmvba.ProtocolMessage) error {
	sendStart := time.Now()
	if n.hub == nil {
		return fmt.Errorf("nil mvba tcp hub")
	}
	if to == n.id {
		traceMVBATCP("send_local from=%d tag=%d round=%d leader=%d", n.id, msg.Tag, msg.Round, msg.Leader)
		wire := dmvba.ReceivedMessage{From: n.id, Msg: msg}
		select {
		case n.hub.recv[to] <- wire:
			if bodyLen, err := gobEncodeSize(mvbaTCPWire{From: n.id, Msg: msg}); err == nil {
				recordSentBytes(4 + bodyLen)
				recordRecvBytes(4 + bodyLen)
			}
			n.hub.recordMVBANetSend(n.id, practicalMVBANetTag(msg), time.Since(sendStart), 0, true, false, 0, nil)
			return nil
		default:
			select {
			case n.hub.recv[to] <- wire:
				n.hub.recordMVBANetSend(n.id, practicalMVBANetTag(msg), time.Since(sendStart), 0, true, false, 0, nil)
				return nil
			case <-time.After(n.hub.enqueueTO):
				err := fmt.Errorf("mvba local enqueue timeout for node %d", to)
				n.hub.recordMVBANetSend(n.id, practicalMVBANetTag(msg), time.Since(sendStart), 0, true, false, 0, err)
				return err
			case <-n.hub.closed:
				err := fmt.Errorf("mvba hub closed")
				n.hub.recordMVBANetSend(n.id, practicalMVBANetTag(msg), time.Since(sendStart), 0, true, false, 0, err)
				return err
			}
		}
	}
	wire := mvbaTCPWire{From: n.id, Msg: msg}
	addr, ok := n.hub.addrByID[to]
	if !ok || strings.TrimSpace(addr) == "" {
		err := fmt.Errorf("mvba tcp addr missing for node %d", to)
		n.hub.recordMVBANetSend(n.id, practicalMVBANetTag(msg), time.Since(sendStart), 0, false, false, 0, err)
		return err
	}
	poolKey := practicalMVBAPoolKey(addr, msg, n.hub.poolLanes)
	traceMVBATCP("send_begin from=%d to=%d tag=%d round=%d leader=%d addr=%s", n.id, to, msg.Tag, msg.Round, msg.Leader, addr)
	// Pipeline-delay model (default): apply the one-way propagation delay HERE,
	// before acquiring the per-peer connection lock, so concurrent sends to the
	// same peer sleep in parallel instead of serializing behind each other's
	// sleep. Legacy mode keeps the sleep inside Write (under the pool lock).
	if !mvbaLegacyDelay() {
		delayBeforeSend(n.id, to, "")
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(wire); err != nil {
		n.hub.recordMVBANetSend(n.id, practicalMVBANetTag(msg), time.Since(sendStart), 0, false, false, 0, err)
		return err
	}
	body := buf.Bytes()
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)

	writeFrame := func(c net.Conn) error {
		_ = c.SetWriteDeadline(time.Now().Add(n.hub.writeTO))
		written, err := c.Write(frame)
		if err != nil {
			return err
		}
		if written != len(frame) {
			return io.ErrShortWrite
		}
		recordSentBytes(4 + len(body))
		return nil
	}

	// Try pooled connection.
	n.hub.poolMu.Lock()
	if n.hub.pool == nil {
		n.hub.pool = make(map[string]*pracPoolConn)
	}
	pc, ok := n.hub.pool[poolKey]
	if ok {
		lockStart := time.Now()
		pc.mu.Lock()
		lockWait := time.Since(lockStart)
		n.hub.poolMu.Unlock()
		if writeFrame(pc.conn) == nil {
			traceMVBATCP("send_ok from=%d to=%d tag=%d mode=pooled", n.id, to, msg.Tag)
			pc.mu.Unlock()
			n.hub.recordMVBANetSend(n.id, practicalMVBANetTag(msg), time.Since(sendStart), lockWait, false, true, 0, nil)
			return nil
		}
		_ = pc.conn.Close()
		pc.mu.Unlock()
		n.hub.poolMu.Lock()
		delete(n.hub.pool, poolKey)
	}
	n.hub.poolMu.Unlock()

	// Dial new.
	var conn net.Conn
	var dErr error
	reconnects := 0
	for attempt := 0; attempt < n.hub.retries; attempt++ {
		conn, dErr = mvbaDial(n.id, to, "tcp", addr, n.hub.dialTO)
		if dErr == nil {
			reconnects++
			break
		}
		traceMVBATCP("dial_retry from=%d to=%d attempt=%d err=%v", n.id, to, attempt+1, dErr)
		time.Sleep(time.Duration(attempt+1) * n.hub.backoff)
	}
	if dErr != nil {
		traceMVBATCP("send_fail from=%d to=%d tag=%d err=%v", n.id, to, msg.Tag, dErr)
		err := fmt.Errorf("mvba tcp dial failed %d->%d: %w", n.id, to, dErr)
		n.hub.recordMVBANetSend(n.id, practicalMVBANetTag(msg), time.Since(sendStart), 0, false, false, reconnects, err)
		return err
	}
	if err := writeFrame(conn); err != nil {
		_ = conn.Close()
		traceMVBATCP("send_fail from=%d to=%d tag=%d err=%v", n.id, to, msg.Tag, err)
		n.hub.recordMVBANetSend(n.id, practicalMVBANetTag(msg), time.Since(sendStart), 0, false, false, reconnects, err)
		return err
	}
	traceMVBATCP("send_ok from=%d to=%d tag=%d mode=new", n.id, to, msg.Tag)

	n.hub.poolMu.Lock()
	if n.hub.pool == nil {
		n.hub.pool = make(map[string]*pracPoolConn)
	}
	if _, exists := n.hub.pool[poolKey]; !exists {
		n.hub.pool[poolKey] = &pracPoolConn{conn: conn}
	} else {
		_ = conn.Close()
	}
	n.hub.poolMu.Unlock()
	n.hub.recordMVBANetSend(n.id, practicalMVBANetTag(msg), time.Since(sendStart), 0, false, false, reconnects, nil)
	return nil
}

func newMVBATCPHub(cfg Config, recv []chan dmvba.ReceivedMessage) (*mvbaTCPHub, error) {
	n := len(recv)
	addrMap := parseNodeAddrMap(firstNonEmpty(cfg.MVBANodeAddrs, os.Getenv("PRACTICAL_MVBA_NODE_ADDRS")))
	if len(addrMap) < n {
		return nil, fmt.Errorf("mvba node addresses incomplete: have=%d need=%d", len(addrMap), n)
	}
	localIDs := parseNodeIDSet(firstNonEmpty(cfg.MVBALocalNodeIDs, os.Getenv("PRACTICAL_MVBA_LOCAL_NODE_IDS")))
	if len(localIDs) == 0 {
		return nil, fmt.Errorf("mvba local node ids required (set MVBALocalNodeIDs/PRACTICAL_MVBA_LOCAL_NODE_IDS)")
	}
	h := &mvbaTCPHub{
		sid:       cfg.SID,
		addrByID:  addrMap,
		recv:      recv,
		listeners: make(map[int]net.Listener, len(localIDs)),
		closed:    make(chan struct{}),
		// For n>=64 under local proc-sim + WAN proxying, LAN-style defaults are
		// too aggressive and amplify pd/quitpd tail timeouts.
		dialTO:    durationFromEnvMsOr("PRACTICAL_MVBA_DIAL_TIMEOUT_MS", 3000*time.Millisecond),
		writeTO:   durationFromEnvMsOr("PRACTICAL_MVBA_WRITE_TIMEOUT_MS", 3000*time.Millisecond),
		readTO:    durationFromEnvMsOr("PRACTICAL_MVBA_READ_TIMEOUT_MS", 45000*time.Millisecond),
		retries:   intFromEnvOr("PRACTICAL_MVBA_SEND_RETRIES", 15),
		backoff:   durationFromEnvMsOr("PRACTICAL_MVBA_RETRY_BACKOFF_MS", 120*time.Millisecond),
		enqueueTO: durationFromEnvMsOr("PRACTICAL_MVBA_ENQUEUE_TIMEOUT_MS", 500*time.Millisecond),
		pool:      make(map[string]*pracPoolConn),
		poolLanes: practicalMVBAPoolLanes(),
		netTiming: strings.TrimSpace(os.Getenv("PRACTICAL_MVBA_NET_TIMING")) != "",
		netStats:  make(map[string]*practicalMVBANetStat),
	}
	for id := range localIDs {
		addr, ok := addrMap[id]
		if !ok {
			return nil, fmt.Errorf("mvba local node %d missing address", id)
		}
		_, port, _ := net.SplitHostPort(addr)
		ln, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", port))
		if err != nil {
			h.close()
			return nil, err
		}
		h.listeners[id] = ln
		h.wg.Add(1)
		go h.acceptLoop(id, ln)
	}
	return h, nil
}

func (h *mvbaTCPHub) acceptLoop(id int, ln net.Listener) {
	defer h.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-h.closed:
				return
			default:
				continue
			}
		}
		go h.readConn(id, conn)
	}
}

func (h *mvbaTCPHub) readConn(id int, conn net.Conn) {
	defer conn.Close()
	for {
		select {
		case <-h.closed:
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(h.readTO))
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		bodyLen := binary.BigEndian.Uint32(lenBuf[:])
		if bodyLen > 16*1024*1024 {
			return
		}
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		recordRecvBytes(4 + len(body))
		var wire mvbaTCPWire
		if err := gob.NewDecoder(bytes.NewReader(body)).Decode(&wire); err != nil {
			continue
		}
		traceMVBATCP("recv id=%d from=%d tag=%d round=%d leader=%d", id, wire.From, wire.Msg.Tag, wire.Msg.Round, wire.Msg.Leader)
		msg := dmvba.ReceivedMessage{From: wire.From, Msg: wire.Msg}
		select {
		case h.recv[id] <- msg:
		default:
			select {
			case h.recv[id] <- msg:
			case <-time.After(h.enqueueTO):
			case <-h.closed:
				return
			}
		}
	}
}

func gobEncodeSize(v any) (int, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		return 0, err
	}
	return buf.Len(), nil
}

func practicalMVBANetTag(msg dmvba.ProtocolMessage) string {
	if msg.Tag == dmvba.TagACSMVBA {
		if inner, ok := msg.Body.(dmvba.ProtocolMessage); ok {
			return string(msg.Tag) + "/" + string(inner.Tag)
		}
	}
	return string(msg.Tag)
}

func practicalMVBAPoolLanes() int {
	lanes := intFromEnvOr("PRACTICAL_MVBA_CONN_LANES", 1)
	if lanes < 1 {
		return 1
	}
	if lanes > 8 {
		return 8
	}
	return lanes
}

func practicalMVBAPoolKey(addr string, msg dmvba.ProtocolMessage, lanes int) string {
	if lanes <= 1 {
		return addr
	}
	lane := practicalMVBALane(msg, lanes)
	return fmt.Sprintf("%s#lane=%d", addr, lane)
}

func practicalMVBALane(msg dmvba.ProtocolMessage, lanes int) int {
	if lanes <= 1 {
		return 0
	}
	tag := msg.Tag
	leader := msg.Leader
	round := msg.Round
	if msg.Tag == dmvba.TagACSMVBA {
		if inner, ok := msg.Body.(dmvba.ProtocolMessage); ok {
			tag = inner.Tag
			leader = inner.Leader
			round = inner.Round
		}
	}
	h := uint32(2166136261)
	for _, b := range []byte(tag) {
		h ^= uint32(b)
		h *= 16777619
	}
	h ^= uint32(leader + 0x9e3779b9)
	h *= 16777619
	h ^= uint32(round + 0x85ebca6b)
	h *= 16777619
	return int(h % uint32(lanes))
}

func (h *mvbaTCPHub) recordMVBANetSend(
	id int,
	tag string,
	sendDur time.Duration,
	lockWait time.Duration,
	local bool,
	poolHit bool,
	reconnects int,
	err error,
) {
	if h == nil || !h.netTiming {
		return
	}
	sendMicros := sendDur.Microseconds()
	if sendMicros < 0 {
		sendMicros = 0
	}
	lockMicros := lockWait.Microseconds()
	if lockMicros < 0 {
		lockMicros = 0
	}
	key := fmt.Sprintf("%d|%s", id, tag)
	h.netStatsMu.Lock()
	defer h.netStatsMu.Unlock()
	stat := h.netStats[key]
	if stat == nil {
		stat = &practicalMVBANetStat{
			id:      id,
			tag:     tag,
			buckets: make([]int64, len(practicalMVBANetTimingBucketsMicros)+1),
		}
		h.netStats[key] = stat
	}
	stat.sends++
	if err != nil {
		stat.failures++
	}
	if local {
		stat.localSends++
	}
	if poolHit {
		stat.poolHits++
	}
	stat.reconnects += int64(reconnects)
	stat.totalSendMicros += sendMicros
	stat.lockWaitMicros += lockMicros
	if sendMicros > stat.maxSendMicros {
		stat.maxSendMicros = sendMicros
	}
	bucketIdx := len(practicalMVBANetTimingBucketsMicros)
	for i, upper := range practicalMVBANetTimingBucketsMicros {
		if sendMicros <= upper {
			bucketIdx = i
			break
		}
	}
	stat.buckets[bucketIdx]++
}

func (h *mvbaTCPHub) dumpMVBANetStats() {
	if h == nil || !h.netTiming {
		return
	}
	h.netStatsMu.Lock()
	stats := make([]practicalMVBANetStat, 0, len(h.netStats))
	for _, stat := range h.netStats {
		cp := *stat
		cp.buckets = append([]int64(nil), stat.buckets...)
		stats = append(stats, cp)
	}
	h.netStatsMu.Unlock()
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].id != stats[j].id {
			return stats[i].id < stats[j].id
		}
		return stats[i].tag < stats[j].tag
	})
	for _, stat := range stats {
		if stat.sends == 0 {
			continue
		}
		meanMS := float64(stat.totalSendMicros) / float64(stat.sends) / 1000.0
		p95MS := float64(practicalMVBANetP95Micros(stat)) / 1000.0
		maxMS := float64(stat.maxSendMicros) / 1000.0
		lockWaitMS := float64(stat.lockWaitMicros) / 1000.0
		fmt.Fprintf(
			os.Stderr,
			"PRACTICAL_MVBA_NET sid=%s id=%d tag=%s sends=%d failures=%d mean_send_ms=%.2f p95_send_ms=%.2f max_send_ms=%.2f lock_wait_ms=%.2f pool_hits=%d reconnects=%d local=%d\n",
			h.sid,
			stat.id,
			stat.tag,
			stat.sends,
			stat.failures,
			meanMS,
			p95MS,
			maxMS,
			lockWaitMS,
			stat.poolHits,
			stat.reconnects,
			stat.localSends,
		)
	}
}

func practicalMVBANetP95Micros(stat practicalMVBANetStat) int64 {
	if stat.sends <= 0 {
		return 0
	}
	target := (stat.sends*95 + 99) / 100
	var seen int64
	for i, count := range stat.buckets {
		seen += count
		if seen >= target {
			if i < len(practicalMVBANetTimingBucketsMicros) {
				return practicalMVBANetTimingBucketsMicros[i]
			}
			return stat.maxSendMicros
		}
	}
	return stat.maxSendMicros
}

func (h *mvbaTCPHub) close() {
	select {
	case <-h.closed:
		return
	default:
		close(h.closed)
	}
	for _, ln := range h.listeners {
		_ = ln.Close()
	}
	h.wg.Wait()
	h.dumpMVBANetStats()
	h.poolMu.Lock()
	for _, pc := range h.pool {
		pc.mu.Lock()
		_ = pc.conn.Close()
		pc.mu.Unlock()
	}
	h.pool = make(map[string]*pracPoolConn)
	h.poolMu.Unlock()
}

type spbcNetDriver struct {
	net      dmvba.Network
	pubKeys  map[int]ed25519.PublicKey
	privKeys map[int]ed25519.PrivateKey
}

func (d *spbcNetDriver) Start(
	ctx context.Context,
	sid string,
	id, n, f, round, leader int,
	input *dmvba.ProposalValue,
) (*dmvba.SPBCHandle, error) {
	if d.net == nil {
		return nil, errors.New("nil spbc network")
	}
	if len(d.pubKeys) < n || len(d.privKeys) < n {
		return nil, errors.New("spbc signer keys not initialized")
	}
	inbound := make(chan dmvba.RoutedSPBCMessage, 64)
	s1 := make(chan dmvba.SPBCS1Result, 1)
	final := make(chan dmvba.SPBCFinalResult, 1)
	threshold := n - f
	if threshold <= 0 {
		threshold = 1
	}

	digestProposal := func(v dmvba.ProposalValue) []byte {
		raw, _ := json.Marshal(v)
		d := sha256.Sum256(append(
			[]byte(fmt.Sprintf("spbc|%s|round=%d|leader=%d|", sid, round, leader)),
			raw...,
		))
		return d[:]
	}

	go func() {
		defer close(s1)
		defer close(final)
		var proposal *dmvba.ProposalValue
		seenEcho := make(map[int][]byte, n)
		s1Sent := false
		if id == leader && input != nil {
			prop := cloneProposalValue(*input)
			proposal = &prop
			if sk, ok := d.privKeys[leader]; ok {
				sig := ed25519.Sign(sk, digestProposal(prop))
				seenEcho[leader] = append([]byte(nil), sig...)
			}
			_ = d.net.Broadcast(dmvba.ProtocolMessage{
				Tag:    dmvba.TagSPBC,
				Round:  round,
				Leader: leader,
				Body:   prop,
			})
		}

		maybeFinalizeLeader := func() bool {
			if id != leader || proposal == nil || len(seenEcho) < threshold {
				return false
			}
			proof := make([]spbcSigMsg, 0, len(seenEcho))
			for signer, sig := range seenEcho {
				proof = append(proof, spbcSigMsg{
					Signer: signer,
					SigHex: hex.EncodeToString(sig),
				})
			}
			sort.Slice(proof, func(i, j int) bool {
				return proof[i].Signer < proof[j].Signer
			})
			_ = d.net.Broadcast(dmvba.ProtocolMessage{
				Tag:    dmvba.TagSPBC,
				Round:  round,
				Leader: leader,
				Body: spbcFinalMsg{
					Proposal: cloneProposalValue(*proposal),
					Proof:    proof,
				},
			})
			final <- dmvba.SPBCFinalResult{
				Leader: leader,
				Value:  cloneProposalValue(*proposal),
				OK:     true,
			}
			return true
		}
		if maybeFinalizeLeader() {
			return
		}

		for {
			select {
			case <-ctx.Done():
				return
			case in, ok := <-inbound:
				if !ok {
					return
				}
				switch body := in.Body.(type) {
				case dmvba.ProposalValue:
					if in.From != leader || proposal != nil {
						continue
					}
					prop := cloneProposalValue(body)
					proposal = &prop
					digest := digestProposal(prop)
					sk := d.privKeys[id]
					echoSig := ed25519.Sign(sk, digest)
					s1Proof := dmvba.SigShare{Signer: id, Sig: append([]byte(nil), echoSig...)}
					if !s1Sent {
						s1Sent = true
						s1 <- dmvba.SPBCS1Result{
							Leader:  leader,
							Value:   prop,
							S1Proof: []dmvba.SigShare{s1Proof},
							OK:      true,
						}
					}
					if id == leader {
						seenEcho[id] = append([]byte(nil), echoSig...)
						if maybeFinalizeLeader() {
							return
						}
						continue
					}
					_ = d.net.Send(leader, dmvba.ProtocolMessage{
						Tag:    dmvba.TagSPBC,
						Round:  round,
						Leader: leader,
						Body: spbcSigMsg{
							Signer: id,
							SigHex: hex.EncodeToString(echoSig),
						},
					})
				case spbcSigMsg:
					if id != leader || proposal == nil || body.Signer != in.From {
						continue
					}
					sig, err := hex.DecodeString(body.SigHex)
					if err != nil {
						continue
					}
					pk, ok := d.pubKeys[body.Signer]
					if !ok || !ed25519.Verify(pk, digestProposal(*proposal), sig) {
						continue
					}
					if _, exists := seenEcho[body.Signer]; exists {
						continue
					}
					seenEcho[body.Signer] = append([]byte(nil), sig...)
					if maybeFinalizeLeader() {
						return
					}
				case spbcFinalMsg:
					if in.From != leader {
						continue
					}
					digest := digestProposal(body.Proposal)
					validCount := 0
					seenSigner := make(map[int]struct{}, len(body.Proof))
					finalProof := make([]dmvba.SigShare, 0, len(body.Proof))
					for _, proof := range body.Proof {
						if _, dup := seenSigner[proof.Signer]; dup {
							continue
						}
						seenSigner[proof.Signer] = struct{}{}
						sig, err := hex.DecodeString(proof.SigHex)
						if err != nil {
							continue
						}
						pk, ok := d.pubKeys[proof.Signer]
						if !ok || !ed25519.Verify(pk, digest, sig) {
							continue
						}
						validCount++
						finalProof = append(finalProof, dmvba.SigShare{
							Signer: proof.Signer,
							Sig:    append([]byte(nil), sig...),
						})
					}
					if validCount < threshold {
						continue
					}
					final <- dmvba.SPBCFinalResult{
						Leader:     leader,
						Value:      cloneProposalValue(body.Proposal),
						FinalProof: finalProof,
						OK:         true,
					}
					return
				}
			}
		}
	}()
	return &dmvba.SPBCHandle{
		Inbound:  inbound,
		S1Out:    s1,
		FinalOut: final,
		Close:    func() {},
	}, nil
}

func cloneProposalValue(in dmvba.ProposalValue) dmvba.ProposalValue {
	out := dmvba.ProposalValue{
		Round: in.Round,
		Hint:  in.Hint,
	}
	if len(in.Payload) > 0 {
		out.Payload = append([]byte(nil), in.Payload...)
	}
	if len(in.Proof) > 0 {
		out.Proof = make([]dmvba.SigShare, len(in.Proof))
		copy(out.Proof, in.Proof)
	}
	return out
}

type practicalMVBABreakdown struct {
	PeerWait time.Duration
	Wall     time.Duration
}

func decideByDumboMVBA(
	ctx context.Context,
	cfg Config,
	old []int,
	proposals map[int][]int,
) ([]int, practicalMVBABreakdown, error) {
	breakdown := practicalMVBABreakdown{}
	start := time.Now()
	traceMVBA := func(format string, args ...any) {
		if os.Getenv("PRACTICAL_TRACE") == "" {
			return
		}
		fmt.Fprintf(os.Stderr, "PRACTICAL_MVBA "+format+"\n", args...)
	}
	n := len(old)
	if n == 0 {
		return nil, breakdown, fmt.Errorf("empty old committee")
	}
	indexByNode := make(map[int]int, n)
	for i, id := range old {
		indexByNode[id] = i
	}

	recv := make([]chan dmvba.ReceivedMessage, n)
	for i := 0; i < n; i++ {
		recv[i] = make(chan dmvba.ReceivedMessage, 8192)
	}

	maxRounds := cfg.MVBARounds
	if maxRounds <= 0 {
		maxRounds = cfg.F + 4
		if maxRounds < 4 {
			maxRounds = 4
		}
	}
	maxRounds = intFromEnvOr("PRACTICAL_MVBA_MAX_ROUNDS", maxRounds)
	waitSPBC := cfg.WaitSPBCTimeout
	if waitSPBC <= 0 {
		switch {
		case n >= 127:
			waitSPBC = 60 * time.Second
		case n >= 96:
			waitSPBC = 35 * time.Second
		case n >= 64:
			waitSPBC = 20 * time.Second
		case n >= 32:
			waitSPBC = 6 * time.Second
		default:
			waitSPBC = 2 * time.Second
		}
	}
	waitSPBC = durationFromEnvMsOr("PRACTICAL_MVBA_WAIT_SPBC_MS", waitSPBC)
	routeTimeout := cfg.RouteSendTimeout
	if routeTimeout <= 0 {
		switch {
		case n >= 127:
			routeTimeout = 12 * time.Second
		case n >= 96:
			routeTimeout = 8 * time.Second
		case n >= 64:
			routeTimeout = 5 * time.Second
		case n >= 32:
			routeTimeout = 1500 * time.Millisecond
		default:
			routeTimeout = 500 * time.Millisecond
		}
	}
	routeTimeout = durationFromEnvMsOr("PRACTICAL_MVBA_ROUTE_TIMEOUT_MS", routeTimeout)

	// Always use TCP MVBA with TBLS coin.
	localIDs := parseNodeIDSet(firstNonEmpty(cfg.MVBALocalNodeIDs, os.Getenv("PRACTICAL_MVBA_LOCAL_NODE_IDS")))
	if len(localIDs) == 0 {
		for i := 0; i < n; i++ {
			localIDs[i] = struct{}{}
		}
	}

	inputs := make([]dmvba.ProposalValue, n)
	nonEmptyInputs := 0
	inputKeyCount := make(map[string]int, n)
	for _, nodeID := range old {
		i := indexByNode[nodeID]
		stableSet := stableFirst(proposals[nodeID], len(proposals[nodeID]))
		payload := mvbaSetPayload{
			Proposer: nodeID,
			Set:      stableSet,
		}
		raw, mErr := json.Marshal(payload)
		if mErr != nil {
			return nil, breakdown, mErr
		}
		inputs[i] = dmvba.ProposalValue{
			Payload: raw,
			Round:   0,
			Hint:    "practical-adkr",
		}
		if len(stableSet) > 0 {
			nonEmptyInputs++
		}
		key := fmt.Sprintf("%v", stableSet)
		inputKeyCount[key]++
	}
	traceMVBA("input_summary n=%d non_empty=%d distinct=%d max_rounds=%d wait_spbc_ms=%.2f route_send_ms=%.2f",
		n,
		nonEmptyInputs,
		len(inputKeyCount),
		maxRounds,
		float64(waitSPBC.Microseconds())/1000.0,
		float64(routeTimeout.Microseconds())/1000.0,
	)

	seed := sha256.Sum256([]byte(cfg.SID + ":practical-adkr:mvba"))
	blsShares, blsPKs, blsPubKey, blsThreshold, blsErr := dmvba.GenerateBLS12381TBLSBundle(n, cfg.F, pracCoinStream(seed[:]))
	if blsErr != nil {
		return nil, breakdown, fmt.Errorf("mvba bls12381: %w", blsErr)
	}

	outs := make([]dmvba.ProposalValue, n)
	errs := make([]error, n)

	hub, hubErr := newMVBATCPHub(cfg, recv)
	if hubErr != nil {
		return nil, breakdown, fmt.Errorf("mvba tcp hub: %w", hubErr)
	}
	defer hub.close()

	// Send retries handle peers that are still starting; avoid turning startup
	// skew into a fixed 30s latency in local multi-process benchmarks.
	peerWaitDefault := 100 * time.Millisecond
	switch {
	case n >= 127:
		peerWaitDefault = 12 * time.Second
	case n >= 96:
		peerWaitDefault = 10 * time.Second
	case n >= 64:
		peerWaitDefault = 8 * time.Second
	case n >= 32:
		peerWaitDefault = 1 * time.Second
	}
	peerWait := durationFromEnvMsOr("PRACTICAL_MVBA_PEER_WAIT_MS", peerWaitDefault)
	peerStart := time.Now()
	deadline := time.Now().Add(peerWait)
	for time.Now().Before(deadline) {
		reachable := 0
		for id, addr := range hub.addrByID {
			if _, isLocal := hub.listeners[id]; isLocal {
				reachable++
				continue
			}
			if conn, err := net.DialTimeout("tcp", addr, hub.dialTO); err == nil {
				_ = conn.Close()
				reachable++
			}
		}
		if reachable >= n-cfg.F {
			break
		}
		if reachable >= len(hub.listeners) && peerWait <= 0 {
			break
		}
		select {
		case <-ctx.Done():
			return nil, breakdown, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	breakdown.PeerWait = time.Since(peerStart)

	var wg sync.WaitGroup
	for nid := range localIDs {
		wg.Add(1)
		nid := nid
		go func() {
			defer wg.Done()
			traceMVBA("node_begin id=%d payload_bytes=%d", nid, len(inputs[nid].Payload))
			signer := dmvba.NewBLS12381Signer(nid, blsShares[nid], blsPubKey, blsPKs, n, blsThreshold)
			neti := &mvbaTCPNet{id: nid, hub: hub}
			traceMVBA("node_runacs_begin id=%d", nid)
			vec, runErr := dmvba.RunMVBACCommonSubset(ctx,
				dmvba.Config{
					SID: cfg.SID + ":practical-adkr:mvba", ID: nid, N: n, F: cfg.F,
					MaxRounds: maxRounds, WaitSPBCTimeout: waitSPBC,
					RouteSendTimeout: routeTimeout,
				},
				neti, signer, recv[nid], inputs[nid], nil,
			)
			traceMVBA("node_runacs_end id=%d err=%v", nid, runErr)
			nonNilVec := 0
			firstPayloadBytes := 0
			if runErr == nil {
				for _, candidate := range vec {
					if candidate != nil {
						nonNilVec++
					}
					if candidate != nil && len(candidate.Payload) > 0 {
						outs[nid] = *candidate
						if firstPayloadBytes == 0 {
							firstPayloadBytes = len(candidate.Payload)
						}
						break
					}
				}
			}
			traceMVBA("node_end id=%d err=%v non_nil_vec=%d out_bytes=%d",
				nid, runErr, nonNilVec, firstPayloadBytes)
			errs[nid] = runErr
		}()
	}

	wg.Wait()

	checkIDs := localIDs
	if len(checkIDs) == 0 {
		checkIDs = make(map[int]struct{}, n)
		for i := 0; i < n; i++ {
			checkIDs[i] = struct{}{}
		}
	}
	for i := range checkIDs {
		if errs[i] != nil {
			return nil, breakdown, fmt.Errorf("mvba node %d failed: %w", i, errs[i])
		}
	}

	votes := make(map[string]int, n)
	decoded := make(map[string][]int, n)
	for i := 0; i < n; i++ {
		if len(outs[i].Payload) == 0 {
			continue
		}
		var p mvbaSetPayload
		if err := json.Unmarshal(outs[i].Payload, &p); err != nil {
			return nil, breakdown, fmt.Errorf("decode mvba output at node %d: %w", old[i], err)
		}
		set := stableFirst(p.Set, len(p.Set))
		sort.Ints(set)
		key := fmt.Sprintf("%v", set)
		votes[key]++
		decoded[key] = set
	}

	bestKey := ""
	bestCount := -1
	for k, c := range votes {
		if c > bestCount {
			bestCount = c
			bestKey = k
		}
	}
	if bestKey == "" {
		return nil, breakdown, fmt.Errorf("mvba returned no decision")
	}
	breakdown.Wall = time.Since(start)
	return append([]int(nil), decoded[bestKey]...), breakdown, nil
}

func parseNodeAddrMap(raw string) map[int]string {
	out := make(map[int]string)
	if strings.TrimSpace(raw) == "" {
		return out
	}
	items := strings.Split(raw, ",")
	for _, item := range items {
		part := strings.TrimSpace(item)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		id, err := strconv.Atoi(strings.TrimSpace(kv[0]))
		if err != nil {
			continue
		}
		addr := strings.TrimSpace(kv[1])
		if addr == "" {
			continue
		}
		out[id] = addr
	}
	return out
}

func parseNodeIDSet(raw string) map[int]struct{} {
	out := make(map[int]struct{})
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	items := strings.Split(raw, ",")
	for _, item := range items {
		part := strings.TrimSpace(item)
		if part == "" {
			continue
		}
		id, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		out[id] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func durationFromEnvMsOr(name string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return time.Duration(n) * time.Millisecond
}

func intFromEnvOr(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func pracCoinStream(seed []byte) cipher.Stream {
	key := sha256.Sum256(seed)
	block, _ := aes.NewCipher(key[:])
	return cipher.NewCTR(block, make([]byte, aes.BlockSize))
}
