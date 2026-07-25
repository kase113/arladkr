package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	dmvba "dumbomvba_go/core"
)

func init() {
	gob.Register(dmvba.ProposalValue{})
	gob.Register(mvbaTCPWire{})
}

type mvbaTCPWire struct {
	From int
	Msg  dmvba.ProtocolMessage
}

const mvbaTCPPortOffset = 10000

// runDumboTCPFallback runs MVBA+ACS agreement over TCP so that every
// instance participates in the network-level consensus.  This path is
// selected automatically when not all committee nodes are local.
//
// The protocol is the SAME RunMVBACCommonSubset (equivalent path) used by
// the in-process path — only the transport layer differs.
func runDumboTCPFallback(
	ctx context.Context,
	cfg Config,
	localIDs []int,
	n int,
	payload []byte,
	descriptors map[int]Descriptor,
	artifacts map[int]*DealerArtifact,
) ([]int, []NodeOutput, error) {
	recv := make([]chan dmvba.ReceivedMessage, n)
	for i := range recv {
		recv[i] = make(chan dmvba.ReceivedMessage, 4096)
	}
	hub, err := newMVBATCPHub(cfg, recv)
	if err != nil {
		return nil, nil, fmt.Errorf("mvba hub: %w", err)
	}
	defer hub.close()

	// Build per-node deterministic ed25519 keys (same derivation as in-proc).
	privKM := make(map[int]ed25519.PrivateKey, n)
	pubSlice := make([]ed25519.PublicKey, n)
	for i := 0; i < n; i++ {
		_, sk, err := deriveMVBAKey(cfg.SID, i)
		if err != nil {
			return nil, nil, fmt.Errorf("keygen %d: %w", i, err)
		}
		pubSlice[i] = sk.Public().(ed25519.PublicKey)
		privKM[i] = sk
	}

	maxR := cfg.F + 4
	if maxR < 4 {
		maxR = 4
	}

	// Rendezvous: wait for all remote TCP listeners to be reachable before
	// starting the MVBA rounds so that the first broadcast isn't lost.
	hub.waitForAllPeers(ctx, 60*time.Second)

	acsVecs := make([][]*dmvba.ProposalValue, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			signer, sErr := dmvba.NewEd25519Signer(i, privKM[i], pubSlice)
			if sErr != nil {
				errs[i] = sErr
				return
			}
			neti := &mvbaTCPNet{id: i, hub: hub}
			vec, runErr := dmvba.RunMVBACCommonSubset(ctx,
				dmvba.Config{
					SID:                cfg.SID + "-mvba",
					ID:                 i,
					N:                  n,
					F:                  cfg.F,
					MaxRounds:          maxR,
					WaitSPBCTimeout:    8 * time.Second,
					RouteSendTimeout:   100 * time.Millisecond,
					UseEquivalentPath:  true,
					EquivalentCoinMode: "deterministic",
				},
				neti, signer, recv[i],
				dmvba.ProposalValue{Payload: payload, Round: 1},
				nil,
			)
			acsVecs[i] = vec
			errs[i] = runErr
		}()
	}
	wg.Wait()

	for i := range errs {
		if errs[i] != nil {
			return nil, nil, fmt.Errorf("dumboMVBA node %d: %w", i, errs[i])
		}
	}

	lockedSet := extractDecidedDealersFromACS(acsVecs, cfg, descriptors, artifacts)
	if len(lockedSet) == 0 {
		return nil, nil, fmt.Errorf("dumboMVBA tcp: failed to extract decided set")
	}

	outputs := make([]NodeOutput, 0, len(localIDs))
	for _, lid := range localIDs {
		outputs = append(outputs, NodeOutput{NodeID: lid, DecidedSet: append([]int(nil), lockedSet...)})
	}
	return lockedSet, outputs, nil
}

// ── TCP hub: one listener per instance, broadcasts to all recv channels ──

type mvbaTCPHub struct {
	addrByID map[int]string
	recv     []chan dmvba.ReceivedMessage
	ln       net.Listener
	closed   chan struct{}
	wg       sync.WaitGroup
	dialTO   time.Duration
	writeTO  time.Duration
	readTO   time.Duration
	retries  int
	backoff  time.Duration
	runtime  *runtimeCrypto
}

func newMVBATCPHub(cfg Config, recv []chan dmvba.ReceivedMessage) (*mvbaTCPHub, error) {
	n := len(cfg.OldCommittee)
	am := tcpParseAddrMap(os.Getenv("RLADKR_NODE_ADDRS"))
	if len(am) < n {
		return nil, fmt.Errorf("mvba addrs incomplete: %d<%d", len(am), n)
	}
	localIDs := sortedUnique(cfg.LocalNodeIDs)
	if len(localIDs) == 0 {
		return nil, fmt.Errorf("mvba local ids required")
	}
	mvbaBase := cfg.AgreementBasePort + mvbaTCPPortOffset

	addrMap := make(map[int]string, len(am))
	for id, addr := range am {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = "127.0.0.1"
		}
		addrMap[id] = net.JoinHostPort(host, strconv.Itoa(mvbaBase+id))
	}

	listenAddr := addrMap[localIDs[0]]
	ln, err := arlListenWithRetry(
		"tcp",
		listenAddr,
		arlDurationFromEnv("RLADKR_MVBA_LISTEN_RETRY_TIMEOUT_MS", 5*time.Second),
		arlDurationFromEnv("RLADKR_MVBA_LISTEN_RETRY_BACKOFF_MS", 100*time.Millisecond),
	)
	if err != nil {
		return nil, fmt.Errorf("mvba listen %s: %w", listenAddr, err)
	}

	h := &mvbaTCPHub{
		addrByID: addrMap,
		recv:     recv,
		ln:       ln,
		closed:   make(chan struct{}),
		dialTO:   5 * time.Second,
		writeTO:  5 * time.Second,
		readTO:   30 * time.Second,
		retries:  15,
		backoff:  200 * time.Millisecond,
		runtime:  cfg.runtime,
	}

	h.wg.Add(1)
	go h.acceptAndBroadcast()
	return h, nil
}

func (h *mvbaTCPHub) acceptAndBroadcast() {
	defer h.wg.Done()
	for {
		conn, err := h.ln.Accept()
		if err != nil {
			select {
			case <-h.closed:
				return
			default:
				continue
			}
		}
		_ = conn.SetReadDeadline(time.Now().Add(h.readTO))
		body, err := io.ReadAll(conn)
		if err != nil {
			_ = conn.Close()
			continue
		}
		h.recordRecvBytes(len(body))
		var wire mvbaTCPWire
		if gob.NewDecoder(bytes.NewReader(body)).Decode(&wire) != nil {
			_ = conn.Close()
			continue
		}
		_ = conn.Close()
		msg := dmvba.ReceivedMessage{From: wire.From, Msg: wire.Msg}
		for _, ch := range h.recv {
			select {
			case ch <- msg:
			default:
				select {
				case ch <- msg:
				case <-time.After(100 * time.Millisecond):
				}
			}
		}
	}
}

// waitForAllPeers blocks until TCP connections to every peer succeed.
func (h *mvbaTCPHub) waitForAllPeers(ctx context.Context, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for id, addr := range h.addrByID {
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return
			default:
			}
			conn, err := net.DialTimeout("tcp", addr, h.dialTO)
			if err == nil {
				_ = conn.Close()
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		_ = id // silence unused
	}
}

func (h *mvbaTCPHub) close() {
	select {
	case <-h.closed:
		return
	default:
		close(h.closed)
	}
	_ = h.ln.Close()
	h.wg.Wait()
}

// ── TCP-backed Network for dumbo MVBA ──

type mvbaTCPNet struct {
	id  int
	hub *mvbaTCPHub
}

func (n *mvbaTCPNet) Broadcast(msg dmvba.ProtocolMessage) error {
	for to := range n.hub.addrByID {
		if err := n.Send(to, msg); err != nil {
			return err
		}
	}
	return nil
}

func (n *mvbaTCPNet) Send(to int, msg dmvba.ProtocolMessage) error {
	wire := mvbaTCPWire{From: n.id, Msg: msg}
	addr, ok := n.hub.addrByID[to]
	if !ok || addr == "" {
		return fmt.Errorf("mvba addr missing %d", to)
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(wire); err != nil {
		return err
	}
	body := buf.Bytes()
	for a := 0; a < n.hub.retries; a++ {
		conn, err := arlDialWithOptionalDelay(n.id, to, "tcp", addr, n.hub.dialTO)
		if err != nil {
			time.Sleep(time.Duration(a+1) * n.hub.backoff)
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(n.hub.writeTO))
		_, wErr := conn.Write(body)
		_ = conn.Close()
		if wErr == nil {
			n.hub.recordSentBytes(len(body))
			return nil
		}
		time.Sleep(time.Duration(a+1) * n.hub.backoff)
	}
	return fmt.Errorf("mvba tcp send failed %d->%d", n.id, to)
}

func (h *mvbaTCPHub) recordSentBytes(n int) {
	if h == nil || h.runtime == nil {
		return
	}
	h.runtime.recordSentBytes(n)
}

func (h *mvbaTCPHub) recordRecvBytes(n int) {
	if h == nil || h.runtime == nil {
		return
	}
	h.runtime.recordRecvBytes(n)
}

// ── Helpers ──

func tcpParseAddrMap(raw string) map[int]string {
	out := make(map[int]string)
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		kv := strings.SplitN(item, "=", 2)
		if len(kv) != 2 {
			continue
		}
		id, err := strconv.Atoi(strings.TrimSpace(kv[0]))
		if err != nil {
			continue
		}
		out[id] = strings.TrimSpace(kv[1])
	}
	return out
}
