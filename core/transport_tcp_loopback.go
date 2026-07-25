package core

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type transportAck struct {
	OK bool `json:"ok"`
}

func listenerReadyMarkerPath(dir string, nodeID int) string {
	return filepath.Join(dir, fmt.Sprintf("node-%04d.ready", nodeID))
}

func writeListenerReadyMarker(dir string, nodeID int, addr string) error {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	payload := []byte(strings.TrimSpace(addr) + "\n")
	return os.WriteFile(listenerReadyMarkerPath(dir, nodeID), payload, 0o644)
}

func waitForListenerReadyMarkers(dir string, nodeCount int, timeout time.Duration) error {
	if strings.TrimSpace(dir) == "" || nodeCount <= 0 {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for {
		ready := 0
		for id := 0; id < nodeCount; id++ {
			if _, err := os.Stat(listenerReadyMarkerPath(dir, id)); err == nil {
				ready++
			}
		}
		if ready >= nodeCount {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("listener-ready barrier timeout: ready=%d/%d dir=%s", ready, nodeCount, dir)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type tcpLoopbackTransport struct {
	mu        sync.RWMutex
	inbox     map[int]chan Message
	addrByID  map[int]string
	listeners map[int]net.Listener
	poolMu    sync.Mutex
	conns     map[string]*tcpLoopbackPoolConn
	closed    chan struct{}
	wg        sync.WaitGroup
	dialTO    time.Duration
	writeTO   time.Duration
	readTO    time.Duration
	acceptTO  time.Duration
	enqueueTO time.Duration
	runtime   *runtimeCrypto
	reuseConn bool
}

type tcpLoopbackPoolConn struct {
	conn net.Conn
	enc  *json.Encoder
	dec  *json.Decoder
	mu   sync.Mutex
}

func waitForRemoteNodeReadiness(cfg Config, t *tcpLoopbackTransport, nodes []int) error {
	localSet := nodeSet(filterNodeIDs(cfg.LocalNodeIDs, nodes))
	if len(localSet) == 0 {
		return nil
	}
	deadline := time.Now().Add(3 * cfg.WaitSPBCTimeout)
	for _, id := range sortedUnique(nodes) {
		if _, isLocal := localSet[id]; isLocal {
			continue
		}
		for {
			t.mu.RLock()
			addr := t.addrByID[id]
			t.mu.RUnlock()
			if strings.TrimSpace(addr) == "" {
				break
			}
			conn, err := net.DialTimeout("tcp", addr, t.dialTO)
			if err == nil {
				_ = conn.Close()
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("remote node %d listener not ready at %s: %w", id, addr, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	return nil
}

func NewTCPLoopbackTransport(nodes []int, buffer int) (agreementTransport, error) {
	return NewTCPLoopbackTransportWithOptions(Config{}, nodes, nodes, buffer, "0.0.0.0", 0)
}

func NewTCPLoopbackTransportWithOptions(
	cfg Config,
	nodes []int,
	localNodes []int,
	buffer int,
	bindHost string,
	basePort int,
) (agreementTransport, error) {
	if buffer <= 0 {
		buffer = 1024
	}
	t := &tcpLoopbackTransport{
		inbox:     make(map[int]chan Message, len(nodes)),
		addrByID:  make(map[int]string, len(nodes)),
		listeners: make(map[int]net.Listener, len(nodes)),
		conns:     make(map[string]*tcpLoopbackPoolConn),
		closed:    make(chan struct{}),
		dialTO:    durationEnvMs("RLADKR_TCP_DIAL_TIMEOUT_MS", defaultTransportDialTimeout(len(nodes))),
		writeTO:   durationEnvMs("RLADKR_TCP_WRITE_TIMEOUT_MS", defaultTransportWriteTimeout(len(nodes))),
		readTO:    durationEnvMs("RLADKR_TCP_READ_TIMEOUT_MS", defaultTransportReadTimeout(len(nodes))),
		acceptTO:  durationEnvMs("RLADKR_TCP_ACCEPT_READ_TIMEOUT_MS", defaultTransportAcceptTimeout(len(nodes))),
		enqueueTO: durationEnvMs("RLADKR_TCP_ENQUEUE_TIMEOUT_MS", defaultTransportEnqueueTimeout(len(nodes))),
		runtime:   cfg.runtime,
		reuseConn: strings.TrimSpace(os.Getenv("RLADKR_TCP_CONN_REUSE")) == "1",
	}
	addrOverrides := parseAddrOverrideMap(os.Getenv("RLADKR_NODE_ADDRS"))
	ordered := append([]int(nil), nodes...)
	sort.Ints(ordered)
	localSet := make(map[int]struct{}, len(localNodes))
	for _, id := range filterNodeIDs(localNodes, nodes) {
		localSet[id] = struct{}{}
	}
	if len(localSet) == 0 {
		for _, id := range ordered {
			localSet[id] = struct{}{}
		}
	}
	dialHost := resolveDialHost(bindHost)
	listenerReadyDir := strings.TrimSpace(os.Getenv("RLADKR_LISTENER_READY_DIR"))
	listenerReadyNodeCount, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("RLADKR_LISTENER_READY_NODE_COUNT")))
	listenerReadyTimeout := durationEnvMs("RLADKR_LISTENER_READY_TIMEOUT_MS", 120000*time.Millisecond)
	for _, id := range ordered {
		if _, isLocal := localSet[id]; isLocal {
			addr := fmt.Sprintf("%s:0", bindHost)
			if ov, ok := addrOverrides[id]; ok {
				// Extract port from the override (which carries the
				// public IP), but listen on bindHost so the socket
				// actually binds on EC2 instances whose interfaces
				// don't own the public IP.
				if _, ovPort, e := net.SplitHostPort(ov); e == nil {
					addr = net.JoinHostPort(bindHost, ovPort)
				}
			}
			if basePort > 0 {
				port := basePort + id
				addr = fmt.Sprintf("%s:%d", bindHost, port)
			}
			ln, err := arlListenWithRetry(
				"tcp",
				addr,
				durationEnvMs("RLADKR_TCP_LISTEN_RETRY_TIMEOUT_MS", 5*time.Second),
				durationEnvMs("RLADKR_TCP_LISTEN_RETRY_BACKOFF_MS", 100*time.Millisecond),
			)
			if err != nil {
				_ = t.Close()
				return nil, err
			}
			t.listeners[id] = ln
			_, port, splitErr := net.SplitHostPort(ln.Addr().String())
			if splitErr != nil {
				_ = t.Close()
				return nil, splitErr
			}
			if ov, ok := addrOverrides[id]; ok {
				t.addrByID[id] = ov
			} else {
				t.addrByID[id] = net.JoinHostPort(dialHost, port)
			}
			t.inbox[id] = make(chan Message, buffer)
			t.wg.Add(1)
			go t.acceptLoop(id, ln)
			if err := writeListenerReadyMarker(listenerReadyDir, id, t.addrByID[id]); err != nil {
				_ = t.Close()
				return nil, err
			}
			continue
		}
		if ov, ok := addrOverrides[id]; ok {
			t.addrByID[id] = ov
			continue
		}
		if basePort > 0 {
			t.addrByID[id] = net.JoinHostPort(dialHost, strconv.Itoa(basePort+id))
		}
	}
	if err := waitForListenerReadyMarkers(listenerReadyDir, listenerReadyNodeCount, listenerReadyTimeout); err != nil {
		_ = t.Close()
		return nil, err
	}
	if err := waitForRemoteNodeReadiness(Config{
		LocalNodeIDs:      append([]int(nil), localNodes...),
		WaitSPBCTimeout:   10 * time.Second,
		SendRetryMax:      3,
		SendRetryBackoff:  30 * time.Millisecond,
		AgreementBindHost: bindHost,
	}, t, ordered); err != nil {
		_ = t.Close()
		return nil, err
	}
	return t, nil
}

func resolveDialHost(bindHost string) string {
	override := os.Getenv("RLADKR_DIAL_HOST")
	if override != "" {
		return override
	}
	switch bindHost {
	case "", "0.0.0.0", "::":
		return "127.0.0.1"
	default:
		return bindHost
	}
}

func (t *tcpLoopbackTransport) RecvChan(id int) (<-chan Message, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	ch, ok := t.inbox[id]
	if !ok {
		return nil, fmt.Errorf("node %d not registered", id)
	}
	return ch, nil
}

func (t *tcpLoopbackTransport) Send(msg Message) error {
	wireBytes := jsonWireMessageBytes(msg)
	t.mu.RLock()
	addr, ok := t.addrByID[msg.To]
	ch, local := t.inbox[msg.To]
	t.mu.RUnlock()
	if !ok {
		return fmt.Errorf("node %d not registered", msg.To)
	}
	if local {
		select {
		case ch <- msg:
			t.recordSendRecvBytes(wireBytes)
			return nil
		case <-time.After(t.enqueueTO):
			return fmt.Errorf("local enqueue timeout for node %d", msg.To)
		}
	}
	if t.reuseConn {
		return t.sendRemotePooled(addr, msg, wireBytes)
	}
	return t.sendRemoteShortConn(addr, msg, wireBytes)
}

func (t *tcpLoopbackTransport) sendRemoteShortConn(addr string, msg Message, wireBytes int) error {
	conn, err := arlDialWithOptionalDelay(msg.From, msg.To, "tcp", addr, t.dialTO)
	if err != nil {
		return err
	}
	defer conn.Close()
	return t.sendRemoteOnConn(conn, json.NewEncoder(conn), json.NewDecoder(conn), msg, wireBytes)
}

func (t *tcpLoopbackTransport) sendRemotePooled(addr string, msg Message, wireBytes int) error {
	key := tcpLoopbackPoolKey(msg.From, msg.To, addr)
	t.poolMu.Lock()
	if t.conns == nil {
		t.conns = make(map[string]*tcpLoopbackPoolConn)
	}
	pc, ok := t.conns[key]
	if ok {
		pc.mu.Lock()
		t.poolMu.Unlock()
		if err := t.sendRemoteOnConn(pc.conn, pc.enc, pc.dec, msg, wireBytes); err == nil {
			pc.mu.Unlock()
			return nil
		}
		_ = pc.conn.Close()
		pc.mu.Unlock()
		t.poolMu.Lock()
		if t.conns[key] == pc {
			delete(t.conns, key)
		}
	} else {
		t.poolMu.Unlock()
	}

	conn, err := arlDialWithOptionalDelay(msg.From, msg.To, "tcp", addr, t.dialTO)
	if err != nil {
		return err
	}
	pc = &tcpLoopbackPoolConn{
		conn: conn,
		enc:  json.NewEncoder(conn),
		dec:  json.NewDecoder(conn),
	}
	pc.mu.Lock()
	if err := t.sendRemoteOnConn(pc.conn, pc.enc, pc.dec, msg, wireBytes); err != nil {
		pc.mu.Unlock()
		_ = conn.Close()
		return err
	}
	pc.mu.Unlock()

	t.poolMu.Lock()
	if existing, exists := t.conns[key]; exists {
		existing.mu.Lock()
		_ = existing.conn.Close()
		existing.mu.Unlock()
	}
	t.conns[key] = pc
	t.poolMu.Unlock()
	return nil
}

func (t *tcpLoopbackTransport) sendRemoteOnConn(conn net.Conn, enc *json.Encoder, dec *json.Decoder, msg Message, wireBytes int) error {
	_ = conn.SetWriteDeadline(time.Now().Add(t.writeTO))
	if err := enc.Encode(msg); err != nil {
		return err
	}
	t.recordSentBytes(wireBytes)
	_ = conn.SetReadDeadline(time.Now().Add(t.readTO))
	var ack transportAck
	if err := dec.Decode(&ack); err != nil {
		return err
	}
	if !ack.OK {
		return fmt.Errorf("transport ack rejected for msg tag=%s", msg.Tag)
	}
	return nil
}

func tcpLoopbackPoolKey(from int, to int, addr string) string {
	return fmt.Sprintf("%d->%d@%s", from, to, addr)
}

func (t *tcpLoopbackTransport) Broadcast(from int, to []int, tag string, body []byte) {
	var wg sync.WaitGroup
	for _, id := range to {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = t.Send(Message{
				From: from,
				To:   id,
				Tag:  tag,
				Body: append([]byte(nil), body...),
			})
		}()
	}
	wg.Wait()
}

func (t *tcpLoopbackTransport) Close() error {
	select {
	case <-t.closed:
		return nil
	default:
		close(t.closed)
	}
	t.mu.Lock()
	for _, ln := range t.listeners {
		_ = ln.Close()
	}
	t.mu.Unlock()
	t.closePooledConns()
	t.wg.Wait()
	return nil
}

func (t *tcpLoopbackTransport) closePooledConns() {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	for key, pc := range t.conns {
		pc.mu.Lock()
		_ = pc.conn.Close()
		pc.mu.Unlock()
		delete(t.conns, key)
	}
}

func (t *tcpLoopbackTransport) recordSentBytes(n int) {
	if t == nil || t.runtime == nil {
		return
	}
	t.runtime.recordSentBytes(n)
}

func (t *tcpLoopbackTransport) recordRecvBytes(n int) {
	if t == nil || t.runtime == nil {
		return
	}
	t.runtime.recordRecvBytes(n)
}

func (t *tcpLoopbackTransport) recordSendRecvBytes(n int) {
	t.recordSentBytes(n)
	t.recordRecvBytes(n)
}

func jsonWireMessageBytes(msg Message) int {
	body, err := json.Marshal(msg)
	if err != nil {
		return 0
	}
	return len(body) + 1
}

func (t *tcpLoopbackTransport) acceptLoop(id int, ln net.Listener) {
	defer t.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-t.closed:
				return
			default:
				continue
			}
		}
		t.wg.Add(1)
		go t.handleAcceptedConn(id, conn)
	}
}

func (t *tcpLoopbackTransport) handleAcceptedConn(id int, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	for {
		select {
		case <-t.closed:
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(t.acceptTO))
		var msg Message
		if err := dec.Decode(&msg); err == nil {
			t.recordRecvBytes(jsonWireMessageBytes(msg))
			t.mu.RLock()
			ch := t.inbox[id]
			t.mu.RUnlock()
			delivered := false
			select {
			case ch <- msg:
				delivered = true
			case <-time.After(t.enqueueTO):
			case <-t.closed:
			}
			_ = conn.SetWriteDeadline(time.Now().Add(t.writeTO))
			if err := enc.Encode(transportAck{OK: delivered}); err != nil {
				return
			}
		} else {
			_ = conn.SetWriteDeadline(time.Now().Add(t.writeTO))
			_ = enc.Encode(transportAck{OK: false})
			return
		}
	}
}

func parseAddrOverrideMap(raw string) map[int]string {
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

func durationEnvMs(name string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	return time.Duration(n) * time.Millisecond
}

func defaultTransportDialTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 5 * time.Second
	case n >= 128:
		return 3 * time.Second
	default:
		return 1200 * time.Millisecond
	}
}

func defaultTransportWriteTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 5 * time.Second
	case n >= 128:
		return 3 * time.Second
	default:
		return 1200 * time.Millisecond
	}
}

func defaultTransportReadTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 10 * time.Second
	case n >= 128:
		return 5 * time.Second
	default:
		return 1200 * time.Millisecond
	}
}

func defaultTransportAcceptTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 10 * time.Second
	case n >= 128:
		return 5 * time.Second
	default:
		return 2500 * time.Millisecond
	}
}

func defaultTransportEnqueueTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 3 * time.Second
	case n >= 128:
		return 1500 * time.Millisecond
	default:
		return 400 * time.Millisecond
	}
}
