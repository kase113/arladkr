package core

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type practicalDelayConfig struct {
	enabled              bool
	nodeCount            int
	matrix               [][]int
	bandwidthBytesPerSec float64
	bandwidthScope       string
	bandwidthStateFile   string
	bandwidthSocket      string
}

var (
	delayOnce sync.Once
	delayCfg  practicalDelayConfig
	bandwidth practicalBandwidthLimiter
	bwSocket  practicalBandwidthSocketClient
)

func loadDelayConfigFromEnv() practicalDelayConfig {
	cfg := practicalDelayConfig{
		bandwidthBytesPerSec: bandwidthBytesPerSecondFromEnv(),
	}
	if cfg.bandwidthBytesPerSec > 0 {
		cfg.bandwidthScope = bandwidthScopeFromEnv("PRACTICAL_BANDWIDTH_SCOPE")
		cfg.bandwidthStateFile = stringsTrim(os.Getenv("PRACTICAL_BANDWIDTH_STATE_FILE"))
		cfg.bandwidthSocket = stringsTrim(os.Getenv("PRACTICAL_BANDWIDTH_SOCKET"))
	}
	if stringsTrim(os.Getenv("PRACTICAL_DELAY_ENABLE")) != "1" {
		return cfg
	}
	path := stringsTrim(os.Getenv("PRACTICAL_DELAY_MATRIX_FILE"))
	if path == "" {
		return cfg
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	var matrix [][]int
	if err := json.Unmarshal(raw, &matrix); err != nil {
		return cfg
	}
	nodeCount := len(matrix)
	if env := stringsTrim(os.Getenv("PRACTICAL_DELAY_NODE_COUNT")); env != "" {
		if n, err := strconv.Atoi(env); err == nil && n > 0 {
			nodeCount = n
		}
	}
	if nodeCount <= 0 || len(matrix) == 0 {
		return cfg
	}
	cfg.enabled = true
	cfg.nodeCount = nodeCount
	cfg.matrix = matrix
	return cfg
}

func bandwidthBytesPerSecondFromEnv() float64 {
	raw := stringsTrim(os.Getenv("PRACTICAL_BANDWIDTH_MBPS"))
	if raw == "" {
		return 0
	}
	mbps, err := strconv.ParseFloat(raw, 64)
	if err != nil || mbps <= 0 {
		return 0
	}
	return mbps * 1000 * 1000 / 8
}

func bandwidthScopeFromEnv(name string) string {
	switch stringsTrim(os.Getenv(name)) {
	case "", "shared":
		return "shared"
	case "per-node-egress":
		return "per-node-egress"
	default:
		return "shared"
	}
}

func delayConfig() practicalDelayConfig {
	delayOnce.Do(func() {
		delayCfg = loadDelayConfigFromEnv()
	})
	return delayCfg
}

func normalizedDelaySlot(id, nodeCount int) int {
	if nodeCount <= 0 {
		return id
	}
	if id < 0 {
		return id
	}
	return id % nodeCount
}

func delayBeforeSend(fromID, toID int, _ string) {
	cfg := delayConfig()
	if !cfg.enabled || cfg.nodeCount <= 0 {
		return
	}
	src := normalizedDelaySlot(fromID, cfg.nodeCount)
	dst := normalizedDelaySlot(toID, cfg.nodeCount)
	if src < 0 || dst < 0 || src >= len(cfg.matrix) || dst >= len(cfg.matrix[src]) {
		return
	}
	delayMs := cfg.matrix[src][dst]
	if delayMs <= 0 {
		return
	}
	time.Sleep(time.Duration(delayMs) * time.Millisecond)
}

type delayedWriteConn struct {
	net.Conn
	delay time.Duration
}

func (c *delayedWriteConn) Write(p []byte) (int, error) {
	if c.delay > 0 {
		time.Sleep(c.delay)
	}
	throttleBandwidth(len(p))
	return c.Conn.Write(p)
}

type practicalBandwidthLimiter struct {
	mu   sync.Mutex
	next time.Time
}

func throttleBandwidth(n int) {
	if n <= 0 {
		return
	}
	cfg := delayConfig()
	bytesPerSec := cfg.bandwidthBytesPerSec
	if bytesPerSec <= 0 {
		return
	}
	if cfg.bandwidthScope == "shared" {
		if cfg.bandwidthSocket != "" && throttleSocketBandwidth(n, cfg.bandwidthSocket) {
			return
		}
		if cfg.bandwidthStateFile != "" {
			throttleSharedBandwidth(n, bytesPerSec, cfg.bandwidthStateFile)
			return
		}
	}
	throttleLocalBandwidth(n, bytesPerSec)
}

func throttleLocalBandwidth(n int, bytesPerSec float64) {
	duration := time.Duration(float64(time.Second) * float64(n) / bytesPerSec)
	if duration <= 0 {
		return
	}
	bandwidth.mu.Lock()
	now := time.Now()
	start := now
	if bandwidth.next.After(now) {
		start = bandwidth.next
	}
	readyAt := start.Add(duration)
	bandwidth.next = readyAt
	wait := readyAt.Sub(now)
	bandwidth.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

type practicalBandwidthSocketClient struct {
	mu         sync.Mutex
	conn       net.Conn
	reader     *bufio.Reader
	socketPath string
}

func throttleSocketBandwidth(n int, socketPath string) bool {
	wait, ok := bwSocket.reserve(n, socketPath)
	if !ok {
		return false
	}
	if wait > 0 {
		time.Sleep(wait)
	}
	return true
}

func (c *practicalBandwidthSocketClient) reserve(n int, socketPath string) (time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if c.conn == nil || c.socketPath != socketPath {
			c.closeLocked()
			conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
			if err != nil {
				return 0, false
			}
			c.conn = conn
			c.reader = bufio.NewReader(conn)
			c.socketPath = socketPath
		}
		_ = c.conn.SetDeadline(time.Now().Add(30 * time.Second))
		if _, err := c.conn.Write([]byte(strconv.Itoa(n) + "\n")); err != nil {
			c.closeLocked()
			continue
		}
		line, err := c.reader.ReadString('\n')
		if err != nil {
			c.closeLocked()
			continue
		}
		waitNs, err := strconv.ParseInt(stringsTrim(line), 10, 64)
		if err != nil || waitNs < 0 {
			return 0, false
		}
		return time.Duration(waitNs), true
	}
	return 0, false
}

func (c *practicalBandwidthSocketClient) closeLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn = nil
	c.reader = nil
	c.socketPath = ""
}

func throttleSharedBandwidth(n int, bytesPerSec float64, stateFile string) {
	duration := time.Duration(float64(time.Second) * float64(n) / bytesPerSec)
	if duration <= 0 {
		return
	}
	file, err := os.OpenFile(stateFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		throttleLocalBandwidth(n, bytesPerSec)
		return
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		throttleLocalBandwidth(n, bytesPerSec)
		return
	}
	now := time.Now()
	start := now
	if _, err := file.Seek(0, 0); err == nil {
		if raw, err := io.ReadAll(file); err == nil {
			if nextUnixNano, err := strconv.ParseInt(stringsTrim(string(raw)), 10, 64); err == nil && nextUnixNano > 0 {
				if next := time.Unix(0, nextUnixNano); next.After(now) {
					start = next
				}
			}
		}
	}
	readyAt := start.Add(duration)
	_ = file.Truncate(0)
	_, _ = file.Seek(0, 0)
	_, _ = file.WriteString(strconv.FormatInt(readyAt.UnixNano(), 10))
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	if wait := readyAt.Sub(now); wait > 0 {
		time.Sleep(wait)
	}
}

func delayDuration(fromID, toID int) time.Duration {
	cfg := delayConfig()
	if !cfg.enabled || cfg.nodeCount <= 0 {
		return 0
	}
	src := normalizedDelaySlot(fromID, cfg.nodeCount)
	dst := normalizedDelaySlot(toID, cfg.nodeCount)
	if src < 0 || dst < 0 || src >= len(cfg.matrix) || dst >= len(cfg.matrix[src]) {
		return 0
	}
	delayMs := cfg.matrix[src][dst]
	if delayMs <= 0 {
		return 0
	}
	return time.Duration(delayMs) * time.Millisecond
}

func dialWithOptionalDelay(fromID, toID int, network, addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, err
	}
	delay := delayDuration(fromID, toID)
	if delay <= 0 && delayConfig().bandwidthBytesPerSec <= 0 {
		return conn, nil
	}
	return &delayedWriteConn{Conn: conn, delay: delay}, nil
}

func dialPlain(network, addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, err
	}
	if delayConfig().bandwidthBytesPerSec <= 0 {
		return conn, nil
	}
	return &delayedWriteConn{Conn: conn}, nil
}

// mvbaLegacyDelay reports whether the MVBA transport should use the legacy delay
// model (time.Sleep inside Write, executed while holding the pooled connection
// lock). Default is the pipeline model; set PRACTICAL_MVBA_LEGACY_DELAY=1 to
// restore the legacy behavior for A/B comparison.
func mvbaLegacyDelay() bool {
	return stringsTrim(os.Getenv("PRACTICAL_MVBA_LEGACY_DELAY")) == "1"
}

// mvbaDial dials for the MVBA transport, honoring the delay model in effect.
// Legacy mode embeds the propagation delay in Write (dialWithOptionalDelay);
// pipeline mode dials a bandwidth-only connection — the one-way propagation
// delay is applied by the caller with delayBeforeSend BEFORE acquiring the
// per-peer connection lock, so concurrent sends no longer serialize behind
// each other's sleep (see mvba_dumbo_adapter.go).
func mvbaDial(fromID, toID int, network, addr string, timeout time.Duration) (net.Conn, error) {
	if mvbaLegacyDelay() {
		return dialWithOptionalDelay(fromID, toID, network, addr, timeout)
	}
	return dialPlain(network, addr, timeout)
}

func stringsTrim(s string) string {
	i := 0
	j := len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	for i < j && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\n' || s[j-1] == '\r') {
		j--
	}
	return s[i:j]
}
