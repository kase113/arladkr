package core

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type arlDelayConfig struct {
	enabled              bool
	nodeCount            int
	matrix               [][]int
	bandwidthBytesPerSec float64
	bandwidthScope       string
	bandwidthStateFile   string
	bandwidthSocket      string
}

var (
	arlDelayOnce sync.Once
	arlDelayCfg  arlDelayConfig
	arlBandwidth arlBandwidthLimiter
	arlBwSocket  arlBandwidthSocketClient
)

func loadArlDelayConfigFromEnv() arlDelayConfig {
	cfg := arlDelayConfig{
		bandwidthBytesPerSec: arlBandwidthBytesPerSecondFromEnv(),
	}
	if cfg.bandwidthBytesPerSec > 0 {
		cfg.bandwidthScope = arlBandwidthScopeFromEnv("RLADKR_BANDWIDTH_SCOPE")
		cfg.bandwidthStateFile = strings.TrimSpace(os.Getenv("RLADKR_BANDWIDTH_STATE_FILE"))
		cfg.bandwidthSocket = strings.TrimSpace(os.Getenv("RLADKR_BANDWIDTH_SOCKET"))
	}
	if strings.TrimSpace(os.Getenv("RLADKR_DELAY_ENABLE")) != "1" {
		return cfg
	}
	path := strings.TrimSpace(os.Getenv("RLADKR_DELAY_MATRIX_FILE"))
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
	if env := strings.TrimSpace(os.Getenv("RLADKR_DELAY_NODE_COUNT")); env != "" {
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

func arlBandwidthBytesPerSecondFromEnv() float64 {
	raw := strings.TrimSpace(os.Getenv("RLADKR_BANDWIDTH_MBPS"))
	if raw == "" {
		return 0
	}
	mbps, err := strconv.ParseFloat(raw, 64)
	if err != nil || mbps <= 0 {
		return 0
	}
	return mbps * 1000 * 1000 / 8
}

func arlBandwidthScopeFromEnv(name string) string {
	switch strings.TrimSpace(os.Getenv(name)) {
	case "", "shared":
		return "shared"
	case "per-node-egress":
		return "per-node-egress"
	default:
		return "shared"
	}
}

func arlDelayConfigValue() arlDelayConfig {
	arlDelayOnce.Do(func() {
		arlDelayCfg = loadArlDelayConfigFromEnv()
	})
	return arlDelayCfg
}

func arlDelaySlot(id, nodeCount int) int {
	if nodeCount <= 0 {
		return id
	}
	if id < 0 {
		return id
	}
	return id % nodeCount
}

func arlDelayDuration(fromID, toID int) time.Duration {
	cfg := arlDelayConfigValue()
	if !cfg.enabled || cfg.nodeCount <= 0 {
		return 0
	}
	src := arlDelaySlot(fromID, cfg.nodeCount)
	dst := arlDelaySlot(toID, cfg.nodeCount)
	if src < 0 || dst < 0 || src >= len(cfg.matrix) || dst >= len(cfg.matrix[src]) {
		return 0
	}
	delayMs := cfg.matrix[src][dst]
	if delayMs <= 0 {
		return 0
	}
	return time.Duration(delayMs) * time.Millisecond
}

func arlDelayBeforeSend(fromID, toID int) {
	if delay := arlDelayDuration(fromID, toID); delay > 0 {
		time.Sleep(delay)
	}
}

type arlDelayedWriteConn struct {
	net.Conn
	delay time.Duration
}

func (c *arlDelayedWriteConn) Write(p []byte) (int, error) {
	if c.delay > 0 {
		time.Sleep(c.delay)
	}
	arlThrottleBandwidth(len(p))
	return c.Conn.Write(p)
}

type arlBandwidthLimiter struct {
	mu   sync.Mutex
	next time.Time
}

func arlThrottleBandwidth(n int) {
	if n <= 0 {
		return
	}
	cfg := arlDelayConfigValue()
	bytesPerSec := cfg.bandwidthBytesPerSec
	if bytesPerSec <= 0 {
		return
	}
	if cfg.bandwidthScope == "shared" {
		if cfg.bandwidthSocket != "" && arlThrottleSocketBandwidth(n, cfg.bandwidthSocket) {
			return
		}
		if cfg.bandwidthStateFile != "" {
			arlThrottleSharedBandwidth(n, bytesPerSec, cfg.bandwidthStateFile)
			return
		}
	}
	arlThrottleLocalBandwidth(n, bytesPerSec)
}

func arlThrottleLocalBandwidth(n int, bytesPerSec float64) {
	duration := time.Duration(float64(time.Second) * float64(n) / bytesPerSec)
	if duration <= 0 {
		return
	}
	arlBandwidth.mu.Lock()
	now := time.Now()
	start := now
	if arlBandwidth.next.After(now) {
		start = arlBandwidth.next
	}
	readyAt := start.Add(duration)
	arlBandwidth.next = readyAt
	wait := readyAt.Sub(now)
	arlBandwidth.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

type arlBandwidthSocketClient struct {
	mu         sync.Mutex
	conn       net.Conn
	reader     *bufio.Reader
	socketPath string
}

func arlThrottleSocketBandwidth(n int, socketPath string) bool {
	wait, ok := arlBwSocket.reserve(n, socketPath)
	if !ok {
		return false
	}
	if wait > 0 {
		time.Sleep(wait)
	}
	return true
}

func (c *arlBandwidthSocketClient) reserve(n int, socketPath string) (time.Duration, bool) {
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
		waitNs, err := strconv.ParseInt(strings.TrimSpace(line), 10, 64)
		if err != nil || waitNs < 0 {
			return 0, false
		}
		return time.Duration(waitNs), true
	}
	return 0, false
}

func (c *arlBandwidthSocketClient) closeLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn = nil
	c.reader = nil
	c.socketPath = ""
}

func arlThrottleSharedBandwidth(n int, bytesPerSec float64, stateFile string) {
	duration := time.Duration(float64(time.Second) * float64(n) / bytesPerSec)
	if duration <= 0 {
		return
	}
	file, err := os.OpenFile(stateFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		arlThrottleLocalBandwidth(n, bytesPerSec)
		return
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		arlThrottleLocalBandwidth(n, bytesPerSec)
		return
	}
	now := time.Now()
	start := now
	if _, err := file.Seek(0, 0); err == nil {
		if raw, err := io.ReadAll(file); err == nil {
			if nextUnixNano, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil && nextUnixNano > 0 {
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

func arlDialWithOptionalDelay(fromID, toID int, network, addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, err
	}
	delay := arlDelayDuration(fromID, toID)
	if delay <= 0 && arlDelayConfigValue().bandwidthBytesPerSec <= 0 {
		return conn, nil
	}
	return &arlDelayedWriteConn{Conn: conn, delay: delay}, nil
}

// arlDialBandwidthOnly dials a connection that models bandwidth throttling but
// NOT propagation delay. It is used by the MVBA transport's pipeline-delay mode:
// the one-way propagation delay is applied by the caller with arlDelayBeforeSend
// BEFORE acquiring the per-peer connection lock, so concurrent sends no longer
// serialize behind each other's sleep (see mvba_tcp.go).
func arlDialBandwidthOnly(network, addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, err
	}
	if arlDelayConfigValue().bandwidthBytesPerSec <= 0 {
		return conn, nil
	}
	return &arlDelayedWriteConn{Conn: conn, delay: 0}, nil
}

// arlMVBALegacyDelay reports whether the MVBA transport should use the legacy
// delay model (time.Sleep inside Write, executed while holding the pooled
// connection lock). Default is the pipeline model; set RLADKR_MVBA_LEGACY_DELAY=1
// to restore the legacy behavior for A/B comparison.
func arlMVBALegacyDelay() bool {
	return strings.TrimSpace(os.Getenv("RLADKR_MVBA_LEGACY_DELAY")) == "1"
}

// arlMVBADial dials for the MVBA transport, honoring the delay model in effect.
// Legacy mode embeds the propagation delay in Write; pipeline mode dials a
// bandwidth-only connection (delay is applied out-of-lock by the caller).
func arlMVBADial(fromID, toID int, network, addr string, timeout time.Duration) (net.Conn, error) {
	if arlMVBALegacyDelay() {
		return arlDialWithOptionalDelay(fromID, toID, network, addr, timeout)
	}
	return arlDialBandwidthOnly(network, addr, timeout)
}
