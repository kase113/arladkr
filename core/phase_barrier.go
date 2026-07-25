package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func phaseBarrierMarkerPath(dir string, phase string, nodeID int) string {
	return filepath.Join(dir, fmt.Sprintf("%s-node-%04d.ready", phase, nodeID))
}

func writePhaseBarrierMarker(dir string, phase string, nodeID int) error {
	if strings.TrimSpace(dir) == "" || strings.TrimSpace(phase) == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(phaseBarrierMarkerPath(dir, phase, nodeID), []byte("ready\n"), 0o644)
}

func waitForPhaseBarrier(dir string, phase string, nodeCount int, timeout time.Duration) error {
	if strings.TrimSpace(dir) == "" || strings.TrimSpace(phase) == "" || nodeCount <= 0 {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for {
		ready := 0
		for id := 0; id < nodeCount; id++ {
			if _, err := os.Stat(phaseBarrierMarkerPath(dir, phase, id)); err == nil {
				ready++
			}
		}
		if ready >= nodeCount {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("phase barrier timeout: phase=%s ready=%d/%d dir=%s", phase, ready, nodeCount, dir)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func recoverBarrierConfig() (dir string, nodeCount int, timeout time.Duration) {
	dir = strings.TrimSpace(os.Getenv("RLADKR_RECOVER_BARRIER_DIR"))
	nodeCount, _ = strconvAtoiSafe(strings.TrimSpace(os.Getenv("RLADKR_RECOVER_BARRIER_NODE_COUNT")))
	timeout = durationEnvMs("RLADKR_RECOVER_BARRIER_TIMEOUT_MS", 180000*time.Millisecond)
	return dir, nodeCount, timeout
}

func waitForRecoverBarrier(localNodeIDs []int) error {
	dir, nodeCount, timeout := recoverBarrierConfig()
	if strings.TrimSpace(dir) == "" || nodeCount <= 0 {
		return nil
	}
	for _, nodeID := range sortedUnique(localNodeIDs) {
		if err := writePhaseBarrierMarker(dir, "recover", nodeID); err != nil {
			return err
		}
	}
	return waitForPhaseBarrier(dir, "recover", nodeCount, timeout)
}

func strconvAtoiSafe(raw string) (int, error) {
	if raw == "" {
		return 0, fmt.Errorf("empty")
	}
	n := 0
	for _, ch := range raw {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("invalid")
		}
		n = n*10 + int(ch-'0')
	}
	return n, nil
}
