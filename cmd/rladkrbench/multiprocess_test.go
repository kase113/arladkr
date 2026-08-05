package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rladkr_go/core"
)

func TestBenchMultiProcessSingleMVBA(t *testing.T) {
	results := runBenchProcesses(t)
	if len(results) != 2 {
		t.Fatalf("expected 2 bench results, got=%d", len(results))
	}
	for _, line := range results {
		for _, token := range []string{
			"success_runs=1",
			"local_node_count=1",
			"required_completed_nodes=1",
			"agreement_path=single-mvba",
		} {
			if !strings.Contains(line, token) {
				t.Fatalf("legacy-off bench output missing token %q: %s", token, line)
			}
		}
	}
}

func TestBenchMultiProcessFourNodePrivateStyleSubsets(t *testing.T) {
	results := runBenchProcessesDetailedWithTopology(t, benchProcessTopology{
		n:       4,
		f:       1,
		kappa:   2,
		timeout: 20 * time.Second,
		localNodeSets: [][]int{
			{0},
			{1},
			{2},
			{3},
		},
	})
	if len(results) != 4 {
		t.Fatalf("expected 4 bench responses, got=%d", len(results))
	}
	for _, res := range results {
		line := extractBenchLine(t, res.stdout)
		if strings.TrimSpace(res.stderr) != "" {
			t.Logf("four-node force stderr:\n%s", res.stderr)
		}
		for _, token := range []string{
			"success_runs=1",
			"local_node_count=1",
			"required_completed_nodes=1",
			"agreement_path=single-mvba",
		} {
			if !strings.Contains(line, token) {
				t.Fatalf("four-node force bench output missing token %q: %s", token, line)
			}
		}
	}
}

func runBenchProcesses(t *testing.T) []string {
	t.Helper()
	return runBenchLines(runBenchProcessesDetailedWithTopology(t, benchProcessTopology{
		n:       2,
		f:       0,
		kappa:   1,
		timeout: 20 * time.Second,
		localNodeSets: [][]int{
			{0},
			{1},
		},
	}))
}

type benchProcessTopology struct {
	n             int
	f             int
	kappa         int
	timeout       time.Duration
	localNodeSets [][]int
}

func runBenchProcessesWithTopology(t *testing.T, topo benchProcessTopology) []string {
	t.Helper()
	return runBenchLines(runBenchProcessesDetailedWithTopology(t, topo))
}

func runBenchProcessesDetailedWithTopology(t *testing.T, topo benchProcessTopology) []benchProcResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	workdir := filepath.Dir(filepath.Dir(mustGetwd(t)))
	basePort := uniqueBasePort(t)
	addrParts := make([]string, 0, topo.n)
	mvbaAddrParts := make([]string, 0, topo.n)
	for i := 0; i < topo.n; i++ {
		addrParts = append(addrParts, fmt.Sprintf("%d=127.0.0.1:%d", i, basePort+i))
		mvbaAddrParts = append(mvbaAddrParts, fmt.Sprintf("%d=127.0.0.1:%d", i, basePort+500+i))
	}
	addrMap := strings.Join(addrParts, ",")
	mvbaAddrMap := strings.Join(mvbaAddrParts, ",")
	keyRoot := t.TempDir()
	publicKeyDir := filepath.Join(keyRoot, "public")
	secretKeyDir := filepath.Join(keyRoot, "secrets")
	oldMembers := make([]int, topo.n)
	receiverIDs := make([]int, topo.n)
	for i := 0; i < topo.n; i++ {
		oldMembers[i] = i
		receiverIDs[i] = topo.n + i
	}
	if err := core.GenerateCVReceiverKeyMaterial(
		publicKeyDir, secretKeyDir, "rladkr-go-bench", receiverIDs,
	); err != nil {
		t.Fatalf("generate multiprocess receiver keys: %v", err)
	}
	if err := core.GenerateCVOldLockKeyMaterial(
		publicKeyDir, secretKeyDir, "rladkr-go-bench", oldMembers, topo.n-topo.f,
	); err != nil {
		t.Fatalf("generate multiprocess old-lock keys: %v", err)
	}
	if err := core.GenerateCVMVBACoinKeyMaterial(
		publicKeyDir, secretKeyDir, "rladkr-go-bench", oldMembers, topo.f+1,
	); err != nil {
		t.Fatalf("generate multiprocess MVBA coin keys: %v", err)
	}
	args := []string{
		"run", "./cmd/rladkrbench",
		"-n", fmt.Sprintf("%d", topo.n),
		"-f", fmt.Sprintf("%d", topo.f),
		"-kappa", fmt.Sprintf("%d", topo.kappa),
		"-runs", "1",
		"-epochs", "1",
		"-transport", "tcp-distributed",
		"-bind-host", "127.0.0.1",
		"-base-port", fmt.Sprintf("%d", basePort),
		"-timeout", topo.timeout.String(),
	}
	results := make([]benchProcResult, len(topo.localNodeSets))
	chans := make([]chan benchProcResult, len(topo.localNodeSets))
	for idx, localSet := range topo.localNodeSets {
		cmd := exec.CommandContext(ctx, "go", args...)
		cmd.Dir = workdir
		localReceivers := make([]int, len(localSet))
		for i, nodeID := range localSet {
			localReceivers[i] = topo.n + nodeID
		}
		cmd.Env = append(os.Environ(),
			"RLADKR_LOCAL_NODE_IDS="+joinIDs(localSet),
			"RLADKR_LOCAL_RECEIVER_IDS="+joinIDs(localReceivers),
			"RLADKR_NODE_ADDRS="+addrMap,
			"RLADKR_MVBA_NODE_ADDRS="+mvbaAddrMap,
			"RLADKR_DIAL_HOST=127.0.0.1",
			"RLADKR_CV_PUBLIC_KEY_DIR="+publicKeyDir,
			"RLADKR_CV_LOCAL_SECRET_DIR="+secretKeyDir,
			"RLADKR_ARTIFACT_CACHE_DIR="+filepath.Join(keyRoot, fmt.Sprintf("node-%d", idx)),
		)
		chans[idx] = make(chan benchProcResult, 1)
		go func(i int, c *exec.Cmd) { chans[i] <- runBenchCommand(c) }(idx, cmd)
	}
	for idx := range chans {
		results[idx] = <-chans[idx]
	}
	for idx, res := range results {
		if res.err != nil {
			t.Fatalf("bench process %d failed: %v\nstdout:\n%s\nstderr:\n%s", idx, res.err, res.stdout, res.stderr)
		}
	}
	return results
}

type benchProcResult struct {
	stdout string
	stderr string
	err    error
}

func runBenchCommand(cmd *exec.Cmd) benchProcResult {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return benchProcResult{
		stdout: stdout.String(),
		stderr: stderr.String(),
		err:    err,
	}
}

func runBenchLines(results []benchProcResult) []string {
	lines := make([]string, 0, len(results))
	for _, res := range results {
		lines = append(lines, extractBenchLine(nil, res.stdout))
	}
	return lines
}

func extractBenchLine(t *testing.T, stdout string) string {
	if t != nil {
		t.Helper()
	}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "E2E_BENCH_RESULT ") {
			return line
		}
	}
	if t != nil {
		t.Fatalf("missing bench result line in stdout: %s", stdout)
	}
	return ""
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	return wd
}

func uniqueBasePort(t *testing.T) int {
	t.Helper()
	return 43000 + (int(time.Now().UnixNano()/1e6) % 1000)
}

func joinIDs(ids []int) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("%d", id))
	}
	return strings.Join(parts, ",")
}
