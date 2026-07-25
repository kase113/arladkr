package core

import (
	"net"
	"os"
	"testing"
	"time"
)

func TestNormalizeConfig_FiltersAndSortsLocalNodeIDs(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:          "local-node-normalize",
		Epoch:        1,
		OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: []int{0, 1, 2, 3},
		FOld:         1,
		FNew:         1,
		LocalNodeIDs: []int{3, 99, 1, 3},
	})
	if got, want := toKey(cfg.LocalNodeIDs), "1,3"; got != want {
		t.Fatalf("unexpected normalized local node ids: got=%s want=%s", got, want)
	}
}

func TestNewTCPLoopbackTransportWithOptions_RegistersOnlyLocalNodes(t *testing.T) {
	transport, err := NewTCPLoopbackTransportWithOptions(Config{}, []int{0, 1, 2, 3}, []int{1, 3}, 8, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("NewTCPLoopbackTransportWithOptions failed: %v", err)
	}
	defer transport.Close()
	if _, err := transport.RecvChan(1); err != nil {
		t.Fatalf("expected local node 1 to be registered: %v", err)
	}
	if _, err := transport.RecvChan(3); err != nil {
		t.Fatalf("expected local node 3 to be registered: %v", err)
	}
	if _, err := transport.RecvChan(0); err == nil {
		t.Fatalf("expected non-local node 0 to be absent")
	}
}

func TestParseLocalNodeIDsEnv(t *testing.T) {
	prev := os.Getenv("RLADKR_LOCAL_NODE_IDS")
	defer os.Setenv("RLADKR_LOCAL_NODE_IDS", prev)
	if err := os.Setenv("RLADKR_LOCAL_NODE_IDS", "3,1,3,9"); err != nil {
		t.Fatalf("Setenv failed: %v", err)
	}
	got := parseLocalNodeIDsEnv([]int{0, 1, 2, 3})
	if want := "1,3"; toKey(got) != want {
		t.Fatalf("unexpected parsed local ids: got=%s want=%s", toKey(got), want)
	}
}

func TestWaitForRemoteNodeReadiness_SucceedsOnceRemoteListenerAppears(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	done := make(chan struct{})
	go func() {
		time.Sleep(40 * time.Millisecond)
		lateLn, lateErr := net.Listen("tcp", addr)
		if lateErr != nil {
			close(done)
			return
		}
		defer lateLn.Close()
		go func() {
			for {
				conn, acceptErr := lateLn.Accept()
				if acceptErr != nil {
					return
				}
				_ = conn.Close()
			}
		}()
		<-done
	}()

	cfg := NormalizeConfig(Config{
		SID:              "remote-ready",
		Epoch:            1,
		OldCommittee:     []int{0, 1},
		NewCommittee:     []int{0, 1},
		FOld:             0,
		FNew:             0,
		LocalNodeIDs:     []int{0},
		SendRetryMax:     2,
		SendRetryBackoff: 5 * time.Millisecond,
	})
	transport, err := NewTCPLoopbackTransportWithOptions(cfg, []int{0, 1}, []int{0}, 8, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("NewTCPLoopbackTransportWithOptions failed: %v", err)
	}
	defer func() {
		close(done)
		_ = transport.Close()
	}()
	impl, ok := transport.(*tcpLoopbackTransport)
	if !ok {
		t.Fatalf("unexpected transport type: %T", transport)
	}
	impl.mu.Lock()
	impl.addrByID[1] = addr
	impl.mu.Unlock()
	if err := waitForRemoteNodeReadiness(cfg, impl, []int{0, 1}); err != nil {
		t.Fatalf("waitForRemoteNodeReadiness failed: %v", err)
	}
}
