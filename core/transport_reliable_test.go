package core

import (
	"fmt"
	"testing"
	"time"
)

type flakyTransport struct {
	failures int
	sent     int
}

func (f *flakyTransport) RecvChan(id int) (<-chan Message, error) {
	ch := make(chan Message)
	return ch, nil
}

func (f *flakyTransport) Send(msg Message) error {
	f.sent++
	if f.sent <= f.failures {
		return fmt.Errorf("synthetic send failure")
	}
	return nil
}

func (f *flakyTransport) Broadcast(from int, to []int, tag string, body []byte) {}

func (f *flakyTransport) Close() error { return nil }

func TestSendWithRetry_RetriesAndSucceeds(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:          "retry-test",
		Epoch:        1,
		OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: []int{0, 1, 2, 3},
		F:            1,
		SendRetryMax: 3,
	})
	cfg.SendRetryBackoff = 1 * time.Millisecond
	ft := &flakyTransport{failures: 2}
	err := sendWithRetry(cfg, ft, Message{From: 0, To: 1, Tag: "X"})
	if err != nil {
		t.Fatalf("sendWithRetry should succeed after retries: %v", err)
	}
	if ft.sent != 3 {
		t.Fatalf("unexpected send attempts: %d", ft.sent)
	}
}

func TestSendWithRetry_FailsAfterMaxRetries(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:          "retry-test-fail",
		Epoch:        1,
		OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: []int{0, 1, 2, 3},
		F:            1,
		SendRetryMax: 2,
	})
	cfg.SendRetryBackoff = 1 * time.Millisecond
	ft := &flakyTransport{failures: 5}
	err := sendWithRetry(cfg, ft, Message{From: 0, To: 1, Tag: "X"})
	if err == nil {
		t.Fatalf("expected sendWithRetry failure")
	}
	if ft.sent != 2 {
		t.Fatalf("unexpected send attempts: %d", ft.sent)
	}
}

func TestSendWithRetry_RBCINITGetsExtendedStartupGrace(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:             "retry-rbc-init",
		Epoch:           1,
		OldCommittee:    []int{0, 1, 2, 3},
		NewCommittee:    []int{0, 1, 2, 3},
		F:               1,
		SendRetryMax:    2,
		WaitSPBCTimeout: 40 * time.Millisecond,
	})
	cfg.SendRetryBackoff = 5 * time.Millisecond
	ft := &flakyTransport{failures: 4}
	err := sendWithRetry(cfg, ft, Message{From: 0, To: 1, Tag: "RBC_INIT"})
	if err != nil {
		t.Fatalf("sendWithRetry should keep retrying RBC_INIT during startup grace: %v", err)
	}
	if ft.sent <= cfg.SendRetryMax {
		t.Fatalf("expected RBC_INIT to exceed normal retry max, got attempts=%d", ft.sent)
	}
}

func TestSendWithRetry_FallbackABAMessagesGetExtendedStartupGrace(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:             "retry-aba-aux",
		Epoch:           1,
		OldCommittee:    []int{0, 1, 2, 3},
		NewCommittee:    []int{0, 1, 2, 3},
		F:               1,
		SendRetryMax:    2,
		WaitSPBCTimeout: 40 * time.Millisecond,
	})
	cfg.SendRetryBackoff = 5 * time.Millisecond
	ft := &flakyTransport{failures: 4}
	err := sendWithRetry(cfg, ft, Message{From: 0, To: 1, Tag: "ABA_AUX"})
	if err != nil {
		t.Fatalf("sendWithRetry should keep retrying ABA_AUX during startup grace: %v", err)
	}
	if ft.sent <= cfg.SendRetryMax {
		t.Fatalf("expected ABA_AUX to exceed normal retry max, got attempts=%d", ft.sent)
	}
}

func TestSendWithRetry_RecoverMessagesGetExtendedGrace(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:          "retry-recover-response",
		Epoch:        1,
		OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: []int{0, 1, 2, 3},
		F:            1,
		SendRetryMax: 2,
	})
	cfg.SendRetryBackoff = 1 * time.Millisecond
	ft := &flakyTransport{failures: 15}
	err := sendWithRetry(cfg, ft, Message{From: 0, To: 1, Tag: "RECOVER_AGGFRAG_RESPONSE"})
	if err != nil {
		t.Fatalf("sendWithRetry should keep retrying recover responses: %v", err)
	}
	if ft.sent <= cfg.SendRetryMax {
		t.Fatalf("expected recover response to exceed normal retry max, got attempts=%d", ft.sent)
	}
}
