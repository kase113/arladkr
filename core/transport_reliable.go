package core

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

func isFallbackStartupTag(tag string) bool {
	tag = strings.TrimSpace(tag)
	return strings.HasPrefix(tag, "RBC_") || strings.HasPrefix(tag, "ABA_")
}

func isRecoverResponseTag(tag string) bool {
	return strings.TrimSpace(tag) == "RECOVER_AGGFRAG_RESPONSE"
}

func sendWithRetry(cfg Config, transport agreementTransport, msg Message) error {
	tries := cfg.SendRetryMax
	if tries <= 0 {
		tries = 1
	}
	backoff := cfg.SendRetryBackoff
	if backoff <= 0 {
		backoff = 10 * time.Millisecond
	}
	if isFallbackStartupTag(msg.Tag) {
		startupDeadline := time.Now().Add(cfg.WaitSPBCTimeout)
		minStartupTries := tries
		if backoff > 0 && cfg.WaitSPBCTimeout > 0 {
			minStartupTries += int(cfg.WaitSPBCTimeout/backoff) + 1
		}
		if minStartupTries > tries && time.Now().Before(startupDeadline) {
			tries = minStartupTries
		}
	}
	if isRecoverResponseTag(msg.Tag) && tries < recoverResponseRetryBudget(backoff) {
		tries = recoverResponseRetryBudget(backoff)
	}
	var lastErr error
	for attempt := 0; attempt < tries; attempt++ {
		if err := transport.Send(msg); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if attempt < tries-1 {
			time.Sleep(time.Duration(attempt+1) * backoff)
		}
	}
	return fmt.Errorf(
		"send failed after retries: from=%d to=%d tag=%s err=%w",
		msg.From,
		msg.To,
		msg.Tag,
		lastErr,
	)
}

func broadcastWithRetry(cfg Config, transport agreementTransport, from int, to []int, tag string, body []byte) error {
	return broadcastWithRetryLimit(cfg, transport, from, to, tag, body, 0)
}

func broadcastWithRetryLimit(cfg Config, transport agreementTransport, from int, to []int, tag string, body []byte, limit int) error {
	if limit <= 0 {
		limit = len(to)
	}
	if limit < 1 {
		limit = 1
	}
	var wg sync.WaitGroup
	errCh := make(chan error, len(to))
	sem := make(chan struct{}, limit)
	for _, id := range to {
		if id == from {
			continue
		}
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := sendWithRetry(cfg, transport, Message{
				From: from,
				To:   id,
				Tag:  tag,
				Body: append([]byte(nil), body...),
			}); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func recoverResponseRetryBudget(backoff time.Duration) int {
	if backoff <= 0 {
		return 30
	}
	tries := 1
	var total time.Duration
	for tries < 30 && total < 45*time.Second {
		total += time.Duration(tries) * backoff
		tries++
	}
	if tries < 30 {
		return 30
	}
	return tries
}
