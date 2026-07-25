package core

import (
	"encoding/hex"
	"sort"
	"time"
)

type readyCandidate struct {
	dealer int
	digest string
}

func canonicalReadyCandidates(
	cfg Config,
	descriptors map[int]Descriptor,
	artifacts map[int]*DealerArtifact,
) []readyCandidate {
	ready := make([]readyCandidate, 0, len(descriptors))
	for dealer, desc := range descriptors {
		art, ok := artifacts[dealer]
		if !ok || art == nil {
			continue
		}
		if ValidateDescriptor(cfg, desc) && OptrandShareVerify(cfg, art) == nil {
			ready = append(ready, readyCandidate{
				dealer: dealer,
				digest: hex.EncodeToString(desc.Digest),
			})
		}
	}
	sort.Slice(ready, func(i, j int) bool {
		if ready[i].digest == ready[j].digest {
			return ready[i].dealer < ready[j].dealer
		}
		return ready[i].digest < ready[j].digest
	})
	return ready
}

func recvMessageWithTimeout(ch <-chan Message, timeout time.Duration) (Message, bool) {
	if timeout <= 0 {
		timeout = 50 * time.Millisecond
	}
	select {
	case msg := <-ch:
		return msg, true
	case <-time.After(timeout):
		return Message{}, false
	}
}

func sameIntSet(a, b []int) bool {
	sa := sortedUnique(a)
	sb := sortedUnique(b)
	if len(sa) != len(sb) {
		return false
	}
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}
