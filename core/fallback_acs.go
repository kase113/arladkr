package core

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func fallbackShutdownGrace(cfg Config) time.Duration {
	if len(localOldNodes(cfg)) >= len(cfg.OldCommittee) {
		return 0
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.AgreementTransport))
	if mode != "tcp-distributed" && mode != "tcp" && mode != "tcp-loopback" {
		return 0
	}
	if cfg.WaitSPBCTimeout <= 0 || !cfg.ForceFallback {
		return 0
	}
	return 12 * cfg.WaitSPBCTimeout
}

type rbcInitMsg struct {
	Sender int    `json:"sender"`
	Blob   string `json:"blob"`
}

type rbcEchoMsg struct {
	Sender int    `json:"sender"`
	Node   int    `json:"node"`
	Digest string `json:"digest"`
	Blob   string `json:"blob"`
}

type rbcReadyMsg struct {
	Sender int    `json:"sender"`
	Node   int    `json:"node"`
	Digest string `json:"digest"`
	Blob   string `json:"blob"`
}

type abaEstMsg struct {
	Dealer int `json:"dealer"`
	Round  int `json:"round"`
	Node   int `json:"node"`
	Bit    int `json:"bit"`
}

type abaAuxMsg struct {
	Dealer int `json:"dealer"`
	Round  int `json:"round"`
	Node   int `json:"node"`
	Bit    int `json:"bit"`
}

type abaConfMsg struct {
	Dealer int   `json:"dealer"`
	Round  int   `json:"round"`
	Node   int   `json:"node"`
	Bits   []int `json:"bits"`
}

type abaCoinShareMsg struct {
	Dealer int    `json:"dealer"`
	Round  int    `json:"round"`
	Node   int    `json:"node"`
	Sig    string `json:"sig"`
}

type rbcState struct {
	sentEcho    bool
	sentReady   bool
	delivered   bool
	echoCounts  map[string]map[int]struct{}
	readyCounts map[string]map[int]struct{}
	blobByDig   map[string][]byte
	deliverBlob []byte
}

var fallbackACSTransportFactory = newAgreementTransport

func runFallbackACSMVBA(
	ctx context.Context,
	cfg Config,
	descriptors map[int]Descriptor,
	artifacts map[int]*DealerArtifact,
) ([]int, []NodeOutput, error) {
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, nil, err
	}
	if c.runtime == nil {
		return nil, nil, fmt.Errorf("runtime not initialized")
	}
	start := time.Now()
	localNodes := localOldNodes(c)
	required := c.F + 1
	if required <= 0 {
		required = 1
	}
	targetSize := c.Kappa
	if targetSize < required {
		targetSize = required
	}
	if targetSize > len(c.runtime.oldOrder) {
		targetSize = len(c.runtime.oldOrder)
	}
	transport, err := fallbackACSTransportFactory(c, c.runtime.oldOrder, len(c.runtime.oldOrder)*128)
	if err != nil {
		return nil, nil, err
	}
	defer transport.Close()
	// Each node proposes digest(AggRLO) over locally ready dealers.
	proposals := make(map[int]descriptorProposal, len(c.runtime.oldOrder))
	seed := fallbackSeedDealers(c, descriptors, artifacts)
	for _, nodeID := range c.runtime.oldOrder {
		p := append([]int(nil), seed...)
		blob, err := BuildFallbackAggRLOProposal(c, p, artifacts)
		if err != nil {
			return nil, nil, err
		}
		proposals[nodeID] = descriptorProposal{
			Set:    p,
			Blob:   blob,
			Digest: rbcDigest(c.SID, nodeID, blob),
		}
	}

	delivered, err := runRBCAllWithTransport(ctx, c, transport, descriptors, artifacts, proposals, targetSize)
	if err != nil {
		return nil, nil, err
	}

	decisions := make(map[int]map[int]int, len(c.runtime.oldOrder))
	for _, node := range c.runtime.oldOrder {
		decisions[node] = make(map[int]int, len(c.runtime.oldOrder))
	}
	for _, dealer := range c.runtime.oldOrder {
		inputBits := make(map[int]int, len(c.runtime.oldOrder))
		for _, node := range c.runtime.oldOrder {
			if blob := delivered[node][dealer]; len(blob) > 0 {
				inputBits[node] = 1
			} else {
				inputBits[node] = 0
			}
		}
		abaOut, abaErr := runBinaryABAForDealerWithTransport(ctx, c, transport, dealer, inputBits)
		if abaErr != nil {
			return nil, nil, abaErr
		}
		for _, node := range c.runtime.oldOrder {
			decisions[node][dealer] = abaOut[node]
		}
	}

	perNode := make([]NodeOutput, 0, len(localNodes))
	setCounts := make(map[string]int, len(localNodes))
	setByKey := make(map[string][]int, len(localNodes))
	for _, node := range localNodes {
		union := make(map[int]struct{})
		for _, dealer := range c.runtime.oldOrder {
			if decisions[node][dealer] != 1 {
				continue
			}
			blob := delivered[node][dealer]
			if len(blob) == 0 {
				continue
			}
			set, vErr := ValidateFallbackAggRLOProposal(blob, c, targetSize, artifacts)
			if vErr != nil {
				continue
			}
			for _, id := range set {
				union[id] = struct{}{}
			}
		}
		candidate := make([]int, 0, len(union))
		for id := range union {
			candidate = append(candidate, id)
		}
		candidate = normalizeCandidate(candidate, targetSize, c.runtime.oldOrder)
		if len(candidate) < required {
			candidate = normalizeCandidate(stableFirst(c.runtime.oldOrder, required), targetSize, c.runtime.oldOrder)
		}
		key := intSetKey(candidate)
		setCounts[key]++
		setByKey[key] = append([]int(nil), candidate...)
		perNode = append(perNode, NodeOutput{
			NodeID:     node,
			DecidedSet: append([]int(nil), candidate...),
			Latency:    time.Since(start),
		})
	}

	decided := pickMostFrequentSet(setCounts, setByKey, c.F, targetSize, c.runtime.oldOrder)
	if linger := fallbackShutdownGrace(c); linger > 0 {
		timer := time.NewTimer(linger)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
		}
	}
	return decided, perNode, nil
}

func runRBCAll(
	ctx context.Context,
	cfg Config,
	descriptors map[int]Descriptor,
	artifacts map[int]*DealerArtifact,
	proposals map[int]descriptorProposal,
	targetSize int,
) (map[int]map[int][]byte, error) {
	transport, err := fallbackACSTransportFactory(cfg, cfg.runtime.oldOrder, len(cfg.runtime.oldOrder)*64)
	if err != nil {
		return nil, err
	}
	defer transport.Close()
	return runRBCAllWithTransport(ctx, cfg, transport, descriptors, artifacts, proposals, targetSize)
}

func runRBCAllWithTransport(
	ctx context.Context,
	cfg Config,
	transport agreementTransport,
	descriptors map[int]Descriptor,
	artifacts map[int]*DealerArtifact,
	proposals map[int]descriptorProposal,
	targetSize int,
) (map[int]map[int][]byte, error) {
	localNodes := localOldNodes(cfg)
	localSet := nodeSet(localNodes)

	n := len(cfg.runtime.oldOrder)
	echoThreshold := n - cfg.F
	readyRelayThreshold := cfg.F + 1
	deliverThreshold := n - cfg.F
	if echoThreshold <= 0 {
		echoThreshold = 1
	}
	if readyRelayThreshold <= 0 {
		readyRelayThreshold = 1
	}
	if deliverThreshold <= 0 {
		deliverThreshold = 1
	}

	states := make(map[int]map[int]*rbcState, len(localNodes))
	for _, node := range localNodes {
		states[node] = make(map[int]*rbcState, n)
		for _, sender := range cfg.runtime.oldOrder {
			states[node][sender] = &rbcState{
				echoCounts:  make(map[string]map[int]struct{}),
				readyCounts: make(map[string]map[int]struct{}),
				blobByDig:   make(map[string][]byte),
			}
		}
	}

	for _, sender := range cfg.runtime.oldOrder {
		prop := proposals[sender]
		if _, isLocalSender := localSet[sender]; !isLocalSender {
			continue
		}
		dig := hex.EncodeToString(rbcDigest(cfg.SID, sender, prop.Blob))
		body, mErr := json.Marshal(rbcInitMsg{
			Sender: sender,
			Blob:   hex.EncodeToString(prop.Blob),
		})
		if mErr != nil {
			return nil, mErr
		}
		if err := broadcastWithRetry(cfg, transport, sender, cfg.runtime.oldOrder, "RBC_INIT", body); err != nil {
			return nil, err
		}
		// Sender processes its own INIT implicitly so local ECHO state is not starved.
		if stBySender, ok := states[sender]; ok {
			st := stBySender[sender]
			st.blobByDig[dig] = append([]byte(nil), prop.Blob...)
			if !st.sentEcho {
				st.sentEcho = true
				if _, ok := st.echoCounts[dig]; !ok {
					st.echoCounts[dig] = make(map[int]struct{})
				}
				st.echoCounts[dig][sender] = struct{}{}
				echoBody, eErr := json.Marshal(rbcEchoMsg{
					Sender: sender,
					Node:   sender,
					Digest: dig,
					Blob:   hex.EncodeToString(prop.Blob),
				})
				if eErr != nil {
					return nil, eErr
				}
				if err := broadcastWithRetry(cfg, transport, sender, cfg.runtime.oldOrder, "RBC_ECHO", echoBody); err != nil {
					return nil, err
				}
			}
		}
	}

	validatedDescriptor := make(map[string]bool, len(cfg.runtime.oldOrder)*2)
	validateByDigest := func(sender int, blob []byte) (string, bool) {
		dig := hex.EncodeToString(rbcDigest(cfg.SID, sender, blob))
		if ok, exists := validatedDescriptor[dig]; exists {
			return dig, ok
		}
		set, err := ValidateFallbackAggRLOProposal(blob, cfg, targetSize, artifacts)
		ok := err == nil && len(set) > 0
		validatedDescriptor[dig] = ok
		return dig, ok
	}
	handleRBCMsg := func(node int, msg Message) error {
		switch msg.Tag {
		case "RBC_INIT":
			var wire rbcInitMsg
			if err := json.Unmarshal(msg.Body, &wire); err != nil {
				return nil
			}
			if _, ok := states[node][wire.Sender]; !ok {
				return nil
			}
			blob, err := hex.DecodeString(wire.Blob)
			if err != nil {
				return nil
			}
			dig, ok := validateByDigest(wire.Sender, blob)
			if !ok {
				return nil
			}
			st := states[node][wire.Sender]
			st.blobByDig[dig] = append([]byte(nil), blob...)
			if st.sentEcho {
				return nil
			}
			st.sentEcho = true
			if _, ok := st.echoCounts[dig]; !ok {
				st.echoCounts[dig] = make(map[int]struct{})
			}
			st.echoCounts[dig][node] = struct{}{}
			echoBody, mErr := json.Marshal(rbcEchoMsg{
				Sender: wire.Sender,
				Node:   node,
				Digest: dig,
				Blob:   hex.EncodeToString(blob),
			})
			if mErr != nil {
				return nil
			}
			if err := broadcastWithRetry(cfg, transport, node, cfg.runtime.oldOrder, "RBC_ECHO", echoBody); err != nil {
				return err
			}
		case "RBC_ECHO":
			var wire rbcEchoMsg
			if err := json.Unmarshal(msg.Body, &wire); err != nil {
				return nil
			}
			st, ok := states[node][wire.Sender]
			if !ok {
				return nil
			}
			blob, err := hex.DecodeString(wire.Blob)
			if err != nil {
				return nil
			}
			dig, ok := validateByDigest(wire.Sender, blob)
			if !ok || wire.Digest != dig {
				return nil
			}
			if _, ok := st.echoCounts[wire.Digest]; !ok {
				st.echoCounts[wire.Digest] = make(map[int]struct{})
			}
			st.echoCounts[wire.Digest][wire.Node] = struct{}{}
			st.blobByDig[wire.Digest] = append([]byte(nil), blob...)
			readyCount := 0
			if c, ok := st.readyCounts[wire.Digest]; ok {
				readyCount = len(c)
			}
			if !st.sentReady && (len(st.echoCounts[wire.Digest]) >= echoThreshold || readyCount >= readyRelayThreshold) {
				st.sentReady = true
				if _, ok := st.readyCounts[wire.Digest]; !ok {
					st.readyCounts[wire.Digest] = make(map[int]struct{})
				}
				st.readyCounts[wire.Digest][node] = struct{}{}
				readyBody, mErr := json.Marshal(rbcReadyMsg{
					Sender: wire.Sender,
					Node:   node,
					Digest: wire.Digest,
					Blob:   hex.EncodeToString(blob),
				})
				if mErr != nil {
					return nil
				}
				if err := broadcastWithRetry(cfg, transport, node, cfg.runtime.oldOrder, "RBC_READY", readyBody); err != nil {
					return err
				}
			}
		case "RBC_READY":
			var wire rbcReadyMsg
			if err := json.Unmarshal(msg.Body, &wire); err != nil {
				return nil
			}
			st, ok := states[node][wire.Sender]
			if !ok {
				return nil
			}
			blob, err := hex.DecodeString(wire.Blob)
			if err != nil {
				return nil
			}
			dig, ok := validateByDigest(wire.Sender, blob)
			if !ok || wire.Digest != dig {
				return nil
			}
			if _, ok := st.readyCounts[wire.Digest]; !ok {
				st.readyCounts[wire.Digest] = make(map[int]struct{})
			}
			st.readyCounts[wire.Digest][wire.Node] = struct{}{}
			st.blobByDig[wire.Digest] = append([]byte(nil), blob...)
			if !st.sentReady && len(st.readyCounts[wire.Digest]) >= readyRelayThreshold {
				st.sentReady = true
				st.readyCounts[wire.Digest][node] = struct{}{}
				readyBody, mErr := json.Marshal(rbcReadyMsg{
					Sender: wire.Sender,
					Node:   node,
					Digest: wire.Digest,
					Blob:   hex.EncodeToString(blob),
				})
				if mErr != nil {
					return nil
				}
				if err := broadcastWithRetry(cfg, transport, node, cfg.runtime.oldOrder, "RBC_READY", readyBody); err != nil {
					return err
				}
			}
			if !st.delivered && len(st.readyCounts[wire.Digest]) >= deliverThreshold {
				st.delivered = true
				st.deliverBlob = append([]byte(nil), blob...)
			}
		}
		return nil
	}

	deadline := time.Now().Add(4 * cfg.WaitSPBCTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		progress := false
		for _, node := range localNodes {
			ch, chErr := transport.RecvChan(node)
			if chErr != nil {
				return nil, chErr
			}
			drained := 0
			for drained < 16 {
				var msg Message
				got := false
				select {
				case msg = <-ch:
					got = true
				default:
				}
				if !got {
					break
				}
				drained++
				progress = true
				if err := handleRBCMsg(node, msg); err != nil {
					return nil, err
				}
			}
			if drained == 0 {
				msg, ok := recvMessageWithTimeout(ch, time.Millisecond)
				if !ok {
					continue
				}
				progress = true
				if err := handleRBCMsg(node, msg); err != nil {
					return nil, err
				}
			}
		}
		if !progress {
			time.Sleep(2 * time.Millisecond)
		}
		allDelivered := true
		for _, node := range localNodes {
			for _, sender := range cfg.runtime.oldOrder {
				if !states[node][sender].delivered {
					allDelivered = false
					break
				}
			}
			if !allDelivered {
				break
			}
		}
		if allDelivered {
			break
		}
	}
	out := make(map[int]map[int][]byte, len(localNodes))
	for _, node := range localNodes {
		out[node] = make(map[int][]byte, len(cfg.runtime.oldOrder))
		for _, sender := range cfg.runtime.oldOrder {
			st := states[node][sender]
			out[node][sender] = append([]byte(nil), st.deliverBlob...)
		}
	}
	return out, nil
}

func runBinaryABAForDealer(
	ctx context.Context,
	cfg Config,
	dealer int,
	inputBits map[int]int,
) (map[int]int, error) {
	if cfg.runtime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}
	transport, err := fallbackACSTransportFactory(cfg, cfg.runtime.oldOrder, len(cfg.runtime.oldOrder)*96)
	if err != nil {
		return nil, err
	}
	defer transport.Close()
	return runBinaryABAForDealerWithTransport(ctx, cfg, transport, dealer, inputBits)
}

func runBinaryABAForDealerWithTransport(
	ctx context.Context,
	cfg Config,
	transport agreementTransport,
	dealer int,
	inputBits map[int]int,
) (map[int]int, error) {
	if cfg.runtime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}
	localNodes := localOldNodes(cfg)
	chans := make(map[int]<-chan Message, len(localNodes))
	for _, node := range localNodes {
		ch, chErr := transport.RecvChan(node)
		if chErr != nil {
			return nil, chErr
		}
		chans[node] = ch
	}

	n := len(cfg.runtime.oldOrder)
	threshold := n - cfg.F
	if threshold <= 0 {
		threshold = 1
	}
	pending := make(map[int][]Message, len(localNodes))
	popPending := func(node int, tag string) (Message, bool) {
		queue := pending[node]
		for i, msg := range queue {
			if msg.Tag != tag {
				continue
			}
			pending[node] = append(queue[:i], queue[i+1:]...)
			return msg, true
		}
		return Message{}, false
	}
	recvForTag := func(node int, tag string, wait time.Duration) (Message, bool) {
		if msg, ok := popPending(node, tag); ok {
			return msg, true
		}
		msg, ok := recvMessageWithTimeout(chans[node], wait)
		if !ok {
			return Message{}, false
		}
		if msg.Tag == tag {
			return msg, true
		}
		pending[node] = append(pending[node], msg)
		return Message{}, false
	}

	estimate := make(map[int]int, len(localNodes))
	decided := make(map[int]int, len(localNodes))
	for _, node := range localNodes {
		estimate[node] = clampBit(inputBits[node])
		decided[node] = -1
	}

	maxRounds := cfg.MVBARounds * 3
	if maxRounds < 3 {
		maxRounds = 3
	}
	for round := 0; round < maxRounds; round++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// EST phase.
		estVotes := make(map[int]map[int]map[int]struct{}, len(localNodes))
		for _, node := range localNodes {
			estVotes[node] = map[int]map[int]struct{}{
				0: make(map[int]struct{}),
				1: make(map[int]struct{}),
			}
			estBit := clampBit(estimate[node])
			estVotes[node][estBit][node] = struct{}{}
			body, mErr := json.Marshal(abaEstMsg{
				Dealer: dealer,
				Round:  round,
				Node:   node,
				Bit:    estBit,
			})
			if mErr != nil {
				return nil, mErr
			}
			if err := broadcastWithRetry(cfg, transport, node, cfg.runtime.oldOrder, "ABA_EST", body); err != nil {
				return nil, err
			}
		}

		estDeadline := time.Now().Add(cfg.WaitSPBCTimeout)
		for time.Now().Before(estDeadline) {
			if err := checkContext(ctx); err != nil {
				return nil, err
			}
			progress := false
			for _, node := range localNodes {
				msg, ok := recvForTag(node, "ABA_EST", 2*time.Millisecond)
				if !ok {
					continue
				}
				progress = true
				var wire abaEstMsg
				if err := json.Unmarshal(msg.Body, &wire); err != nil {
					continue
				}
				if wire.Dealer != dealer || wire.Round != round || wire.Node != msg.From {
					continue
				}
				bit := clampBit(wire.Bit)
				if _, ok := estVotes[node][bit]; !ok {
					estVotes[node][bit] = make(map[int]struct{})
				}
				estVotes[node][bit][wire.Node] = struct{}{}
			}
			allReady := true
			for _, node := range localNodes {
				totalSeen := len(estVotes[node][0]) + len(estVotes[node][1])
				if len(estVotes[node][0]) < threshold && len(estVotes[node][1]) < threshold && totalSeen < n {
					allReady = false
					break
				}
			}
			if allReady {
				break
			}
			if !progress {
				time.Sleep(time.Millisecond)
			}
		}

		estBin := make(map[int]abaBitSet, len(localNodes))
		auxInput := make(map[int]int, len(localNodes))
		for _, node := range localNodes {
			set := abaBitSet{
				zero: len(estVotes[node][0]) >= threshold,
				one:  len(estVotes[node][1]) >= threshold,
			}
			if !set.hasAny() {
				if cfg.DisableABAFallbackEstimate {
					return nil, fmt.Errorf("aba est round %d node %d missing threshold evidence", round, node)
				}
				fallback := chooseFallbackBit(len(estVotes[node][0]), len(estVotes[node][1]), estimate[node])
				set = bitSetFromSingle(fallback)
			}
			estBin[node] = set
			if v, ok := set.single(); ok {
				auxInput[node] = v
			} else {
				auxInput[node] = clampBit(estimate[node])
			}
		}

		// AUX phase.
		auxVotes := make(map[int]map[int]map[int]struct{}, len(localNodes))
		auxSeen := make(map[int]map[int]struct{}, len(localNodes))
		for _, node := range localNodes {
			auxVotes[node] = map[int]map[int]struct{}{
				0: make(map[int]struct{}),
				1: make(map[int]struct{}),
			}
			auxSeen[node] = make(map[int]struct{})
			auxBit := clampBit(auxInput[node])
			auxVotes[node][auxBit][node] = struct{}{}
			auxSeen[node][node] = struct{}{}

			body, mErr := json.Marshal(abaAuxMsg{
				Dealer: dealer,
				Round:  round,
				Node:   node,
				Bit:    auxBit,
			})
			if mErr != nil {
				return nil, mErr
			}
			if err := broadcastWithRetry(cfg, transport, node, cfg.runtime.oldOrder, "ABA_AUX", body); err != nil {
				return nil, err
			}
		}

		auxDeadline := time.Now().Add(cfg.WaitSPBCTimeout)
		for time.Now().Before(auxDeadline) {
			if err := checkContext(ctx); err != nil {
				return nil, err
			}
			progress := false
			for _, node := range localNodes {
				msg, ok := recvForTag(node, "ABA_AUX", 2*time.Millisecond)
				if !ok {
					continue
				}
				progress = true
				var wire abaAuxMsg
				if err := json.Unmarshal(msg.Body, &wire); err != nil {
					continue
				}
				if wire.Dealer != dealer || wire.Round != round || wire.Node != msg.From {
					continue
				}
				bit := clampBit(wire.Bit)
				auxVotes[node][bit][wire.Node] = struct{}{}
				auxSeen[node][wire.Node] = struct{}{}
			}
			allReady := true
			for _, node := range localNodes {
				if len(auxSeen[node]) < threshold && len(auxSeen[node]) < n {
					allReady = false
					break
				}
			}
			if allReady {
				break
			}
			if !progress {
				time.Sleep(time.Millisecond)
			}
		}

		auxSet := make(map[int]abaBitSet, len(localNodes))
		for _, node := range localNodes {
			set := abaBitSet{
				zero: len(auxVotes[node][0]) >= threshold,
				one:  len(auxVotes[node][1]) >= threshold,
			}
			if !set.hasAny() {
				set = abaBitSet{
					zero: len(auxVotes[node][0]) > 0,
					one:  len(auxVotes[node][1]) > 0,
				}
			}
			if !set.hasAny() {
				set = estBin[node]
			}
			if !set.hasAny() {
				set = bitSetFromSingle(auxInput[node])
			}
			auxSet[node] = set
		}

		// CONF phase.
		confVotes := make(map[int]map[int]map[int]struct{}, len(localNodes))
		confSeen := make(map[int]map[int]struct{}, len(localNodes))
		for _, node := range localNodes {
			confVotes[node] = map[int]map[int]struct{}{
				0: make(map[int]struct{}),
				1: make(map[int]struct{}),
			}
			confSeen[node] = make(map[int]struct{})
			bits := auxSet[node].toSlice()
			for _, b := range bits {
				confVotes[node][b][node] = struct{}{}
			}
			confSeen[node][node] = struct{}{}
			body, mErr := json.Marshal(abaConfMsg{
				Dealer: dealer,
				Round:  round,
				Node:   node,
				Bits:   bits,
			})
			if mErr != nil {
				return nil, mErr
			}
			if err := broadcastWithRetry(cfg, transport, node, cfg.runtime.oldOrder, "ABA_CONF", body); err != nil {
				return nil, err
			}
		}

		confDeadline := time.Now().Add(cfg.WaitSPBCTimeout)
		for time.Now().Before(confDeadline) {
			if err := checkContext(ctx); err != nil {
				return nil, err
			}
			progress := false
			for _, node := range localNodes {
				msg, ok := recvForTag(node, "ABA_CONF", 2*time.Millisecond)
				if !ok {
					continue
				}
				progress = true
				var wire abaConfMsg
				if err := json.Unmarshal(msg.Body, &wire); err != nil {
					continue
				}
				if wire.Dealer != dealer || wire.Round != round || wire.Node != msg.From {
					continue
				}
				set := bitSetFromSlice(wire.Bits)
				if !set.hasAny() {
					continue
				}
				if set.zero {
					confVotes[node][0][wire.Node] = struct{}{}
				}
				if set.one {
					confVotes[node][1][wire.Node] = struct{}{}
				}
				confSeen[node][wire.Node] = struct{}{}
			}
			allReady := true
			for _, node := range localNodes {
				if len(confSeen[node]) < threshold && len(confSeen[node]) < n {
					allReady = false
					break
				}
			}
			if allReady {
				break
			}
			if !progress {
				time.Sleep(time.Millisecond)
			}
		}

		confSet := make(map[int]abaBitSet, len(localNodes))
		for _, node := range localNodes {
			set := abaBitSet{
				zero: len(confVotes[node][0]) >= threshold,
				one:  len(confVotes[node][1]) >= threshold,
			}
			if !set.hasAny() {
				set = abaBitSet{
					zero: len(confVotes[node][0]) > 0,
					one:  len(confVotes[node][1]) > 0,
				}
			}
			if !set.hasAny() {
				set = auxSet[node]
			}
			confSet[node] = set
		}

		coinBits, cErr := deriveCommonCoinBit(ctx, cfg, transport, chans, pending, dealer, round)
		if cErr != nil {
			return nil, cErr
		}

		for _, node := range localNodes {
			coin := clampBit(coinBits[node])
			if v, ok := confSet[node].single(); ok {
				if decided[node] == -1 && coin == v {
					decided[node] = v
				}
				estimate[node] = v
			} else {
				estimate[node] = coin
			}
		}

		allDecided := true
		for _, node := range localNodes {
			if decided[node] == -1 {
				allDecided = false
				break
			}
		}
		if allDecided {
			return decided, nil
		}
	}

	for _, node := range localNodes {
		if decided[node] == -1 {
			decided[node] = clampBit(estimate[node])
		}
	}
	return decided, nil
}

func deriveCommonCoinBit(
	ctx context.Context,
	cfg Config,
	transport agreementTransport,
	chans map[int]<-chan Message,
	pending map[int][]Message,
	dealer int,
	round int,
) (map[int]int, error) {
	if cfg.runtime == nil || cfg.runtime.coinSigner == nil {
		return nil, fmt.Errorf("coin signer not initialized")
	}
	digest := hashBytes(
		[]byte("rladkr-aba-coin"),
		[]byte(cfg.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d|round=%d", cfg.Epoch, dealer, round)),
	)
	coinThreshold := cfg.runtime.coinSigner.Threshold()
	if coinThreshold <= 0 {
		coinThreshold = 1
	}

	localNodes := localOldNodes(cfg)
	sharesByNode := make(map[int]map[int][]byte, len(localNodes))
	coinBits := make(map[int]int, len(localNodes))
	recoveredCert := make(map[int][]byte, len(localNodes))
	popPending := func(node int, tag string) (Message, bool) {
		queue := pending[node]
		for i, msg := range queue {
			if msg.Tag != tag {
				continue
			}
			pending[node] = append(queue[:i], queue[i+1:]...)
			return msg, true
		}
		return Message{}, false
	}
	recvForTag := func(node int, tag string, wait time.Duration) (Message, bool) {
		if msg, ok := popPending(node, tag); ok {
			return msg, true
		}
		msg, ok := recvMessageWithTimeout(chans[node], wait)
		if !ok {
			return Message{}, false
		}
		if msg.Tag == tag {
			return msg, true
		}
		pending[node] = append(pending[node], msg)
		return Message{}, false
	}

	tryRecover := func(node int) error {
		if _, ok := recoveredCert[node]; ok {
			return nil
		}
		shares := sharesByNode[node]
		if len(shares) < coinThreshold {
			return nil
		}
		cert, err := cfg.runtime.coinSigner.Recover("ABA_COIN", digest, shares)
		if err != nil {
			return err
		}
		if !cfg.runtime.coinSigner.VerifyRecovered("ABA_COIN", digest, cert) {
			return fmt.Errorf("coin certificate verify failed")
		}
		recoveredCert[node] = cert
		coinBits[node] = int(hashBytes([]byte("rladkr-coin-bit"), cert)[0] & 1)
		return nil
	}

	for _, node := range localNodes {
		localShare, err := cfg.runtime.coinSigner.SignShare(node, "ABA_COIN", digest)
		if err != nil {
			return nil, err
		}
		sharesByNode[node] = map[int][]byte{
			node: append([]byte(nil), localShare...),
		}
		body, mErr := json.Marshal(abaCoinShareMsg{
			Dealer: dealer,
			Round:  round,
			Node:   node,
			Sig:    hex.EncodeToString(localShare),
		})
		if mErr != nil {
			return nil, mErr
		}
		if err := broadcastWithRetry(cfg, transport, node, cfg.runtime.oldOrder, "ABA_COIN_SHARE", body); err != nil {
			return nil, err
		}
		if err := tryRecover(node); err != nil {
			return nil, err
		}
	}

	coinDeadline := time.Now().Add(2 * cfg.WaitSPBCTimeout)
	for time.Now().Before(coinDeadline) {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		progress := false
		for _, node := range localNodes {
			msg, ok := recvForTag(node, "ABA_COIN_SHARE", 2*time.Millisecond)
			if !ok {
				continue
			}
			progress = true
			var wire abaCoinShareMsg
			if err := json.Unmarshal(msg.Body, &wire); err != nil {
				continue
			}
			if wire.Dealer != dealer || wire.Round != round || wire.Node != msg.From {
				continue
			}
			sig, err := hex.DecodeString(wire.Sig)
			if err != nil {
				continue
			}
			if !cfg.runtime.coinSigner.VerifyShare(wire.Node, "ABA_COIN", digest, sig) {
				continue
			}
			if _, ok := sharesByNode[node]; !ok {
				sharesByNode[node] = make(map[int][]byte)
			}
			if _, ok := sharesByNode[node][wire.Node]; ok {
				continue
			}
			sharesByNode[node][wire.Node] = append([]byte(nil), sig...)
			if err := tryRecover(node); err != nil {
				return nil, err
			}
		}
		if len(recoveredCert) == len(localNodes) {
			break
		}
		if !progress {
			time.Sleep(time.Millisecond)
		}
	}

	if len(recoveredCert) == 0 {
		return nil, fmt.Errorf("failed to recover common coin: no threshold share set collected")
	}
	if len(recoveredCert) < len(localNodes) && cfg.DisableCoinBitFallback {
		return nil, fmt.Errorf(
			"coin bits incomplete and fallback disabled: recovered=%d total=%d",
			len(recoveredCert),
			len(localNodes),
		)
	}
	fallbackBit := 0
	for _, node := range localNodes {
		if bit, ok := coinBits[node]; ok {
			fallbackBit = bit
			break
		}
	}
	for _, node := range localNodes {
		if _, ok := coinBits[node]; !ok {
			coinBits[node] = fallbackBit
		}
	}
	return coinBits, nil
}

type abaBitSet struct {
	zero bool
	one  bool
}

func (s abaBitSet) hasAny() bool {
	return s.zero || s.one
}

func (s abaBitSet) toSlice() []int {
	out := make([]int, 0, 2)
	if s.zero {
		out = append(out, 0)
	}
	if s.one {
		out = append(out, 1)
	}
	return out
}

func (s abaBitSet) single() (int, bool) {
	if s.zero == s.one {
		return 0, false
	}
	if s.one {
		return 1, true
	}
	return 0, true
}

func bitSetFromSingle(bit int) abaBitSet {
	if clampBit(bit) == 1 {
		return abaBitSet{one: true}
	}
	return abaBitSet{zero: true}
}

func bitSetFromSlice(bits []int) abaBitSet {
	out := abaBitSet{}
	for _, b := range bits {
		if b == 0 {
			out.zero = true
		}
		if b == 1 {
			out.one = true
		}
	}
	return out
}

func clampBit(bit int) int {
	if bit != 0 {
		return 1
	}
	return 0
}

func chooseFallbackBit(zeroVotes, oneVotes, local int) int {
	switch {
	case oneVotes > zeroVotes:
		return 1
	case zeroVotes > oneVotes:
		return 0
	default:
		return clampBit(local)
	}
}

func checkContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func rbcDigest(sid string, sender int, blob []byte) []byte {
	return hashBytes(
		[]byte("rladkr-rbc-digest"),
		[]byte(sid),
		[]byte(fmt.Sprintf("|sender=%d", sender)),
		blob,
	)
}

func intSetKey(v []int) string {
	if len(v) == 0 {
		return "[]"
	}
	parts := make([]string, 0, len(v))
	for _, n := range sortedUnique(v) {
		parts = append(parts, fmt.Sprintf("%d", n))
	}
	return strings.Join(parts, ",")
}

func pickMostFrequentSet(
	counts map[string]int,
	setByKey map[string][]int,
	f int,
	targetSize int,
	universe []int,
) []int {
	bestKey := ""
	bestCnt := -1
	for k, c := range counts {
		if c > bestCnt || (c == bestCnt && k < bestKey) {
			bestKey = k
			bestCnt = c
		}
	}
	threshold := len(universe) - f
	if bestCnt >= threshold {
		return normalizeCandidate(setByKey[bestKey], targetSize, universe)
	}
	// No super-majority, merge all local outputs then normalize.
	merged := make([]int, 0)
	for _, set := range setByKey {
		merged = append(merged, set...)
	}
	return normalizeCandidate(merged, targetSize, universe)
}
