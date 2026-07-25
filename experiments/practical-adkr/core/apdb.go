package core

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type apdbReceiptRequest struct {
	Dealer int           `json:"dealer"`
	Root   []byte        `json:"root"`
	Reply  string        `json:"reply"`
	TR     DXTTranscript `json:"tr"`
}

type apdbReceiptResponse struct {
	Dealer  int         `json:"dealer"`
	Receipt APDBReceipt `json:"receipt"`
}

func runAPDBDispersal(
	ctx context.Context,
	cfg Config,
	old []int,
	transcripts map[int]*DXTTranscript,
	nodePriv map[int]ed25519.PrivateKey,
	nodePub map[int]ed25519.PublicKey,
	dxt *DXTBackend,
) (*APDBDispersalResult, error) {
	threshold := apdbCertificateThreshold(cfg.F, len(old))
	localValid := make(map[int][]int, len(old))
	certs := make(map[int]APDBCertificate, len(old))
	for _, nodeID := range old {
		localValid[nodeID] = make([]int, 0, len(old))
	}

	addrMap := parseNodeAddrMap(cfg.ProtocolNodeAddrs)
	if len(addrMap) < len(old) {
		return nil, fmt.Errorf("protocol node addresses incomplete: have=%d need_at_least=%d", len(addrMap), len(old))
	}
	localIDs := parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	if len(localIDs) == 0 {
		return nil, fmt.Errorf("protocol local node ids empty")
	}

	receiptTO := 8 * time.Second
	if cfg.RouteSendTimeout > 0 {
		candidate := 8 * cfg.RouteSendTimeout
		if candidate > receiptTO {
			receiptTO = candidate
		}
	}

	lnByID := make(map[int]net.Listener, len(localIDs))
	var lnWG sync.WaitGroup
	stop := make(chan struct{})
	defer func() {
		close(stop)
		for _, ln := range lnByID {
			_ = ln.Close()
		}
		lnWG.Wait()
	}()

	for nodeID := range localIDs {
		if _, ok := nodePriv[nodeID]; !ok {
			continue
		}
		addr, ok := addrMap[nodeID]
		if !ok || strings.TrimSpace(addr) == "" {
			continue
		}
		_, port, _ := net.SplitHostPort(addr)
		ln, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", port))
		if err != nil {
			continue
		}
		lnByID[nodeID] = ln
		lnWG.Add(1)
		go func(id int, l net.Listener) {
			defer lnWG.Done()
			for {
				conn, err := l.Accept()
				if err != nil {
					select {
					case <-stop:
						return
					default:
						continue
					}
				}
				_ = conn.SetReadDeadline(time.Now().Add(receiptTO))
				var req apdbReceiptRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					_ = conn.Close()
					continue
				}
				if body, mErr := json.Marshal(req); mErr == nil {
					recordRecvBytes(len(body))
				}
				_ = conn.Close()
				if !dxt.VerifyTranscript(id, &req.TR) {
					continue
				}
				chunkHash := hashChunk(req.Root, req.Dealer, id)
				msg := hashReceiptMsg(req.Dealer, id, req.Root, chunkHash)
				sig := ed25519.Sign(nodePriv[id], msg)
				resp := apdbReceiptResponse{
					Dealer: req.Dealer,
					Receipt: APDBReceipt{
						NodeID:    id,
						Sender:    req.Dealer,
						ChunkHash: chunkHash,
						Signature: sig,
					},
				}
				dial, err := dialWithOptionalDelay(nodeID, req.Dealer, "tcp", req.Reply, receiptTO)
				if err != nil {
					continue
				}
				_ = dial.SetWriteDeadline(time.Now().Add(receiptTO))
				if body, mErr := json.Marshal(resp); mErr == nil {
					recordSentBytes(len(body))
				}
				_ = json.NewEncoder(dial).Encode(resp)
				_ = dial.Close()
			}
		}(nodeID, ln)
	}
	if len(lnByID) == 0 {
		return nil, fmt.Errorf("apdb listeners unavailable for configured protocol transport")
	}
	if cfg.StrictNetwork {
		if err := waitForAPDBReady(ctx, cfg, old, lnByID); err != nil {
			return nil, err
		}
		return collectDistributedAPDBCertificates(ctx, cfg, old, transcripts, nodePub, addrMap, localIDs)
	}

	for _, dealer := range old {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		tr := transcripts[dealer]
		if tr == nil {
			continue
		}
		raw, err := json.Marshal(tr)
		if err != nil {
			return nil, err
		}
		root := sha256.Sum256(raw)

		replyLn, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			return nil, err
		}
		replyAddr := dialableProtocolReplyAddr(replyLn.Addr().String(), addrMap, localIDs)

		respCh := make(chan apdbReceiptResponse, len(old)*2)
		var replyWG sync.WaitGroup
		replyWG.Add(1)
		go func() {
			defer replyWG.Done()
			for {
				conn, err := replyLn.Accept()
				if err != nil {
					return
				}
				_ = conn.SetReadDeadline(time.Now().Add(receiptTO))
				var resp apdbReceiptResponse
				if err := json.NewDecoder(conn).Decode(&resp); err == nil {
					if body, mErr := json.Marshal(resp); mErr == nil {
						recordRecvBytes(len(body))
					}
					select {
					case respCh <- resp:
					default:
					}
				}
				_ = conn.Close()
			}
		}()

		req := apdbReceiptRequest{
			Dealer: dealer,
			Root:   root[:],
			Reply:  replyAddr,
			TR:     *tr,
		}
		reqBytes, err := json.Marshal(req)
		if err != nil {
			_ = replyLn.Close()
			replyWG.Wait()
			return nil, err
		}
		for _, nodeID := range old {
			addr, ok := addrMap[nodeID]
			if !ok || strings.TrimSpace(addr) == "" {
				continue
			}
			conn, err := dialWithOptionalDelay(dealer, nodeID, "tcp", addr, receiptTO)
			if err != nil {
				continue
			}
			_ = conn.SetWriteDeadline(time.Now().Add(receiptTO))
			recordSentBytes(len(reqBytes))
			_, _ = conn.Write(reqBytes)
			_ = conn.Close()
		}

		receipts := make([]APDBReceipt, 0, len(old))
		seen := make(map[int]struct{}, len(old))
		deadline := time.NewTimer(receiptTO)
	collectReceipts:
		for len(receipts) < threshold {
			select {
			case <-ctx.Done():
				deadline.Stop()
				_ = replyLn.Close()
				replyWG.Wait()
				return nil, ctx.Err()
			case <-deadline.C:
				break collectReceipts
			case resp := <-respCh:
				if resp.Dealer != dealer {
					continue
				}
				if _, ok := seen[resp.Receipt.NodeID]; ok {
					continue
				}
				seen[resp.Receipt.NodeID] = struct{}{}
				receipts = append(receipts, resp.Receipt)
			}
		}
		deadline.Stop()
		_ = replyLn.Close()
		replyWG.Wait()

		if len(receipts) < threshold {
			continue
		}
		sort.Slice(receipts, func(i, j int) bool {
			return receipts[i].NodeID < receipts[j].NodeID
		})
		cert := APDBCertificate{
			Sender:   dealer,
			Root:     root[:],
			Receipts: append([]APDBReceipt(nil), receipts[:threshold]...),
		}
		certs[dealer] = cert

		for _, nodeID := range old {
			if verifyAPDBCertificate(cert, nodePub) {
				localValid[nodeID] = append(localValid[nodeID], dealer)
			}
		}
	}
	return &APDBDispersalResult{
		LocalValid:   localValid,
		Certificates: certs,
	}, nil
}

func collectDistributedAPDBCertificates(
	ctx context.Context,
	cfg Config,
	old []int,
	transcripts map[int]*DXTTranscript,
	nodePub map[int]ed25519.PublicKey,
	addrMap map[int]string,
	localIDs map[int]struct{},
) (*APDBDispersalResult, error) {
	cacheDir := strings.TrimSpace(os.Getenv("PRACTICAL_ARTIFACT_CACHE_DIR"))
	if cacheDir == "" {
		return nil, fmt.Errorf("strict-network distributed APDB requires PRACTICAL_ARTIFACT_CACHE_DIR")
	}
	dir := filepath.Join(cacheDir, "apdb-certs", practicalRunID(cfg, old, cfg.NewCommittee))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create apdb cert dir: %w", err)
	}
	localDealers := make([]int, 0, len(localIDs))
	for _, dealer := range old {
		if _, ok := localIDs[dealer]; ok {
			localDealers = append(localDealers, dealer)
		}
	}
	if len(localDealers) == 0 {
		return nil, fmt.Errorf("strict-network distributed APDB has no local old dealer")
	}
	threshold := apdbCertificateThreshold(cfg.F, len(old))
	receiptTO := 8 * time.Second
	if cfg.RouteSendTimeout > 0 {
		candidate := 8 * cfg.RouteSendTimeout
		if candidate > receiptTO {
			receiptTO = candidate
		}
	}
	for _, dealer := range localDealers {
		path := apdbCertCachePath(dir, dealer)
		if cert, err := readAPDBCertCache(path); err == nil && verifyAPDBCertificate(cert, nodePub) {
			continue
		}
		tr := transcripts[dealer]
		if tr == nil {
			return nil, fmt.Errorf("missing transcript for local APDB dealer %d", dealer)
		}
		cert, err := collectAPDBCertificateForDealer(ctx, dealer, tr, old, threshold, receiptTO, addrMap, localIDs, nodePub)
		if err != nil {
			return nil, err
		}
		if err := writeAPDBCertCache(path, cert); err != nil {
			return nil, err
		}
	}

	localValid := make(map[int][]int, len(old))
	for _, nodeID := range old {
		localValid[nodeID] = make([]int, 0, len(old))
	}
	certs := make(map[int]APDBCertificate, len(old))
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		for _, dealer := range old {
			if _, ok := certs[dealer]; ok {
				continue
			}
			cert, err := readAPDBCertCache(apdbCertCachePath(dir, dealer))
			if err != nil || !verifyAPDBCertificate(cert, nodePub) {
				continue
			}
			certs[dealer] = cert
		}
		if len(certs) == len(old) {
			dealers := make([]int, 0, len(certs))
			for dealer := range certs {
				dealers = append(dealers, dealer)
			}
			sort.Ints(dealers)
			for _, nodeID := range old {
				localValid[nodeID] = append(localValid[nodeID], dealers...)
			}
			return &APDBDispersalResult{
				LocalValid:   localValid,
				Certificates: certs,
			}, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for distributed apdb certs: have=%d need=%d err=%w", len(certs), len(old), ctx.Err())
		case <-ticker.C:
		}
	}
}

func collectAPDBCertificateForDealer(
	ctx context.Context,
	dealer int,
	tr *DXTTranscript,
	old []int,
	threshold int,
	receiptTO time.Duration,
	addrMap map[int]string,
	localIDs map[int]struct{},
	nodePub map[int]ed25519.PublicKey,
) (APDBCertificate, error) {
	raw, err := json.Marshal(tr)
	if err != nil {
		return APDBCertificate{}, err
	}
	root := sha256.Sum256(raw)
	replyLn, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return APDBCertificate{}, err
	}
	replyAddr := dialableProtocolReplyAddr(replyLn.Addr().String(), addrMap, localIDs)
	respCh := make(chan apdbReceiptResponse, len(old)*2)
	var replyWG sync.WaitGroup
	replyWG.Add(1)
	go func() {
		defer replyWG.Done()
		for {
			conn, err := replyLn.Accept()
			if err != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(receiptTO))
			var resp apdbReceiptResponse
			if err := json.NewDecoder(conn).Decode(&resp); err == nil {
				if body, mErr := json.Marshal(resp); mErr == nil {
					recordRecvBytes(len(body))
				}
				select {
				case respCh <- resp:
				default:
				}
			}
			_ = conn.Close()
		}
	}()
	req := apdbReceiptRequest{
		Dealer: dealer,
		Root:   root[:],
		Reply:  replyAddr,
		TR:     *tr,
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		_ = replyLn.Close()
		replyWG.Wait()
		return APDBCertificate{}, err
	}
	for _, nodeID := range old {
		addr, ok := addrMap[nodeID]
		if !ok || strings.TrimSpace(addr) == "" {
			continue
		}
		conn, err := dialWithOptionalDelay(dealer, nodeID, "tcp", addr, receiptTO)
		if err != nil {
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(receiptTO))
		recordSentBytes(len(reqBytes))
		_, _ = conn.Write(reqBytes)
		_ = conn.Close()
	}
	receipts := make([]APDBReceipt, 0, len(old))
	seen := make(map[int]struct{}, len(old))
	deadline := time.NewTimer(receiptTO)
collectReceipts:
	for len(receipts) < threshold {
		select {
		case <-ctx.Done():
			deadline.Stop()
			_ = replyLn.Close()
			replyWG.Wait()
			return APDBCertificate{}, ctx.Err()
		case <-deadline.C:
			break collectReceipts
		case resp := <-respCh:
			if resp.Dealer != dealer {
				continue
			}
			if _, ok := seen[resp.Receipt.NodeID]; ok {
				continue
			}
			seen[resp.Receipt.NodeID] = struct{}{}
			receipts = append(receipts, resp.Receipt)
		}
	}
	deadline.Stop()
	_ = replyLn.Close()
	replyWG.Wait()
	if len(receipts) < threshold {
		return APDBCertificate{}, fmt.Errorf("distributed APDB dealer %d insufficient receipts: have=%d need=%d", dealer, len(receipts), threshold)
	}
	sort.Slice(receipts, func(i, j int) bool {
		return receipts[i].NodeID < receipts[j].NodeID
	})
	cert := APDBCertificate{
		Sender:   dealer,
		Root:     append([]byte(nil), root[:]...),
		Receipts: append([]APDBReceipt(nil), receipts[:threshold]...),
	}
	if !verifyAPDBCertificate(cert, nodePub) {
		return APDBCertificate{}, fmt.Errorf("distributed APDB dealer %d produced invalid cert", dealer)
	}
	return cert, nil
}

func dialableProtocolReplyAddr(listenerAddr string, addrMap map[int]string, localIDs map[int]struct{}) string {
	host, port, err := net.SplitHostPort(listenerAddr)
	if err != nil {
		return listenerAddr
	}
	if host != "" && host != "0.0.0.0" && host != "::" && host != "[::]" {
		return listenerAddr
	}
	for id := range localIDs {
		addr := strings.TrimSpace(addrMap[id])
		if addr == "" {
			continue
		}
		peerHost, _, splitErr := net.SplitHostPort(addr)
		if splitErr == nil && peerHost != "" && peerHost != "0.0.0.0" && peerHost != "::" && peerHost != "[::]" {
			return net.JoinHostPort(peerHost, port)
		}
	}
	return net.JoinHostPort("127.0.0.1", port)
}

func waitForAPDBReady(ctx context.Context, cfg Config, old []int, lnByID map[int]net.Listener) error {
	cacheDir := strings.TrimSpace(os.Getenv("PRACTICAL_ARTIFACT_CACHE_DIR"))
	if cacheDir == "" {
		return fmt.Errorf("strict-network APDB ready barrier requires PRACTICAL_ARTIFACT_CACHE_DIR")
	}
	readyDir := filepath.Join(cacheDir, "apdb-ready", practicalRunID(cfg, old, cfg.NewCommittee))
	if err := os.MkdirAll(readyDir, 0o755); err != nil {
		return fmt.Errorf("create apdb ready dir: %w", err)
	}
	for nodeID := range lnByID {
		path := filepath.Join(readyDir, fmt.Sprintf("old-%06d.ready", nodeID))
		if err := os.WriteFile(path, []byte("ready\n"), 0o644); err != nil {
			return fmt.Errorf("write apdb ready file: %w", err)
		}
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		matches, err := filepath.Glob(filepath.Join(readyDir, "old-*.ready"))
		if err == nil && len(matches) >= len(old) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for apdb ready barrier: have=%d need=%d err=%w", len(matches), len(old), ctx.Err())
		case <-ticker.C:
		}
	}
}

func apdbCertCachePath(dir string, dealer int) string {
	return filepath.Join(dir, fmt.Sprintf("dealer-%06d.json", dealer))
}

func readAPDBCertCache(path string) (APDBCertificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return APDBCertificate{}, err
	}
	var cert APDBCertificate
	if err := json.Unmarshal(data, &cert); err != nil {
		return APDBCertificate{}, err
	}
	if len(cert.Receipts) == 0 {
		return APDBCertificate{}, fmt.Errorf("empty apdb cert cache")
	}
	return cert, nil
}

func writeAPDBCertCache(path string, cert APDBCertificate) error {
	data, err := json.Marshal(&cert)
	if err != nil {
		return fmt.Errorf("marshal apdb cert cache: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write apdb cert cache temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename apdb cert cache: %w", err)
	}
	return nil
}

func runAPDBDispersalLocal(
	ctx context.Context,
	cfg Config,
	old []int,
	transcripts map[int]*DXTTranscript,
	nodePriv map[int]ed25519.PrivateKey,
	nodePub map[int]ed25519.PublicKey,
	dxt *DXTBackend,
) (*APDBDispersalResult, error) {
	threshold := apdbCertificateThreshold(cfg.F, len(old))
	localValid := make(map[int][]int, len(old))
	certs := make(map[int]APDBCertificate, len(old))
	for _, nodeID := range old {
		localValid[nodeID] = make([]int, 0, len(old))
	}
	receiptTO := 8 * time.Second
	if cfg.RouteSendTimeout > 0 {
		candidate := 8 * cfg.RouteSendTimeout
		if candidate > receiptTO {
			receiptTO = candidate
		}
	}
	for _, dealer := range old {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		tr := transcripts[dealer]
		if tr == nil {
			continue
		}
		raw, err := json.Marshal(tr)
		if err != nil {
			return nil, err
		}
		root := sha256.Sum256(raw)
		receiptCh := make(chan APDBReceipt, len(old)*2)
		for _, nodeID := range old {
			nid := nodeID
			go func() {
				if !dxt.VerifyTranscript(nid, tr) {
					return
				}
				chunkHash := hashChunk(root[:], dealer, nid)
				msg := hashReceiptMsg(dealer, nid, root[:], chunkHash)
				sig := ed25519.Sign(nodePriv[nid], msg)
				select {
				case receiptCh <- APDBReceipt{
					NodeID:    nid,
					Sender:    dealer,
					ChunkHash: chunkHash,
					Signature: sig,
				}:
				case <-ctx.Done():
				}
			}()
		}
		receipts := make([]APDBReceipt, 0, len(old))
		seen := make(map[int]struct{}, len(old))
		deadline := time.NewTimer(receiptTO)
		for len(receipts) < threshold {
			select {
			case <-ctx.Done():
				deadline.Stop()
				return nil, ctx.Err()
			case <-deadline.C:
				goto doneCollect
			case rc := <-receiptCh:
				if _, ok := seen[rc.NodeID]; ok {
					continue
				}
				seen[rc.NodeID] = struct{}{}
				receipts = append(receipts, rc)
			}
		}
	doneCollect:
		deadline.Stop()
		if len(receipts) < threshold {
			continue
		}
		sort.Slice(receipts, func(i, j int) bool { return receipts[i].NodeID < receipts[j].NodeID })
		cert := APDBCertificate{
			Sender:   dealer,
			Root:     root[:],
			Receipts: append([]APDBReceipt(nil), receipts[:threshold]...),
		}
		certs[dealer] = cert
		for _, nodeID := range old {
			if verifyAPDBCertificate(cert, nodePub) {
				localValid[nodeID] = append(localValid[nodeID], dealer)
			}
		}
	}
	return &APDBDispersalResult{
		LocalValid:   localValid,
		Certificates: certs,
	}, nil
}

func verifyAPDBCertificate(cert APDBCertificate, nodePub map[int]ed25519.PublicKey) bool {
	if len(cert.Receipts) == 0 {
		return false
	}
	required := 0
	if committeeSize := len(nodePub); committeeSize > 0 {
		f := (committeeSize - 1) / 3
		required = apdbCertificateThreshold(f, committeeSize)
	}
	if required > 0 && len(cert.Receipts) < required {
		return false
	}
	seen := make(map[int]struct{}, len(cert.Receipts))
	for _, rc := range cert.Receipts {
		if rc.Sender != cert.Sender {
			return false
		}
		if _, ok := seen[rc.NodeID]; ok {
			return false
		}
		seen[rc.NodeID] = struct{}{}
		pk, ok := nodePub[rc.NodeID]
		if !ok {
			return false
		}
		msg := hashReceiptMsg(cert.Sender, rc.NodeID, cert.Root, rc.ChunkHash)
		if !ed25519.Verify(pk, msg, rc.Signature) {
			return false
		}
	}
	return true
}

func apdbCertificateThreshold(f int, committeeSize int) int {
	threshold := 2*f + 1
	if threshold < f+1 {
		threshold = f + 1
	}
	if committeeSize > 0 && threshold > committeeSize {
		threshold = committeeSize
	}
	return threshold
}

func hashChunk(root []byte, dealer int, nodeID int) []byte {
	h := sha256.New()
	h.Write([]byte("PADKR-APDB-CHUNK"))
	h.Write(root)
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(dealer))
	binary.BigEndian.PutUint64(b[8:], uint64(nodeID))
	h.Write(b[:])
	return h.Sum(nil)
}

func hashReceiptMsg(dealer int, nodeID int, root []byte, chunkHash []byte) []byte {
	h := sha256.New()
	h.Write([]byte("PADKR-APDB-RECEIPT"))
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(dealer))
	binary.BigEndian.PutUint64(b[8:], uint64(nodeID))
	h.Write(b[:])
	h.Write(root)
	h.Write(chunkHash)
	return h.Sum(nil)
}
