package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestAPDBMerkleProofAllShardsN4(t *testing.T) {
	testAPDBMerkleProofAllShards(t, 4)
}

func TestAPDBMerkleProofAllShardsN7(t *testing.T) {
	testAPDBMerkleProofAllShards(t, 7)
}

func testAPDBMerkleProofAllShards(t *testing.T, total int) {
	t.Helper()
	shards := make([][]byte, total)
	leaves := make([][]byte, total)
	for i := range shards {
		shards[i] = []byte(fmt.Sprintf("shard-%d-of-%d", i, total))
		leaves[i] = apdbShardLeaf(3, i, shards[i])
	}
	root, proofs, err := apdbMerkleTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	for i := range leaves {
		if !verifyAPDBMerkleProof(leaves[i], i, total, proofs[i], root) {
			t.Fatalf("valid proof rejected for shard %d/%d", i, total)
		}
		mutatedShard := append([]byte(nil), shards[i]...)
		mutatedShard[0] ^= 1
		if verifyAPDBMerkleProof(apdbShardLeaf(3, i, mutatedShard), i, total, proofs[i], root) {
			t.Fatalf("mutated shard accepted for shard %d/%d", i, total)
		}
		mutatedRoot := append([]byte(nil), root...)
		mutatedRoot[0] ^= 1
		if verifyAPDBMerkleProof(leaves[i], i, total, proofs[i], mutatedRoot) {
			t.Fatalf("mutated root accepted for shard %d/%d", i, total)
		}
		mutatedProof := make([][]byte, len(proofs[i]))
		for j := range proofs[i] {
			mutatedProof[j] = append([]byte(nil), proofs[i][j]...)
		}
		mutatedProof[0][0] ^= 1
		if verifyAPDBMerkleProof(leaves[i], i, total, mutatedProof, root) {
			t.Fatalf("mutated proof accepted for shard %d/%d", i, total)
		}
	}
}

func TestAPDBRSAnyThresholdSubsetRecoversExactValue(t *testing.T) {
	const dataShards, totalShards = 3, 7
	value := bytes.Repeat([]byte("exact-practical-apdb-transcript|"), 37)
	shards, err := recoverEncodeValue(value, dataShards, totalShards)
	if err != nil {
		t.Fatal(err)
	}
	var subsets int
	for a := 0; a < totalShards; a++ {
		for b := a + 1; b < totalShards; b++ {
			for c := b + 1; c < totalShards; c++ {
				subset := map[int][]byte{a: shards[a], b: shards[b], c: shards[c]}
				recovered, err := recoverDecodeValue(subset, dataShards, totalShards)
				if err != nil || !bytes.Equal(recovered, value) {
					t.Fatalf("subset {%d,%d,%d} recovery mismatch: err=%v", a, b, c, err)
				}
				subsets++
			}
		}
	}
	if subsets != 35 {
		t.Fatalf("tested %d subsets, want 35", subsets)
	}
}

func TestVerifyNetworkAPDBCertificateBindsErasureMetadata(t *testing.T) {
	const dealer = 2
	const totalShards, dataShards = 7, 3
	nodePub := make(map[int]ed25519.PublicKey, totalShards)
	nodePriv := make(map[int]ed25519.PrivateKey, totalShards)
	for i := 0; i < totalShards; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		nodePub[i], nodePriv[i] = pub, priv
	}
	valueDigest := sha256.Sum256([]byte("exact transcript"))
	merkleRoot := sha256.Sum256([]byte("shard tree"))
	build := func(k, n int) APDBCertificate {
		root := apdbCommitmentRoot(dealer, valueDigest[:], merkleRoot[:], k, n)
		cert := APDBCertificate{
			Sender: dealer, Root: root, ValueDigest: valueDigest[:], MerkleRoot: merkleRoot[:],
			DataShards: k, TotalShards: n,
		}
		for holder := 0; holder < 6; holder++ {
			chunkHash := sha256.Sum256([]byte(fmt.Sprintf("holder-%d-shard", holder)))
			receipt := APDBReceipt{NodeID: holder, Sender: dealer, ChunkHash: chunkHash[:]}
			receipt.Signature = ed25519.Sign(nodePriv[holder], hashReceiptMsg(dealer, holder, root, receipt.ChunkHash))
			cert.Receipts = append(cert.Receipts, receipt)
		}
		return cert
	}

	valid := build(dataShards, totalShards)
	if !verifyAPDBCertificate(valid, nodePub) {
		t.Fatal("valid network APDB certificate rejected")
	}
	if verifyAPDBCertificate(build(4, totalShards), nodePub) {
		t.Fatal("accepted certificate whose data-shard threshold exceeds n-2f")
	}
	if verifyAPDBCertificate(build(dataShards, 6), nodePub) {
		t.Fatal("accepted certificate for a different total shard count")
	}
	if !verifyAPDBCertificate(build(5, totalShards), nodePub, 1) {
		t.Fatal("rejected certificate using explicitly configured f=1")
	}
	if verifyAPDBCertificate(build(dataShards, totalShards), nodePub, 1) {
		t.Fatal("accepted max-f erasure threshold under configured f=1")
	}
	tampered := valid
	tampered.Root = append([]byte(nil), valid.Root...)
	tampered.Root[0] ^= 1
	if verifyAPDBCertificate(tampered, nodePub) {
		t.Fatal("accepted certificate with a tampered commitment root")
	}
}

func TestNetworkAPDBCompletesWithoutAllDealers(t *testing.T) {
	t.Setenv("PRACTICAL_ARTIFACT_CACHE_DIR", t.TempDir())
	t.Setenv("PRACTICAL_RUN_ID", "apdb-missing-dealer")
	old := []int{0, 1, 2, 3}
	newCommittee := []int{10, 11, 12, 13}
	allIDs := append(append([]int(nil), old...), newCommittee...)
	cfg := Config{
		SID: "apdb-missing-dealer", Epoch: 9, OldCommittee: old, NewCommittee: newCommittee, F: 1,
		PaillierBits: 2048, ProtocolNodeAddrs: buildAddrCSV(allIDs, nextTestBase(300)),
		ProtocolLocalNodeIDs: buildIDsCSV(allIDs),
	}
	dxt := setupDXTBackend(t, cfg)
	transcripts := make(map[int]*DXTTranscript, 3)
	for _, dealer := range old[:3] {
		transcript, _, err := dxt.Deal(context.Background(), dealer, nil)
		if err != nil {
			t.Fatalf("DXT dealer %d: %v", dealer, err)
		}
		if !dxt.VerifyTranscript(0, transcript) {
			t.Fatalf("DXT dealer %d produced invalid transcript", dealer)
		}
		transcripts[dealer] = transcript
	}

	nodePub := make(map[int]ed25519.PublicKey, len(old))
	nodePriv := make(map[int]ed25519.PrivateKey, len(old))
	for _, id := range old {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		nodePub[id], nodePriv[id] = pub, priv
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	services := make(map[int]*networkAPDBService, 3)
	for _, id := range old[:3] {
		processCfg := cfg
		processCfg.StrictNetwork = true
		processCfg.ProtocolLocalNodeIDs = fmt.Sprintf("%d", id)
		service, err := startNetworkAPDBService(ctx, processCfg, old, transcripts, nodePriv, nodePub, dxt)
		if err != nil {
			t.Fatalf("start APDB node %d: %v", id, err)
		}
		services[id] = service
		defer service.close()
	}

	type output struct {
		node   int
		result *APDBDispersalResult
		err    error
	}
	outputs := make(chan output, 3)
	var wg sync.WaitGroup
	for _, id := range old[:3] {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			processCfg := cfg
			processCfg.StrictNetwork = true
			processCfg.ProtocolLocalNodeIDs = fmt.Sprintf("%d", id)
			result, err := runNetworkRSAPDB(ctx, processCfg, old, transcripts, nodePub, services[id])
			outputs <- output{node: id, result: result, err: err}
		}()
	}
	wg.Wait()
	close(outputs)
	for output := range outputs {
		if output.err != nil {
			t.Fatalf("APDB node %d: %v", output.node, output.err)
		}
		if len(output.result.Certificates) != 3 {
			t.Fatalf("APDB node %d certificates=%d want=3", output.node, len(output.result.Certificates))
		}
		for dealer, certificate := range output.result.Certificates {
			if dealer == 3 || !verifyAPDBCertificate(certificate, nodePub, cfg.F) {
				t.Fatalf("APDB node %d accepted invalid/absent dealer %d", output.node, dealer)
			}
		}
	}
}
