package core

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func cvAggregateDispersalBindingFixture(
	t testing.TB,
) (*cvAggregateTranscript, *cvAggregateDispersal, *cvAggregateDispersalBindingStatement) {
	t.Helper()
	_, context, _, leaves := cvM4Fixture(t)
	agg, err := cvAgg(&context, leaves)
	if err != nil {
		t.Fatal(err)
	}
	dispersal, err := cvDisperseAggregate(agg, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := cvAggregateDispersalBindingStatementFromVerified(agg, dispersal)
	if err != nil {
		t.Fatal(err)
	}
	return agg, dispersal, statement
}

func cvAggregateDispersalBindingShape(capacity int) *cvAggregateDispersalBindingCircuit {
	return &cvAggregateDispersalBindingCircuit{Statement: cvPoseidon2BytesWitness{
		Chunks: make([]frontend.Variable, capacity),
		Active: make([]frontend.Variable, capacity),
	}}
}

func TestCVAggregateDispersalBindingCircuit(t *testing.T) {
	agg, dispersal, statement := cvAggregateDispersalBindingFixture(t)
	wire, err := statement.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	capacity := (len(wire) + cvSemanticCommitmentChunkBytes - 1) / cvSemanticCommitmentChunkBytes
	circuit := cvAggregateDispersalBindingShape(capacity)
	assignment, err := cvAggregateDispersalBindingAssignment(agg, dispersal, capacity)
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(*cvAggregateDispersalBindingStatement){
		"aggregate digest": func(s *cvAggregateDispersalBindingStatement) { s.aggregateDigest[0] ^= 1 },
		"payload digest":   func(s *cvAggregateDispersalBindingStatement) { s.payloadDigest[0] ^= 1 },
		"nonce":            func(s *cvAggregateDispersalBindingStatement) { s.nonce[0] ^= 1 },
		"data shards":      func(s *cvAggregateDispersalBindingStatement) { s.dataShards-- },
		"total shards":     func(s *cvAggregateDispersalBindingStatement) { s.totalShards++ },
		"shard bytes":      func(s *cvAggregateDispersalBindingStatement) { s.shardBytes++ },
		"root":             func(s *cvAggregateDispersalBindingStatement) { s.root[0] ^= 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			bad := *statement
			bad.aggregateDigest = append([]byte(nil), statement.aggregateDigest...)
			bad.payloadDigest = append([]byte(nil), statement.payloadDigest...)
			bad.nonce = append([]byte(nil), statement.nonce...)
			bad.root = append([]byte(nil), statement.root...)
			mutate(&bad)
			badWire, err := bad.canonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			badWitness, err := cvPoseidon2BytesCircuitWitness(badWire, capacity)
			if err != nil {
				t.Fatal(err)
			}
			badAssignment := *assignment
			badAssignment.Statement = badWitness
			if err := test.IsSolved(circuit, &badAssignment, ecc.BN254.ScalarField()); err == nil {
				t.Fatalf("binding accepted mutated %s", name)
			}
		})
	}
}

func TestCVVerifyAggregateDispersalRejectsReboundNonce(t *testing.T) {
	agg, dispersal, _ := cvAggregateDispersalBindingFixture(t)
	bad := *dispersal
	bad.nonce = append([]byte(nil), dispersal.nonce...)
	bad.nonce[0] ^= 1
	bad.shards = make([]cvAggregateShard, len(dispersal.shards))
	payloads := make([][]byte, len(dispersal.shards))
	for i := range dispersal.shards {
		payloads[i] = append([]byte(nil), dispersal.shards[i].payload...)
	}
	bad.root, _ = cvBuildAggregateMerkle(bad.nonce, payloads)
	_, branches := cvBuildAggregateMerkle(bad.nonce, payloads)
	for i := range bad.shards {
		bad.shards[i] = cvAggregateShard{
			index: i, payload: payloads[i], siblings: branches[i],
		}
	}
	if bytes.Equal(bad.root, dispersal.root) {
		t.Fatal("nonce mutation unexpectedly preserved the root")
	}
	if err := cvVerifyAggregateDispersal(agg, &bad); err == nil {
		t.Fatal("native verifier accepted a non-deterministic dispersal nonce")
	}
	if _, err := cvAggregateDispersalBindingStatementFromVerified(agg, &bad); err == nil {
		t.Fatal("binding statement accepted a non-deterministic dispersal")
	}
}

func TestCVVerifyAggregateDispersalRejectsNonCanonicalShardPartition(t *testing.T) {
	agg, _, _ := cvAggregateDispersalBindingFixture(t)
	dispersal, err := cvDisperseAggregate(agg, 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(dispersal.shards[1].payload) < 2 {
		t.Fatal("fixture shard is too short")
	}

	bad := *dispersal
	bad.shards = make([]cvAggregateShard, len(dispersal.shards))
	payloads := make([][]byte, len(dispersal.shards))
	for i := range dispersal.shards {
		payloads[i] = append([]byte(nil), dispersal.shards[i].payload...)
	}
	payloads[0] = append(payloads[0], payloads[1][0])
	payloads[1] = append([]byte(nil), payloads[1][1:]...)
	root, branches := cvBuildAggregateMerkle(dispersal.nonce, payloads)
	bad.root = root
	for i := range bad.shards {
		bad.shards[i] = cvAggregateShard{
			index: i, payload: payloads[i], siblings: branches[i],
		}
	}
	if err := cvVerifyAggregateDispersal(agg, &bad); err == nil {
		t.Fatal("native verifier accepted a non-canonical shard byte partition")
	}
}

func TestCVAggregateDispersalBindingCircuitConstraintBudget(t *testing.T) {
	_, _, statement := cvAggregateDispersalBindingFixture(t)
	wire, err := statement.canonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	capacity := (len(wire) + cvSemanticCommitmentChunkBytes - 1) / cvSemanticCommitmentChunkBytes
	ccs, err := frontend.Compile(
		ecc.BN254.ScalarField(), r1cs.NewBuilder,
		cvAggregateDispersalBindingShape(capacity),
	)
	if err != nil {
		t.Fatal(err)
	}
	const maximumConstraints = 30_000
	if constraints := ccs.GetNbConstraints(); constraints > maximumConstraints {
		t.Fatalf("aggregate dispersal binding grew to %d constraints", constraints)
	} else {
		t.Logf("aggregate dispersal binding statement_bytes=%d constraints=%d", len(wire), constraints)
	}
}
