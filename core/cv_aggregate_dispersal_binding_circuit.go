package core

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

const (
	cvAggregateDispersalStatementDomain = "ARL-CV-sAPVSS/aggregate-dispersal-statement/v1"
	cvAggregateDispersalBindingDomain   = "ARL-CV-sAPVSS/aggregate-dispersal-binding/v1"
)

// cvAggregateDispersalBindingStatement is the compact public description of a
// natively verified aggregate dispersal. totalShards fixes the canonical shard
// positions 0..totalShards-1; the Merkle root binds each position because the
// native leaf hash includes its index.
type cvAggregateDispersalBindingStatement struct {
	aggregateDigest []byte
	payloadDigest   []byte
	nonce           []byte
	dataShards      int
	totalShards     int
	shardBytes      int
	root            []byte
}

func (s *cvAggregateDispersalBindingStatement) canonicalBytes() ([]byte, error) {
	if s == nil || len(s.aggregateDigest) != 32 || len(s.payloadDigest) != 32 ||
		len(s.nonce) != 32 || len(s.root) != 32 || s.dataShards <= 0 ||
		s.totalShards < s.dataShards || s.shardBytes <= 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate dispersal binding statement")
	}
	var wire bytes.Buffer
	for _, field := range [][]byte{
		[]byte(cvAggregateDispersalStatementDomain),
		s.aggregateDigest,
		s.payloadDigest,
		s.nonce,
	} {
		if err := cvWriteBytes(&wire, field); err != nil {
			return nil, err
		}
	}
	for _, value := range []int{s.dataShards, s.totalShards, s.shardBytes} {
		if err := cvWriteUint32(&wire, value); err != nil {
			return nil, err
		}
	}
	if err := cvWriteBytes(&wire, s.root); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

func cvAggregateDispersalBindingStatementFromVerified(
	agg *cvAggregateTranscript,
	dispersal *cvAggregateDispersal,
) (*cvAggregateDispersalBindingStatement, error) {
	if err := cvVerifyAggregateDispersal(agg, dispersal); err != nil {
		return nil, err
	}
	if len(dispersal.shards) == 0 || len(dispersal.shards[0].payload) == 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate dispersal shard size")
	}
	shardBytes := len(dispersal.shards[0].payload)
	for i := range dispersal.shards {
		if len(dispersal.shards[i].payload) != shardBytes {
			return nil, fmt.Errorf("non-canonical CV-sAPVSS aggregate shard size")
		}
	}
	return &cvAggregateDispersalBindingStatement{
		aggregateDigest: append([]byte(nil), agg.digest...),
		payloadDigest:   append([]byte(nil), dispersal.payloadDigest...),
		nonce:           append([]byte(nil), dispersal.nonce...),
		dataShards:      dispersal.dataShards,
		totalShards:     len(dispersal.shards),
		shardBytes:      shardBytes,
		root:            append([]byte(nil), dispersal.root...),
	}, nil
}

// cvAggregateDispersalBindingCircuit binds the exact canonical statement
// produced after native SHA-256 Merkle and Reed-Solomon verification. It does
// not prove those relations inside BN254; cvVerifyAggregateDispersal remains
// the mandatory dispersal-validity gate.
type cvAggregateDispersalBindingCircuit struct {
	Statement cvPoseidon2BytesWitness
	Expected  frontend.Variable `gnark:",public"`
}

func (c *cvAggregateDispersalBindingCircuit) Define(api frontend.API) error {
	return cvAssertPoseidon2BytesCommitment(
		api,
		cvAggregateDispersalBindingDomain,
		c.Statement.Length,
		c.Statement.LastBytes,
		c.Statement.Chunks,
		c.Statement.Active,
		c.Expected,
	)
}

func cvAggregateDispersalBindingAssignment(
	agg *cvAggregateTranscript,
	dispersal *cvAggregateDispersal,
	capacity int,
) (*cvAggregateDispersalBindingCircuit, error) {
	statement, err := cvAggregateDispersalBindingStatementFromVerified(agg, dispersal)
	if err != nil {
		return nil, err
	}
	wire, err := statement.canonicalBytes()
	if err != nil {
		return nil, err
	}
	commitment, err := cvPoseidon2BytesCommitment(
		cvAggregateDispersalBindingDomain, wire, cvMaxCanonicalFieldBytes,
	)
	if err != nil {
		return nil, err
	}
	witness, err := cvPoseidon2BytesCircuitWitness(wire, capacity)
	if err != nil {
		return nil, err
	}
	return &cvAggregateDispersalBindingCircuit{
		Statement: witness,
		Expected:  new(big.Int).SetBytes(commitment),
	}, nil
}
