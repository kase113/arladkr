package core

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

const cvAggregateStatementBindingDomain = "ARL-CV-sAPVSS/aggregate-statement-binding/v1"

// cvAggregateStatementBindingCircuit is a backend integration circuit. It
// binds canonical aggregate public-statement bytes, but does not prove the
// aggregate witness relation and therefore has a non-production proof profile.
type cvAggregateStatementBindingCircuit struct {
	Statement cvPoseidon2BytesWitness
	Expected  frontend.Variable `gnark:",public"`
}

func (c *cvAggregateStatementBindingCircuit) Define(api frontend.API) error {
	return cvAssertPoseidon2BytesCommitment(
		api,
		cvAggregateStatementBindingDomain,
		c.Statement.Length,
		c.Statement.LastBytes,
		c.Statement.Chunks,
		c.Statement.Active,
		c.Expected,
	)
}

func cvAggregateStatementBindingShape(capacity int) *cvAggregateStatementBindingCircuit {
	return &cvAggregateStatementBindingCircuit{Statement: cvPoseidon2BytesWitness{
		Chunks: make([]frontend.Variable, capacity),
		Active: make([]frontend.Variable, capacity),
	}}
}

func cvAggregateStatementBindingCommitment(statementWire []byte) ([]byte, error) {
	statement, err := cvDecodeAggregateArgumentStatement(statementWire)
	if err != nil {
		return nil, err
	}
	canonical, err := cvAggregateArgumentStatementCanonicalBytes(statement)
	if err != nil || len(canonical) == 0 {
		return nil, fmt.Errorf("invalid aggregate statement binding wire")
	}
	return cvPoseidon2BytesCommitment(
		cvAggregateStatementBindingDomain, canonical, cvMaxAggregateCircuitProfileBytes,
	)
}

func cvAggregateStatementBindingAssignment(
	statementWire []byte,
	capacity int,
) (*cvAggregateStatementBindingCircuit, error) {
	commitment, err := cvAggregateStatementBindingCommitment(statementWire)
	if err != nil {
		return nil, err
	}
	witness, err := cvPoseidon2BytesCircuitWitness(statementWire, capacity)
	if err != nil {
		return nil, err
	}
	return &cvAggregateStatementBindingCircuit{
		Statement: witness,
		Expected:  new(big.Int).SetBytes(commitment),
	}, nil
}

type cvAggregateStatementBindingPublicWitness struct {
	Expected frontend.Variable `gnark:",public"`
}

func (*cvAggregateStatementBindingPublicWitness) Define(frontend.API) error {
	return nil
}

func cvAggregateStatementBindingPublicAssignment(
	statementWire []byte,
) (*cvAggregateStatementBindingPublicWitness, error) {
	commitment, err := cvAggregateStatementBindingCommitment(statementWire)
	if err != nil {
		return nil, err
	}
	return &cvAggregateStatementBindingPublicWitness{
		Expected: new(big.Int).SetBytes(commitment),
	}, nil
}
