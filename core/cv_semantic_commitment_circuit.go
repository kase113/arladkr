package core

import (
	"fmt"
	"math/big"

	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// cvSemanticCommitmentCircuit verifies the native streaming commitment with a
// fixed circuit capacity. Active is constrained to a non-empty prefix, so one
// setup can accept canonical leaf wires of different lengths up to the same
// configured limit without changing the commitment definition.
type cvSemanticCommitmentCircuit struct {
	Length    frontend.Variable
	LastBytes frontend.Variable
	Chunks    []frontend.Variable
	Active    []frontend.Variable
	Expected  frontend.Variable `gnark:",public"`
}

func cvSemanticCommitmentDomainElement() *big.Int {
	return cvPoseidon2DomainElement(cvSemanticCommitmentDomain)
}

func cvPoseidon2DomainElement(domain string) *big.Int {
	var element bnfr.Element
	element.SetBytes(hashBytes([]byte(domain)))
	return element.BigInt(new(big.Int))
}

func cvAssertPoseidon2BytesCommitment(
	api frontend.API,
	domain string,
	length, lastBytes frontend.Variable,
	chunks, active []frontend.Variable,
	expected frontend.Variable,
) error {
	if domain == "" || len(chunks) == 0 || len(chunks) != len(active) {
		return fmt.Errorf("invalid Poseidon2 byte commitment circuit capacity")
	}
	api.ToBinary(length, 32)
	api.ToBinary(lastBytes, 5)
	api.AssertIsEqual(api.IsZero(lastBytes), 0)
	api.AssertIsEqual(active[0], 1)

	activeCount := frontend.Variable(0)
	finalChunk := frontend.Variable(0)
	for i := range chunks {
		api.AssertIsBoolean(active[i])
		if i > 0 {
			api.AssertIsEqual(api.Mul(active[i], api.Sub(1, active[i-1])), 0)
		}
		api.ToBinary(chunks[i], 8*cvSemanticCommitmentChunkBytes)
		api.AssertIsEqual(api.Mul(api.Sub(1, active[i]), chunks[i]), 0)
		activeCount = api.Add(activeCount, active[i])
		nextInactive := frontend.Variable(1)
		if i+1 < len(active) {
			nextInactive = api.Sub(1, active[i+1])
		}
		isFinal := api.Mul(active[i], nextInactive)
		finalChunk = api.Add(finalChunk, api.Mul(isFinal, chunks[i]))
	}
	api.AssertIsEqual(
		length,
		api.Add(api.Mul(api.Sub(activeCount, 1), cvSemanticCommitmentChunkBytes), lastBytes),
	)

	// The final packed element must use only LastBytes bytes. This prevents a
	// witness from claiming a shorter wire while retaining hidden high bytes.
	finalBits := api.ToBinary(finalChunk, 8*cvSemanticCommitmentChunkBytes)
	lastByteSelectors := make([]frontend.Variable, cvSemanticCommitmentChunkBytes)
	selectorSum := frontend.Variable(0)
	for byteCount := 1; byteCount <= cvSemanticCommitmentChunkBytes; byteCount++ {
		selector := api.IsZero(api.Sub(lastBytes, byteCount))
		lastByteSelectors[byteCount-1] = selector
		selectorSum = api.Add(selectorSum, selector)
	}
	api.AssertIsEqual(selectorSum, 1)
	for byteCount, selector := range lastByteSelectors {
		for bit := (byteCount + 1) * 8; bit < len(finalBits); bit++ {
			api.AssertIsEqual(api.Mul(selector, finalBits[bit]), 0)
		}
	}

	permutation, err := poseidon2.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return err
	}
	state := frontend.Variable(0)
	state = permutation.Compress(state, cvPoseidon2DomainElement(domain))
	state = permutation.Compress(state, length)
	for i := range chunks {
		compressed := permutation.Compress(state, chunks[i])
		state = api.Select(active[i], compressed, state)
	}
	api.AssertIsEqual(state, expected)
	return nil
}

func (c *cvSemanticCommitmentCircuit) Define(api frontend.API) error {
	return cvAssertPoseidon2BytesCommitment(
		api, cvSemanticCommitmentDomain,
		c.Length, c.LastBytes, c.Chunks, c.Active, c.Expected,
	)
}

func cvSemanticCommitmentCircuitAssignment(leafWire []byte, capacity int) (*cvSemanticCommitmentCircuit, error) {
	commitment, err := cvLeafSemanticCommitment(leafWire)
	if err != nil {
		return nil, err
	}
	chunkCount := (len(leafWire) + cvSemanticCommitmentChunkBytes - 1) / cvSemanticCommitmentChunkBytes
	if capacity < chunkCount {
		return nil, fmt.Errorf("semantic commitment circuit capacity is too small")
	}
	assignment := &cvSemanticCommitmentCircuit{
		Length: len(leafWire), LastBytes: len(leafWire) - (chunkCount-1)*cvSemanticCommitmentChunkBytes,
		Chunks: make([]frontend.Variable, capacity), Active: make([]frontend.Variable, capacity),
		Expected: new(big.Int).SetBytes(commitment),
	}
	for i := 0; i < capacity; i++ {
		assignment.Chunks[i] = 0
		assignment.Active[i] = 0
	}
	for i := 0; i < chunkCount; i++ {
		start := i * cvSemanticCommitmentChunkBytes
		end := start + cvSemanticCommitmentChunkBytes
		if end > len(leafWire) {
			end = len(leafWire)
		}
		assignment.Chunks[i] = new(big.Int).SetBytes(leafWire[start:end])
		assignment.Active[i] = 1
	}
	return assignment, nil
}
