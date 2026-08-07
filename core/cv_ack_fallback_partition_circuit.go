package core

import (
	"fmt"
	"math/bits"

	"github.com/consensys/gnark/frontend"
)

// cvACKFallbackPartitionCircuit verifies only the canonical partition shape.
// The enclosing aggregate circuit must use the constrained active entries and
// FallbackForReceiver selectors to verify the corresponding ACK signature or
// fallback relation; this gadget does not replace either cryptographic check.
type cvACKFallbackPartitionCircuit struct {
	ACKIndices     []frontend.Variable
	ACKActive      []frontend.Variable
	FallbackIndex  []frontend.Variable
	FallbackActive []frontend.Variable

	FallbackForReceiver []frontend.Variable

	receiverCount int
	maxFallback   int
}

func cvACKFallbackPartitionShape(n, f int) *cvACKFallbackPartitionCircuit {
	return &cvACKFallbackPartitionCircuit{
		ACKIndices:          make([]frontend.Variable, n),
		ACKActive:           make([]frontend.Variable, n),
		FallbackIndex:       make([]frontend.Variable, f),
		FallbackActive:      make([]frontend.Variable, f),
		FallbackForReceiver: make([]frontend.Variable, n),
		receiverCount:       n,
		maxFallback:         f,
	}
}

func cvAssertCanonicalIndexSet(
	api frontend.API,
	indices, active []frontend.Variable,
	receiverCount int,
) {
	indexBits := bits.Len(uint(receiverCount))
	for i := range indices {
		api.AssertIsBoolean(active[i])
		api.AssertIsEqual(api.Mul(api.Sub(1, active[i]), indices[i]), 0)
		if i > 0 {
			api.AssertIsEqual(api.Mul(active[i], api.Sub(1, active[i-1])), 0)
			strictDelta := api.Mul(active[i], api.Sub(indices[i], indices[i-1], 1))
			api.ToBinary(strictDelta, indexBits)
		}
	}
}

func (c *cvACKFallbackPartitionCircuit) Define(api frontend.API) error {
	if c.receiverCount <= 0 || c.maxFallback < 0 || c.maxFallback >= c.receiverCount ||
		len(c.ACKIndices) != c.receiverCount || len(c.ACKActive) != c.receiverCount ||
		len(c.FallbackIndex) != c.maxFallback || len(c.FallbackActive) != c.maxFallback ||
		len(c.FallbackForReceiver) != c.receiverCount {
		return fmt.Errorf("invalid ACK/fallback partition circuit shape")
	}
	cvAssertCanonicalIndexSet(api, c.ACKIndices, c.ACKActive, c.receiverCount)
	cvAssertCanonicalIndexSet(api, c.FallbackIndex, c.FallbackActive, c.receiverCount)

	ackCount := frontend.Variable(0)
	for i := range c.ACKActive {
		ackCount = api.Add(ackCount, c.ACKActive[i])
	}
	fallbackCount := frontend.Variable(0)
	for i := range c.FallbackActive {
		fallbackCount = api.Add(fallbackCount, c.FallbackActive[i])
	}
	api.AssertIsEqual(api.Add(ackCount, fallbackCount), c.receiverCount)

	for receiver := 1; receiver <= c.receiverCount; receiver++ {
		ackMembership := frontend.Variable(0)
		for i := range c.ACKIndices {
			ackMembership = api.Add(
				ackMembership,
				api.Mul(c.ACKActive[i], api.IsZero(api.Sub(c.ACKIndices[i], receiver))),
			)
		}
		fallbackMembership := frontend.Variable(0)
		for i := range c.FallbackIndex {
			fallbackMembership = api.Add(
				fallbackMembership,
				api.Mul(c.FallbackActive[i], api.IsZero(api.Sub(c.FallbackIndex[i], receiver))),
			)
		}
		api.AssertIsBoolean(c.FallbackForReceiver[receiver-1])
		api.AssertIsEqual(c.FallbackForReceiver[receiver-1], fallbackMembership)
		api.AssertIsEqual(api.Add(ackMembership, fallbackMembership), 1)
	}
	return nil
}

func cvACKFallbackPartitionAssignment(
	receiverCount, maxFallback int,
	ackIndices, fallbackIndices []int,
) *cvACKFallbackPartitionCircuit {
	assignment := &cvACKFallbackPartitionCircuit{
		ACKIndices:          make([]frontend.Variable, receiverCount),
		ACKActive:           make([]frontend.Variable, receiverCount),
		FallbackIndex:       make([]frontend.Variable, maxFallback),
		FallbackActive:      make([]frontend.Variable, maxFallback),
		FallbackForReceiver: make([]frontend.Variable, receiverCount),
		receiverCount:       receiverCount,
		maxFallback:         maxFallback,
	}
	for i := range assignment.ACKIndices {
		assignment.ACKIndices[i] = 0
		assignment.ACKActive[i] = 0
	}
	for i := range assignment.FallbackIndex {
		assignment.FallbackIndex[i] = 0
		assignment.FallbackActive[i] = 0
	}
	for i := range assignment.FallbackForReceiver {
		assignment.FallbackForReceiver[i] = 0
	}
	for i, receiver := range ackIndices {
		assignment.ACKIndices[i] = receiver
		assignment.ACKActive[i] = 1
	}
	for i, receiver := range fallbackIndices {
		assignment.FallbackIndex[i] = receiver
		assignment.FallbackActive[i] = 1
		if receiver > 0 && receiver <= receiverCount {
			assignment.FallbackForReceiver[receiver-1] = 1
		}
	}
	return assignment
}
