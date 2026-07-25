package core

import (
	"fmt"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func cvBenchmarkFixture(b *testing.B, receivers, f, k int) (cvLeafContextV1, []*cvLeafV1) {
	b.Helper()
	if receivers <= 0 || f < 0 || f >= receivers || k != f+1 {
		b.Fatal("invalid CV benchmark topology")
	}
	profile := cvChunkProfile{chunkBits: 8, maxComponents: k}
	chunks, err := cvChunkCount(profile)
	if err != nil {
		b.Fatal(err)
	}
	receiverKeys := make([]bls12381.G1Affine, receivers)
	for i := range receiverKeys {
		receiverKeys[i], err = cvReceiverPublicKey(cvTestScalar(uint64(100 + i)))
		if err != nil {
			b.Fatal(err)
		}
	}
	context := cvLeafContextV1{
		sessionID:          []byte(fmt.Sprintf("cv-benchmark-n%d-f%d", receivers, f)),
		epoch:              1,
		sharingDegree:      f,
		profile:            profile,
		receiverPublicKeys: receiverKeys,
		dealerSetPolicy:    []byte("first-f-plus-one"),
		proofProfile:       cvLeafV1GrothProofProfile,
	}
	leaves := make([]*cvLeafV1, k)
	for dealer := 0; dealer < k; dealer++ {
		scalars := make([]fr.Element, f+1)
		blindings := make([]fr.Element, f+1)
		for coefficient := 0; coefficient <= f; coefficient++ {
			scalars[coefficient] = cvTestScalar(uint64(10 + dealer*10 + coefficient))
			blindings[coefficient] = cvTestScalar(uint64(1000 + dealer*10 + coefficient))
		}
		commonCoins := cvTestCoins(chunks, uint64(2000+dealer*chunks))
		scalarCoins := make([][]fr.Element, receivers)
		blindingCoins := make([]fr.Element, receivers)
		for receiver := 0; receiver < receivers; receiver++ {
			scalarCoins[receiver] = append([]fr.Element(nil), commonCoins...)
			blindingCoins[receiver] = cvTestScalar(uint64(3000 + dealer))
		}
		leaves[dealer], err = cvReferenceDealV1(
			context, uint64(dealer), scalars, blindings, scalarCoins, blindingCoins,
		)
		if err != nil {
			b.Fatal(err)
		}
	}
	return context, leaves
}

func benchmarkCVTopologies(b *testing.B, run func(*testing.B, *cvLeafContextV1, []*cvLeafV1)) {
	b.Helper()
	for _, topology := range []struct {
		name       string
		receivers  int
		f          int
		components int
	}{
		{name: "n4_f1_k2", receivers: 4, f: 1, components: 2},
		{name: "n7_f2_k3", receivers: 7, f: 2, components: 3},
	} {
		b.Run(topology.name, func(b *testing.B) {
			context, leaves := cvBenchmarkFixture(b, topology.receivers, topology.f, topology.components)
			run(b, &context, leaves)
		})
	}
}

func BenchmarkCVBoundedDLogCold(b *testing.B) {
	const (
		bound = uint64(4095)
		want  = uint64(2047)
	)
	var target bls12381.G1Affine
	target.ScalarMultiplication(&genG1, new(big.Int).SetUint64(want))

	b.Run("Cold", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			got, ok := cvBoundedDLog(&target, bound)
			if !ok || got != want {
				b.Fatalf("bounded DLog = %d, %v; want %d, true", got, ok, want)
			}
		}
	})

	b.Run("Reuse", func(b *testing.B) {
		solver := cvNewBoundedDLogSolver(bound)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			got, ok := solver.solve(&target)
			if !ok || got != want {
				b.Fatalf("bounded DLog = %d, %v; want %d, true", got, ok, want)
			}
		}
	})
}

func BenchmarkCVSAPVSSM4Materialize(b *testing.B) {
	cfg, leafContext, _, leaves := cvM4Fixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cvMaterializeAndLockAggregateV1(cfg, &leafContext, leaves); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCVVerifyLeafV1(b *testing.B) {
	benchmarkCVTopologies(b, func(b *testing.B, context *cvLeafContextV1, leaves []*cvLeafV1) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := cvVerifyLeafV1(context, leaves[0]); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCVLeafProofParts(b *testing.B) {
	benchmarkCVTopologies(b, func(b *testing.B, _ *cvLeafContextV1, leaves []*cvLeafV1) {
		leaf := leaves[0]
		b.Run("Sharing", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := cvVerifySharingV1(leaf, &leaf.proof.sharing); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("Chunking", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := cvVerifyChunkingV1(leaf, &leaf.proof.chunking); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("ExactRange", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := cvVerifyExactRangeV1(leaf, &leaf.proof.chunking.exactRange); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}

func BenchmarkCVAggV1Current(b *testing.B) {
	benchmarkCVTopologies(b, func(b *testing.B, context *cvLeafContextV1, leaves []*cvLeafV1) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := cvAggV1(context, leaves); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCVAVerV1Current(b *testing.B) {
	benchmarkCVTopologies(b, func(b *testing.B, context *cvLeafContextV1, leaves []*cvLeafV1) {
		agg, err := cvAggV1(context, leaves)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := cvAVerV1(context, agg, leaves); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func cvBenchmarkAcceptedLeaves(b *testing.B, context *cvLeafContextV1, leaves []*cvLeafV1) []*cvVerifiedLeafV1 {
	b.Helper()
	accepted := make([]*cvVerifiedLeafV1, len(leaves))
	for i := range leaves {
		var err error
		accepted[i], err = cvAcceptedLeafV1(context, leaves[i], nil)
		if err != nil {
			b.Fatal(err)
		}
	}
	return accepted
}

func BenchmarkCVAggV1Verified(b *testing.B) {
	benchmarkCVTopologies(b, func(b *testing.B, context *cvLeafContextV1, leaves []*cvLeafV1) {
		accepted := cvBenchmarkAcceptedLeaves(b, context, leaves)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := cvAggVerifiedV1(context, accepted); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCVAVerV1Verified(b *testing.B) {
	benchmarkCVTopologies(b, func(b *testing.B, context *cvLeafContextV1, leaves []*cvLeafV1) {
		agg, err := cvAggV1(context, leaves)
		if err != nil {
			b.Fatal(err)
		}
		accepted := cvBenchmarkAcceptedLeaves(b, context, leaves)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := cvAVerVerifiedV1(context, agg, accepted); err != nil {
				b.Fatal(err)
			}
		}
	})
}
