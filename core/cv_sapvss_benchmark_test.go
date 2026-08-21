package core

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func cvBenchmarkFixture(b *testing.B, receivers, f, k int) (cvLeafContext, []*cvLeaf) {
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
	context := cvLeafContext{
		sessionID:                 []byte(fmt.Sprintf("cv-benchmark-n%d-f%d", receivers, f)),
		epoch:                     1,
		sharingDegree:             f,
		profile:                   profile,
		receiverPublicKeys:        receiverKeys,
		receiverSigningPublicKeys: cvTestSigningKeys(b, len(receiverKeys), 29001),
		dealerSetPolicy:           []byte("first-f-plus-one"),
		proofProfile:              cvLeafGrothProofProfile,
	}
	leaves := make([]*cvLeaf, k)
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
		leaves[dealer], err = cvReferenceDeal(
			context, uint64(dealer), scalars, blindings, scalarCoins, blindingCoins,
		)
		if err != nil {
			b.Fatal(err)
		}
	}
	return context, leaves
}

func benchmarkCVTopologies(b *testing.B, run func(*testing.B, *cvLeafContext, []*cvLeaf)) {
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
		if _, err := cvMaterializeAndLockAggregate(cfg, &leafContext, leaves); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCVVerifyLeaf(b *testing.B) {
	benchmarkCVTopologies(b, func(b *testing.B, context *cvLeafContext, leaves []*cvLeaf) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := cvVerifyLeaf(context, leaves[0]); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCVLeafProofParts(b *testing.B) {
	benchmarkCVTopologies(b, func(b *testing.B, _ *cvLeafContext, leaves []*cvLeaf) {
		leaf := leaves[0]
		b.Run("Sharing", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := cvVerifySharing(leaf, &leaf.proof.sharing); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("Chunking", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := cvVerifyChunking(leaf, &leaf.proof.chunking); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("ExactRange", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := cvVerifyExactRange(leaf, &leaf.proof.chunking.exactRange); err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}

func BenchmarkCVAggCurrent(b *testing.B) {
	benchmarkCVTopologies(b, func(b *testing.B, context *cvLeafContext, leaves []*cvLeaf) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := cvAgg(context, leaves); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCVAVerCurrent(b *testing.B) {
	benchmarkCVTopologies(b, func(b *testing.B, context *cvLeafContext, leaves []*cvLeaf) {
		agg, err := cvAgg(context, leaves)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := cvAVer(context, agg, leaves); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func cvBenchmarkAcceptedLeaves(b *testing.B, context *cvLeafContext, leaves []*cvLeaf) []*cvVerifiedLeaf {
	b.Helper()
	accepted := make([]*cvVerifiedLeaf, len(leaves))
	for i := range leaves {
		var err error
		accepted[i], err = cvAcceptedLeaf(context, leaves[i], nil)
		if err != nil {
			b.Fatal(err)
		}
	}
	return accepted
}

func BenchmarkCVAggVerified(b *testing.B) {
	benchmarkCVTopologies(b, func(b *testing.B, context *cvLeafContext, leaves []*cvLeaf) {
		accepted := cvBenchmarkAcceptedLeaves(b, context, leaves)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := cvAggVerified(context, accepted); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCVAVerVerified(b *testing.B) {
	benchmarkCVTopologies(b, func(b *testing.B, context *cvLeafContext, leaves []*cvLeaf) {
		agg, err := cvAgg(context, leaves)
		if err != nil {
			b.Fatal(err)
		}
		accepted := cvBenchmarkAcceptedLeaves(b, context, leaves)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := cvAVerVerified(context, agg, accepted); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCVV2ProposerCatalogVerifyN32(b *testing.B) {
	if os.Getenv("RLADKR_RUN_N32_LOCAL_BENCH") != "1" {
		b.Skip("set RLADKR_RUN_N32_LOCAL_BENCH=1 to build and verify the n=32 catalog fixture")
	}
	oldRoster := make([]int, 32)
	newRoster := make([]int, 32)
	for i := range oldRoster {
		oldRoster[i] = i
		newRoster[i] = 32 + i
	}
	cfg := Config{
		SID: "cv-v2-n32-catalog-benchmark", Epoch: 1,
		OldCommittee: oldRoster, NewCommittee: newRoster,
		OldFaults: 10, NewFaults: 10,
		CVProposerSampleSize: 3, CVValidatorSampleSize: 3,
	}
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		b.Fatal(err)
	}
	if params.poolSize != 22 {
		b.Fatalf("n=32 pool size=%d, want 22", params.poolSize)
	}

	keyRoot := b.TempDir()
	receiverPublic := filepath.Join(keyRoot, "receiver-public")
	receiverSecret := filepath.Join(keyRoot, "receiver-secret")
	if err := cvGenerateReceiverRegistryV2(receiverPublic, receiverSecret, cfg.SID, uint64(cfg.Epoch), newRoster); err != nil {
		b.Fatal(err)
	}
	receivers, err := cvLoadReceiverRegistryV2(
		receiverPublic, receiverSecret, cfg.SID, uint64(cfg.Epoch), newRoster, newRoster,
	)
	if err != nil {
		b.Fatal(err)
	}
	validatorPublic := filepath.Join(keyRoot, "validator-public")
	validatorSecret := filepath.Join(keyRoot, "validator-secret")
	if err := cvGenerateValidatorRegistryV2(validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), oldRoster); err != nil {
		b.Fatal(err)
	}
	validators, err := cvLoadValidatorRegistryV2(
		validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), oldRoster, oldRoster,
	)
	if err != nil {
		b.Fatal(err)
	}
	leafContext := &cvLeafContextV2{
		SID: cfg.SID, Epoch: uint64(cfg.Epoch),
		OldRoster: append([]int(nil), oldRoster...), NewRoster: append([]int(nil), newRoster...),
		ReceiverRegistryDigest: append([]byte(nil), receivers.registryDigest...),
		SharingDegree:          params.newShareDegree,
		Profile:                cvChunkProfile{chunkBits: 8, maxComponents: params.componentCount},
	}
	components := make([]cvComponentVerificationResultV2, params.poolSize)
	for i := range components {
		leaf, buildErr := cvBuildReferenceAllACKLeafV2(oldRoster[i], leafContext, receivers, validators)
		if buildErr != nil {
			b.Fatalf("build component %d: %v", i, buildErr)
		}
		payload, encodeErr := cvLeafV2CanonicalBytesAfterValidation(leaf, receivers, validators)
		if encodeErr != nil {
			b.Fatalf("encode component %d: %v", i, encodeErr)
		}
		components[i] = cvComponentVerificationResultV2{
			ref:     cvComponentRefV2{Header: cvComponentHeaderV2{DealerID: oldRoster[i]}},
			payload: payload,
		}
	}
	service := &cvAPDBNetworkServiceV2{cfg: cvAPDBNetworkServiceConfigV2{
		LeafContext: leafContext, Receivers: receivers, Validators: validators,
	}}
	previousProcs := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previousProcs)
	b.Setenv("RLADKR_LEAF_VERIFY_WORKERS", "4")
	b.ReportAllocs()
	b.ReportMetric(float64(len(components)), "components/op")
	refs := make([]cvComponentRefV2, len(components))
	for index := range components {
		refs[index] = components[index].ref
	}
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		verified, _ := cvRunComponentPipelineV2(
			refs, 1, cvLeafVerifyWorkers(len(components)),
			func(ref cvComponentRefV2) cvComponentVerificationResultV2 {
				return components[ref.Header.DealerID]
			},
			service.verifyRecoveredComponentV2,
		)
		for i := range verified {
			if verified[i].verifyErr != nil || verified[i].leaf == nil {
				b.Fatalf("verify component %d: %v", i, verified[i].verifyErr)
			}
		}
	}
}

func BenchmarkCVV2ReceiverEvaluationVerificationN127(b *testing.B) {
	if os.Getenv("RLADKR_RUN_N127_EVAL_BENCH") != "1" {
		b.Skip("set RLADKR_RUN_N127_EVAL_BENCH=1 to benchmark n=127 receiver evaluation verification")
	}
	const (
		n = 127
		f = 42
	)
	oldRoster := make([]int, n)
	newRoster := make([]int, n)
	for index := range oldRoster {
		oldRoster[index] = index
		newRoster[index] = n + index
	}
	context := &cvLeafContextV2{
		SID: "cv-v2-n127-evaluation-benchmark", Epoch: 1,
		OldRoster: oldRoster, NewRoster: newRoster,
		ReceiverRegistryDigest: hashBytes([]byte("cv-v2-n127-evaluation-benchmark-registry")),
		SharingDegree:          n - f - 1,
		Profile:                cvChunkProfile{chunkBits: 8, maxComponents: f + 1},
	}
	commitments := make([]bls12381.G1Affine, context.SharingDegree+1)
	for index := range commitments {
		var scalar fr.Element
		if _, err := scalar.SetRandom(); err != nil {
			b.Fatal(err)
		}
		commitments[index] = cvPointTimes(&genG1, &scalar)
	}
	evaluations := make([]bls12381.G1Affine, n)
	for index := range evaluations {
		evaluations[index] = cvEvaluateCommitments(commitments, index+1)
	}
	previousProcs := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previousProcs)

	b.Run("batch", func(b *testing.B) {
		b.ReportAllocs()
		for iteration := 0; iteration < b.N; iteration++ {
			if err := cvVerifyReceiverEvaluationsBatchV2(context, 0, commitments, evaluations, false); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("exact", func(b *testing.B) {
		b.ReportAllocs()
		for iteration := 0; iteration < b.N; iteration++ {
			if err := cvVerifyReceiverEvaluationsExactV2(commitments, evaluations); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCVV2OwnershipVerificationN127(b *testing.B) {
	if os.Getenv("RLADKR_RUN_N127_OWNERSHIP_BENCH") != "1" {
		b.Skip("set RLADKR_RUN_N127_OWNERSHIP_BENCH=1 to benchmark n=127 ownership verification")
	}
	const (
		n = 127
		f = 42
	)
	oldRoster := make([]int, n)
	newRoster := make([]int, n)
	for index := range oldRoster {
		oldRoster[index] = index
		newRoster[index] = n + index
	}
	context := &cvLeafContextV2{
		SID: "cv-v2-n127-ownership-benchmark", Epoch: 1,
		OldRoster: oldRoster, NewRoster: newRoster,
		ReceiverRegistryDigest: hashBytes([]byte("cv-v2-n127-ownership-benchmark-registry")),
		SharingDegree:          n - f - 1,
		Profile:                cvChunkProfile{chunkBits: 8, maxComponents: f + 1},
	}
	offers := make([]*cvReceiverLaneOfferV2, n)
	publicKeys := make([]bls12381.G1Affine, n)
	for index := range offers {
		secret := cvTestScalar(uint64(index + 1))
		publicKey, err := cvReceiverPublicKey(secret)
		if err != nil {
			b.Fatal(err)
		}
		publicKeys[index] = publicKey
		scalar := cvTestScalar(uint64(1000 + index))
		blinding := cvTestScalar(uint64(2000 + index))
		offers[index], _, err = cvEncryptReceiverLanesV2(
			context, oldRoster[0], newRoster[index], index+1,
			&publicKeys[index], scalar, blinding,
		)
		if err != nil {
			b.Fatal(err)
		}
	}
	previousProcs := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previousProcs)

	b.Run("batch", func(b *testing.B) {
		b.ReportAllocs()
		for iteration := 0; iteration < b.N; iteration++ {
			if err := cvVerifyOwnershipBatchV2(context, oldRoster[0], offers, publicKeys, false); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("exact", func(b *testing.B) {
		b.ReportAllocs()
		for iteration := 0; iteration < b.N; iteration++ {
			for index := range offers {
				if err := cvVerifyOwnershipAfterPointDecodingV2(
					context, oldRoster[0], offers[index], &publicKeys[index],
				); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}
