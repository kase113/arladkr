package core

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestValidateCVEpochConfigRequiresDeployableProfile(t *testing.T) {
	base := NormalizeConfig(Config{
		SID:                      "cv-epoch-config",
		OldCommittee:             []int{0, 1, 2, 3},
		NewCommittee:             []int{4, 5, 6, 7},
		FOld:                     1,
		FNew:                     1,
		APVSSProvider:            "cv-sapvss",
		ARCMode:                  "materialized",
		DeriveMode:               "scalar",
		AgreementKernel:          "commonsubset-tcp",
		AgreementTransport:       "tcp-distributed",
		LocalNodeIDs:             []int{0},
		CVPublicKeyDir:           "/keys/public",
		CVLocalSecretDir:         "/keys/private-0",
		CVLocalReceiverIDs:       []int{4},
		ArtifactCacheDir:         "/state/node-0",
		MaxARCCandidatesPerEpoch: 2,
	})
	if err := validateCVEpochConfig(base); err != nil {
		t.Fatalf("valid CV epoch config rejected: %v", err)
	}
	compact := base
	compact.APVSSFallbackProfile = apvssFallbackCompactBatchProfile
	if err := validateCVEpochConfig(compact); err == nil || !strings.Contains(err.Error(), "experimental") {
		t.Fatalf("compact profile crossed production admission without opt-in: %v", err)
	}
	compact.AllowExperimentalAPVSS = true
	compact.APVSSBenchmarkFallbackCount = compact.FNew
	if err := validateCVEpochConfig(compact); err != nil {
		t.Fatalf("explicit experimental compact profile rejected: %v", err)
	}
	forced := base
	forced.APVSSBenchmarkFallbackCount = 1
	if err := validateCVEpochConfig(forced); err == nil || !strings.Contains(err.Error(), "experimental") {
		t.Fatalf("forced fallback scheduling crossed experimental gate: %v", err)
	}
	waitAll := base
	waitAll.APVSSBenchmarkWaitAllACKs = true
	if err := validateCVEpochConfig(waitAll); err == nil || !strings.Contains(err.Error(), "experimental") {
		t.Fatalf("wait-all ACK scheduling crossed experimental gate: %v", err)
	}
	waitAll.AllowExperimentalAPVSS = true
	if err := validateCVEpochConfig(waitAll); err != nil {
		t.Fatalf("explicit experimental wait-all ACK mode rejected: %v", err)
	}

	tests := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"provider", func(c *Config) { c.APVSSProvider = "optrand" }, "cv-sapvss"},
		{"arc", func(c *Config) { c.ARCMode = "header-only" }, "materialized"},
		{"derive", func(c *Config) { c.DeriveMode = "aggregate" }, "scalar"},
		{"kernel", func(c *Config) { c.AgreementKernel = "dumbomvba-direct" }, "common-subset"},
		{"old node", func(c *Config) { c.LocalNodeIDs = []int{0, 1} }, "one local old node"},
		{"public keys", func(c *Config) { c.CVPublicKeyDir = "" }, "public key directory"},
		{"secret keys", func(c *Config) { c.CVLocalSecretDir = "" }, "secret key directory"},
		{"same key dir", func(c *Config) { c.CVLocalSecretDir = c.CVPublicKeyDir }, "separate"},
		{"receiver", func(c *Config) { c.CVLocalReceiverIDs = nil }, "local receiver"},
		{"store", func(c *Config) { c.ArtifactCacheDir = "" }, "artifact store"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.edit(&cfg)
			err := validateCVEpochConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestNormalizeConfigDefaultsToCVOnlyProfile(t *testing.T) {
	cfg := NormalizeConfig(Config{FOld: 1, FNew: 1})
	if cfg.APVSSProvider != "cv-sapvss" || cfg.ARCMode != "materialized" || cfg.DeriveMode != "scalar" {
		t.Fatalf("default profile = %s/%s/%s", cfg.APVSSProvider, cfg.ARCMode, cfg.DeriveMode)
	}
	if cfg.APVSSFallbackProfile != apvssFallbackExactLaneProfile || cfg.AllowExperimentalAPVSS {
		t.Fatalf("default APVSS fallback profile = %q experimental=%t",
			cfg.APVSSFallbackProfile, cfg.AllowExperimentalAPVSS)
	}
	for _, provider := range []string{"optrand", "bls-pvss", "scalar-shamir"} {
		legacy := NormalizeConfig(Config{
			SID: "legacy", OldCommittee: []int{0}, NewCommittee: []int{1}, APVSSProvider: provider,
		})
		if err := ValidateConfig(legacy); err == nil || !strings.Contains(err.Error(), "provider") {
			t.Fatalf("legacy provider %q error = %v", provider, err)
		}
	}
}

func TestCVReceiptExchangeReturnsCommonKeyAndLocalShares(t *testing.T) {
	cfg, leafContext, receiverSecrets, leaves := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	agg, err := cvAgg(&leafContext, leaves)
	if err != nil {
		t.Fatal(err)
	}
	nodes := sortedUnique(cfg.OldCommittee)
	transport := newCVRouterTestTransport(nodes, 128)
	router, err := newCVSAPVSSRouter(context.Background(), transport, cfg.SID, cfg.Epoch, nodes, nodes, 64)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = router.Close() })
	services := make([]*cvComponentService, len(nodes))
	for i, node := range nodes {
		store, storeErr := newCVComponentLeafStore(t.TempDir())
		if storeErr != nil {
			t.Fatal(storeErr)
		}
		services[i], err = newCVComponentService(context.Background(), cfg, &leafContext, node, transport, router, store)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, service := range services {
			_ = service.Close()
		}
	})

	type result struct {
		shares   map[int][]byte
		receipts map[int][]byte
		key      []byte
		err      error
	}
	results := make(chan result, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		i := i
		go func() {
			shares, receipts, key, exchangeErr := services[i].ExchangeReceipts(
				ctx, agg, cfg.NewCommittee, map[int]fr.Element{i: receiverSecrets[i]},
			)
			results <- result{shares: shares, receipts: receipts, key: key, err: exchangeErr}
		}()
	}
	first, second := <-results, <-results
	for _, got := range []result{first, second} {
		if got.err != nil {
			t.Fatal(got.err)
		}
		if len(got.shares) != 1 || len(got.receipts) < leafContext.sharingDegree+1 {
			t.Fatalf("local shares/verified receipts = %d/%d", len(got.shares), len(got.receipts))
		}
	}
	if !bytes.Equal(first.key, second.key) {
		t.Fatal("valid receipt subsets produced different threshold public keys")
	}
}

func TestRestrictThresholdSignerToLocalMembers(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	cfg.runtime.lockSigner.restrictSigningTo([]int{0})
	if _, err := cfg.runtime.lockSigner.SignShare(0, "test", digest); err != nil {
		t.Fatalf("local signer rejected: %v", err)
	}
	if _, err := cfg.runtime.lockSigner.SignShare(1, "test", digest); err == nil {
		t.Fatal("restricted signer signed for a non-local holder")
	}
}

func TestCVMaterializedAggRLOWitnessRoundTrip(t *testing.T) {
	cfg, leafContext, _, leaves := cvM4Fixture(t)
	materialized, err := cvMaterializeAndLockAggregate(cfg, &leafContext, leaves)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvMaterializedAggRLOWitnessCanonicalBytes(materialized.rlo)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeMaterializedAggRLOWitness(wire, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Digest, materialized.rlo.Digest) ||
		!bytes.Equal(digestAggHeaderForLock(decoded.Header), digestAggHeaderForLock(materialized.rlo.Header)) {
		t.Fatal("materialized AggRLO witness changed its statement")
	}
	if _, err := cvDecodeMaterializedAggRLOWitness(append(wire, 0), cfg); err == nil {
		t.Fatal("accepted materialized AggRLO witness with trailing bytes")
	}

	tampered := cloneAggRLO(materialized.rlo)
	tampered.Lock.Certificate[0] ^= 1
	tampered.Digest = digestAggRLO(*tampered)
	tamperedWire, err := cvMaterializedAggRLOWitnessCanonicalBytes(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeMaterializedAggRLOWitness(tamperedWire, cfg); err == nil {
		t.Fatal("accepted materialized AggRLO witness with an invalid certificate")
	}
	if len(decoded.Lock.ShareSignatures) != 0 || !bytes.Equal(decoded.Lock.Certificate, materialized.rlo.Lock.Certificate) {
		t.Fatal("compact AggRLO witness retained individual ARC shares")
	}
}

func TestCVBuildEpochContextAndRandomDealerLeaf(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	dirs := generateCVReceiverKeysForTest(t, cfg.SID, cfg.NewCommittee)
	material, err := cvLoadReceiverKeyMaterial(
		dirs.public, dirs.secret, cfg.SID, cfg.NewCommittee, []int{cfg.NewCommittee[0]},
	)
	if err != nil {
		t.Fatal(err)
	}
	leafContext, err := cvBuildEpochLeafContext(cfg, material)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(leafContext.dealerSetPolicy, material.registryDigest) {
		t.Fatal("CV epoch context does not bind receiver ID registry digest")
	}
	leaf, err := cvRandomDealerLeaf(leafContext, cfg.LocalNodeIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.dealerID != uint64(cfg.LocalNodeIDs[0]) || !leaf.hasLeafNIZK {
		t.Fatal("random CV dealer leaf has the wrong dealer or proof profile")
	}
	if err := cvVerifyLeaf(&leafContext, leaf); err != nil {
		t.Fatalf("random CV dealer leaf rejected: %v", err)
	}
}

func TestCVBuildEpochContextUsesNewCommitteeFaultThreshold(t *testing.T) {
	receiverIDs := []int{10, 11, 12, 13, 14, 15, 16}
	receiverKeys := make([]bls12381.G1Affine, len(receiverIDs))
	for i := range receiverKeys {
		key, err := cvReceiverPublicKey(cvTestScalar(uint64(i + 1)))
		if err != nil {
			t.Fatal(err)
		}
		receiverKeys[i] = key
	}
	cfg := NormalizeConfig(Config{
		SID:          "cv-asymmetric-thresholds",
		OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: receiverIDs,
		FOld:         1,
		FNew:         2,
	})
	leafContext, err := cvBuildEpochLeafContext(cfg, &cvReceiverKeyMaterial{
		receiverPublicKeys: receiverKeys,
		registryDigest:     make([]byte, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if leafContext.sharingDegree != 2 {
		t.Fatalf("APVSS sharing degree=%d, want f_n=2", leafContext.sharingDegree)
	}
	if leafContext.profile.maxComponents != 2 {
		t.Fatalf("aggregate component bound=%d, want f_o+1=2", leafContext.profile.maxComponents)
	}
}

func TestRunCVEpochRejectsLegacyProfileBeforeNetwork(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	cfg.APVSSProvider = "optrand"
	if _, err := RunCVEpoch(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "cv-sapvss") {
		t.Fatalf("legacy profile error = %v", err)
	}
}

func TestCVRunMaterializedAgreementRejectsMissingLocalRLO(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	cfg.LocalNodeIDs = []int{0}
	if _, _, err := cvRunMaterializedAgreement(context.Background(), cfg, nil); err == nil {
		t.Fatal("materialized agreement accepted a missing local RLO")
	}
}

func TestPrepareCVRuntimeSkipsLegacyPVSSKeyMaterial(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.runtime.receiverStates) != 0 || len(cfg.runtime.vePublicKeys) != 0 ||
		len(cfg.runtime.vePrivateKeys) != 0 || len(cfg.runtime.blsPVSSSecretKeys) != 0 ||
		len(cfg.runtime.blsPVSSPublicKeys) != 0 {
		t.Fatal("CV runtime generated unused legacy PVSS/key-evolution material")
	}
}
