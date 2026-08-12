package core

import (
	"bytes"
	"math/big"
	"testing"
)

func cvV2ParamsTestConfig() Config {
	return Config{
		SID:                   "cv-v2-params",
		Epoch:                 1,
		OldCommittee:          []int{0, 1, 2, 3, 4, 5, 6},
		NewCommittee:          []int{10, 11, 12, 13},
		OldFaults:             2,
		NewFaults:             1,
		CVProposerSampleSize:  3,
		CVValidatorSampleSize: 3,
	}
}

func TestCVDeriveV2ParamsUsesExplicitFaultBounds(t *testing.T) {
	params, err := cvDeriveV2Params(cvV2ParamsTestConfig())
	if err != nil {
		t.Fatalf("derive V2 params: %v", err)
	}
	if params.componentCount != 3 || params.poolSize != 5 ||
		params.apdbLockThreshold != 5 || params.decisionThreshold != 5 ||
		params.recoveryThreshold != 3 || params.newShareDegree != 2 ||
		params.newShareThreshold != 3 || params.validatorThreshold != 2 {
		t.Fatalf("unexpected V2 threshold derivation: %+v", params)
	}
	if params.proposerFailureBound.Sign() != 0 {
		t.Fatalf("proposer failure probability = %s, want 0", params.proposerFailureBound)
	}
	wantValidatorFailure := big.NewRat(1, 7)
	if params.validatorFailureBound.Cmp(wantValidatorFailure) != 0 {
		t.Fatalf("validator failure probability = %s, want %s", params.validatorFailureBound, wantValidatorFailure)
	}
}

func TestCVDeriveV2ParamsRejectsImplicitSamplesAndConflictingFaultBounds(t *testing.T) {
	missingSamples := cvV2ParamsTestConfig()
	missingSamples.CVProposerSampleSize = 0
	if _, err := cvDeriveV2Params(missingSamples); err == nil {
		t.Fatal("accepted V2 parameters with an implicit proposer sample size")
	}

	conflict := cvV2ParamsTestConfig()
	conflict.FOld = 1
	if _, err := cvDeriveV2Params(conflict); err == nil {
		t.Fatal("accepted conflicting legacy and V2 old fault bounds")
	}
}

func TestCVV2StartupAcceptsAuditedAggregatedRangeBackend(t *testing.T) {
	if _, err := cvValidateV2Startup(cvV2ParamsTestConfig()); err != nil {
		t.Fatalf("V2 startup rejected aggregated range backend: %v", err)
	}
}

func TestCVV2ProtocolVersionRejectsLegacyContextWire(t *testing.T) {
	if cvSAPVSSV2ProtocolVersion != "cv-sapvss-v2-scalar-group" {
		t.Fatalf("unexpected CV V2 protocol label %q", cvSAPVSSV2ProtocolVersion)
	}
	context := &cvLeafContextV2{
		SID: "cv-v2-version", Epoch: 1, OldRoster: []int{0}, NewRoster: []int{1},
		ReceiverRegistryDigest: hashBytes([]byte("cv-v2-version-registry")),
		SharingDegree:          0,
		Profile:                cvChunkProfile{chunkBits: 8, maxComponents: 1},
	}
	wire, err := cvLeafContextV2CanonicalBytes(context)
	if err != nil {
		t.Fatal(err)
	}
	const legacyDomain = "ARL-CV-sAPVSS/v2/leaf-context"
	var legacy bytes.Buffer
	if err := cvWriteBytes(&legacy, []byte(legacyDomain)); err != nil {
		t.Fatal(err)
	}
	currentPrefixBytes := 4 + len(cvLeafContextWireDomainV2)
	if len(wire) <= currentPrefixBytes {
		t.Fatal("invalid current CV V2 context wire")
	}
	legacy.Write(wire[currentPrefixBytes:])
	if _, err := cvDecodeLeafContextV2(legacy.Bytes()); err == nil {
		t.Fatal("accepted legacy dual-lane CV V2 context wire")
	}
}

func TestCVV2ValidatorFailureBoundUsesExactIntegerArithmetic(t *testing.T) {
	got, err := cvV2ValidatorFailureBound(7, 2, 3, 2)
	if err != nil {
		t.Fatalf("compute validator failure bound: %v", err)
	}
	if got.Cmp(big.NewRat(1, 7)) != 0 {
		t.Fatalf("validator failure probability = %s, want 1/7", got)
	}
}
