package core

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

func scalarShamirAggRLOFixture(t *testing.T) (Config, map[int]*DealerArtifact, []int, *AggRLO) {
	t.Helper()
	cfg, artifacts := scalarShamirProviderFixture(t)
	cfg.RecoverResponseMode = "local"
	dealers := stableFirst(cfg.runtime.oldOrder, cfg.Kappa)
	agg, err := NewScalarShamirAPVSS().Agg(cfg, dealers, artifacts)
	if err != nil {
		t.Fatalf("build scalar aggregate failed: %v", err)
	}
	rlo, _, err := BuildAggRLO(cfg, dealers, agg)
	if err != nil {
		t.Fatalf("build scalar AggRLO failed: %v", err)
	}
	return cfg, artifacts, dealers, rlo
}

func cloneAggFragResponsesForTest(in []AggFragResponse) []AggFragResponse {
	out := make([]AggFragResponse, len(in))
	for i, response := range in {
		out[i] = AggFragResponse{
			Provider:           response.Provider,
			Dealer:             response.Dealer,
			ContributionDigest: append([]byte(nil), response.ContributionDigest...),
			Payload:            append([]byte(nil), response.Payload...),
			Ciphertexts:        cloneBytesMap(response.Ciphertexts),
		}
	}
	return out
}

func TestScalarShamirAggFragResponsesPreserveExactArtifacts(t *testing.T) {
	cfg, artifacts, dealers, rlo := scalarShamirAggRLOFixture(t)
	responses, err := BuildAggFragResponses(cfg, rlo, artifacts)
	if err != nil {
		t.Fatalf("build scalar AggFrag responses failed: %v", err)
	}
	if len(responses) != len(dealers) {
		t.Fatalf("response count=%d, want %d", len(responses), len(dealers))
	}
	for _, response := range responses {
		artifact := artifacts[response.Dealer]
		if response.Provider != "scalar-shamir" ||
			!bytes.Equal(response.Payload, artifact.Payload) ||
			!reflect.DeepEqual(response.Ciphertexts, artifact.Ciphertexts) ||
			!bytes.Equal(response.ContributionDigest, artifact.ContributionDigest) {
			t.Fatalf("response does not preserve dealer=%d artifact", response.Dealer)
		}
	}
	if err := VerifyAggFragResponses(cfg, rlo, responses, artifacts); err != nil {
		t.Fatalf("verify scalar AggFrag responses failed: %v", err)
	}

	dealer := responses[0].Dealer
	receiver := cfg.runtime.receiverOrder[0]
	tests := []struct {
		name   string
		mutate func([]AggFragResponse) []AggFragResponse
	}{
		{name: "duplicate", mutate: func(in []AggFragResponse) []AggFragResponse {
			return append(in, in[0])
		}},
		{name: "provider", mutate: func(in []AggFragResponse) []AggFragResponse {
			in[0].Provider = "optrand"
			return in
		}},
		{name: "payload", mutate: func(in []AggFragResponse) []AggFragResponse {
			in[0].Payload[0] ^= 1
			return in
		}},
		{name: "ciphertext", mutate: func(in []AggFragResponse) []AggFragResponse {
			in[0].Ciphertexts[receiver][0] ^= 1
			return in
		}},
		{name: "contribution digest", mutate: func(in []AggFragResponse) []AggFragResponse {
			in[0].ContributionDigest[0] ^= 1
			return in
		}},
		{name: "missing dealer", mutate: func(in []AggFragResponse) []AggFragResponse {
			return in[1:]
		}},
		{name: "unexpected dealer", mutate: func(in []AggFragResponse) []AggFragResponse {
			in[0].Dealer = 999
			return in
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bad := test.mutate(cloneAggFragResponsesForTest(responses))
			if err := VerifyAggFragResponses(cfg, rlo, bad, artifacts); err == nil {
				t.Fatalf("accepted %s tampering for dealer=%d", test.name, dealer)
			}
		})
	}
}

func TestCollectAggFragResponses_ScalarShamirNetwork(t *testing.T) {
	cfg, artifacts, dealers, rlo := scalarShamirAggRLOFixture(t)
	cfg.AgreementTransport = "tcp-loopback"
	cfg.RecoverResponseMode = "network"
	responses, err := CollectAggFragResponses(context.Background(), cfg, rlo, artifacts)
	if err != nil {
		t.Fatalf("collect scalar network responses failed: %v", err)
	}
	if len(responses) != len(dealers) {
		t.Fatalf("network response count=%d, want %d", len(responses), len(dealers))
	}
	for _, response := range responses {
		artifact := artifacts[response.Dealer]
		if response.Provider != "scalar-shamir" ||
			!bytes.Equal(response.Payload, artifact.Payload) ||
			!reflect.DeepEqual(response.Ciphertexts, artifact.Ciphertexts) {
			t.Fatalf("network response changed dealer=%d bytes", response.Dealer)
		}
	}
	if err := VerifyAggFragResponses(cfg, rlo, responses, artifacts); err != nil {
		t.Fatalf("verify scalar network responses failed: %v", err)
	}
}

func TestRecoverAndDeriveFromAggRLO_ScalarReturnsDirectVerifiedOutput(t *testing.T) {
	cfg, artifacts, dealers, _ := scalarShamirAggRLOFixture(t)
	recoverOut, err := RecoverAgg(cfg, dealers, artifacts)
	if err != nil {
		t.Fatalf("recover scalar aggregate failed: %v", err)
	}
	gotDealers, gotRecovered, gotShares, gotPublicKey, err := RecoverAndDeriveFromAggRLO(cfg, recoverOut, artifacts)
	if err != nil {
		t.Fatalf("derive direct scalar output failed: %v", err)
	}
	if !reflect.DeepEqual(gotDealers, dealers) ||
		!reflect.DeepEqual(gotShares, recoverOut.Recovered.ScalarShares) ||
		!bytes.Equal(gotPublicKey, recoverOut.Recovered.ThresholdPublicKey) ||
		!bytes.Equal(gotRecovered[-1], recoverOut.Recovered.RecoveredMaterial) {
		t.Fatalf("derive did not return the recovered scalar object directly")
	}

	tests := []struct {
		name   string
		mutate func(*RecoverAggOutput)
	}{
		{name: "threshold", mutate: func(out *RecoverAggOutput) { out.Recovered.ScalarThreshold++ }},
		{name: "missing receiver", mutate: func(out *RecoverAggOutput) { delete(out.Recovered.ScalarShares, cfg.runtime.receiverOrder[0]) }},
		{name: "unknown receiver", mutate: func(out *RecoverAggOutput) { out.Recovered.ScalarShares[999] = []byte{1} }},
		{name: "scalar bytes", mutate: func(out *RecoverAggOutput) { out.Recovered.ScalarShares[cfg.runtime.receiverOrder[0]][0] ^= 1 }},
		{name: "identity public key", mutate: func(out *RecoverAggOutput) {
			identity, marshalErr := edwards25519.NewBlakeSHA256Ed25519().Point().Null().MarshalBinary()
			if marshalErr != nil {
				t.Fatalf("marshal identity failed: %v", marshalErr)
			}
			out.Recovered.ThresholdPublicKey = identity
		}},
		{name: "malformed public key", mutate: func(out *RecoverAggOutput) { out.Recovered.ThresholdPublicKey = []byte{1, 2, 3} }},
		{name: "recovered material", mutate: func(out *RecoverAggOutput) { out.Recovered.RecoveredMaterial[0] ^= 1 }},
		{name: "aggregate digest", mutate: func(out *RecoverAggOutput) { out.Recovered.AggregateDigest[0] ^= 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bad := &RecoverAggOutput{
				AggRLO:    cloneAggRLO(recoverOut.AggRLO),
				Recovered: cloneAPVSSRecovered(recoverOut.Recovered),
			}
			test.mutate(bad)
			if _, _, _, _, err := RecoverAndDeriveFromAggRLO(cfg, bad, artifacts); err == nil {
				t.Fatalf("accepted scalar recovered-object tamper: %s", test.name)
			}
		})
	}
}

func TestRunEpoch_ScalarShamirReconstructsReturnedPublicKey(t *testing.T) {
	cfg := baseTestConfig()
	cfg.APVSSProvider = "scalar-shamir"
	cfg.DeriveMode = "scalar"
	cfg.RecoverResponseMode = "local"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := RunEpoch(ctx, cfg)
	if err != nil {
		t.Fatalf("run scalar-shamir epoch failed: %v", err)
	}
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("initialize scalar test runtime failed: %v", err)
	}
	suite := edwards25519.NewBlakeSHA256Ed25519()
	shares := make([]*share.PriShare, 0, cfg.FNew+1)
	for _, receiver := range cfg.runtime.receiverOrder[:cfg.FNew+1] {
		scalar := suite.Scalar()
		if err := scalar.UnmarshalBinary(result.NewShares[receiver]); err != nil {
			t.Fatalf("decode receiver=%d scalar failed: %v", receiver, err)
		}
		shares = append(shares, &share.PriShare{I: cfg.runtime.receiverIndex[receiver], V: scalar})
	}
	secret, err := share.RecoverSecret(suite, shares, cfg.FNew+1, len(cfg.runtime.receiverOrder))
	if err != nil {
		t.Fatalf("reconstruct epoch scalar failed: %v", err)
	}
	publicKey := suite.Point()
	if err := publicKey.UnmarshalBinary(result.NewPublicKey); err != nil {
		t.Fatalf("decode epoch public key failed: %v", err)
	}
	if !suite.Point().Mul(secret, nil).Equal(publicKey) {
		t.Fatal("epoch scalar shares do not reconstruct the returned public key")
	}
}
