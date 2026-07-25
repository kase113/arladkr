package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"testing"

	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

func TestScalarShamirDealerArtifactUsesProviderLocalSchemaV1(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:           "scalar-shamir-transcript-test",
		Epoch:         1,
		OldCommittee:  []int{3, 1, 2, 0},
		NewCommittee:  []int{13, 10, 12, 11},
		FOld:          1,
		FNew:          1,
		APVSSProvider: "scalar-shamir",
	})
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure runtime failed: %v", err)
	}
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("build scalar-shamir artifacts failed: %v", err)
	}
	art := artifacts[cfg.runtime.oldOrder[0]]
	transcript, err := decodeDealerTranscript(art.Payload)
	if err != nil {
		t.Fatalf("decode scalar-shamir transcript failed: %v", err)
	}
	if transcript.Version != 1 {
		t.Fatalf("transcript schema version=%d, want 1", transcript.Version)
	}
	if transcript.Provider != "scalar-shamir" {
		t.Fatalf("transcript provider=%q, want scalar-shamir", transcript.Provider)
	}
	if transcript.Threshold != cfg.FNew+1 {
		t.Fatalf("transcript threshold=%d, want %d", transcript.Threshold, cfg.FNew+1)
	}
	if !reflect.DeepEqual(transcript.ReceiverIDs, cfg.runtime.receiverOrder) {
		t.Fatalf("receiver IDs=%v, want runtime order %v", transcript.ReceiverIDs, cfg.runtime.receiverOrder)
	}
	wantMetadata := hashBytes(
		[]byte("rladkr-transcript-meta"),
		[]byte(cfg.SID),
		[]byte("|epoch=1"),
	)
	if !bytesEq(transcript.MetadataHash, wantMetadata) {
		t.Fatalf("metadata hash mismatch")
	}

	receiver := cfg.runtime.receiverOrder[0]
	payload, packets, err := buildDealerTranscript(cfg, art.Dealer)
	if err != nil {
		t.Fatalf("build scalar-shamir transcript packets failed: %v", err)
	}
	if !bytesEq(payload, art.Payload) {
		t.Fatalf("artifact payload differs from deterministic scalar-shamir transcript")
	}
	packet := packets[receiver]
	var wire dealerShareWire
	if err := json.Unmarshal(packet, &wire); err != nil {
		t.Fatalf("decode scalar-shamir share wire failed: %v", err)
	}
	if wire.Version != 1 || wire.Provider != "scalar-shamir" {
		t.Fatalf("share packet identity=(%q,%d), want (scalar-shamir,1)", wire.Provider, wire.Version)
	}
	if _, err := decodeDealerSharePacket(packet); err != nil {
		t.Fatalf("scalar schema-v1 share packet rejected: %v", err)
	}
	openedPacket, err := openSharePacketForReceiver(
		cfg,
		art.Dealer,
		receiver,
		art.Descriptor.Header.Root,
		art.Ciphertexts[receiver],
	)
	if err != nil {
		t.Fatalf("open scalar-shamir artifact ciphertext failed: %v", err)
	}
	openedShare, err := decodeDealerSharePacket(openedPacket)
	if err != nil {
		t.Fatalf("decode opened scalar-shamir share failed: %v", err)
	}
	if openedShare.Version != 1 || openedShare.Provider != "scalar-shamir" {
		t.Fatalf("opened scalar share identity=(%q,%d), want (scalar-shamir,1)", openedShare.Provider, openedShare.Version)
	}
}

func TestScalarShamirVEEnvelopeBindsProviderLocalSchemaV1(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.APVSSProvider = "scalar-shamir"
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure runtime failed: %v", err)
	}
	dealer := cfg.runtime.oldOrder[0]
	receiver := cfg.runtime.receiverOrder[0]
	payload, packets, err := buildDealerTranscript(cfg, dealer)
	if err != nil {
		t.Fatalf("build scalar-shamir packets failed: %v", err)
	}
	root := hashBytes([]byte("rladkr-root"), payload)
	inner, err := veEncryptSharePacket(cfg, dealer, receiver, root, packets[receiver])
	if err != nil {
		t.Fatalf("VE encrypt scalar-shamir packet failed: %v", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(inner, &object); err != nil {
		t.Fatalf("decode VE envelope object failed: %v", err)
	}
	var shareVersion int
	rawVersion, ok := object["share_version"]
	if !ok {
		t.Fatalf("scalar-shamir VE envelope omitted share_version")
	}
	if err := json.Unmarshal(rawVersion, &shareVersion); err != nil {
		t.Fatalf("decode VE share_version failed: %v", err)
	}
	if shareVersion != 1 {
		t.Fatalf("VE share_version=%d, want 1", shareVersion)
	}
	var shareProvider string
	rawProvider, ok := object["share_provider"]
	if !ok {
		t.Fatalf("scalar-shamir VE envelope omitted share_provider")
	}
	if err := json.Unmarshal(rawProvider, &shareProvider); err != nil {
		t.Fatalf("decode VE share_provider failed: %v", err)
	}
	if shareProvider != "scalar-shamir" {
		t.Fatalf("VE share_provider=%q, want scalar-shamir", shareProvider)
	}
	for _, tc := range []struct {
		name  string
		field string
		value json.RawMessage
	}{
		{name: "version", field: "share_version", value: json.RawMessage("2")},
		{name: "provider", field: "share_provider", value: json.RawMessage(`"optrand"`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := make(map[string]json.RawMessage, len(object))
			for key, value := range object {
				mutated[key] = append(json.RawMessage(nil), value...)
			}
			mutated[tc.field] = tc.value
			tampered, err := json.Marshal(mutated)
			if err != nil {
				t.Fatalf("marshal tampered VE envelope failed: %v", err)
			}
			if _, err := veDecryptSharePacket(cfg, dealer, receiver, root, tampered); err == nil {
				t.Fatalf("tampered scalar-shamir %s accepted", tc.field)
			}
		})
	}
}

func TestScalarShamirVERejectsLegacySchemaV1Packet(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.APVSSProvider = "scalar-shamir"
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure runtime failed: %v", err)
	}
	dealer := cfg.runtime.oldOrder[0]
	receiver := cfg.runtime.receiverOrder[0]
	payload, packets, err := buildDealerTranscript(cfg, dealer)
	if err != nil {
		t.Fatalf("build scalar-shamir packets failed: %v", err)
	}
	var downgraded dealerShareWire
	if err := json.Unmarshal(packets[receiver], &downgraded); err != nil {
		t.Fatalf("decode scalar-shamir packet failed: %v", err)
	}
	downgraded.Provider = ""
	legacyPacket, err := json.Marshal(downgraded)
	if err != nil {
		t.Fatalf("marshal downgraded packet failed: %v", err)
	}
	decoded, err := decodeDealerSharePacket(legacyPacket)
	if err != nil {
		t.Fatalf("decode legacy schema-v1 packet failed: %v", err)
	}
	if decoded.Version != 1 || decoded.Provider != "" {
		t.Fatalf("legacy packet identity=(%q,%d), want (empty,1)", decoded.Provider, decoded.Version)
	}

	root := hashBytes([]byte("rladkr-root"), payload)
	if _, err := veEncryptSharePacket(cfg, dealer, receiver, root, legacyPacket); err == nil {
		t.Fatalf("scalar-shamir VE accepted legacy schema-v1 packet")
	}
}

func TestScalarShamirVERejectsValidLegacyV1Envelope(t *testing.T) {
	optrandCfg := NormalizeConfig(baseTestConfig())
	if err := ensureRuntime(&optrandCfg); err != nil {
		t.Fatalf("ensure optrand runtime failed: %v", err)
	}
	scalarCfg := NormalizeConfig(baseTestConfig())
	scalarCfg.APVSSProvider = "scalar-shamir"
	if err := ensureRuntime(&scalarCfg); err != nil {
		t.Fatalf("ensure scalar-shamir runtime failed: %v", err)
	}
	dealer := optrandCfg.runtime.oldOrder[0]
	receiver := optrandCfg.runtime.receiverOrder[0]
	payload, packets, err := buildDealerTranscript(optrandCfg, dealer)
	if err != nil {
		t.Fatalf("build optrand packets failed: %v", err)
	}
	root := hashBytes([]byte("rladkr-root"), payload)
	inner, err := veEncryptSharePacket(optrandCfg, dealer, receiver, root, packets[receiver])
	if err != nil {
		t.Fatalf("VE encrypt valid optrand v1 packet failed: %v", err)
	}
	if _, err := veDecryptSharePacket(optrandCfg, dealer, receiver, root, inner); err != nil {
		t.Fatalf("optrand VE rejected valid v1 envelope: %v", err)
	}
	if _, err := veDecryptSharePacket(scalarCfg, dealer, receiver, root, inner); err == nil {
		t.Fatalf("scalar-shamir VE accepted valid legacy v1 envelope")
	}
}

func TestScalarShamirDealerStreamIsSeparatedFromLegacyOptrand(t *testing.T) {
	optrandCfg := NormalizeConfig(baseTestConfig())
	if err := ensureRuntime(&optrandCfg); err != nil {
		t.Fatalf("ensure optrand runtime failed: %v", err)
	}
	scalarCfg := NormalizeConfig(baseTestConfig())
	scalarCfg.APVSSProvider = "scalar-shamir"
	if err := ensureRuntime(&scalarCfg); err != nil {
		t.Fatalf("ensure scalar-shamir runtime failed: %v", err)
	}
	dealer := optrandCfg.runtime.oldOrder[0]
	optrandPayload, _, err := buildDealerTranscript(optrandCfg, dealer)
	if err != nil {
		t.Fatalf("build optrand transcript failed: %v", err)
	}
	scalarPayload, _, err := buildDealerTranscript(scalarCfg, dealer)
	if err != nil {
		t.Fatalf("build scalar-shamir transcript failed: %v", err)
	}
	var optrandWire, scalarWire dealerTranscriptWire
	if err := json.Unmarshal(optrandPayload, &optrandWire); err != nil {
		t.Fatalf("decode optrand wire failed: %v", err)
	}
	if err := json.Unmarshal(scalarPayload, &scalarWire); err != nil {
		t.Fatalf("decode scalar-shamir wire failed: %v", err)
	}
	wantLegacy := expectedLegacyOptrandCommitmentsForTest(t, optrandCfg, dealer)
	if !reflect.DeepEqual(optrandWire.Commitments, wantLegacy) {
		t.Fatalf("legacy optrand deterministic stream output changed")
	}
	if optrandWire.Commitments[0] == scalarWire.Commitments[0] {
		t.Fatalf("scalar-shamir and optrand derived the same secret commitment")
	}
}

func TestScalarShamirUsesProviderNeutralSharedModules(t *testing.T) {
	source, err := os.ReadFile("apvss_scalar_shamir_provider.go")
	if err != nil {
		t.Fatalf("read scalar provider source failed: %v", err)
	}
	for _, forbidden := range []string{
		"OptrandAggregatedTranscript",
		"OptrandTranscript",
		"buildSingleDealerArtifactOptrand",
	} {
		if bytes.Contains(source, []byte(forbidden)) {
			t.Fatalf("scalar provider depends on legacy implementation name %q", forbidden)
		}
	}
}

func expectedLegacyOptrandCommitmentsForTest(t *testing.T, cfg Config, dealer int) []string {
	t.Helper()
	suite := edwards25519.NewBlakeSHA256Ed25519()
	threshold := len(cfg.runtime.receiverOrder) - cfg.FNew
	if threshold < 1 {
		threshold = 1
	}
	if threshold > len(cfg.runtime.receiverOrder) {
		threshold = len(cfg.runtime.receiverOrder)
	}
	stream := deterministicStream(
		"rladkr-dealer-shamir",
		[]byte(cfg.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d", cfg.Epoch, dealer)),
		encodeInts(cfg.runtime.receiverOrder),
	)
	secret := suite.Scalar().Pick(stream)
	priPoly := share.NewPriPoly(suite, threshold, secret, stream)
	_, commitments := priPoly.Commit(suite.Point().Base()).Info()
	out := make([]string, 0, len(commitments))
	for _, commitment := range commitments {
		raw, err := commitment.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal expected optrand commitment failed: %v", err)
		}
		out = append(out, hex.EncodeToString(raw))
	}
	return out
}

func TestDecodeDealerTranscriptEnforcesVersionProviderAndUniqueReceivers(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.APVSSProvider = "scalar-shamir"
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure runtime failed: %v", err)
	}
	payload, _, err := buildDealerTranscript(cfg, cfg.runtime.oldOrder[0])
	if err != nil {
		t.Fatalf("build transcript failed: %v", err)
	}
	var valid dealerTranscriptWire
	if err := json.Unmarshal(payload, &valid); err != nil {
		t.Fatalf("decode transcript wire failed: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*dealerTranscriptWire)
	}{
		{name: "unsupported global v2", mutate: func(w *dealerTranscriptWire) { w.Version = 2 }},
		{name: "scalar schema v1 declares other provider", mutate: func(w *dealerTranscriptWire) { w.Provider = "optrand" }},
		{name: "duplicate receiver", mutate: func(w *dealerTranscriptWire) { w.ReceiverIDs[1] = w.ReceiverIDs[0] }},
		{name: "invalid metadata hash", mutate: func(w *dealerTranscriptWire) { w.MetadataHash = "not-hex" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := valid
			wire.ReceiverIDs = append([]int(nil), valid.ReceiverIDs...)
			tt.mutate(&wire)
			bad, err := json.Marshal(wire)
			if err != nil {
				t.Fatalf("marshal mutated transcript failed: %v", err)
			}
			if _, err := decodeDealerTranscript(bad); err == nil {
				t.Fatalf("expected transcript rejection")
			}
		})
	}
}

func TestDecodeDealerTranscriptEnforcesCanonicalProviderField(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure runtime failed: %v", err)
	}
	payload, _, err := buildDealerTranscript(cfg, cfg.runtime.oldOrder[0])
	if err != nil {
		t.Fatalf("build v1 transcript failed: %v", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatalf("decode v1 transcript object failed: %v", err)
	}
	tests := []struct {
		name          string
		version       string
		providerValue string
	}{
		{name: "v1 empty", version: "1", providerValue: `""`},
		{name: "v1 null", version: "1", providerValue: `null`},
		{name: "unsupported v2 empty", version: "2", providerValue: `""`},
		{name: "unsupported v2 null", version: "2", providerValue: `null`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			object["v"] = json.RawMessage(tt.version)
			object["provider"] = json.RawMessage(tt.providerValue)
			withProvider, err := json.Marshal(object)
			if err != nil {
				t.Fatalf("marshal explicit provider failed: %v", err)
			}
			if _, err := decodeDealerTranscript(withProvider); err == nil {
				t.Fatalf("v%s transcript accepted explicit provider=%s", tt.version, tt.providerValue)
			}
		})
	}
}

func TestDecodeDealerTranscriptRejectsNonCanonicalCommitments(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.APVSSProvider = "scalar-shamir"
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure runtime failed: %v", err)
	}
	payload, _, err := buildDealerTranscript(cfg, cfg.runtime.oldOrder[0])
	if err != nil {
		t.Fatalf("build transcript failed: %v", err)
	}
	var valid dealerTranscriptWire
	if err := json.Unmarshal(payload, &valid); err != nil {
		t.Fatalf("decode transcript wire failed: %v", err)
	}
	nullRaw, err := edwards25519.NewBlakeSHA256Ed25519().Point().Null().MarshalBinary()
	if err != nil {
		t.Fatalf("marshal identity point failed: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*dealerTranscriptWire)
	}{
		{name: "identity commitment", mutate: func(w *dealerTranscriptWire) {
			w.Commitments[0] = hex.EncodeToString(nullRaw)
		}},
		{name: "malformed commitment", mutate: func(w *dealerTranscriptWire) {
			w.Commitments[0] = hex.EncodeToString([]byte{1, 2, 3})
		}},
		{name: "commitment count mismatch", mutate: func(w *dealerTranscriptWire) {
			w.Commitments = w.Commitments[:len(w.Commitments)-1]
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := valid
			wire.Commitments = append([]string(nil), valid.Commitments...)
			tt.mutate(&wire)
			bad, err := json.Marshal(wire)
			if err != nil {
				t.Fatalf("marshal mutated transcript failed: %v", err)
			}
			if _, err := decodeDealerTranscript(bad); err == nil {
				t.Fatalf("accepted %s", tt.name)
			}
		})
	}
}

func TestDecodeDealerTranscriptRejectsCanonicalSmallOrderCommitment(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.APVSSProvider = "scalar-shamir"
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure runtime failed: %v", err)
	}
	payload, _, err := buildDealerTranscript(cfg, cfg.runtime.oldOrder[0])
	if err != nil {
		t.Fatalf("build transcript failed: %v", err)
	}
	var wire dealerTranscriptWire
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatalf("decode transcript wire failed: %v", err)
	}

	orderTwo := bytes.Repeat([]byte{0xff}, 32)
	orderTwo[0] = 0xec
	orderTwo[31] = 0x7f
	suite := edwards25519.NewBlakeSHA256Ed25519()
	point := suite.Point()
	if err := point.UnmarshalBinary(orderTwo); err != nil {
		t.Fatalf("decode canonical order-2 point failed: %v", err)
	}
	canonical, err := point.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal canonical order-2 point failed: %v", err)
	}
	if !bytes.Equal(orderTwo, canonical) {
		t.Fatalf("order-2 test point is not canonically encoded")
	}
	if point.Equal(suite.Point().Null()) {
		t.Fatalf("order-2 test point unexpectedly equals identity")
	}

	wire.Commitments[0] = hex.EncodeToString(orderTwo)
	bad, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal transcript with order-2 commitment failed: %v", err)
	}
	if _, err := decodeDealerTranscript(bad); err == nil {
		t.Fatalf("accepted canonical non-identity small-order commitment")
	}
}

func TestDecodeDealerTranscriptRejectsNonCanonicalJSON(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.APVSSProvider = "scalar-shamir"
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure runtime failed: %v", err)
	}
	payload, _, err := buildDealerTranscript(cfg, cfg.runtime.oldOrder[0])
	if err != nil {
		t.Fatalf("build transcript failed: %v", err)
	}
	for _, tt := range nonCanonicalJSONVariantsForTest(t, payload) {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeDealerTranscript(tt.payload); err == nil {
				t.Fatalf("accepted non-canonical transcript JSON")
			}
		})
	}
}

func TestDecodeDealerTranscriptRejectsInvalidBoundsAndEncodings(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.APVSSProvider = "scalar-shamir"
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure runtime failed: %v", err)
	}
	payload, _, err := buildDealerTranscript(cfg, cfg.runtime.oldOrder[0])
	if err != nil {
		t.Fatalf("build transcript failed: %v", err)
	}
	var valid dealerTranscriptWire
	if err := json.Unmarshal(payload, &valid); err != nil {
		t.Fatalf("decode transcript wire failed: %v", err)
	}
	nonCanonicalPoint := nonCanonicalPointEncodingForTest(t)

	tests := []struct {
		name   string
		mutate func(*dealerTranscriptWire)
	}{
		{name: "short metadata hash", mutate: func(w *dealerTranscriptWire) {
			w.MetadataHash = hex.EncodeToString(make([]byte, 31))
		}},
		{name: "long metadata hash", mutate: func(w *dealerTranscriptWire) {
			w.MetadataHash = hex.EncodeToString(make([]byte, 33))
		}},
		{name: "threshold above receiver count", mutate: func(w *dealerTranscriptWire) {
			w.Threshold = len(w.ReceiverIDs) + 1
			for len(w.Commitments) < w.Threshold {
				w.Commitments = append(w.Commitments, w.Commitments[0])
			}
		}},
		{name: "non-canonical point encoding", mutate: func(w *dealerTranscriptWire) {
			w.Commitments[0] = hex.EncodeToString(nonCanonicalPoint)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := valid
			wire.Commitments = append([]string(nil), valid.Commitments...)
			tt.mutate(&wire)
			bad, err := json.Marshal(wire)
			if err != nil {
				t.Fatalf("marshal mutated transcript failed: %v", err)
			}
			if _, err := decodeDealerTranscript(bad); err == nil {
				t.Fatalf("accepted %s", tt.name)
			}
		})
	}
}

func TestDecodeDealerSharePacketAcceptsProviderLocalSchemaV1Pairs(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure runtime failed: %v", err)
	}
	_, packets, err := buildDealerTranscript(cfg, cfg.runtime.oldOrder[0])
	if err != nil {
		t.Fatalf("build transcript failed: %v", err)
	}
	var wire dealerShareWire
	if err := json.Unmarshal(packets[cfg.runtime.receiverOrder[0]], &wire); err != nil {
		t.Fatalf("decode share wire failed: %v", err)
	}
	for _, identity := range []struct {
		name     string
		provider string
		version  int
	}{
		{name: "legacy optrand", provider: "", version: 1},
		{name: "scalar shamir", provider: "scalar-shamir", version: 1},
	} {
		wire.Provider = identity.provider
		wire.Version = identity.version
		payload, err := json.Marshal(wire)
		if err != nil {
			t.Fatalf("marshal %s share failed: %v", identity.name, err)
		}
		if _, err := decodeDealerSharePacket(payload); err != nil {
			t.Fatalf("%s schema pair rejected: %v", identity.name, err)
		}
	}
	for _, identity := range []struct {
		provider string
		version  int
	}{
		{provider: "", version: 0},
		{provider: "", version: 2},
		{provider: "scalar-shamir", version: 2},
		{provider: "optrand", version: 1},
	} {
		wire.Provider = identity.provider
		wire.Version = identity.version
		payload, err := json.Marshal(wire)
		if err != nil {
			t.Fatalf("marshal invalid share identity failed: %v", err)
		}
		if _, err := decodeDealerSharePacket(payload); err == nil {
			t.Fatalf("unsupported share identity=(%q,%d) accepted", identity.provider, identity.version)
		}
	}
}

func TestDecodeDealerSharePacketRejectsNonCanonicalJSON(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.APVSSProvider = "scalar-shamir"
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure runtime failed: %v", err)
	}
	_, packets, err := buildDealerTranscript(cfg, cfg.runtime.oldOrder[0])
	if err != nil {
		t.Fatalf("build transcript failed: %v", err)
	}
	packet := packets[cfg.runtime.receiverOrder[0]]
	for _, tt := range nonCanonicalJSONVariantsForTest(t, packet) {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeDealerSharePacket(tt.payload); err == nil {
				t.Fatalf("accepted non-canonical share packet JSON")
			}
		})
	}
}

func TestDecodeDealerSharePacketRejectsInvalidDigestAndScalarEncoding(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.APVSSProvider = "scalar-shamir"
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure runtime failed: %v", err)
	}
	_, packets, err := buildDealerTranscript(cfg, cfg.runtime.oldOrder[0])
	if err != nil {
		t.Fatalf("build transcript failed: %v", err)
	}
	var valid dealerShareWire
	if err := json.Unmarshal(packets[cfg.runtime.receiverOrder[0]], &valid); err != nil {
		t.Fatalf("decode share wire failed: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*dealerShareWire)
	}{
		{name: "short transcript digest", mutate: func(w *dealerShareWire) {
			w.TranscriptDigest = hex.EncodeToString(make([]byte, 31))
		}},
		{name: "long transcript digest", mutate: func(w *dealerShareWire) {
			w.TranscriptDigest = hex.EncodeToString(make([]byte, 33))
		}},
		{name: "non-canonical scalar encoding", mutate: func(w *dealerShareWire) {
			w.ShareValue = hex.EncodeToString(bytes.Repeat([]byte{0xff}, 32))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := valid
			tt.mutate(&wire)
			bad, err := json.Marshal(wire)
			if err != nil {
				t.Fatalf("marshal mutated share failed: %v", err)
			}
			if _, err := decodeDealerSharePacket(bad); err == nil {
				t.Fatalf("accepted %s", tt.name)
			}
		})
	}
}

func TestScalarShamirContributionDigestUsesIsolatedDomainAndBindsArtifact(t *testing.T) {
	cfg := NormalizeConfig(baseTestConfig())
	cfg.APVSSProvider = "scalar-shamir"
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure runtime failed: %v", err)
	}
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("build scalar-shamir artifacts failed: %v", err)
	}
	art := artifacts[cfg.runtime.oldOrder[0]]
	want := expectedScalarShamirContributionDigestForTest(art)
	if !bytesEq(art.ContributionDigest, want) {
		t.Fatalf("artifact contribution digest was not computed with scalar-shamir domain")
	}
	if !bytesEq(scalarShamirContributionDigest(art), want) {
		t.Fatalf("scalar-shamir contribution helper does not match canonical field ordering")
	}
	if bytesEq(want, optrandContributionDigest(art)) {
		t.Fatalf("scalar-shamir and optrand contribution domains collided")
	}

	reversed := cloneDealerArtifactForScalarDigestTest(art)
	reversed.Ciphertexts = make(map[int][]byte, len(art.Ciphertexts))
	for i := len(cfg.runtime.receiverOrder) - 1; i >= 0; i-- {
		receiver := cfg.runtime.receiverOrder[i]
		reversed.Ciphertexts[receiver] = append([]byte(nil), art.Ciphertexts[receiver]...)
	}
	if !bytesEq(want, scalarShamirContributionDigest(reversed)) {
		t.Fatalf("digest depends on ciphertext map insertion order")
	}

	mutations := []struct {
		name   string
		mutate func(*DealerArtifact)
	}{
		{name: "dealer", mutate: func(a *DealerArtifact) { a.Dealer++ }},
		{name: "descriptor digest", mutate: func(a *DealerArtifact) { a.Descriptor.Digest[0] ^= 1 }},
		{name: "root", mutate: func(a *DealerArtifact) { a.Descriptor.Header.Root[0] ^= 1 }},
		{name: "commitment", mutate: func(a *DealerArtifact) { a.Descriptor.Header.Commitment[0] ^= 1 }},
		{name: "payload", mutate: func(a *DealerArtifact) { a.Payload[0] ^= 1 }},
		{name: "receiver ID", mutate: func(a *DealerArtifact) {
			for receiver, ciphertext := range a.Ciphertexts {
				delete(a.Ciphertexts, receiver)
				a.Ciphertexts[receiver+100] = ciphertext
				break
			}
		}},
		{name: "ciphertext", mutate: func(a *DealerArtifact) {
			for receiver := range a.Ciphertexts {
				a.Ciphertexts[receiver][0] ^= 1
				break
			}
		}},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			mutated := cloneDealerArtifactForScalarDigestTest(art)
			tt.mutate(mutated)
			if bytesEq(want, scalarShamirContributionDigest(mutated)) {
				t.Fatalf("digest did not bind %s", tt.name)
			}
		})
	}
}

func TestScalarShamirHashUsesLengthPrefixedFraming(t *testing.T) {
	const wantHex = "b5ea9e4d252308ea8ba8326b43ae5e8781e040fbdac588754d3a061cf6eb45aa"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("decode fixed hash vector failed: %v", err)
	}
	got := scalarShamirHash("d", []byte("ab"), nil, []byte("c"))
	if !bytes.Equal(got, want) {
		t.Fatalf("scalarShamirHash fixed vector mismatch: got=%x want=%s", got, wantHex)
	}
	left := scalarShamirHash("d", []byte("ab"), []byte("c"))
	right := scalarShamirHash("d", []byte("a"), []byte("bc"))
	if bytes.Equal(left, right) {
		t.Fatalf("length framing did not separate ambiguous part boundaries")
	}
}

func TestScalarShamirProviderADistVerAndDeepCopy(t *testing.T) {
	cfg, artifacts := scalarShamirProviderFixture(t)
	provider := NewScalarShamirAPVSS()
	dealer := cfg.runtime.oldOrder[0]
	art := artifacts[dealer]

	tx, err := provider.ADist(cfg, art)
	if err != nil {
		t.Fatalf("ADist failed: %v", err)
	}
	if err := provider.Ver(cfg, tx, art); err != nil {
		t.Fatalf("Ver failed: %v", err)
	}
	if tx.Dealer != dealer || !bytes.Equal(tx.Payload, art.Payload) ||
		!bytes.Equal(tx.DescriptorID, art.Descriptor.Digest) ||
		!reflect.DeepEqual(tx.Ciphertexts, art.Ciphertexts) {
		t.Fatalf("ADist transcript did not preserve the verified artifact")
	}

	receiver := cfg.runtime.receiverOrder[0]
	tx.Payload[0] ^= 1
	tx.DescriptorID[0] ^= 1
	tx.Ciphertexts[receiver][0] ^= 1
	tx.Ciphertexts[999] = []byte{1}
	if bytes.Equal(tx.Payload, art.Payload) ||
		bytes.Equal(tx.DescriptorID, art.Descriptor.Digest) ||
		bytes.Equal(tx.Ciphertexts[receiver], art.Ciphertexts[receiver]) {
		t.Fatal("ADist output aliases artifact storage")
	}
	if _, ok := art.Ciphertexts[999]; ok {
		t.Fatal("ADist ciphertext map aliases artifact storage")
	}
}

func TestScalarShamirProviderVerRejectsTranscriptAndArtifactTampering(t *testing.T) {
	cfg, artifacts := scalarShamirProviderFixture(t)
	provider := NewScalarShamirAPVSS()
	dealer := cfg.runtime.oldOrder[0]
	art := artifacts[dealer]
	validTx, err := provider.ADist(cfg, art)
	if err != nil {
		t.Fatalf("ADist failed: %v", err)
	}
	receiver := cfg.runtime.receiverOrder[0]

	txMutations := []struct {
		name   string
		mutate func(*APVSSTranscript)
	}{
		{name: "payload", mutate: func(tx *APVSSTranscript) { tx.Payload[0] ^= 1 }},
		{name: "ciphertext bytes", mutate: func(tx *APVSSTranscript) { tx.Ciphertexts[receiver][0] ^= 1 }},
		{name: "missing receiver", mutate: func(tx *APVSSTranscript) { delete(tx.Ciphertexts, receiver) }},
		{name: "extra receiver", mutate: func(tx *APVSSTranscript) { tx.Ciphertexts[999] = []byte{1} }},
		{name: "descriptor ID", mutate: func(tx *APVSSTranscript) { tx.DescriptorID[0] ^= 1 }},
		{name: "dealer", mutate: func(tx *APVSSTranscript) { tx.Dealer++ }},
	}
	for _, tt := range txMutations {
		t.Run("tx/"+tt.name, func(t *testing.T) {
			tx := cloneScalarShamirTranscriptForTest(validTx)
			tt.mutate(tx)
			if err := provider.Ver(cfg, tx, art); err == nil {
				t.Fatalf("Ver accepted tampered transcript %s", tt.name)
			}
		})
	}

	artifactMutations := []struct {
		name   string
		mutate func(*DealerArtifact)
	}{
		{name: "payload", mutate: func(a *DealerArtifact) { a.Payload[0] ^= 1 }},
		{name: "ciphertext bytes", mutate: func(a *DealerArtifact) { a.Ciphertexts[receiver][0] ^= 1 }},
		{name: "missing receiver", mutate: func(a *DealerArtifact) { delete(a.Ciphertexts, receiver) }},
		{name: "extra receiver", mutate: func(a *DealerArtifact) { a.Ciphertexts[999] = []byte{1} }},
		{name: "contribution digest", mutate: func(a *DealerArtifact) { a.ContributionDigest[0] ^= 1 }},
		{name: "descriptor digest", mutate: func(a *DealerArtifact) { a.Descriptor.Digest[0] ^= 1 }},
		{name: "descriptor root", mutate: func(a *DealerArtifact) { a.Descriptor.Header.Root[0] ^= 1 }},
		{name: "descriptor metadata context", mutate: func(a *DealerArtifact) { a.Descriptor.Header.MetadataHash[0] ^= 1 }},
		{name: "descriptor SID context", mutate: func(a *DealerArtifact) { a.Descriptor.Header.SID += "-other" }},
		{name: "descriptor epoch context", mutate: func(a *DealerArtifact) { a.Descriptor.Header.Epoch++ }},
		{name: "artifact dealer", mutate: func(a *DealerArtifact) { a.Dealer++ }},
		{name: "descriptor dealer", mutate: func(a *DealerArtifact) { a.Descriptor.Dealer++ }},
		{name: "lock certificate", mutate: func(a *DealerArtifact) { a.Descriptor.Lock.Certificate[0] ^= 1 }},
	}
	for _, tt := range artifactMutations {
		t.Run("artifact/"+tt.name, func(t *testing.T) {
			bad := cloneDealerArtifactForScalarDigestTest(art)
			tt.mutate(bad)
			if err := provider.Ver(cfg, validTx, bad); err == nil {
				t.Fatalf("Ver accepted tampered artifact %s", tt.name)
			}
		})
	}
}

func TestScalarShamirProviderRejectsLegacyAndMalformedTranscriptSemantics(t *testing.T) {
	cfg, artifacts := scalarShamirProviderFixture(t)
	provider := NewScalarShamirAPVSS()
	dealer := cfg.runtime.oldOrder[0]
	valid := artifacts[dealer]

	tests := []struct {
		name   string
		mutate func(*dealerTranscriptWire)
	}{
		{name: "legacy schema v1", mutate: func(w *dealerTranscriptWire) { w.Provider = "" }},
		{name: "wrong provider", mutate: func(w *dealerTranscriptWire) { w.Provider = "optrand" }},
		{name: "wrong dealer", mutate: func(w *dealerTranscriptWire) { w.Dealer++ }},
		{name: "wrong metadata", mutate: func(w *dealerTranscriptWire) {
			w.MetadataHash = hex.EncodeToString(hashBytes([]byte("other transcript metadata")))
		}},
		{name: "wrong threshold", mutate: func(w *dealerTranscriptWire) {
			w.Threshold = 1
			w.Commitments = w.Commitments[:1]
		}},
		{name: "receiver order", mutate: func(w *dealerTranscriptWire) {
			w.ReceiverIDs[0], w.ReceiverIDs[1] = w.ReceiverIDs[1], w.ReceiverIDs[0]
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bad := rebuildScalarShamirArtifactPayloadForTest(t, cfg, valid, tt.mutate)
			tx := &APVSSTranscript{
				Dealer:       bad.Dealer,
				Payload:      append([]byte(nil), bad.Payload...),
				Ciphertexts:  cloneBytesMap(bad.Ciphertexts),
				DescriptorID: append([]byte(nil), bad.Descriptor.Digest...),
			}
			if err := provider.Ver(cfg, tx, bad); err == nil {
				t.Fatalf("Ver accepted %s transcript", tt.name)
			}
		})
	}
}

func TestScalarShamirProviderAggAVerUsesCanonicalScalarDigest(t *testing.T) {
	cfg, artifacts := scalarShamirProviderFixture(t)
	provider := NewScalarShamirAPVSS()
	dealers := []int{cfg.runtime.oldOrder[1], cfg.runtime.oldOrder[0]}

	agg, err := provider.Agg(cfg, dealers, artifacts)
	if err != nil {
		t.Fatalf("Agg failed: %v", err)
	}
	if err := provider.AVer(cfg, agg, artifacts); err != nil {
		t.Fatalf("AVer failed: %v", err)
	}
	wantDealers := sortedUnique(dealers)
	if agg.Provider != "scalar-shamir" || !reflect.DeepEqual(agg.Dealers, wantDealers) {
		t.Fatalf("unexpected scalar aggregate provider/dealers: %+v", agg)
	}
	if agg.ListTranscript == nil || agg.ListTranscript.Trusted {
		t.Fatalf("scalar aggregate did not carry an untrusted contribution container")
	}
	parts := make([][]byte, 0, 1+len(wantDealers))
	parts = append(parts, encodeInts(wantDealers))
	for _, dealer := range wantDealers {
		parts = append(parts, artifacts[dealer].ContributionDigest)
	}
	wantDigest := scalarShamirHash("scalar-shamir-agg-v1", parts...)
	if !bytes.Equal(agg.AggregateDigest, wantDigest) ||
		!bytes.Equal(agg.ListTranscript.AggregateDigest, wantDigest) {
		t.Fatalf("aggregate digest does not use scalar-shamir framing")
	}
	optrandParts := [][]byte{[]byte("optrand-agg"), encodeInts(wantDealers)}
	for _, dealer := range wantDealers {
		optrandParts = append(optrandParts, artifacts[dealer].ContributionDigest)
	}
	if bytes.Equal(agg.AggregateDigest, hashBytes(optrandParts...)) {
		t.Fatal("scalar aggregate reused optrand aggregate domain")
	}
}

func TestScalarShamirProviderAggRejectsInvalidInputs(t *testing.T) {
	cfg, artifacts := scalarShamirProviderFixture(t)
	provider := NewScalarShamirAPVSS()
	d0, d1 := cfg.runtime.oldOrder[0], cfg.runtime.oldOrder[1]

	tests := []struct {
		name      string
		dealers   []int
		artifacts func() map[int]*DealerArtifact
	}{
		{name: "empty", dealers: nil, artifacts: func() map[int]*DealerArtifact { return artifacts }},
		{name: "duplicate", dealers: []int{d0, d0}, artifacts: func() map[int]*DealerArtifact { return artifacts }},
		{name: "below threshold", dealers: []int{d0}, artifacts: func() map[int]*DealerArtifact { return artifacts }},
		{name: "missing artifact", dealers: []int{d0, d1}, artifacts: func() map[int]*DealerArtifact {
			out := cloneScalarShamirArtifactsForTest(artifacts)
			delete(out, d1)
			return out
		}},
		{name: "invalid artifact", dealers: []int{d0, d1}, artifacts: func() map[int]*DealerArtifact {
			out := cloneScalarShamirArtifactsForTest(artifacts)
			out[d1].Payload[0] ^= 1
			return out
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := provider.Agg(cfg, tt.dealers, tt.artifacts()); err == nil {
				t.Fatalf("Agg accepted %s input", tt.name)
			}
		})
	}
}

func TestScalarShamirProviderAVerRejectsAggregateTampering(t *testing.T) {
	cfg, artifacts := scalarShamirProviderFixture(t)
	provider := NewScalarShamirAPVSS()
	dealers := []int{cfg.runtime.oldOrder[0], cfg.runtime.oldOrder[1]}
	valid, err := provider.Agg(cfg, dealers, artifacts)
	if err != nil {
		t.Fatalf("Agg failed: %v", err)
	}
	d0 := valid.Dealers[0]

	tests := []struct {
		name   string
		mutate func(*APVSSAggregate)
	}{
		{name: "provider", mutate: func(a *APVSSAggregate) { a.Provider = "optrand" }},
		{name: "outer dealer set", mutate: func(a *APVSSAggregate) { a.Dealers[0] = 999 }},
		{name: "outer dealer order", mutate: func(a *APVSSAggregate) { a.Dealers[0], a.Dealers[1] = a.Dealers[1], a.Dealers[0] }},
		{name: "outer dealer count", mutate: func(a *APVSSAggregate) { a.Dealers = a.Dealers[:1] }},
		{name: "outer digest", mutate: func(a *APVSSAggregate) { a.AggregateDigest[0] ^= 1 }},
		{name: "inner dealer set", mutate: func(a *APVSSAggregate) { a.ListTranscript.Dealers[0] = 999 }},
		{name: "inner dealer order", mutate: func(a *APVSSAggregate) {
			a.ListTranscript.Dealers[0], a.ListTranscript.Dealers[1] = a.ListTranscript.Dealers[1], a.ListTranscript.Dealers[0]
		}},
		{name: "inner dealer count", mutate: func(a *APVSSAggregate) { a.ListTranscript.Dealers = a.ListTranscript.Dealers[:1] }},
		{name: "inner digest", mutate: func(a *APVSSAggregate) { a.ListTranscript.AggregateDigest[0] ^= 1 }},
		{name: "contribution digest", mutate: func(a *APVSSAggregate) { a.ListTranscript.ContributionDigests[d0][0] ^= 1 }},
		{name: "missing contribution", mutate: func(a *APVSSAggregate) { delete(a.ListTranscript.ContributionDigests, d0) }},
		{name: "extra contribution", mutate: func(a *APVSSAggregate) { a.ListTranscript.ContributionDigests[999] = []byte{1} }},
		{name: "trusted flag", mutate: func(a *APVSSAggregate) { a.ListTranscript.Trusted = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bad := cloneAPVSSAggregate(valid)
			tt.mutate(bad)
			if err := provider.AVer(cfg, bad, artifacts); err == nil {
				t.Fatalf("AVer accepted %s tampering", tt.name)
			}
		})
	}

	badArtifacts := cloneScalarShamirArtifactsForTest(artifacts)
	badArtifacts[d0].ContributionDigest[0] ^= 1
	if err := provider.AVer(cfg, valid, badArtifacts); err == nil {
		t.Fatal("AVer accepted tampered received artifact")
	}
}

func TestScalarShamirProviderRecReturnsReconstructableThresholdShares(t *testing.T) {
	cfg, artifacts := scalarShamirProviderFixture(t)
	provider := NewScalarShamirAPVSS()
	dealers := append([]int(nil), cfg.runtime.oldOrder[:cfg.FOld+1]...)
	agg, err := provider.Agg(cfg, dealers, artifacts)
	if err != nil {
		t.Fatalf("Agg failed: %v", err)
	}
	recovered, err := provider.Rec(cfg, agg, artifacts)
	if err != nil {
		t.Fatalf("Rec failed: %v", err)
	}
	if recovered.OutputKind != APVSSOutputScalar {
		t.Fatalf("output kind=%q, want scalar", recovered.OutputKind)
	}
	if recovered.ScalarThreshold != cfg.FNew+1 {
		t.Fatalf("scalar threshold=%d, want %d", recovered.ScalarThreshold, cfg.FNew+1)
	}
	if !bytes.Equal(recovered.AggregateDigest, agg.AggregateDigest) {
		t.Fatal("recovered aggregate digest mismatch")
	}
	if len(recovered.ScalarShares) != len(cfg.runtime.receiverOrder) {
		t.Fatalf("scalar share count=%d, want %d", len(recovered.ScalarShares), len(cfg.runtime.receiverOrder))
	}
	if len(recovered.ContributionDigests) != len(dealers) {
		t.Fatalf("contribution count=%d, want %d", len(recovered.ContributionDigests), len(dealers))
	}

	suite := edwards25519.NewBlakeSHA256Ed25519()
	publicKey := suite.Point()
	if err := publicKey.UnmarshalBinary(recovered.ThresholdPublicKey); err != nil {
		t.Fatalf("decode threshold public key failed: %v", err)
	}
	canonicalPublicKey, err := publicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal threshold public key failed: %v", err)
	}
	if !bytes.Equal(canonicalPublicKey, recovered.ThresholdPublicKey) {
		t.Fatal("threshold public key is not canonically encoded")
	}
	if publicKey.Equal(suite.Point().Null()) {
		t.Fatal("threshold public key is identity")
	}
	eight := suite.Scalar().SetInt64(8)
	inverseEight := suite.Scalar().Inv(eight)
	projected := suite.Point().Mul(inverseEight, suite.Point().Mul(eight, publicKey))
	if !projected.Equal(publicKey) {
		t.Fatal("threshold public key is outside prime-order subgroup")
	}

	shares := make([]*share.PriShare, 0, len(cfg.runtime.receiverOrder))
	for _, receiver := range cfg.runtime.receiverOrder {
		raw, ok := recovered.ScalarShares[receiver]
		if !ok {
			t.Fatalf("missing scalar share for receiver=%d", receiver)
		}
		scalar := suite.Scalar()
		if err := scalar.UnmarshalBinary(raw); err != nil {
			t.Fatalf("decode scalar share for receiver=%d failed: %v", receiver, err)
		}
		canonical, err := scalar.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal scalar share for receiver=%d failed: %v", receiver, err)
		}
		if !bytes.Equal(canonical, raw) {
			t.Fatalf("scalar share for receiver=%d is non-canonical", receiver)
		}
		shares = append(shares, &share.PriShare{I: cfg.runtime.receiverIndex[receiver], V: scalar})
	}

	for left := 0; left < len(shares); left++ {
		for right := left + 1; right < len(shares); right++ {
			secret, err := share.RecoverSecret(
				suite,
				[]*share.PriShare{shares[left], shares[right]},
				recovered.ScalarThreshold,
				len(shares),
			)
			if err != nil {
				t.Fatalf("recover from pair (%d,%d) failed: %v", left, right, err)
			}
			if got := suite.Point().Mul(secret, nil); !got.Equal(publicKey) {
				t.Fatalf("pair (%d,%d) recovered a secret inconsistent with public key", left, right)
			}
		}
	}
	if _, err := share.RecoverSecret(
		suite,
		[]*share.PriShare{shares[0]},
		recovered.ScalarThreshold,
		len(shares),
	); err == nil {
		t.Fatal("fewer than F+1 shares unexpectedly satisfied reconstruction harness")
	}

	wantMaterialParts := [][]byte{
		agg.AggregateDigest,
		encodeInts([]int{cfg.FNew + 1}),
		encodeInts(agg.Dealers),
	}
	for _, dealer := range agg.Dealers {
		wantMaterialParts = append(
			wantMaterialParts,
			encodeInts([]int{dealer}),
			agg.ListTranscript.ContributionDigests[dealer],
		)
	}
	for _, receiver := range cfg.runtime.receiverOrder {
		wantMaterialParts = append(
			wantMaterialParts,
			encodeInts([]int{receiver}),
			recovered.ScalarShares[receiver],
		)
	}
	wantMaterialParts = append(wantMaterialParts, recovered.ThresholdPublicKey)
	wantMaterial := scalarShamirHash("scalar-shamir-recovered-v1", wantMaterialParts...)
	if !bytes.Equal(recovered.RecoveredMaterial, wantMaterial) {
		t.Fatal("recovered material does not bind canonical scalar output")
	}

	recovered.ContributionDigests[dealers[0]][0] ^= 1
	if bytes.Equal(
		recovered.ContributionDigests[dealers[0]],
		agg.ListTranscript.ContributionDigests[dealers[0]],
	) {
		t.Fatal("recovered contribution digest aliases aggregate storage")
	}
}

func TestScalarShamirProviderRecMatchesEveryVerifiedDealerShareAndCommitment(t *testing.T) {
	cfg, artifacts := scalarShamirProviderFixture(t)
	provider := NewScalarShamirAPVSS()
	dealers := append([]int(nil), cfg.runtime.oldOrder[:cfg.FOld+2]...)
	agg, err := provider.Agg(cfg, dealers, artifacts)
	if err != nil {
		t.Fatalf("Agg failed: %v", err)
	}
	recovered, err := provider.Rec(cfg, agg, artifacts)
	if err != nil {
		t.Fatalf("Rec failed: %v", err)
	}

	suite := edwards25519.NewBlakeSHA256Ed25519()
	wantShares := make(map[int]*share.PriShare, len(cfg.runtime.receiverOrder))
	for _, receiver := range cfg.runtime.receiverOrder {
		wantShares[receiver] = &share.PriShare{
			I: cfg.runtime.receiverIndex[receiver],
			V: suite.Scalar().Zero(),
		}
	}
	wantPublicKey := suite.Point().Null()
	for _, dealer := range agg.Dealers {
		art := artifacts[dealer]
		transcript, err := decodeDealerTranscript(art.Payload)
		if err != nil {
			t.Fatalf("decode dealer=%d transcript failed: %v", dealer, err)
		}
		wantPublicKey.Add(wantPublicKey, transcript.PubPoly.Commit())
		transcriptDigest := hashBytes([]byte("rladkr-transcript-digest"), transcript.Raw)
		for _, receiver := range cfg.runtime.receiverOrder {
			plain, err := openSharePacketForReceiver(
				cfg,
				dealer,
				receiver,
				art.Descriptor.Header.Root,
				art.Ciphertexts[receiver],
			)
			if err != nil {
				t.Fatalf("open dealer=%d receiver=%d failed: %v", dealer, receiver, err)
			}
			packet, err := decodeDealerSharePacket(plain)
			zeroBytes(plain)
			if err != nil {
				t.Fatalf("decode dealer=%d receiver=%d share failed: %v", dealer, receiver, err)
			}
			if packet.Provider != "scalar-shamir" || packet.Version != 1 || packet.Dealer != dealer || packet.Receiver != receiver ||
				packet.ShareIndex != cfg.runtime.receiverIndex[receiver] ||
				!bytes.Equal(packet.TranscriptDigest, transcriptDigest) ||
				!transcript.PubPoly.Check(&share.PriShare{I: packet.ShareIndex, V: packet.ShareValue}) {
				t.Fatalf("invalid fixture share fields for dealer=%d receiver=%d", dealer, receiver)
			}
			wantShares[receiver].V.Add(wantShares[receiver].V, packet.ShareValue)
		}
	}

	for _, receiver := range cfg.runtime.receiverOrder {
		want, err := wantShares[receiver].V.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal expected share failed: %v", err)
		}
		if !bytes.Equal(recovered.ScalarShares[receiver], want) {
			t.Fatalf("aggregate scalar share mismatch for receiver=%d", receiver)
		}
	}
	wantPublicKeyRaw, err := wantPublicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal expected public key failed: %v", err)
	}
	if !bytes.Equal(recovered.ThresholdPublicKey, wantPublicKeyRaw) {
		t.Fatal("threshold public key does not equal sum of constant commitments")
	}
}

func TestScalarShamirProviderRecRejectsIncompleteOrTamperedSharesAtomically(t *testing.T) {
	cfg, artifacts := scalarShamirProviderFixture(t)
	provider := NewScalarShamirAPVSS()
	dealers := append([]int(nil), cfg.runtime.oldOrder[:cfg.FOld+1]...)
	validAgg, err := provider.Agg(cfg, dealers, artifacts)
	if err != nil {
		t.Fatalf("Agg failed: %v", err)
	}
	dealer := validAgg.Dealers[0]
	receiver := cfg.runtime.receiverOrder[0]
	otherReceiver := cfg.runtime.receiverOrder[1]

	t.Run("missing receiver ciphertext", func(t *testing.T) {
		badArtifacts := cloneScalarShamirArtifactsForTest(artifacts)
		delete(badArtifacts[dealer].Ciphertexts, receiver)
		got, err := provider.Rec(cfg, validAgg, badArtifacts)
		if err == nil || got != nil {
			t.Fatalf("Rec returned partial result for missing ciphertext: result=%+v err=%v", got, err)
		}
	})
	t.Run("tampered ciphertext bytes", func(t *testing.T) {
		badArtifacts := cloneScalarShamirArtifactsForTest(artifacts)
		badArtifacts[dealer].Ciphertexts[receiver][0] ^= 1
		got, err := provider.Rec(cfg, validAgg, badArtifacts)
		if err == nil || got != nil {
			t.Fatalf("Rec returned partial result for tampered ciphertext: result=%+v err=%v", got, err)
		}
	})

	validWire := openedScalarShareWireForTest(t, cfg, artifacts[dealer], receiver)
	otherWire := openedScalarShareWireForTest(t, cfg, artifacts[dealer], otherReceiver)
	tests := []struct {
		name       string
		sealCfg    Config
		sealFor    int
		mutateWire func(*dealerShareWire)
	}{
		{name: "share provider downgrade", sealCfg: func() Config {
			legacy := cfg
			legacy.APVSSProvider = "optrand"
			return legacy
		}(), sealFor: receiver, mutateWire: func(w *dealerShareWire) { w.Provider = "" }},
		{name: "share index replaced by another valid index", sealCfg: cfg, sealFor: receiver, mutateWire: func(w *dealerShareWire) {
			w.ShareIndex = otherWire.ShareIndex
			w.ShareValue = otherWire.ShareValue
		}},
		{name: "receiver context", sealCfg: cfg, sealFor: otherReceiver, mutateWire: func(w *dealerShareWire) {
			w.Receiver = otherReceiver
			w.ShareIndex = otherWire.ShareIndex
			w.ShareValue = otherWire.ShareValue
		}},
		{name: "transcript digest", sealCfg: cfg, sealFor: receiver, mutateWire: func(w *dealerShareWire) {
			w.TranscriptDigest = hex.EncodeToString(hashBytes([]byte("wrong transcript digest")))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := validWire
			tt.mutateWire(&wire)
			packet, err := json.Marshal(wire)
			if err != nil {
				t.Fatalf("marshal tampered share failed: %v", err)
			}
			ciphertext, err := sealSharePacketForReceiver(
				tt.sealCfg,
				dealer,
				tt.sealFor,
				artifacts[dealer].Descriptor.Header.Root,
				packet,
			)
			if err != nil {
				t.Fatalf("seal tampered share failed: %v", err)
			}
			badArtifacts := cloneScalarShamirArtifactsForTest(artifacts)
			badArtifacts[dealer].Ciphertexts[receiver] = ciphertext
			badArtifacts[dealer].ContributionDigest = scalarShamirContributionDigest(badArtifacts[dealer])
			badArtifacts[dealer].Fingerprint = fingerprintDealerArtifact(badArtifacts[dealer])
			badAgg, err := provider.Agg(cfg, dealers, badArtifacts)
			if err != nil {
				t.Fatalf("Agg rejected opaque tampered share before Rec: %v", err)
			}
			got, err := provider.Rec(cfg, badAgg, badArtifacts)
			if err == nil || got != nil {
				t.Fatalf("Rec returned partial result for %s: result=%+v err=%v", tt.name, got, err)
			}
		})
	}
}

func scalarShamirProviderFixture(t *testing.T) (Config, map[int]*DealerArtifact) {
	t.Helper()
	cfg := NormalizeConfig(baseTestConfig())
	cfg.APVSSProvider = "scalar-shamir"
	cfg.DeriveMode = "scalar"
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatalf("ensure scalar-shamir runtime failed: %v", err)
	}
	artifacts, err := BuildDealerArtifacts(cfg)
	if err != nil {
		t.Fatalf("build scalar-shamir artifacts failed: %v", err)
	}
	return cfg, artifacts
}

func cloneScalarShamirTranscriptForTest(in *APVSSTranscript) *APVSSTranscript {
	return &APVSSTranscript{
		Dealer:       in.Dealer,
		Payload:      append([]byte(nil), in.Payload...),
		Ciphertexts:  cloneBytesMap(in.Ciphertexts),
		DescriptorID: append([]byte(nil), in.DescriptorID...),
	}
}

func cloneScalarShamirArtifactsForTest(in map[int]*DealerArtifact) map[int]*DealerArtifact {
	out := make(map[int]*DealerArtifact, len(in))
	for dealer, art := range in {
		out[dealer] = cloneDealerArtifactForScalarDigestTest(art)
	}
	return out
}

func openedScalarShareWireForTest(t *testing.T, cfg Config, art *DealerArtifact, receiver int) dealerShareWire {
	t.Helper()
	plain, err := openSharePacketForReceiver(
		cfg,
		art.Dealer,
		receiver,
		art.Descriptor.Header.Root,
		art.Ciphertexts[receiver],
	)
	if err != nil {
		t.Fatalf("open scalar share for receiver=%d failed: %v", receiver, err)
	}
	defer zeroBytes(plain)
	var wire dealerShareWire
	if err := json.Unmarshal(plain, &wire); err != nil {
		t.Fatalf("decode scalar share wire for receiver=%d failed: %v", receiver, err)
	}
	return wire
}

func rebuildScalarShamirArtifactPayloadForTest(
	t *testing.T,
	cfg Config,
	art *DealerArtifact,
	mutate func(*dealerTranscriptWire),
) *DealerArtifact {
	t.Helper()
	var wire dealerTranscriptWire
	if err := json.Unmarshal(art.Payload, &wire); err != nil {
		t.Fatalf("decode fixture transcript failed: %v", err)
	}
	wire.ReceiverIDs = append([]int(nil), wire.ReceiverIDs...)
	wire.Commitments = append([]string(nil), wire.Commitments...)
	mutate(&wire)
	payload, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal mutated transcript failed: %v", err)
	}
	root := hashBytes([]byte("rladkr-root"), payload)
	commitment := hashBytes([]byte("rladkr-commit"), payload)
	holders := append([]int(nil), cfg.runtime.oldOrder...)
	lockThreshold := len(holders) - cfg.FOld
	if lockThreshold < 1 {
		lockThreshold = 1
	}
	rebuilt, err := buildArtifactCommon(
		cfg,
		art.Dealer,
		payload,
		root,
		commitment,
		holders,
		lockThreshold,
		func() (map[int][]byte, error) { return cloneBytesMap(art.Ciphertexts), nil },
	)
	if err != nil {
		t.Fatalf("rebuild mutated artifact failed: %v", err)
	}
	return rebuilt
}

func expectedScalarShamirContributionDigestForTest(art *DealerArtifact) []byte {
	receivers := make([]int, 0, len(art.Ciphertexts))
	for receiver := range art.Ciphertexts {
		receivers = append(receivers, receiver)
	}
	sort.Ints(receivers)
	parts := make([][]byte, 0, 6+len(receivers))
	parts = append(parts,
		[]byte(fmt.Sprintf("dealer=%d", art.Dealer)),
		art.Descriptor.Digest,
		art.Descriptor.Header.Root,
		art.Descriptor.Header.Commitment,
		art.Payload,
		encodeInts(receivers),
	)
	for _, receiver := range receivers {
		parts = append(parts, hashBytes([]byte("ct"), art.Ciphertexts[receiver]))
	}
	return expectedScalarShamirHashForTest("scalar-shamir-contribution-v1", parts...)
}

func expectedScalarShamirHashForTest(domain string, parts ...[]byte) []byte {
	h := sha256.New()
	items := make([][]byte, 0, 1+len(parts))
	items = append(items, []byte(domain))
	items = append(items, parts...)
	var length [8]byte
	for _, item := range items {
		binary.BigEndian.PutUint64(length[:], uint64(len(item)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(item)
	}
	return h.Sum(nil)
}

type nonCanonicalJSONTestCase struct {
	name    string
	payload []byte
}

func nonCanonicalJSONVariantsForTest(t *testing.T, canonical []byte) []nonCanonicalJSONTestCase {
	t.Helper()
	return []nonCanonicalJSONTestCase{
		{name: "whitespace", payload: append(append([]byte(nil), canonical...), '\n')},
		{name: "unknown field", payload: appendJSONObjectFieldForTest(canonical, `,"unknown":true`)},
		{name: "duplicate field", payload: appendJSONObjectFieldForTest(canonical, `,"v":2`)},
		{name: "reordered fields", payload: reverseJSONObjectFieldsForTest(t, canonical)},
	}
}

func appendJSONObjectFieldForTest(canonical []byte, field string) []byte {
	out := append([]byte(nil), canonical[:len(canonical)-1]...)
	out = append(out, field...)
	return append(out, '}')
}

func reverseJSONObjectFieldsForTest(t *testing.T, canonical []byte) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &object); err != nil {
		t.Fatalf("decode canonical object failed: %v", err)
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	var out bytes.Buffer
	out.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			out.WriteByte(',')
		}
		encodedKey, err := json.Marshal(key)
		if err != nil {
			t.Fatalf("marshal object key failed: %v", err)
		}
		out.Write(encodedKey)
		out.WriteByte(':')
		out.Write(object[key])
	}
	out.WriteByte('}')
	if bytes.Equal(out.Bytes(), canonical) {
		t.Fatalf("reordered object unexpectedly equals canonical JSON")
	}
	return out.Bytes()
}

func nonCanonicalPointEncodingForTest(t *testing.T) []byte {
	t.Helper()
	suite := edwards25519.NewBlakeSHA256Ed25519()
	identity := suite.Point().Null()
	for low := 237; low <= 255; low++ {
		for _, sign := range []byte{0, 0x80} {
			candidate := bytes.Repeat([]byte{0xff}, 32)
			candidate[0] = byte(low)
			candidate[31] = 0x7f | sign
			point := suite.Point()
			if err := point.UnmarshalBinary(candidate); err != nil || point.Equal(identity) {
				continue
			}
			canonical, err := point.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal decoded point failed: %v", err)
			}
			if !bytes.Equal(canonical, candidate) {
				return candidate
			}
		}
	}
	t.Fatalf("failed to construct a non-canonical point accepted by kyber")
	return nil
}

func cloneDealerArtifactForScalarDigestTest(art *DealerArtifact) *DealerArtifact {
	clone := *art
	clone.Payload = append([]byte(nil), art.Payload...)
	clone.ContributionDigest = append([]byte(nil), art.ContributionDigest...)
	clone.Fingerprint = append([]byte(nil), art.Fingerprint...)
	clone.Descriptor.Digest = append([]byte(nil), art.Descriptor.Digest...)
	clone.Descriptor.Fingerprint = append([]byte(nil), art.Descriptor.Fingerprint...)
	clone.Descriptor.Header.Root = append([]byte(nil), art.Descriptor.Header.Root...)
	clone.Descriptor.Header.Commitment = append([]byte(nil), art.Descriptor.Header.Commitment...)
	clone.Descriptor.Header.MetadataHash = append([]byte(nil), art.Descriptor.Header.MetadataHash...)
	clone.Descriptor.Lock.Holders = append([]int(nil), art.Descriptor.Lock.Holders...)
	clone.Descriptor.Lock.ShareSignatures = cloneSigMap(art.Descriptor.Lock.ShareSignatures)
	clone.Descriptor.Lock.Certificate = append([]byte(nil), art.Descriptor.Lock.Certificate...)
	clone.Ciphertexts = make(map[int][]byte, len(art.Ciphertexts))
	for receiver, ciphertext := range art.Ciphertexts {
		clone.Ciphertexts[receiver] = append([]byte(nil), ciphertext...)
	}
	return &clone
}
