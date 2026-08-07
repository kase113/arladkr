package core

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type cvAggregateArgumentTestVerifier struct {
	profile       string
	circuitDigest []byte
	vkDigest      []byte
	wantStatement []byte
	wantProof     []byte
	err           error
}

func (v *cvAggregateArgumentTestVerifier) ProofProfile() string          { return v.profile }
func (v *cvAggregateArgumentTestVerifier) CircuitDigest() []byte         { return v.circuitDigest }
func (v *cvAggregateArgumentTestVerifier) VerificationKeyDigest() []byte { return v.vkDigest }
func (v *cvAggregateArgumentTestVerifier) Verify(statementWire, proof []byte) error {
	if !bytes.Equal(statementWire, v.wantStatement) || !bytes.Equal(proof, v.wantProof) {
		return errors.New("unexpected verifier input")
	}
	return v.err
}

func cvAggregateArgumentTestStatement() cvAggregateArgumentStatement {
	return cvAggregateArgumentStatement{
		contextDigest: bytes.Repeat([]byte{1}, 32), proposer: 7,
		manifestDigest: bytes.Repeat([]byte{2}, 32), aggregateDigest: bytes.Repeat([]byte{3}, 32),
		payloadDigest: bytes.Repeat([]byte{4}, 32), freshShardRoot: bytes.Repeat([]byte{5}, 32),
	}
}

func cvAggregateArgumentTestProof() *cvAggregateArgument {
	return &cvAggregateArgument{
		statement: cvAggregateArgumentTestStatement(), proofProfile: "gnark-groth16-bn254/v1",
		circuitDigest: bytes.Repeat([]byte{6}, 32), verificationKeyDigest: bytes.Repeat([]byte{7}, 32),
		proof: []byte{8, 9, 10},
	}
}

func TestCVAggregateArgumentStatementCodec(t *testing.T) {
	statement := cvAggregateArgumentTestStatement()
	wire, err := cvAggregateArgumentStatementCanonicalBytes(&statement)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAggregateArgumentStatement(wire)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := cvAggregateArgumentStatementCanonicalBytes(decoded)
	if err != nil || !bytes.Equal(reencoded, wire) {
		t.Fatalf("aggregate argument statement did not round trip: %v", err)
	}
	digest, err := cvAggregateArgumentStatementDigest(&statement)
	if err != nil || len(digest) != 32 {
		t.Fatalf("invalid aggregate argument statement digest: %v", err)
	}
	for _, malformed := range [][]byte{wire[:len(wire)-1], append(append([]byte(nil), wire...), 0)} {
		if _, err := cvDecodeAggregateArgumentStatement(malformed); err == nil {
			t.Fatal("accepted malformed aggregate argument statement")
		}
	}
}

func TestCVAggregateArgumentCodecAndDigestBinding(t *testing.T) {
	argument := cvAggregateArgumentTestProof()
	wire, err := cvAggregateArgumentCanonicalBytes(argument)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeAggregateArgument(wire)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := cvAggregateArgumentCanonicalBytes(decoded)
	if err != nil || !bytes.Equal(reencoded, wire) {
		t.Fatalf("aggregate argument did not round trip: %v", err)
	}
	for _, malformed := range [][]byte{wire[:len(wire)-1], append(append([]byte(nil), wire...), 0)} {
		if _, err := cvDecodeAggregateArgument(malformed); err == nil {
			t.Fatal("accepted malformed aggregate argument proof wire")
		}
	}
	baseDigest, err := cvAggregateArgumentDigest(argument)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []*cvAggregateArgument{
		cvAggregateArgumentTestProof(), cvAggregateArgumentTestProof(), cvAggregateArgumentTestProof(),
		cvAggregateArgumentTestProof(), cvAggregateArgumentTestProof(), cvAggregateArgumentTestProof(),
	}
	mutations[0].statement.contextDigest[0] ^= 1
	mutations[1].statement.manifestDigest[0] ^= 1
	mutations[2].proofProfile = "gnark-groth16-bn254/v2"
	mutations[3].circuitDigest[0] ^= 1
	mutations[4].verificationKeyDigest[0] ^= 1
	mutations[5].proof[0] ^= 1
	for i, mutation := range mutations {
		digest, digestErr := cvAggregateArgumentDigest(mutation)
		if digestErr != nil || bytes.Equal(digest, baseDigest) {
			t.Fatalf("mutation %d was not bound by aggregate argument digest: %v", i, digestErr)
		}
	}
}

func TestCVAggregateArgumentRejectsInvalidEnvelope(t *testing.T) {
	for name, mutate := range map[string]func(*cvAggregateArgument){
		"empty-profile":        func(argument *cvAggregateArgument) { argument.proofProfile = "" },
		"non-ascii-profile":    func(argument *cvAggregateArgument) { argument.proofProfile = "gnark v1" },
		"short-circuit-digest": func(argument *cvAggregateArgument) { argument.circuitDigest = argument.circuitDigest[:31] },
		"short-vk-digest": func(argument *cvAggregateArgument) {
			argument.verificationKeyDigest = argument.verificationKeyDigest[:31]
		},
		"empty-proof": func(argument *cvAggregateArgument) { argument.proof = nil },
	} {
		t.Run(name, func(t *testing.T) {
			argument := cvAggregateArgumentTestProof()
			mutate(argument)
			if _, err := cvAggregateArgumentCanonicalBytes(argument); err == nil {
				t.Fatal("accepted invalid aggregate argument envelope")
			}
		})
	}
}

func TestCVBuildAggregateArgumentStatementBindsEpochAndRoster(t *testing.T) {
	sid := "aggregate-argument-builder"
	cfg := NormalizeConfig(Config{
		SID: sid, Epoch: 3, OldCommittee: []int{0, 1, 2, 3}, NewCommittee: []int{0, 1, 2, 3},
		FOld: 1, FNew: 1, Kappa: 2,
	})
	secrets := []uint64{11, 13, 17, 19}
	keys := make([]bls12381.G1Affine, len(secrets))
	for i, secret := range secrets {
		var err error
		keys[i], err = cvReceiverPublicKey(cvTestScalar(secret))
		if err != nil {
			t.Fatal(err)
		}
	}
	leafContext := cvLeafContext{
		sessionID: []byte(sid), epoch: 3, sharingDegree: 1,
		profile:            cvChunkProfile{chunkBits: 8, maxComponents: 2},
		receiverPublicKeys: keys, receiverSigningPublicKeys: cvTestSigningKeys(t, len(keys), 41000),
		dealerSetPolicy: []byte("aggregate-argument-test"), proofProfile: cvLeafStructuralProofProfile,
	}
	header := AggHeader{
		SID: sid, Epoch: 3, Dealers: []int{0, 1},
		AggregateDigest: bytes.Repeat([]byte{20}, 32), PayloadDigest: bytes.Repeat([]byte{21}, 32),
		FreshShardRoot: bytes.Repeat([]byte{22}, 32),
	}
	header.MetadataHash = hashBytes(
		[]byte("aggrlo-meta"), []byte(sid), []byte(fmt.Sprintf("|epoch=%d", header.Epoch)),
		encodeInts(header.Dealers), header.AggregateDigest, header.PayloadDigest, header.FreshShardRoot,
	)
	manifest := bytes.Repeat([]byte{23}, 32)
	statement, err := cvBuildAggregateArgumentStatement(cfg, &leafContext, 2, manifest, header)
	if err != nil {
		t.Fatal(err)
	}
	if statement.proposer != 2 || !bytes.Equal(statement.contextDigest, cvLeafContextDigest(&leafContext)) ||
		!bytes.Equal(statement.manifestDigest, manifest) {
		t.Fatal("aggregate argument builder lost public-input binding")
	}
	if _, err := cvBuildAggregateArgumentStatement(cfg, &leafContext, 9, manifest, header); err == nil {
		t.Fatal("aggregate argument accepted proposer outside old committee")
	}
	badHeader := header
	badHeader.Dealers = []int{0, 9}
	badHeader.MetadataHash = hashBytes(
		[]byte("aggrlo-meta"), []byte(sid), []byte(fmt.Sprintf("|epoch=%d", badHeader.Epoch)),
		encodeInts(badHeader.Dealers), badHeader.AggregateDigest, badHeader.PayloadDigest, badHeader.FreshShardRoot,
	)
	if _, err := cvBuildAggregateArgumentStatement(cfg, &leafContext, 2, manifest, badHeader); err == nil {
		t.Fatal("aggregate argument accepted dealer outside old committee")
	}
}

func TestCVVerifyAggregateArgumentRequiresExactBackendBinding(t *testing.T) {
	argument := cvAggregateArgumentTestProof()
	statementWire, err := cvAggregateArgumentStatementCanonicalBytes(&argument.statement)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &cvAggregateArgumentTestVerifier{
		profile: argument.proofProfile, circuitDigest: append([]byte(nil), argument.circuitDigest...),
		vkDigest:      append([]byte(nil), argument.verificationKeyDigest...),
		wantStatement: statementWire, wantProof: append([]byte(nil), argument.proof...),
	}
	if err := cvVerifyAggregateArgument(argument, &argument.statement, verifier); err != nil {
		t.Fatal(err)
	}

	wrongStatement := argument.statement
	wrongStatement.aggregateDigest = append([]byte(nil), wrongStatement.aggregateDigest...)
	wrongStatement.aggregateDigest[0] ^= 1
	if err := cvVerifyAggregateArgument(argument, &wrongStatement, verifier); err == nil {
		t.Fatal("aggregate argument verified against the wrong public statement")
	}
	verifier.profile = "gnark-groth16-bn254/v2"
	if err := cvVerifyAggregateArgument(argument, &argument.statement, verifier); err == nil {
		t.Fatal("aggregate argument verified under the wrong proof profile")
	}
	verifier.profile = argument.proofProfile
	verifier.circuitDigest[0] ^= 1
	if err := cvVerifyAggregateArgument(argument, &argument.statement, verifier); err == nil {
		t.Fatal("aggregate argument verified under the wrong circuit")
	}
	verifier.circuitDigest[0] ^= 1
	verifier.vkDigest[0] ^= 1
	if err := cvVerifyAggregateArgument(argument, &argument.statement, verifier); err == nil {
		t.Fatal("aggregate argument verified under the wrong verification key")
	}
	verifier.vkDigest[0] ^= 1
	verifier.err = errors.New("proof rejected")
	if err := cvVerifyAggregateArgument(argument, &argument.statement, verifier); err == nil {
		t.Fatal("aggregate argument ignored backend verification failure")
	}
	if err := cvVerifyAggregateArgument(argument, &argument.statement, nil); err == nil {
		t.Fatal("aggregate argument verified without a backend")
	}
}
