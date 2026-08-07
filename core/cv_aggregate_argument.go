package core

import (
	"bytes"
	"fmt"
)

const (
	cvAggregateArgumentStatementDomain = "ARL-CV-sAPVSS/aggregate-argument-statement/v1"
	cvAggregateArgumentProofDomain     = "ARL-CV-sAPVSS/aggregate-argument-proof/v1"
	cvAggregateArgumentDigestDomain    = "ARL-CV-sAPVSS/aggregate-argument-digest/v1"
	cvMaxAggregateArgumentProfileBytes = 128
	cvMaxAggregateArgumentProofBytes   = 1 << 20
)

// cvAggregateArgumentStatement is the public input shared by the aggregate
// prover, ARC holders, and the final certified-object verifier. It deliberately
// excludes the proof digest so generating a proof cannot create a hash cycle.
type cvAggregateArgumentStatement struct {
	contextDigest   []byte
	proposer        int
	manifestDigest  []byte
	aggregateDigest []byte
	payloadDigest   []byte
	freshShardRoot  []byte
}

// cvAggregateArgument is a backend-neutral proof envelope. circuitDigest and
// verificationKeyDigest prevent a proof from being replayed under a different
// circuit shape or setup ceremony.
type cvAggregateArgument struct {
	statement             cvAggregateArgumentStatement
	proofProfile          string
	circuitDigest         []byte
	verificationKeyDigest []byte
	proof                 []byte
}

// cvAggregateArgumentVerifier is intentionally supplied by the caller. There
// is no permissive global registry or fallback verifier for unknown profiles.
type cvAggregateArgumentVerifier interface {
	ProofProfile() string
	CircuitDigest() []byte
	VerificationKeyDigest() []byte
	Verify(statementWire, proof []byte) error
}

func cvRequireProductionAggregateArgumentVerifier(verifier cvAggregateArgumentVerifier) error {
	if verifier == nil || verifier.ProofProfile() != cvAggregateCircuitProofProfile {
		return fmt.Errorf("production aggregate argument verifier profile is unavailable")
	}
	return nil
}

func cvValidAggregateArgumentProfile(profile string) bool {
	if len(profile) == 0 || len(profile) > cvMaxAggregateArgumentProfileBytes {
		return false
	}
	for i := range profile {
		c := profile[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '/' {
			continue
		}
		return false
	}
	return true
}

func cvValidateAggregateArgumentStatement(statement *cvAggregateArgumentStatement) error {
	if statement == nil || statement.proposer < 0 ||
		len(statement.contextDigest) != 32 || len(statement.manifestDigest) != 32 ||
		len(statement.aggregateDigest) != 32 || len(statement.payloadDigest) != 32 ||
		len(statement.freshShardRoot) != 32 {
		return fmt.Errorf("invalid CV-sAPVSS aggregate argument statement")
	}
	return nil
}

func cvBuildAggregateArgumentStatement(
	cfg Config,
	leafContext *cvLeafContext,
	proposer int,
	manifestDigest []byte,
	header AggHeader,
) (*cvAggregateArgumentStatement, error) {
	c := NormalizeConfig(cfg)
	if err := ValidateConfig(c); err != nil {
		return nil, err
	}
	if err := cvValidateLeafContext(leafContext); err != nil {
		return nil, err
	}
	if string(leafContext.sessionID) != c.SID || int(leafContext.epoch) != c.Epoch {
		return nil, fmt.Errorf("aggregate argument context does not match epoch")
	}
	if _, ok := nodeSet(c.OldCommittee)[proposer]; !ok {
		return nil, fmt.Errorf("aggregate argument proposer is outside old committee")
	}
	if len(manifestDigest) != 32 || header.SID != c.SID || header.Epoch != c.Epoch ||
		len(header.Dealers) != c.FOld+1 {
		return nil, fmt.Errorf("aggregate argument header does not match epoch")
	}
	if _, err := validateFinalDealerSet(c, header.Dealers); err != nil {
		return nil, fmt.Errorf("aggregate argument dealer set: %w", err)
	}
	if _, err := cvNetworkAggHeaderCanonicalBytes(header); err != nil {
		return nil, err
	}
	statement := &cvAggregateArgumentStatement{
		contextDigest:   append([]byte(nil), cvLeafContextDigest(leafContext)...),
		proposer:        proposer,
		manifestDigest:  append([]byte(nil), manifestDigest...),
		aggregateDigest: append([]byte(nil), header.AggregateDigest...),
		payloadDigest:   append([]byte(nil), header.PayloadDigest...),
		freshShardRoot:  append([]byte(nil), header.FreshShardRoot...),
	}
	if err := cvValidateAggregateArgumentStatement(statement); err != nil {
		return nil, err
	}
	return statement, nil
}

func cvAggregateArgumentStatementCanonicalBytes(statement *cvAggregateArgumentStatement) ([]byte, error) {
	if err := cvValidateAggregateArgumentStatement(statement); err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAggregateArgumentStatementDomain))
	_ = cvWriteBytes(&wire, statement.contextDigest)
	cvWriteUint64(&wire, uint64(statement.proposer))
	_ = cvWriteBytes(&wire, statement.manifestDigest)
	_ = cvWriteBytes(&wire, statement.aggregateDigest)
	_ = cvWriteBytes(&wire, statement.payloadDigest)
	_ = cvWriteBytes(&wire, statement.freshShardRoot)
	return wire.Bytes(), nil
}

func cvDecodeAggregateArgumentStatement(wire []byte) (*cvAggregateArgumentStatement, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregateArgumentStatementDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateArgumentStatementDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate argument statement domain")
	}
	contextDigest, err := r.bytes(32)
	if err != nil || len(contextDigest) != 32 {
		return nil, fmt.Errorf("invalid aggregate argument context digest")
	}
	proposer, err := r.uint64()
	if err != nil || proposer > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid aggregate argument proposer")
	}
	fields := make([][]byte, 4)
	for i := range fields {
		fields[i], err = r.bytes(32)
		if err != nil || len(fields[i]) != 32 {
			return nil, fmt.Errorf("invalid aggregate argument digest field")
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing aggregate argument statement bytes")
	}
	statement := &cvAggregateArgumentStatement{
		contextDigest: contextDigest, proposer: int(proposer), manifestDigest: fields[0],
		aggregateDigest: fields[1], payloadDigest: fields[2], freshShardRoot: fields[3],
	}
	canonical, err := cvAggregateArgumentStatementCanonicalBytes(statement)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS aggregate argument statement")
	}
	return statement, nil
}

func cvAggregateArgumentStatementDigest(statement *cvAggregateArgumentStatement) ([]byte, error) {
	wire, err := cvAggregateArgumentStatementCanonicalBytes(statement)
	if err != nil {
		return nil, err
	}
	return hashBytes([]byte(cvAggregateArgumentStatementDomain), wire), nil
}

func cvAggregateArgumentCanonicalBytes(argument *cvAggregateArgument) ([]byte, error) {
	if argument == nil || !cvValidAggregateArgumentProfile(argument.proofProfile) ||
		len(argument.circuitDigest) != 32 || len(argument.verificationKeyDigest) != 32 ||
		len(argument.proof) == 0 || len(argument.proof) > cvMaxAggregateArgumentProofBytes {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate argument")
	}
	statementWire, err := cvAggregateArgumentStatementCanonicalBytes(&argument.statement)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAggregateArgumentProofDomain))
	_ = cvWriteBytes(&wire, statementWire)
	_ = cvWriteBytes(&wire, []byte(argument.proofProfile))
	_ = cvWriteBytes(&wire, argument.circuitDigest)
	_ = cvWriteBytes(&wire, argument.verificationKeyDigest)
	_ = cvWriteBytes(&wire, argument.proof)
	return wire.Bytes(), nil
}

func cvDecodeAggregateArgument(wire []byte) (*cvAggregateArgument, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregateArgumentProofDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateArgumentProofDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate argument domain")
	}
	statementWire, err := r.bytes(1 << 20)
	if err != nil {
		return nil, fmt.Errorf("invalid aggregate argument statement wire")
	}
	statement, err := cvDecodeAggregateArgumentStatement(statementWire)
	if err != nil {
		return nil, err
	}
	profile, err := r.bytes(cvMaxAggregateArgumentProfileBytes)
	if err != nil || !cvValidAggregateArgumentProfile(string(profile)) {
		return nil, fmt.Errorf("invalid aggregate argument proof profile")
	}
	circuitDigest, err := r.bytes(32)
	if err != nil || len(circuitDigest) != 32 {
		return nil, fmt.Errorf("invalid aggregate argument circuit digest")
	}
	verificationKeyDigest, err := r.bytes(32)
	if err != nil || len(verificationKeyDigest) != 32 {
		return nil, fmt.Errorf("invalid aggregate argument verification-key digest")
	}
	proof, err := r.bytes(cvMaxAggregateArgumentProofBytes)
	if err != nil || len(proof) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid aggregate argument proof")
	}
	argument := &cvAggregateArgument{
		statement: *statement, proofProfile: string(profile),
		circuitDigest:         append([]byte(nil), circuitDigest...),
		verificationKeyDigest: append([]byte(nil), verificationKeyDigest...),
		proof:                 append([]byte(nil), proof...),
	}
	canonical, err := cvAggregateArgumentCanonicalBytes(argument)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS aggregate argument")
	}
	return argument, nil
}

func cvAggregateArgumentDigest(argument *cvAggregateArgument) ([]byte, error) {
	wire, err := cvAggregateArgumentCanonicalBytes(argument)
	if err != nil {
		return nil, err
	}
	return hashBytes([]byte(cvAggregateArgumentDigestDomain), wire), nil
}

func cvVerifyAggregateArgument(
	argument *cvAggregateArgument,
	expectedStatement *cvAggregateArgumentStatement,
	verifier cvAggregateArgumentVerifier,
) error {
	if argument == nil || verifier == nil {
		return fmt.Errorf("aggregate argument verifier is unavailable")
	}
	argumentWire, err := cvAggregateArgumentCanonicalBytes(argument)
	if err != nil {
		return err
	}
	decoded, err := cvDecodeAggregateArgument(argumentWire)
	if err != nil {
		return err
	}
	statementWire, err := cvAggregateArgumentStatementCanonicalBytes(&decoded.statement)
	if err != nil {
		return err
	}
	expectedWire, err := cvAggregateArgumentStatementCanonicalBytes(expectedStatement)
	if err != nil {
		return err
	}
	if !bytes.Equal(statementWire, expectedWire) {
		return fmt.Errorf("aggregate argument public statement mismatch")
	}
	if decoded.proofProfile != verifier.ProofProfile() ||
		!cvValidAggregateArgumentProfile(verifier.ProofProfile()) {
		return fmt.Errorf("aggregate argument proof profile mismatch")
	}
	if !bytes.Equal(decoded.circuitDigest, verifier.CircuitDigest()) ||
		len(verifier.CircuitDigest()) != 32 {
		return fmt.Errorf("aggregate argument circuit digest mismatch")
	}
	if !bytes.Equal(decoded.verificationKeyDigest, verifier.VerificationKeyDigest()) ||
		len(verifier.VerificationKeyDigest()) != 32 {
		return fmt.Errorf("aggregate argument verification-key digest mismatch")
	}
	if err := verifier.Verify(statementWire, append([]byte(nil), decoded.proof...)); err != nil {
		return fmt.Errorf("invalid aggregate argument proof: %w", err)
	}
	return nil
}
