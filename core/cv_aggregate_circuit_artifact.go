package core

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/consensys/gnark/constraint"
)

const (
	cvAggregateCircuitProfileDomain     = "ARL-CV-sAPVSS/aggregate-circuit-profile/v1"
	cvAggregateCircuitArtifactDomain    = "ARL-CV-sAPVSS/aggregate-circuit-artifact/v1"
	cvAggregateCircuitProofProfile      = "gnark-groth16-bn254/v1"
	cvAggregateStatementBindingProfile  = "gnark-groth16-bn254/statement-binding-v1"
	cvAggregateCircuitBackend           = "gnark-groth16"
	cvAggregateCircuitCurve             = "bn254"
	cvAggregateCircuitRelation          = "cv-aggregate-succinct-relation"
	cvAggregateStatementBindingRelation = "cv-aggregate-statement-binding"
	cvAggregateCircuitReceiptMode       = "feldman"
	cvMaxAggregateCircuitProfileBytes   = 1 << 16
)

// cvAggregateCircuitProfile describes every fixed-shape choice that can alter
// the aggregate relation. The R1CS digest below remains authoritative for the
// compiled constraints; this profile prevents a key from being silently
// reused under a different protocol-level shape or backend label.
type cvAggregateCircuitProfile struct {
	proofProfile string
	backend      string
	curve        string
	relation     string
	receiptMode  string

	componentCount      int
	receiverCount       int
	maxFallback         int
	digitCount          int
	aggregatePointCount int
	statementCapacity   int
	certificateCapacity int
	dispersalCapacity   int
}

func cvValidateAggregateCircuitProfile(profile *cvAggregateCircuitProfile) error {
	if profile == nil || !cvValidAggregateArgumentProfile(profile.proofProfile) ||
		!cvValidAggregateArgumentProfile(profile.backend) ||
		!cvValidAggregateArgumentProfile(profile.curve) ||
		!cvValidAggregateArgumentProfile(profile.relation) ||
		!cvValidAggregateArgumentProfile(profile.receiptMode) ||
		profile.componentCount <= 0 || profile.receiverCount <= 0 ||
		profile.maxFallback < 0 || profile.maxFallback >= profile.receiverCount ||
		profile.digitCount <= 0 || profile.aggregatePointCount <= 0 ||
		profile.statementCapacity <= 0 || profile.certificateCapacity <= 0 ||
		profile.dispersalCapacity <= 0 {
		return fmt.Errorf("invalid CV-sAPVSS aggregate circuit profile")
	}
	profileRelationOK :=
		(profile.proofProfile == cvAggregateCircuitProofProfile && profile.relation == cvAggregateCircuitRelation) ||
			(profile.proofProfile == cvAggregateStatementBindingProfile && profile.relation == cvAggregateStatementBindingRelation)
	if !profileRelationOK || profile.backend != cvAggregateCircuitBackend ||
		profile.curve != cvAggregateCircuitCurve ||
		profile.receiptMode != cvAggregateCircuitReceiptMode {
		return fmt.Errorf("unsupported CV-sAPVSS aggregate circuit profile backend")
	}
	return nil
}

func cvAggregateCircuitProfileCanonicalBytes(profile *cvAggregateCircuitProfile) ([]byte, error) {
	if err := cvValidateAggregateCircuitProfile(profile); err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	for _, value := range []string{
		cvAggregateCircuitProfileDomain,
		profile.proofProfile,
		profile.backend,
		profile.curve,
		profile.relation,
		profile.receiptMode,
	} {
		if err := cvWriteBytes(&wire, []byte(value)); err != nil {
			return nil, err
		}
	}
	for _, value := range []int{
		profile.componentCount,
		profile.receiverCount,
		profile.maxFallback,
		profile.digitCount,
		profile.aggregatePointCount,
		profile.statementCapacity,
		profile.certificateCapacity,
		profile.dispersalCapacity,
	} {
		if err := cvWriteUint32(&wire, value); err != nil {
			return nil, err
		}
	}
	return wire.Bytes(), nil
}

func cvDecodeAggregateCircuitProfile(wire []byte) (*cvAggregateCircuitProfile, error) {
	if len(wire) == 0 || len(wire) > cvMaxAggregateCircuitProfileBytes {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate circuit profile wire")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregateCircuitProfileDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateCircuitProfileDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate circuit profile domain")
	}
	fields := make([]string, 5)
	for i := range fields {
		value, err := r.bytes(cvMaxAggregateArgumentProfileBytes)
		if err != nil || len(value) == 0 {
			return nil, fmt.Errorf("invalid CV-sAPVSS aggregate circuit profile field")
		}
		fields[i] = string(value)
	}
	values := make([]int, 8)
	for i := range values {
		value, err := r.uint32()
		if err != nil {
			return nil, fmt.Errorf("invalid CV-sAPVSS aggregate circuit profile dimension")
		}
		values[i] = value
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV-sAPVSS aggregate circuit profile bytes")
	}
	profile := &cvAggregateCircuitProfile{
		proofProfile: fields[0], backend: fields[1], curve: fields[2],
		relation: fields[3], receiptMode: fields[4],
		componentCount: values[0], receiverCount: values[1], maxFallback: values[2],
		digitCount: values[3], aggregatePointCount: values[4], statementCapacity: values[5],
		certificateCapacity: values[6], dispersalCapacity: values[7],
	}
	canonical, err := cvAggregateCircuitProfileCanonicalBytes(profile)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS aggregate circuit profile")
	}
	return profile, nil
}

func cvAggregateCircuitProfileDigest(profile *cvAggregateCircuitProfile) ([]byte, error) {
	wire, err := cvAggregateCircuitProfileCanonicalBytes(profile)
	if err != nil {
		return nil, err
	}
	return hashBytes([]byte(cvAggregateCircuitProfileDomain), wire), nil
}

// cvDigestWriterTo hashes the exact bytes emitted by a gnark WriterTo without
// retaining proving-key or R1CS-sized buffers in memory.
func cvDigestWriterTo(domain string, writer io.WriterTo) ([]byte, error) {
	if domain == "" || writer == nil {
		return nil, fmt.Errorf("invalid CV-sAPVSS circuit artifact writer")
	}
	hasher := sha256.New()
	if _, err := hasher.Write([]byte(domain)); err != nil {
		return nil, err
	}
	written, err := writer.WriteTo(hasher)
	if err != nil {
		return nil, fmt.Errorf("hash CV-sAPVSS circuit artifact: %w", err)
	}
	if written < 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS circuit artifact byte count")
	}
	return hasher.Sum(nil), nil
}

type cvAggregateCircuitArtifact struct {
	profile               cvAggregateCircuitProfile
	circuitDigest         []byte
	verificationKeyDigest []byte
	publicVariables       uint64
	secretVariables       uint64
	constraints           uint64
	setupValidated        bool
}

func cvBuildAggregateCircuitArtifact(
	profile *cvAggregateCircuitProfile,
	ccs constraint.ConstraintSystem,
	vk io.WriterTo,
) (*cvAggregateCircuitArtifact, error) {
	if err := cvValidateAggregateCircuitProfile(profile); err != nil {
		return nil, err
	}
	if ccs == nil || vk == nil {
		return nil, fmt.Errorf("missing CV-sAPVSS aggregate circuit setup artifact")
	}
	profileDigest, err := cvAggregateCircuitProfileDigest(profile)
	if err != nil {
		return nil, err
	}
	r1csDigest, err := cvDigestWriterTo("ARL-CV-sAPVSS/r1cs/v1", ccs)
	if err != nil {
		return nil, err
	}
	verificationKeyDigest, err := cvDigestWriterTo("ARL-CV-sAPVSS/verification-key/v1", vk)
	if err != nil {
		return nil, err
	}
	circuitDigest := hashBytes(
		[]byte("ARL-CV-sAPVSS/circuit/v1"), profileDigest, r1csDigest,
	)
	return &cvAggregateCircuitArtifact{
		profile: *profile, circuitDigest: circuitDigest,
		verificationKeyDigest: verificationKeyDigest,
		publicVariables:       uint64(ccs.GetNbPublicVariables()),
		secretVariables:       uint64(ccs.GetNbSecretVariables()),
		constraints:           uint64(ccs.GetNbConstraints()),
		setupValidated:        true,
	}, nil
}

func cvValidateAggregateCircuitArtifact(artifact *cvAggregateCircuitArtifact) error {
	if artifact == nil || len(artifact.circuitDigest) != 32 ||
		len(artifact.verificationKeyDigest) != 32 || artifact.publicVariables == 0 ||
		artifact.secretVariables == 0 || artifact.constraints == 0 {
		return fmt.Errorf("invalid CV-sAPVSS aggregate circuit artifact")
	}
	if err := cvValidateAggregateCircuitProfile(&artifact.profile); err != nil {
		return err
	}
	return nil
}

func cvAggregateCircuitArtifactCanonicalBytes(artifact *cvAggregateCircuitArtifact) ([]byte, error) {
	if err := cvValidateAggregateCircuitArtifact(artifact); err != nil {
		return nil, err
	}
	profileWire, err := cvAggregateCircuitProfileCanonicalBytes(&artifact.profile)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	if err := cvWriteBytes(&wire, []byte(cvAggregateCircuitArtifactDomain)); err != nil {
		return nil, err
	}
	if err := cvWriteBytes(&wire, profileWire); err != nil {
		return nil, err
	}
	for _, digest := range [][]byte{artifact.circuitDigest, artifact.verificationKeyDigest} {
		if err := cvWriteBytes(&wire, digest); err != nil {
			return nil, err
		}
	}
	for _, value := range []uint64{
		artifact.publicVariables, artifact.secretVariables, artifact.constraints,
	} {
		cvWriteUint64(&wire, value)
	}
	return wire.Bytes(), nil
}

func cvDecodeAggregateCircuitArtifact(wire []byte) (*cvAggregateCircuitArtifact, error) {
	if len(wire) == 0 || len(wire) > cvMaxAggregateCircuitProfileBytes+512 {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate circuit artifact wire")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregateCircuitArtifactDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateCircuitArtifactDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate circuit artifact domain")
	}
	profileWire, err := r.bytes(cvMaxAggregateCircuitProfileBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate circuit profile wire")
	}
	profile, err := cvDecodeAggregateCircuitProfile(profileWire)
	if err != nil {
		return nil, err
	}
	digests := make([][]byte, 2)
	for i := range digests {
		digests[i], err = r.bytes(32)
		if err != nil || len(digests[i]) != 32 {
			return nil, fmt.Errorf("invalid CV-sAPVSS aggregate circuit artifact digest")
		}
	}
	metrics := make([]uint64, 3)
	for i := range metrics {
		metrics[i], err = r.uint64()
		if err != nil {
			return nil, fmt.Errorf("invalid CV-sAPVSS aggregate circuit artifact metric")
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV-sAPVSS aggregate circuit artifact bytes")
	}
	artifact := &cvAggregateCircuitArtifact{
		profile: *profile, circuitDigest: digests[0], verificationKeyDigest: digests[1],
		publicVariables: metrics[0], secretVariables: metrics[1], constraints: metrics[2],
	}
	if err := cvValidateAggregateCircuitArtifact(artifact); err != nil {
		return nil, err
	}
	canonical, err := cvAggregateCircuitArtifactCanonicalBytes(artifact)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS aggregate circuit artifact")
	}
	return artifact, nil
}

// cvValidateAggregateCircuitArtifactAgainst recomputes both setup identities
// from locally supplied bytes. Decoding an artifact wire alone is intentionally
// insufficient: the wire carries the claimed digests, while this method binds
// them to the verifier's actual compiled R1CS and verification key.
func cvValidateAggregateCircuitArtifactAgainst(
	artifact *cvAggregateCircuitArtifact,
	ccs constraint.ConstraintSystem,
	vk io.WriterTo,
) error {
	if err := cvValidateAggregateCircuitArtifact(artifact); err != nil {
		return err
	}
	if ccs == nil || vk == nil {
		return fmt.Errorf("missing local CV-sAPVSS aggregate circuit setup")
	}
	profileDigest, err := cvAggregateCircuitProfileDigest(&artifact.profile)
	if err != nil {
		return err
	}
	r1csDigest, err := cvDigestWriterTo("ARL-CV-sAPVSS/r1cs/v1", ccs)
	if err != nil {
		return err
	}
	wantCircuitDigest := hashBytes([]byte("ARL-CV-sAPVSS/circuit/v1"), profileDigest, r1csDigest)
	if !bytes.Equal(wantCircuitDigest, artifact.circuitDigest) {
		return fmt.Errorf("CV-sAPVSS aggregate circuit digest does not match local R1CS")
	}
	wantVKDigest, err := cvDigestWriterTo("ARL-CV-sAPVSS/verification-key/v1", vk)
	if err != nil {
		return err
	}
	if !bytes.Equal(wantVKDigest, artifact.verificationKeyDigest) {
		return fmt.Errorf("CV-sAPVSS aggregate verification-key digest mismatch")
	}
	if uint64(ccs.GetNbPublicVariables()) != artifact.publicVariables ||
		uint64(ccs.GetNbSecretVariables()) != artifact.secretVariables ||
		uint64(ccs.GetNbConstraints()) != artifact.constraints {
		return fmt.Errorf("CV-sAPVSS aggregate circuit metrics mismatch")
	}
	artifact.setupValidated = true
	return nil
}

func (a *cvAggregateCircuitArtifact) ProofProfile() string {
	if a == nil || !a.setupValidated {
		return ""
	}
	return a.profile.proofProfile
}

func (a *cvAggregateCircuitArtifact) CircuitDigest() []byte {
	if a == nil || !a.setupValidated {
		return nil
	}
	return append([]byte(nil), a.circuitDigest...)
}

func (a *cvAggregateCircuitArtifact) VerificationKeyDigest() []byte {
	if a == nil || !a.setupValidated {
		return nil
	}
	return append([]byte(nil), a.verificationKeyDigest...)
}

// cvAggregateProofBackend verifies proof bytes only. Setup identity is owned by
// cvArtifactBoundAggregateArgumentVerifier so a backend cannot supply arbitrary
// profile, circuit, or verification-key digests.
type cvAggregateProofBackend interface {
	Verify(statementWire, proof []byte) error
}

type cvArtifactBoundAggregateArgumentVerifier struct {
	artifact *cvAggregateCircuitArtifact
	backend  cvAggregateProofBackend
}

func cvBindAggregateArgumentVerifier(
	artifact *cvAggregateCircuitArtifact,
	backend cvAggregateProofBackend,
) (*cvArtifactBoundAggregateArgumentVerifier, error) {
	if err := cvValidateAggregateCircuitArtifact(artifact); err != nil {
		return nil, err
	}
	if !artifact.setupValidated || backend == nil {
		return nil, fmt.Errorf("aggregate argument setup or proof backend is not validated")
	}
	boundArtifact := *artifact
	boundArtifact.circuitDigest = append([]byte(nil), artifact.circuitDigest...)
	boundArtifact.verificationKeyDigest = append([]byte(nil), artifact.verificationKeyDigest...)
	return &cvArtifactBoundAggregateArgumentVerifier{artifact: &boundArtifact, backend: backend}, nil
}

func (v *cvArtifactBoundAggregateArgumentVerifier) ProofProfile() string {
	if v == nil {
		return ""
	}
	return v.artifact.ProofProfile()
}

func (v *cvArtifactBoundAggregateArgumentVerifier) CircuitDigest() []byte {
	if v == nil {
		return nil
	}
	return v.artifact.CircuitDigest()
}

func (v *cvArtifactBoundAggregateArgumentVerifier) VerificationKeyDigest() []byte {
	if v == nil {
		return nil
	}
	return v.artifact.VerificationKeyDigest()
}

func (v *cvArtifactBoundAggregateArgumentVerifier) Verify(statementWire, proof []byte) error {
	if v == nil || v.backend == nil || v.artifact == nil || !v.artifact.setupValidated {
		return fmt.Errorf("aggregate argument proof backend is unavailable")
	}
	return v.backend.Verify(append([]byte(nil), statementWire...), append([]byte(nil), proof...))
}
