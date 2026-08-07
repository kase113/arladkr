package core

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

const (
	cvComponentStatementCommitmentDomain   = "ARL-CV-sAPVSS/component-statement-commitment/v1"
	cvComponentCertificateCommitmentDomain = "ARL-CV-sAPVSS/component-certificate-commitment/v1"
)

type cvPoseidon2BytesWitness struct {
	Length    frontend.Variable
	LastBytes frontend.Variable
	Chunks    []frontend.Variable
	Active    []frontend.Variable
}

// cvComponentCertificateBindingCircuit binds the exact statement and recovered
// certificate bytes used by native threshold-BLS verification. It does not
// verify the BLS pairing; cvValidateComponentDescriptor remains mandatory.
type cvComponentCertificateBindingCircuit struct {
	Statement   cvPoseidon2BytesWitness
	Certificate cvPoseidon2BytesWitness

	StatementCommitment   frontend.Variable `gnark:",public"`
	CertificateCommitment frontend.Variable `gnark:",public"`
}

func (c *cvComponentCertificateBindingCircuit) Define(api frontend.API) error {
	if err := cvAssertPoseidon2BytesCommitment(
		api, cvComponentStatementCommitmentDomain,
		c.Statement.Length, c.Statement.LastBytes,
		c.Statement.Chunks, c.Statement.Active,
		c.StatementCommitment,
	); err != nil {
		return fmt.Errorf("component statement binding: %w", err)
	}
	if err := cvAssertPoseidon2BytesCommitment(
		api, cvComponentCertificateCommitmentDomain,
		c.Certificate.Length, c.Certificate.LastBytes,
		c.Certificate.Chunks, c.Certificate.Active,
		c.CertificateCommitment,
	); err != nil {
		return fmt.Errorf("component certificate binding: %w", err)
	}
	return nil
}

func cvPoseidon2BytesCircuitWitness(value []byte, capacity int) (cvPoseidon2BytesWitness, error) {
	if len(value) == 0 {
		return cvPoseidon2BytesWitness{}, fmt.Errorf("empty Poseidon2 byte witness")
	}
	chunkCount := (len(value) + cvSemanticCommitmentChunkBytes - 1) / cvSemanticCommitmentChunkBytes
	if capacity < chunkCount {
		return cvPoseidon2BytesWitness{}, fmt.Errorf("Poseidon2 byte witness capacity is too small")
	}
	witness := cvPoseidon2BytesWitness{
		Length: len(value), LastBytes: len(value) - (chunkCount-1)*cvSemanticCommitmentChunkBytes,
		Chunks: make([]frontend.Variable, capacity), Active: make([]frontend.Variable, capacity),
	}
	for i := range witness.Chunks {
		witness.Chunks[i] = 0
		witness.Active[i] = 0
	}
	for i := 0; i < chunkCount; i++ {
		start := i * cvSemanticCommitmentChunkBytes
		end := start + cvSemanticCommitmentChunkBytes
		if end > len(value) {
			end = len(value)
		}
		witness.Chunks[i] = new(big.Int).SetBytes(value[start:end])
		witness.Active[i] = 1
	}
	return witness, nil
}

func cvComponentCertificateBindingAssignment(
	descriptor *cvComponentDescriptor,
	statementCapacity, certificateCapacity int,
) (*cvComponentCertificateBindingCircuit, error) {
	if err := cvValidateComponentDescriptorShape(descriptor); err != nil {
		return nil, err
	}
	statementWire, err := cvComponentStatementCanonicalBytes(
		descriptor.dealer, descriptor.leafDigest, &descriptor.dispersal,
	)
	if err != nil {
		return nil, err
	}
	statementCommitment, err := cvPoseidon2BytesCommitment(
		cvComponentStatementCommitmentDomain, statementWire, cvMaxNetworkPayloadBytes,
	)
	if err != nil {
		return nil, err
	}
	certificateCommitment, err := cvPoseidon2BytesCommitment(
		cvComponentCertificateCommitmentDomain, descriptor.certificate, cvMaxComponentSignatureBytes,
	)
	if err != nil {
		return nil, err
	}
	statementWitness, err := cvPoseidon2BytesCircuitWitness(statementWire, statementCapacity)
	if err != nil {
		return nil, err
	}
	certificateWitness, err := cvPoseidon2BytesCircuitWitness(descriptor.certificate, certificateCapacity)
	if err != nil {
		return nil, err
	}
	return &cvComponentCertificateBindingCircuit{
		Statement: statementWitness, Certificate: certificateWitness,
		StatementCommitment:   new(big.Int).SetBytes(statementCommitment),
		CertificateCommitment: new(big.Int).SetBytes(certificateCommitment),
	}, nil
}
