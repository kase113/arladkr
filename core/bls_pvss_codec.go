package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	blsPVSSWireDomain   = "arladkr-bls-pvss-v1"
	blsPVSSMaxSIDBytes  = 4096
	blsPVSSMaxReceivers = 1 << 20
)

func encodeBlsPVSSDealerTranscript(tx *BlsPVSSDealerTranscript) ([]byte, error) {
	if tx == nil {
		return nil, fmt.Errorf("nil BLS PVSS transcript")
	}
	if tx.NIZKProof == nil {
		return nil, fmt.Errorf("missing BLS PVSS proof")
	}
	if len(tx.SID) > blsPVSSMaxSIDBytes {
		return nil, fmt.Errorf("BLS PVSS SID too long: %d", len(tx.SID))
	}
	n := len(tx.ReceiverOrder)
	if n == 0 || n > blsPVSSMaxReceivers {
		return nil, fmt.Errorf("invalid BLS PVSS receiver count: %d", n)
	}
	if len(tx.Commitments) != n || len(tx.EncryptedShares) != n {
		return nil, fmt.Errorf(
			"BLS PVSS vector length mismatch: receivers=%d commitments=%d ciphertexts=%d",
			n,
			len(tx.Commitments),
			len(tx.EncryptedShares),
		)
	}

	var out bytes.Buffer
	if err := writeBlsPVSSBytes(&out, []byte(blsPVSSWireDomain)); err != nil {
		return nil, err
	}
	if err := writeBlsPVSSBytes(&out, []byte(tx.SID)); err != nil {
		return nil, err
	}
	if err := binary.Write(&out, binary.BigEndian, int64(tx.Epoch)); err != nil {
		return nil, err
	}
	if err := binary.Write(&out, binary.BigEndian, int64(tx.Dealer)); err != nil {
		return nil, err
	}
	if err := binary.Write(&out, binary.BigEndian, uint32(n)); err != nil {
		return nil, err
	}
	for _, receiver := range tx.ReceiverOrder {
		if err := binary.Write(&out, binary.BigEndian, int64(receiver)); err != nil {
			return nil, err
		}
	}
	if _, err := out.Write(g1Bytes(&tx.Zeta)); err != nil {
		return nil, err
	}
	for i := range tx.Commitments {
		if _, err := out.Write(g1Bytes(&tx.Commitments[i])); err != nil {
			return nil, err
		}
	}
	for i := range tx.EncryptedShares {
		if _, err := out.Write(g2Bytes(&tx.EncryptedShares[i])); err != nil {
			return nil, err
		}
	}
	if err := out.WriteByte(1); err != nil {
		return nil, err
	}
	for _, encoded := range [][]byte{
		frBytes(&tx.NIZKProof.Challenge),
		frBytes(&tx.NIZKProof.Response),
		g1Bytes(&tx.NIZKProof.Commitment1),
		g2Bytes(&tx.NIZKProof.Commitment2),
	} {
		if _, err := out.Write(encoded); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

func decodeBlsPVSSDealerTranscript(payload []byte) (*BlsPVSSDealerTranscript, error) {
	r := bytes.NewReader(payload)
	domain, err := readBlsPVSSBytes(r, len(blsPVSSWireDomain))
	if err != nil {
		return nil, fmt.Errorf("decode BLS PVSS domain: %w", err)
	}
	if string(domain) != blsPVSSWireDomain {
		return nil, fmt.Errorf("unexpected BLS PVSS domain: %q", domain)
	}
	sid, err := readBlsPVSSBytes(r, blsPVSSMaxSIDBytes)
	if err != nil {
		return nil, fmt.Errorf("decode BLS PVSS SID: %w", err)
	}
	var epoch64, dealer64 int64
	if err := binary.Read(r, binary.BigEndian, &epoch64); err != nil {
		return nil, fmt.Errorf("decode BLS PVSS epoch: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &dealer64); err != nil {
		return nil, fmt.Errorf("decode BLS PVSS dealer: %w", err)
	}
	epoch, err := checkedBlsPVSSInt(epoch64, "epoch")
	if err != nil {
		return nil, err
	}
	dealer, err := checkedBlsPVSSInt(dealer64, "dealer")
	if err != nil {
		return nil, err
	}
	var count uint32
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, fmt.Errorf("decode BLS PVSS receiver count: %w", err)
	}
	if count == 0 || count > blsPVSSMaxReceivers {
		return nil, fmt.Errorf("invalid BLS PVSS receiver count: %d", count)
	}
	n := int(count)
	receivers := make([]int, n)
	for i := range receivers {
		var receiver64 int64
		if err := binary.Read(r, binary.BigEndian, &receiver64); err != nil {
			return nil, fmt.Errorf("decode BLS PVSS receiver[%d]: %w", i, err)
		}
		receivers[i], err = checkedBlsPVSSInt(receiver64, "receiver")
		if err != nil {
			return nil, err
		}
	}

	tx := &BlsPVSSDealerTranscript{
		SID:             string(sid),
		Epoch:           epoch,
		ReceiverOrder:   receivers,
		Dealer:          dealer,
		Commitments:     make([]bls12381.G1Affine, n),
		EncryptedShares: make([]bls12381.G2Affine, n),
	}
	if err := readBlsPVSSG1(r, &tx.Zeta, "zeta"); err != nil {
		return nil, err
	}
	for i := range tx.Commitments {
		if err := readBlsPVSSG1(r, &tx.Commitments[i], fmt.Sprintf("commitment[%d]", i)); err != nil {
			return nil, err
		}
	}
	for i := range tx.EncryptedShares {
		if err := readBlsPVSSG2(r, &tx.EncryptedShares[i], fmt.Sprintf("ciphertext[%d]", i)); err != nil {
			return nil, err
		}
	}
	present, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("decode BLS PVSS proof marker: %w", err)
	}
	if present != 1 {
		return nil, fmt.Errorf("invalid BLS PVSS proof marker: %d", present)
	}
	proof := &ChaumPedersenNIZK{}
	if err := readBlsPVSSScalar(r, &proof.Challenge, "challenge"); err != nil {
		return nil, err
	}
	if err := readBlsPVSSScalar(r, &proof.Response, "response"); err != nil {
		return nil, err
	}
	if err := readBlsPVSSG1(r, &proof.Commitment1, "proof commitment1"); err != nil {
		return nil, err
	}
	if err := readBlsPVSSG2(r, &proof.Commitment2, "proof commitment2"); err != nil {
		return nil, err
	}
	tx.NIZKProof = proof
	if r.Len() != 0 {
		return nil, fmt.Errorf("trailing BLS PVSS transcript bytes: %d", r.Len())
	}
	return tx, nil
}

func writeBlsPVSSBytes(out *bytes.Buffer, value []byte) error {
	if uint64(len(value)) > uint64(^uint32(0)) {
		return fmt.Errorf("BLS PVSS byte string too long: %d", len(value))
	}
	if err := binary.Write(out, binary.BigEndian, uint32(len(value))); err != nil {
		return err
	}
	_, err := out.Write(value)
	return err
}

func readBlsPVSSBytes(r *bytes.Reader, max int) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if int(length) > max {
		return nil, fmt.Errorf("length %d exceeds maximum %d", length, max)
	}
	value := make([]byte, int(length))
	if _, err := io.ReadFull(r, value); err != nil {
		return nil, err
	}
	return value, nil
}

func checkedBlsPVSSInt(value int64, field string) (int, error) {
	converted := int(value)
	if int64(converted) != value {
		return 0, fmt.Errorf("BLS PVSS %s does not fit int: %d", field, value)
	}
	return converted, nil
}

func readBlsPVSSG1(r *bytes.Reader, point *bls12381.G1Affine, field string) error {
	encoded := make([]byte, bls12381.SizeOfG1AffineCompressed)
	if _, err := io.ReadFull(r, encoded); err != nil {
		return fmt.Errorf("decode BLS PVSS %s: %w", field, err)
	}
	consumed, err := point.SetBytes(encoded)
	if err != nil {
		return fmt.Errorf("decode BLS PVSS %s: %w", field, err)
	}
	if consumed != len(encoded) {
		return fmt.Errorf("decode BLS PVSS %s consumed %d bytes, need %d", field, consumed, len(encoded))
	}
	return nil
}

func readBlsPVSSG2(r *bytes.Reader, point *bls12381.G2Affine, field string) error {
	encoded := make([]byte, bls12381.SizeOfG2AffineCompressed)
	if _, err := io.ReadFull(r, encoded); err != nil {
		return fmt.Errorf("decode BLS PVSS %s: %w", field, err)
	}
	consumed, err := point.SetBytes(encoded)
	if err != nil {
		return fmt.Errorf("decode BLS PVSS %s: %w", field, err)
	}
	if consumed != len(encoded) {
		return fmt.Errorf("decode BLS PVSS %s consumed %d bytes, need %d", field, consumed, len(encoded))
	}
	return nil
}

func readBlsPVSSScalar(r *bytes.Reader, scalar *fr.Element, field string) error {
	encoded := make([]byte, fr.Bytes)
	if _, err := io.ReadFull(r, encoded); err != nil {
		return fmt.Errorf("decode BLS PVSS %s: %w", field, err)
	}
	if err := scalar.SetBytesCanonical(encoded); err != nil {
		return fmt.Errorf("decode BLS PVSS %s: %w", field, err)
	}
	return nil
}
