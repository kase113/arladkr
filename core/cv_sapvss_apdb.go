package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	cvAPDBInstanceDomain  = "ARL-CV-sAPVSS/v2-scalar-group/apdb-instance"
	cvAPDBStoredDomain    = "ARL-CV-sAPVSS/v2-scalar-group/apdb-stored"
	cvAPDBShardDomain     = "ARL-CV-sAPVSS/v2-scalar-group/apdb-shard"
	cvAPDBNodeDomain      = "ARL-CV-sAPVSS/v2-scalar-group/apdb-node"
	cvAPDBLockWireDomain  = "ARL-CV-sAPVSS/v2-scalar-group/apdb-lock"
	cvAPDBStoreWireDomain = "ARL-CV-sAPVSS/v2-scalar-group/apdb-store"
)

// cvAPDBLockV2 is the compact public certificate of an immutable APDB
// instance. Individual holder identities and signature shares never enter it.
type cvAPDBLockV2 struct {
	InstanceDigest []byte
	Root           []byte
	Certificate    []byte
}

type cvAPDBStoreV2 struct {
	InstanceDigest []byte
	Root           []byte
	Index          int
	Shard          []byte
	Siblings       [][]byte
}

type cvAPDBEncodedV2 struct {
	instanceDigest []byte
	root           []byte
	dataShards     int
	totalShards    int
	shardBytes     int
	stores         []cvAPDBStoreV2
}

func cvAPDBInstanceDigestV2(label string, parts ...[]byte) ([]byte, error) {
	if label == "" {
		return nil, fmt.Errorf("empty CV V2 APDB instance label")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(label))
	for _, part := range parts {
		if err := cvWriteBytes(&wire, part); err != nil {
			return nil, err
		}
	}
	return hashBytes([]byte(cvAPDBInstanceDomain), wire.Bytes()), nil
}

func cvAPDBStoredStatementV2(instanceDigest, root []byte) ([]byte, error) {
	if len(instanceDigest) != 32 || len(root) != 32 {
		return nil, fmt.Errorf("invalid CV V2 APDB stored statement")
	}
	return hashBytes([]byte(cvAPDBStoredDomain), instanceDigest, root), nil
}

func cvAPDBEncodeV2(instanceDigest, payload []byte, dataShards, totalShards, maximumPayload int) (*cvAPDBEncodedV2, error) {
	if len(instanceDigest) != 32 || len(payload) == 0 || maximumPayload <= 0 || len(payload) > maximumPayload ||
		dataShards <= 0 || totalShards < dataShards {
		return nil, fmt.Errorf("invalid CV V2 APDB encoding parameters")
	}
	shardBytes := (8 + len(payload) + dataShards - 1) / dataShards
	return cvAPDBEncodeSizedV2(instanceDigest, payload, dataShards, totalShards, shardBytes, maximumPayload)
}

func cvAPDBEncodeSizedV2(
	instanceDigest, payload []byte, dataShards, totalShards, shardBytes, maximumPayload int,
) (*cvAPDBEncodedV2, error) {
	if len(instanceDigest) != 32 || len(payload) == 0 || maximumPayload <= 0 || len(payload) > maximumPayload ||
		dataShards <= 0 || totalShards < dataShards || shardBytes <= 0 ||
		8+len(payload) > dataShards*shardBytes {
		return nil, fmt.Errorf("invalid CV V2 fixed-size APDB encoding parameters")
	}
	packed := make([]byte, dataShards*shardBytes)
	binary.BigEndian.PutUint64(packed[:8], uint64(len(payload)))
	copy(packed[8:], payload)
	shards, err := cvErasureEncode(packed, dataShards, totalShards)
	if err != nil {
		return nil, fmt.Errorf("encode CV V2 APDB payload: %w", err)
	}
	if len(shards) != totalShards || len(shards) == 0 || len(shards[0]) == 0 {
		return nil, fmt.Errorf("invalid CV V2 APDB encoded shard set")
	}
	root, branches := cvAPDBBuildMerkleV2(instanceDigest, shards)
	encoded := &cvAPDBEncodedV2{
		instanceDigest: append([]byte(nil), instanceDigest...), root: root,
		dataShards: dataShards, totalShards: totalShards, shardBytes: len(shards[0]),
		stores: make([]cvAPDBStoreV2, totalShards),
	}
	for i := range shards {
		encoded.stores[i] = cvAPDBStoreV2{
			InstanceDigest: append([]byte(nil), instanceDigest...), Root: append([]byte(nil), root...), Index: i,
			Shard: append([]byte(nil), shards[i]...), Siblings: cvCloneByteSlices(branches[i]),
		}
	}
	return encoded, nil
}

func cvAPDBBuildMerkleV2(instanceDigest []byte, shards [][]byte) ([]byte, [][][]byte) {
	levels := [][][]byte{make([][]byte, len(shards))}
	for i := range shards {
		levels[0][i] = cvAPDBShardHashV2(instanceDigest, i, shards[i])
	}
	for len(levels[len(levels)-1]) > 1 {
		level := levels[len(levels)-1]
		padded := level
		if len(level)%2 == 1 {
			padded = append(append([][]byte(nil), level...), level[len(level)-1])
		}
		next := make([][]byte, 0, len(padded)/2)
		for i := 0; i < len(padded); i += 2 {
			next = append(next, hashBytes([]byte(cvAPDBNodeDomain), padded[i], padded[i+1]))
		}
		levels = append(levels, next)
	}
	branches := make([][][]byte, len(shards))
	for i := range shards {
		index := i
		for depth := 0; depth < len(levels)-1; depth++ {
			level := levels[depth]
			sibling := index ^ 1
			if sibling >= len(level) {
				sibling = len(level) - 1
			}
			branches[i] = append(branches[i], append([]byte(nil), level[sibling]...))
			index /= 2
		}
	}
	return append([]byte(nil), levels[len(levels)-1][0]...), branches
}

func cvAPDBShardHashV2(instanceDigest []byte, index int, shard []byte) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(index))
	return hashBytes([]byte(cvAPDBShardDomain), instanceDigest, encoded[:], shard)
}

func cvVerifyAPDBStoreV2(store *cvAPDBStoreV2, totalShards, shardBytes int) error {
	if store == nil || len(store.InstanceDigest) != 32 || len(store.Root) != 32 || store.Index < 0 ||
		store.Index >= totalShards || shardBytes <= 0 || len(store.Shard) != shardBytes {
		return fmt.Errorf("invalid CV V2 APDB store")
	}
	wantDepth := cvAPDBMerkleDepth(totalShards)
	if len(store.Siblings) != wantDepth {
		return fmt.Errorf("invalid CV V2 APDB Merkle branch depth")
	}
	digest := cvAPDBShardHashV2(store.InstanceDigest, store.Index, store.Shard)
	index := store.Index
	for _, sibling := range store.Siblings {
		if len(sibling) != 32 {
			return fmt.Errorf("invalid CV V2 APDB Merkle sibling")
		}
		if index%2 == 0 {
			digest = hashBytes([]byte(cvAPDBNodeDomain), digest, sibling)
		} else {
			digest = hashBytes([]byte(cvAPDBNodeDomain), sibling, digest)
		}
		index /= 2
	}
	if !bytes.Equal(digest, store.Root) {
		return fmt.Errorf("CV V2 APDB store root mismatch")
	}
	return nil
}

func cvAPDBMerkleDepth(totalShards int) int {
	depth := 0
	for totalShards > 1 {
		depth++
		totalShards = (totalShards + 1) / 2
	}
	return depth
}

func cvNewAPDBLockV2(encoded *cvAPDBEncodedV2, certificate []byte) (*cvAPDBLockV2, error) {
	if encoded == nil || len(encoded.instanceDigest) != 32 || len(encoded.root) != 32 || len(certificate) == 0 ||
		len(certificate) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 APDB lock")
	}
	return &cvAPDBLockV2{
		InstanceDigest: append([]byte(nil), encoded.instanceDigest...), Root: append([]byte(nil), encoded.root...),
		Certificate: append([]byte(nil), certificate...),
	}, nil
}

func cvVerifyAPDBLockV2(lock *cvAPDBLockV2, signer *tblsThresholdSigner) error {
	if lock == nil || len(lock.InstanceDigest) != 32 || len(lock.Root) != 32 || len(lock.Certificate) == 0 ||
		len(lock.Certificate) > cvMaxComponentSignatureBytes || !cvV2SignerHasRole(signer, cvV2RoleAPDB) {
		return fmt.Errorf("invalid CV V2 APDB lock")
	}
	statement, err := cvAPDBStoredStatementV2(lock.InstanceDigest, lock.Root)
	if err != nil || !signer.VerifyRecovered(cvAPDBStoredDomain, statement, lock.Certificate) {
		return fmt.Errorf("invalid CV V2 APDB lock certificate")
	}
	return nil
}

func cvRecoverAPDBV2(
	lock *cvAPDBLockV2, stores []cvAPDBStoreV2, dataShards, totalShards, shardBytes, maximumPayload int,
	bindingCheck func([]byte) error,
) ([]byte, error) {
	if lock == nil || len(lock.InstanceDigest) != 32 || len(lock.Root) != 32 || dataShards <= 0 ||
		totalShards < dataShards || shardBytes <= 0 || maximumPayload <= 0 || len(stores) < dataShards {
		return nil, fmt.Errorf("invalid CV V2 APDB recovery input")
	}
	shards := make([][]byte, totalShards)
	seen := make(map[int]struct{}, len(stores))
	for i := range stores {
		store := &stores[i]
		if !bytes.Equal(store.InstanceDigest, lock.InstanceDigest) || !bytes.Equal(store.Root, lock.Root) ||
			cvVerifyAPDBStoreV2(store, totalShards, shardBytes) != nil {
			return nil, fmt.Errorf("invalid CV V2 APDB recovery store")
		}
		if _, duplicate := seen[store.Index]; duplicate {
			return nil, fmt.Errorf("duplicate CV V2 APDB recovery store index")
		}
		seen[store.Index] = struct{}{}
		shards[store.Index] = append([]byte(nil), store.Shard...)
	}
	if len(seen) < dataShards {
		return nil, fmt.Errorf("insufficient CV V2 APDB recovery stores")
	}
	packed, err := cvErasureDecode(shards, dataShards)
	if err != nil {
		return nil, fmt.Errorf("decode CV V2 APDB payload: %w", err)
	}
	if len(packed) < 8 {
		return nil, fmt.Errorf("truncated CV V2 APDB payload")
	}
	length := binary.BigEndian.Uint64(packed[:8])
	if length == 0 || length > uint64(len(packed)-8) || length > uint64(maximumPayload) {
		return nil, fmt.Errorf("invalid recovered CV V2 APDB payload length")
	}
	payload := append([]byte(nil), packed[8:8+int(length)]...)
	reencoded, err := cvAPDBEncodeSizedV2(
		lock.InstanceDigest, payload, dataShards, totalShards, shardBytes, maximumPayload,
	)
	if err != nil || !bytes.Equal(reencoded.root, lock.Root) {
		return nil, fmt.Errorf("CV V2 APDB deterministic re-encoding root mismatch")
	}
	if bindingCheck != nil {
		if err := bindingCheck(payload); err != nil {
			return nil, fmt.Errorf("CV V2 APDB binding check: %w", err)
		}
	}
	return payload, nil
}

func cvAPDBLockV2CanonicalBytes(lock *cvAPDBLockV2) ([]byte, error) {
	if lock == nil || len(lock.InstanceDigest) != 32 || len(lock.Root) != 32 || len(lock.Certificate) == 0 ||
		len(lock.Certificate) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 APDB lock")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAPDBLockWireDomain))
	_ = cvWriteBytes(&wire, lock.InstanceDigest)
	_ = cvWriteBytes(&wire, lock.Root)
	_ = cvWriteBytes(&wire, lock.Certificate)
	return wire.Bytes(), nil
}

func cvDecodeAPDBLockV2(wire []byte) (*cvAPDBLockV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAPDBLockWireDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAPDBLockWireDomain)) {
		return nil, fmt.Errorf("invalid CV V2 APDB lock domain")
	}
	instanceDigest, err := r.bytes(32)
	if err != nil || len(instanceDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 APDB lock instance")
	}
	root, err := r.bytes(32)
	if err != nil || len(root) != 32 {
		return nil, fmt.Errorf("invalid CV V2 APDB lock root")
	}
	certificate, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(certificate) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 APDB lock certificate")
	}
	lock := &cvAPDBLockV2{InstanceDigest: instanceDigest, Root: root, Certificate: certificate}
	canonical, err := cvAPDBLockV2CanonicalBytes(lock)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 APDB lock")
	}
	return lock, nil
}

func cvAPDBStoreV2CanonicalBytes(store *cvAPDBStoreV2, totalShards, shardBytes int) ([]byte, error) {
	if err := cvVerifyAPDBStoreV2(store, totalShards, shardBytes); err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAPDBStoreWireDomain))
	_ = cvWriteBytes(&wire, store.InstanceDigest)
	_ = cvWriteBytes(&wire, store.Root)
	if err := cvWriteUint32(&wire, store.Index); err != nil {
		return nil, err
	}
	_ = cvWriteBytes(&wire, store.Shard)
	if err := cvWriteUint32(&wire, len(store.Siblings)); err != nil {
		return nil, err
	}
	for _, sibling := range store.Siblings {
		_ = cvWriteBytes(&wire, sibling)
	}
	return wire.Bytes(), nil
}

func cvDecodeAPDBStoreV2(wire []byte, totalShards, shardBytes int) (*cvAPDBStoreV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAPDBStoreWireDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAPDBStoreWireDomain)) {
		return nil, fmt.Errorf("invalid CV V2 APDB store domain")
	}
	instanceDigest, err := r.bytes(32)
	if err != nil || len(instanceDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 APDB store instance")
	}
	root, err := r.bytes(32)
	if err != nil || len(root) != 32 {
		return nil, fmt.Errorf("invalid CV V2 APDB store root")
	}
	index, err := r.uint32()
	if err != nil || index < 0 || index >= totalShards {
		return nil, fmt.Errorf("invalid CV V2 APDB store index")
	}
	shard, err := r.bytes(shardBytes)
	if err != nil || len(shard) != shardBytes {
		return nil, fmt.Errorf("invalid CV V2 APDB store shard")
	}
	depth, err := r.uint32()
	if err != nil || depth != cvAPDBMerkleDepth(totalShards) {
		return nil, fmt.Errorf("invalid CV V2 APDB store branch depth")
	}
	siblings := make([][]byte, depth)
	for i := range siblings {
		siblings[i], err = r.bytes(32)
		if err != nil || len(siblings[i]) != 32 {
			return nil, fmt.Errorf("invalid CV V2 APDB store sibling")
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV V2 APDB store bytes")
	}
	store := &cvAPDBStoreV2{InstanceDigest: instanceDigest, Root: root, Index: index, Shard: shard, Siblings: siblings}
	canonical, err := cvAPDBStoreV2CanonicalBytes(store, totalShards, shardBytes)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 APDB store")
	}
	return store, nil
}

func cvCloneByteSlices(input [][]byte) [][]byte {
	out := make([][]byte, len(input))
	for i := range input {
		out[i] = append([]byte(nil), input[i]...)
	}
	return out
}

const cvAPDBPayloadWireDomain = "ARL-CV-sAPVSS/v2-scalar-group/apdb-recover-payload"

type cvAPDBPayloadResponseV2 struct {
	InstanceDigest []byte
	Payload        []byte
}

func cvAPDBPayloadResponseV2CanonicalBytes(response *cvAPDBPayloadResponseV2) ([]byte, error) {
	if response == nil || len(response.InstanceDigest) != 32 || len(response.Payload) == 0 {
		return nil, fmt.Errorf("invalid CV V2 APDB payload response")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAPDBPayloadWireDomain))
	_ = cvWriteBytes(&wire, response.InstanceDigest)
	_ = cvWriteBytes(&wire, response.Payload)
	return wire.Bytes(), nil
}

func cvDecodeAPDBPayloadResponseV2(wire []byte, maximumPayload int) (*cvAPDBPayloadResponseV2, error) {
	if maximumPayload <= 0 {
		return nil, fmt.Errorf("invalid CV V2 APDB payload response limit")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAPDBPayloadWireDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvAPDBPayloadWireDomain)) {
		return nil, fmt.Errorf("invalid CV V2 APDB payload response domain")
	}
	instanceDigest, err := r.bytes(32)
	if err != nil {
		return nil, fmt.Errorf("invalid CV V2 APDB payload response instance")
	}
	payload, err := r.bytes(maximumPayload)
	if err != nil || len(payload) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 APDB payload response body")
	}
	return &cvAPDBPayloadResponseV2{InstanceDigest: instanceDigest, Payload: payload}, nil
}
