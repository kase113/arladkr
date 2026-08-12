package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const cvScalarStateV2Version = 2

type cvScalarStateV2 struct {
	Version         int    `json:"version"`
	SID             string `json:"sid"`
	Epoch           uint64 `json:"epoch"`
	ReceiverID      int    `json:"receiver_id"`
	AggregateDigest []byte `json:"aggregate_digest"`
	Scalar          []byte `json:"scalar"`
	Output          []byte `json:"output"`
}

type cvScalarStoreV2 struct{ root string }

func newCVScalarStoreV2(root string) (*cvScalarStoreV2, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("empty CV V2 scalar store root")
	}
	store := &cvScalarStoreV2{root: filepath.Join(root, "scalar-state-v2")}
	if err := cvEnsurePrivateStoreDir(store.root); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *cvScalarStoreV2) PersistOnce(
	sid string, epoch uint64, receiverID int, aggregateDigest []byte,
	scalar fr.Element, output *cvScalarShareOutputV2,
) error {
	if s == nil || sid == "" || epoch == 0 || receiverID < 0 || len(aggregateDigest) != 32 || output == nil ||
		output.ReceiverID != receiverID || !bytes.Equal(output.AggregateDigest, aggregateDigest) {
		return fmt.Errorf("invalid CV V2 scalar state input")
	}
	if public := cvPointTimes(&genG1, &scalar); !public.Equal(&output.Y) {
		return fmt.Errorf("CV V2 scalar state does not match public output")
	}
	outputWire, err := cvScalarShareOutputV2CanonicalBytes(output)
	if err != nil {
		return err
	}
	encodedScalar := scalar.Bytes()
	state := cvScalarStateV2{
		Version: cvScalarStateV2Version, SID: sid, Epoch: epoch, ReceiverID: receiverID,
		AggregateDigest: append([]byte(nil), aggregateDigest...), Scalar: append([]byte(nil), encodedScalar[:]...),
		Output: outputWire,
	}
	raw, err := json.Marshal(&state)
	if err != nil {
		return err
	}
	return cvPutImmutableFile(s.path(sid, epoch, receiverID), raw)
}

func (s *cvScalarStoreV2) Read(sid string, epoch uint64, receiverID int) (*cvScalarStateV2, error) {
	raw, err := cvReadImmutableFile(s.path(sid, epoch, receiverID))
	if err != nil {
		return nil, err
	}
	var state cvScalarStateV2
	if err := cvDecodeStrictJSON(raw, &state); err != nil || state.Version != cvScalarStateV2Version ||
		state.SID != sid || state.Epoch != epoch || state.ReceiverID != receiverID ||
		len(state.AggregateDigest) != 32 || len(state.Scalar) != fr.Bytes || len(state.Output) == 0 {
		return nil, fmt.Errorf("invalid CV V2 scalar state")
	}
	return &state, nil
}

func (s *cvScalarStoreV2) path(sid string, epoch uint64, receiverID int) string {
	digest := hashBytes([]byte("ARL-CV-sAPVSS/v2-scalar-group/scalar-store-key"), []byte(sid))
	return filepath.Join(s.root, hex.EncodeToString(digest[:8]), fmt.Sprintf("epoch-%020d", epoch),
		fmt.Sprintf("receiver-%06d.private.json", receiverID))
}
