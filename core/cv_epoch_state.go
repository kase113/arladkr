package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"sort"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvEpochStateVersion   = 1
	cvEpochStateDomain    = "ARL-CV-sAPVSS/epoch-state/v1"
	cvMaxEpochStateBytes  = 32 << 20
	cvEpochPublicFilename = "public-state.json"
)

// CVEpochPublicState is the hash-linked public output of one completed epoch.
// The old-committee quorum key remains a separate protocol-control key; this
// state records the scalar threshold key handed to the new committee.
type CVEpochPublicState struct {
	Version             int    `json:"version"`
	SID                 string `json:"sid"`
	Epoch               int    `json:"epoch"`
	PreviousStateDigest []byte `json:"previous_state_digest"`
	OldCommittee        []int  `json:"old_committee"`
	NewCommittee        []int  `json:"new_committee"`
	FOld                int    `json:"f_old"`
	FNew                int    `json:"f_new"`
	AggRLODigest        []byte `json:"aggrlo_digest"`
	AggregateDigest     []byte `json:"aggregate_digest"`
	ContextDigest       []byte `json:"context_digest"`
	NewPublicKey        []byte `json:"new_public_key"`
	Digest              []byte `json:"digest"`
}

type cvEpochLocalState struct {
	Version    int                `json:"version"`
	Public     CVEpochPublicState `json:"public"`
	ReceiverID int                `json:"receiver_id"`
	Share      []byte             `json:"share"`
	Receipts   map[int][]byte     `json:"receipts"`
	Aggregate  []byte             `json:"aggregate"`
}

func cvEffectivePreviousStateDigest(value []byte) ([]byte, error) {
	if len(value) == 0 {
		return make([]byte, sha256.Size), nil
	}
	if len(value) != sha256.Size {
		return nil, fmt.Errorf("previous epoch state digest must be 32 bytes")
	}
	return append([]byte(nil), value...), nil
}

func cvEpochStateDigest(state *CVEpochPublicState) ([]byte, error) {
	if state == nil {
		return nil, fmt.Errorf("nil CV epoch public state")
	}
	statement := struct {
		Domain              string `json:"domain"`
		Version             int    `json:"version"`
		SID                 string `json:"sid"`
		Epoch               int    `json:"epoch"`
		PreviousStateDigest []byte `json:"previous_state_digest"`
		OldCommittee        []int  `json:"old_committee"`
		NewCommittee        []int  `json:"new_committee"`
		FOld                int    `json:"f_old"`
		FNew                int    `json:"f_new"`
		AggRLODigest        []byte `json:"aggrlo_digest"`
		AggregateDigest     []byte `json:"aggregate_digest"`
		ContextDigest       []byte `json:"context_digest"`
		NewPublicKey        []byte `json:"new_public_key"`
	}{
		Domain: cvEpochStateDomain, Version: state.Version, SID: state.SID, Epoch: state.Epoch,
		PreviousStateDigest: state.PreviousStateDigest,
		OldCommittee:        state.OldCommittee, NewCommittee: state.NewCommittee,
		FOld: state.FOld, FNew: state.FNew, AggRLODigest: state.AggRLODigest,
		AggregateDigest: state.AggregateDigest, ContextDigest: state.ContextDigest,
		NewPublicKey: state.NewPublicKey,
	}
	raw, err := json.Marshal(statement)
	if err != nil {
		return nil, err
	}
	digest := hashBytes([]byte(cvEpochStateDomain), raw)
	return digest, nil
}

func BuildCVEpochState(
	cfg Config,
	result *EpochResult,
) (*CVEpochPublicState, map[int]cvEpochLocalState, error) {
	cfg = NormalizeConfig(cfg)
	if result == nil || cfg.SID == "" || cfg.Epoch <= 0 || len(result.RecoveredAggregate) == 0 ||
		len(result.AggRLODigest) != sha256.Size || len(result.NewPublicKey) == 0 {
		return nil, nil, fmt.Errorf("incomplete CV epoch state input")
	}
	oldCommittee := sortedUnique(cfg.OldCommittee)
	newCommittee := sortedUnique(cfg.NewCommittee)
	if len(oldCommittee) != len(cfg.OldCommittee) || len(newCommittee) != len(cfg.NewCommittee) {
		return nil, nil, fmt.Errorf("CV epoch state committee contains duplicate members")
	}
	previousDigest, err := cvEffectivePreviousStateDigest(cfg.PreviousEpochStateDigest)
	if err != nil {
		return nil, nil, err
	}
	aggregate, err := cvDecodeAggregate(result.RecoveredAggregate)
	if err != nil {
		return nil, nil, fmt.Errorf("decode CV epoch aggregate state: %w", err)
	}
	contextPrevious, err := cvEffectivePreviousStateDigest(aggregate.context.previousStateDigest)
	if err != nil || string(aggregate.context.sessionID) != cfg.SID || int(aggregate.context.epoch) != cfg.Epoch ||
		aggregate.context.sharingDegree != cfg.FNew || !bytes.Equal(contextPrevious, previousDigest) {
		return nil, nil, fmt.Errorf("CV epoch aggregate context does not match state transition")
	}
	if len(result.CVReceipts) < cfg.FNew+1 {
		return nil, nil, fmt.Errorf("insufficient receipts for CV epoch state: have=%d need=%d", len(result.CVReceipts), cfg.FNew+1)
	}
	reconstructedKey, err := cvThresholdPublicKeyFromReceipts(
		&aggregate.context, aggregate, newCommittee, result.CVReceipts,
	)
	if err != nil || !bytes.Equal(reconstructedKey, result.NewPublicKey) {
		return nil, nil, fmt.Errorf("CV epoch state public key does not match verified receipts")
	}
	var publicKey bls12381.G1Affine
	consumed, err := publicKey.SetBytes(result.NewPublicKey)
	if err != nil || consumed != len(result.NewPublicKey) || !cvValidG1(&publicKey, false) {
		return nil, nil, fmt.Errorf("invalid CV epoch state public key")
	}
	state := &CVEpochPublicState{
		Version: cvEpochStateVersion, SID: cfg.SID, Epoch: cfg.Epoch,
		PreviousStateDigest: previousDigest, OldCommittee: oldCommittee, NewCommittee: newCommittee,
		FOld: cfg.FOld, FNew: cfg.FNew, AggRLODigest: append([]byte(nil), result.AggRLODigest...),
		AggregateDigest: append([]byte(nil), aggregate.digest...),
		ContextDigest:   cvLeafContextDigest(&aggregate.context),
		NewPublicKey:    append([]byte(nil), result.NewPublicKey...),
	}
	state.Digest, err = cvEpochStateDigest(state)
	if err != nil {
		return nil, nil, err
	}
	locals := make(map[int]cvEpochLocalState, len(result.NewShares))
	indices, err := cvReceiverIndices(&aggregate.context, newCommittee)
	if err != nil {
		return nil, nil, err
	}
	for receiverID, shareWire := range result.NewShares {
		index, ok := indices[receiverID]
		receiptWire := result.CVReceipts[receiverID]
		if !ok || len(receiptWire) == 0 {
			return nil, nil, fmt.Errorf("local CV epoch share %d lacks its public receipt", receiverID)
		}
		if err := cvVerifyPersistedShare(shareWire, receiptWire, &aggregate.context, aggregate, index); err != nil {
			return nil, nil, fmt.Errorf("local CV epoch share %d: %w", receiverID, err)
		}
		locals[receiverID] = cvEpochLocalState{
			Version: cvEpochStateVersion, Public: cloneCVEpochPublicState(*state), ReceiverID: receiverID,
			Share: append([]byte(nil), shareWire...), Receipts: cloneByteMap(result.CVReceipts),
			Aggregate: append([]byte(nil), result.RecoveredAggregate...),
		}
	}
	if len(locals) == 0 {
		return nil, nil, fmt.Errorf("CV epoch state has no local scalar share")
	}
	return state, locals, nil
}

func PersistCVEpochState(root string, cfg Config, result *EpochResult) (*CVEpochPublicState, error) {
	if root == "" {
		return nil, fmt.Errorf("empty CV epoch state directory")
	}
	state, locals, err := BuildCVEpochState(cfg, result)
	if err != nil {
		return nil, err
	}
	dir := cvEpochStateDir(root, state.SID, state.Epoch)
	publicRaw, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	if err := cvPutImmutableFile(filepath.Join(dir, cvEpochPublicFilename), publicRaw); err != nil {
		return nil, fmt.Errorf("persist CV epoch public state: %w", err)
	}
	for receiverID, local := range locals {
		raw, marshalErr := json.Marshal(&local)
		if marshalErr != nil {
			return nil, marshalErr
		}
		if len(raw) > cvMaxEpochStateBytes {
			return nil, fmt.Errorf("CV epoch local state exceeds size limit")
		}
		if err := cvPutImmutableFile(cvEpochLocalStatePath(dir, receiverID), raw); err != nil {
			return nil, fmt.Errorf("persist CV epoch receiver %d state: %w", receiverID, err)
		}
	}
	return state, nil
}

func LoadCVEpochState(root, sid string, epoch, receiverID int) (*CVEpochPublicState, error) {
	if root == "" || sid == "" || epoch <= 0 || receiverID < 0 {
		return nil, fmt.Errorf("invalid CV epoch state lookup")
	}
	dir := cvEpochStateDir(root, sid, epoch)
	publicRaw, err := cvReadImmutableFile(filepath.Join(dir, cvEpochPublicFilename))
	if err != nil {
		return nil, fmt.Errorf("read CV epoch public state: %w", err)
	}
	localRaw, err := cvReadImmutableFile(cvEpochLocalStatePath(dir, receiverID))
	if err != nil {
		return nil, fmt.Errorf("read CV epoch local state: %w", err)
	}
	if len(publicRaw) > cvMaxEpochStateBytes || len(localRaw) > cvMaxEpochStateBytes {
		return nil, fmt.Errorf("CV epoch state exceeds size limit")
	}
	var public CVEpochPublicState
	if err := cvDecodeStrictJSON(publicRaw, &public); err != nil {
		return nil, fmt.Errorf("decode CV epoch public state: %w", err)
	}
	var local cvEpochLocalState
	if err := cvDecodeStrictJSON(localRaw, &local); err != nil {
		return nil, fmt.Errorf("decode CV epoch local state: %w", err)
	}
	if public.SID != sid || public.Epoch != epoch || local.Version != cvEpochStateVersion ||
		local.ReceiverID != receiverID || !bytes.Equal(local.Public.Digest, public.Digest) {
		return nil, fmt.Errorf("CV epoch local state context mismatch")
	}
	if err := verifyCVEpochPublicState(&public); err != nil {
		return nil, err
	}
	if err := verifyCVEpochPublicState(&local.Public); err != nil {
		return nil, fmt.Errorf("invalid CV epoch public state embedded in local state: %w", err)
	}
	aggregate, err := cvDecodeAggregate(local.Aggregate)
	if err != nil || !bytes.Equal(aggregate.digest, public.AggregateDigest) ||
		!bytes.Equal(cvLeafContextDigest(&aggregate.context), public.ContextDigest) {
		return nil, fmt.Errorf("CV epoch local aggregate does not match public state")
	}
	key, err := cvThresholdPublicKeyFromReceipts(
		&aggregate.context, aggregate, public.NewCommittee, local.Receipts,
	)
	if err != nil || !bytes.Equal(key, public.NewPublicKey) {
		return nil, fmt.Errorf("CV epoch persisted receipts do not reconstruct the public key")
	}
	indices, err := cvReceiverIndices(&aggregate.context, public.NewCommittee)
	if err != nil {
		return nil, err
	}
	index, ok := indices[receiverID]
	if !ok {
		return nil, fmt.Errorf("CV epoch local receiver is outside the persisted roster")
	}
	if err := cvVerifyPersistedShare(local.Share, local.Receipts[receiverID], &aggregate.context, aggregate, index); err != nil {
		return nil, err
	}
	return &public, nil
}

func verifyCVEpochPublicState(state *CVEpochPublicState) error {
	if state == nil || state.Version != cvEpochStateVersion || state.SID == "" || state.Epoch <= 0 ||
		len(state.PreviousStateDigest) != sha256.Size || len(state.AggRLODigest) != sha256.Size ||
		len(state.AggregateDigest) != sha256.Size || len(state.ContextDigest) != sha256.Size ||
		len(state.NewPublicKey) == 0 || len(state.Digest) != sha256.Size {
		return fmt.Errorf("invalid CV epoch public state")
	}
	if !sort.IntsAreSorted(state.OldCommittee) || !sort.IntsAreSorted(state.NewCommittee) ||
		len(sortedUnique(state.OldCommittee)) != len(state.OldCommittee) ||
		len(sortedUnique(state.NewCommittee)) != len(state.NewCommittee) {
		return fmt.Errorf("non-canonical CV epoch state committee")
	}
	digest, err := cvEpochStateDigest(state)
	if err != nil || !bytes.Equal(digest, state.Digest) {
		return fmt.Errorf("CV epoch public state digest mismatch")
	}
	return nil
}

func cvVerifyPersistedShare(
	shareWire, receiptWire []byte,
	context *cvLeafContext,
	aggregate *cvAggregateTranscript,
	receiverIndex int,
) error {
	if len(shareWire) != fr.Bytes {
		return fmt.Errorf("invalid persisted scalar share length")
	}
	var share fr.Element
	if err := share.SetBytesCanonical(shareWire); err != nil {
		return fmt.Errorf("invalid persisted scalar share")
	}
	receipt, err := cvDecodeReceipt(receiptWire, context, aggregate, receiverIndex)
	if err != nil {
		return fmt.Errorf("invalid persisted scalar receipt: %w", err)
	}
	var publicShare bls12381.G1Affine
	publicShare.ScalarMultiplication(&genG1, share.BigInt(new(big.Int)))
	if !publicShare.Equal(&receipt.publicScalar) {
		return fmt.Errorf("persisted scalar share does not match its receipt")
	}
	return nil
}

func cvEpochStateDir(root, sid string, epoch int) string {
	sidDigest := sha256.Sum256([]byte(sid))
	return filepath.Join(root, hex.EncodeToString(sidDigest[:8]), fmt.Sprintf("epoch-%020d", epoch))
}

func cvEpochLocalStatePath(dir string, receiverID int) string {
	return filepath.Join(dir, fmt.Sprintf("receiver-%06d.private.json", receiverID))
}

func cvDecodeStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON state")
		}
		return err
	}
	return nil
}

func cloneCVEpochPublicState(in CVEpochPublicState) CVEpochPublicState {
	in.PreviousStateDigest = append([]byte(nil), in.PreviousStateDigest...)
	in.OldCommittee = append([]int(nil), in.OldCommittee...)
	in.NewCommittee = append([]int(nil), in.NewCommittee...)
	in.AggRLODigest = append([]byte(nil), in.AggRLODigest...)
	in.AggregateDigest = append([]byte(nil), in.AggregateDigest...)
	in.ContextDigest = append([]byte(nil), in.ContextDigest...)
	in.NewPublicKey = append([]byte(nil), in.NewPublicKey...)
	in.Digest = append([]byte(nil), in.Digest...)
	return in
}

func cloneByteMap(in map[int][]byte) map[int][]byte {
	out := make(map[int][]byte, len(in))
	for id, value := range in {
		out[id] = append([]byte(nil), value...)
	}
	return out
}
