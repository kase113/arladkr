package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

type receiverStateStore interface {
	Load(sid string, epoch int) (map[int]ReceiverState, error)
	Save(sid string, epoch int, states map[int]ReceiverState) error
}

type fileReceiverStateStore struct {
	root string
}

type receiverStateSnapshot struct {
	SID    string          `json:"sid"`
	Epoch  int             `json:"epoch"`
	States []ReceiverState `json:"states"`
}

type receiverStateEnvelope struct {
	Version    int    `json:"version"`
	SID        string `json:"sid"`
	Epoch      int    `json:"epoch"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type receiverStateIndex struct {
	Version      int               `json:"version"`
	SID          string            `json:"sid"`
	HighestEpoch int               `json:"highest_epoch"`
	EpochHashes  map[string]string `json:"epoch_hashes"`
}

func newReceiverStateStore(dir string) receiverStateStore {
	return &fileReceiverStateStore{root: dir}
}

func (s *fileReceiverStateStore) Load(sid string, epoch int) (map[int]ReceiverState, error) {
	if idx, idxErr := s.loadIndex(sid); idxErr != nil {
		return nil, idxErr
	} else if idx != nil && idx.HighestEpoch > epoch {
		return nil, fmt.Errorf(
			"state rollback detected: requested epoch=%d but highest persisted epoch=%d",
			epoch,
			idx.HighestEpoch,
		)
	}
	path := s.snapshotPath(sid, epoch)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if idx, idxErr := s.loadIndex(sid); idxErr != nil {
		return nil, idxErr
	} else if idx != nil {
		if idx.HighestEpoch >= epoch {
			wantHash, ok := idx.EpochHashes[fmt.Sprintf("%d", epoch)]
			if !ok {
				return nil, fmt.Errorf("missing snapshot hash for epoch=%d in state index", epoch)
			}
			gotHash := hex.EncodeToString(hashBytes(raw))
			if wantHash != gotHash {
				return nil, fmt.Errorf("snapshot hash mismatch for epoch=%d", epoch)
			}
		}
	}

	snap, err := s.decodeSnapshot(sid, epoch, raw)
	if err != nil {
		return nil, err
	}
	out := make(map[int]ReceiverState, len(snap.States))
	for _, st := range snap.States {
		out[st.NodeID] = cloneReceiverState(st)
	}
	return out, nil
}

func (s *fileReceiverStateStore) Save(sid string, epoch int, states map[int]ReceiverState) error {
	if sid == "" || epoch <= 0 {
		return fmt.Errorf("invalid sid/epoch for state save")
	}
	path := s.snapshotPath(sid, epoch)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	ids := make([]int, 0, len(states))
	for id := range states {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	ordered := make([]ReceiverState, 0, len(ids))
	for _, id := range ids {
		ordered = append(ordered, cloneReceiverState(states[id]))
	}
	snap := receiverStateSnapshot{
		SID:    sid,
		Epoch:  epoch,
		States: ordered,
	}
	plain, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	enc, err := s.encodeSnapshot(sid, epoch, plain)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(enc, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := s.updateIndex(sid, epoch, body); err != nil {
		return err
	}
	return nil
}

func (s *fileReceiverStateStore) decodeSnapshot(sid string, epoch int, raw []byte) (*receiverStateSnapshot, error) {
	var env receiverStateEnvelope
	if err := json.Unmarshal(raw, &env); err == nil && env.Version == 2 && env.Ciphertext != "" {
		plain, decErr := decryptStateEnvelope(sid, env)
		if decErr != nil {
			return nil, decErr
		}
		var snap receiverStateSnapshot
		if err := json.Unmarshal(plain, &snap); err != nil {
			return nil, err
		}
		if snap.SID != sid || snap.Epoch != epoch {
			return nil, fmt.Errorf("state snapshot mismatch sid/epoch at %s", s.snapshotPath(sid, epoch))
		}
		return &snap, nil
	}
	// Backward compatibility with legacy plain snapshot.
	var legacy receiverStateSnapshot
	if err := json.Unmarshal(raw, &legacy); err != nil {
		return nil, err
	}
	if legacy.SID != sid || legacy.Epoch != epoch {
		return nil, fmt.Errorf("state snapshot mismatch sid/epoch at %s", s.snapshotPath(sid, epoch))
	}
	return &legacy, nil
}

func (s *fileReceiverStateStore) encodeSnapshot(sid string, epoch int, plain []byte) (*receiverStateEnvelope, error) {
	key := deriveStateStoreKey(sid)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ad := hashBytes(
		[]byte("rladkr-state-store-ad"),
		[]byte(sid),
		[]byte(fmt.Sprintf("|epoch=%d", epoch)),
	)
	ciphertext := aead.Seal(nil, nonce, plain, ad)
	return &receiverStateEnvelope{
		Version:    2,
		SID:        sid,
		Epoch:      epoch,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

func decryptStateEnvelope(sid string, env receiverStateEnvelope) ([]byte, error) {
	key := deriveStateStoreKey(sid)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, err
	}
	ad := hashBytes(
		[]byte("rladkr-state-store-ad"),
		[]byte(sid),
		[]byte(fmt.Sprintf("|epoch=%d", env.Epoch)),
	)
	return aead.Open(nil, nonce, ct, ad)
}

func deriveStateStoreKey(sid string) []byte {
	master := os.Getenv("RLADKR_STATESTORE_KEY")
	if master == "" {
		master = "rladkr-default-local-key"
	}
	key := hashBytes(
		[]byte("rladkr-state-store-key"),
		[]byte(master),
		[]byte(sid),
	)
	return key[:32]
}

func (s *fileReceiverStateStore) loadIndex(sid string) (*receiverStateIndex, error) {
	path := s.indexPath(sid)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var idx receiverStateIndex
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, err
	}
	if idx.SID != sid {
		return nil, fmt.Errorf("state index sid mismatch at %s", path)
	}
	if idx.EpochHashes == nil {
		idx.EpochHashes = make(map[string]string)
	}
	return &idx, nil
}

func (s *fileReceiverStateStore) updateIndex(sid string, epoch int, snapshotRaw []byte) error {
	idx, err := s.loadIndex(sid)
	if err != nil {
		return err
	}
	if idx == nil {
		idx = &receiverStateIndex{
			Version:      1,
			SID:          sid,
			HighestEpoch: 0,
			EpochHashes:  make(map[string]string),
		}
	}
	if epoch <= idx.HighestEpoch {
		return fmt.Errorf(
			"state store anti-rollback reject save: epoch=%d highest_epoch=%d",
			epoch,
			idx.HighestEpoch,
		)
	}
	idx.HighestEpoch = epoch
	idx.EpochHashes[fmt.Sprintf("%d", epoch)] = hex.EncodeToString(hashBytes(snapshotRaw))

	body, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	path := s.indexPath(sid)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (s *fileReceiverStateStore) snapshotPath(sid string, epoch int) string {
	safeSID := sanitizeSID(sid)
	return filepath.Join(s.root, safeSID, fmt.Sprintf("epoch_%06d.json", epoch))
}

func (s *fileReceiverStateStore) indexPath(sid string) string {
	safeSID := sanitizeSID(sid)
	return filepath.Join(s.root, safeSID, "index.json")
}

var sidSanitizer = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func sanitizeSID(s string) string {
	clean := sidSanitizer.ReplaceAllString(s, "_")
	if clean == "" {
		return "default"
	}
	return clean
}
