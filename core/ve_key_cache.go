package core

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

type veKeyCacheEnvelope struct {
	Version int               `json:"version"`
	SID     string            `json:"sid"`
	Epoch   int               `json:"epoch"`
	NodeID  int               `json:"node_id"`
	Public  veKeyCachePublic  `json:"public"`
	Private veKeyCachePrivate `json:"private"`
}

type veKeyCachePublic struct {
	N       string `json:"n"`
	NSquare string `json:"n_square"`
	G       string `json:"g"`
}

type veKeyCachePrivate struct {
	Lambda string `json:"lambda"`
	Mu     string `json:"mu"`
}

func veKeyCacheDir() string {
	return os.Getenv("RLADKR_VE_KEY_CACHE_DIR")
}

func veKeyCachePath(root, sid string, epoch, nodeID int) string {
	return filepath.Join(root, sanitizeSID(sid), fmt.Sprintf("epoch_%06d", epoch), fmt.Sprintf("receiver_%06d.json", nodeID))
}

func loadOrCreateVEKeyCache(cfg *Config, receiverID int) (*PaillierPrivateKey, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	root := veKeyCacheDir()
	if root == "" {
		return GeneratePaillierKeyWithReader(
			2048,
			newDeterministicReader(
				deterministicStream(
					"rladkr-ve-paillier-key",
					[]byte(cfg.SID),
					[]byte(fmt.Sprintf("|receiver=%d", receiverID)),
				),
			),
		)
	}
	path := veKeyCachePath(root, cfg.SID, cfg.Epoch, receiverID)
	if key, err := loadVEKeyCache(path, cfg.SID, cfg.Epoch, receiverID); err == nil && key != nil {
		return key, nil
	}
	key, err := GeneratePaillierKeyWithReader(
		2048,
		newDeterministicReader(
			deterministicStream(
				"rladkr-ve-paillier-key",
				[]byte(cfg.SID),
				[]byte(fmt.Sprintf("|receiver=%d", receiverID)),
			),
		),
	)
	if err != nil {
		return nil, err
	}
	if err := saveVEKeyCache(path, cfg.SID, cfg.Epoch, receiverID, key); err != nil {
		return nil, err
	}
	return key, nil
}

func loadVEKeyCache(path, sid string, epoch, nodeID int) (*PaillierPrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env veKeyCacheEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, err
	}
	if env.Version != 1 || env.SID != sid || env.Epoch != epoch || env.NodeID != nodeID {
		return nil, fmt.Errorf("ve key cache metadata mismatch")
	}
	return veKeyFromEnvelope(env)
}

func saveVEKeyCache(path, sid string, epoch, nodeID int, key *PaillierPrivateKey) error {
	if key == nil || key.PublicKey == nil {
		return fmt.Errorf("nil ve key")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	env := veKeyCacheEnvelope{
		Version: 1,
		SID:     sid,
		Epoch:   epoch,
		NodeID:  nodeID,
		Public: veKeyCachePublic{
			N:       key.PublicKey.N.Text(16),
			NSquare: key.PublicKey.NSquare.Text(16),
			G:       key.PublicKey.G.Text(16),
		},
		Private: veKeyCachePrivate{
			Lambda: key.Lambda.Text(16),
			Mu:     key.Mu.Text(16),
		},
	}
	body, err := json.MarshalIndent(env, "", "  ")
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
	return nil
}

func veKeyFromEnvelope(env veKeyCacheEnvelope) (*PaillierPrivateKey, error) {
	n, ok := new(big.Int).SetString(env.Public.N, 16)
	if !ok {
		return nil, fmt.Errorf("invalid public n")
	}
	nSquare, ok := new(big.Int).SetString(env.Public.NSquare, 16)
	if !ok {
		return nil, fmt.Errorf("invalid public n_square")
	}
	g, ok := new(big.Int).SetString(env.Public.G, 16)
	if !ok {
		return nil, fmt.Errorf("invalid public g")
	}
	lambda, ok := new(big.Int).SetString(env.Private.Lambda, 16)
	if !ok {
		return nil, fmt.Errorf("invalid private lambda")
	}
	mu, ok := new(big.Int).SetString(env.Private.Mu, 16)
	if !ok {
		return nil, fmt.Errorf("invalid private mu")
	}
	return &PaillierPrivateKey{
		PublicKey: &PaillierPublicKey{
			N:       n,
			NSquare: nSquare,
			G:       g,
		},
		Lambda: lambda,
		Mu:     mu,
	}, nil
}
