package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

func sealForReceiver(cfg Config, dealer, receiver int, root []byte, payload []byte) ([]byte, error) {
	if cfg.runtime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}
	x := ecdh.X25519()
	ephemeral, err := x.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	state, ok := cfg.runtime.receiverState(receiver)
	if !ok {
		return nil, fmt.Errorf("unknown receiver state: %d", receiver)
	}
	peer, err := publicKeyFromRaw(state.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid receiver public key: %w", err)
	}
	shared, err := ephemeral.ECDH(peer)
	if err != nil {
		return nil, err
	}
	salt := hashBytes(
		[]byte("rladkr-seal-salt"),
		[]byte(cfg.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d|receiver=%d", cfg.Epoch, dealer, receiver)),
		root,
	)
	key := hashBytes(
		[]byte("rladkr-seal-key"),
		shared,
		salt,
	)
	block, err := aes.NewCipher(key[:32])
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
	ad := bindingAD(cfg, dealer, receiver, root)
	ciphertext := aead.Seal(nil, nonce, payload, ad)
	pub := ephemeral.PublicKey().Bytes()

	out := make([]byte, 0, len(pub)+len(nonce)+len(ciphertext))
	out = append(out, pub...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	zeroBytes(shared)
	zeroBytes(key)
	return out, nil
}

func openForReceiver(cfg Config, dealer, receiver int, root []byte, ciphertext []byte) ([]byte, error) {
	if cfg.runtime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}
	state, ok := cfg.runtime.receiverState(receiver)
	if !ok {
		return nil, fmt.Errorf("unknown receiver state: %d", receiver)
	}
	sk, err := privateKeyFromRaw(state.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("invalid receiver secret key: %w", err)
	}
	pubSize := len(sk.PublicKey().Bytes())
	if len(ciphertext) <= pubSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	peerPub, err := publicKeyFromRaw(ciphertext[:pubSize])
	if err != nil {
		return nil, err
	}
	shared, err := sk.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	salt := hashBytes(
		[]byte("rladkr-seal-salt"),
		[]byte(cfg.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d|receiver=%d", cfg.Epoch, dealer, receiver)),
		root,
	)
	key := hashBytes(
		[]byte("rladkr-seal-key"),
		shared,
		salt,
	)
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	rest := ciphertext[pubSize:]
	if len(rest) <= aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext missing nonce or body")
	}
	nonce := rest[:aead.NonceSize()]
	body := rest[aead.NonceSize():]
	ad := bindingAD(cfg, dealer, receiver, root)
	plain, decErr := aead.Open(nil, nonce, body, ad)
	zeroBytes(shared)
	zeroBytes(key)
	if decErr != nil {
		return nil, decErr
	}
	return plain, nil
}

func bindingAD(cfg Config, dealer, receiver int, root []byte) []byte {
	return hashBytes(
		[]byte("rladkr-seal-ad"),
		[]byte(cfg.SID),
		[]byte(fmt.Sprintf("|epoch=%d|dealer=%d|receiver=%d", cfg.Epoch, dealer, receiver)),
		root,
	)
}
