package core

import (
	"crypto/ecdh"
	"fmt"
)

func rfsInitState(cfg Config, receiver int) (ReceiverState, error) {
	chainKey := hashBytes(
		[]byte("rladkr-rfs-init-chain"),
		[]byte(cfg.SID),
		[]byte(fmt.Sprintf("|receiver=%d|epoch=%d", receiver, cfg.Epoch)),
	)
	seed := hashBytes(
		[]byte("rladkr-rfs-init-seed"),
		chainKey,
		[]byte(fmt.Sprintf("|receiver=%d", receiver)),
	)
	rawSK, pub, err := deriveX25519KeyMaterial(seed)
	if err != nil {
		return ReceiverState{}, err
	}
	return ReceiverState{
		NodeID:           receiver,
		Epoch:            cfg.Epoch,
		PublicKey:        pub,
		SecretKey:        rawSK,
		ChainKey:         chainKey,
		TransportKeyHash: hashBytes([]byte("rladkr-rfs-transport-hash"), rawSK, chainKey),
	}, nil
}

func rfsUpdateState(
	cfg Config,
	current ReceiverState,
	receiver int,
	contextDigest []byte,
) (ReceiverState, ReceiverState, error) {
	if current.NodeID != receiver {
		return ReceiverState{}, ReceiverState{}, fmt.Errorf("receiver state node mismatch: have=%d want=%d", current.NodeID, receiver)
	}
	if current.Epoch != cfg.Epoch {
		return ReceiverState{}, ReceiverState{}, fmt.Errorf(
			"receiver state epoch mismatch: have=%d want=%d",
			current.Epoch,
			cfg.Epoch,
		)
	}
	nextChain := hashBytes(
		[]byte("rladkr-rfs-chain-next"),
		current.ChainKey,
		contextDigest,
		[]byte(cfg.SID),
		[]byte(fmt.Sprintf("|receiver=%d|epoch=%d", receiver, cfg.Epoch)),
	)
	nextSeed := hashBytes(
		[]byte("rladkr-rfs-sk-next"),
		current.SecretKey,
		nextChain,
		[]byte(fmt.Sprintf("|receiver=%d", receiver)),
	)
	rawSK, pub, err := deriveX25519KeyMaterial(nextSeed)
	if err != nil {
		return ReceiverState{}, ReceiverState{}, err
	}
	old := cloneReceiverState(current)
	next := ReceiverState{
		NodeID:           receiver,
		Epoch:            cfg.Epoch + 1,
		PublicKey:        pub,
		SecretKey:        rawSK,
		ChainKey:         nextChain,
		TransportKeyHash: hashBytes([]byte("rladkr-rfs-transport-hash"), rawSK, nextChain),
	}
	return next, old, nil
}

func rfsErase(old *ReceiverState, buffers ...[]byte) {
	if old != nil {
		zeroBytes(old.SecretKey)
		zeroBytes(old.ChainKey)
		zeroBytes(old.TransportKeyHash)
		zeroBytes(old.PublicKey)
		old.SecretKey = nil
		old.ChainKey = nil
		old.TransportKeyHash = nil
		old.PublicKey = nil
	}
	for _, b := range buffers {
		zeroBytes(b)
	}
}

func deriveX25519KeyMaterial(seed []byte) ([]byte, []byte, error) {
	seedMaterial := append([]byte(nil), seed...)
	for i := 0; i < 16; i++ {
		candidate := hashBytes(
			[]byte("rladkr-rfs-key-candidate"),
			seedMaterial,
			[]byte(fmt.Sprintf("|try=%d", i)),
		)[:32]
		sk, err := privateKeyFromRaw(candidate)
		if err != nil {
			continue
		}
		return append([]byte(nil), sk.Bytes()...), append([]byte(nil), sk.PublicKey().Bytes()...), nil
	}
	return nil, nil, fmt.Errorf("unable to derive valid x25519 key material")
}

func privateKeyFromRaw(raw []byte) (*ecdh.PrivateKey, error) {
	x := ecdh.X25519()
	return x.NewPrivateKey(raw)
}

func publicKeyFromRaw(raw []byte) (*ecdh.PublicKey, error) {
	x := ecdh.X25519()
	return x.NewPublicKey(raw)
}

func cloneReceiverState(in ReceiverState) ReceiverState {
	return ReceiverState{
		NodeID:           in.NodeID,
		Epoch:            in.Epoch,
		PublicKey:        append([]byte(nil), in.PublicKey...),
		SecretKey:        append([]byte(nil), in.SecretKey...),
		ChainKey:         append([]byte(nil), in.ChainKey...),
		TransportKeyHash: append([]byte(nil), in.TransportKeyHash...),
	}
}
