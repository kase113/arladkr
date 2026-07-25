package core

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

type PaillierPublicKey struct {
	N       *big.Int
	NSquare *big.Int
	G       *big.Int
}

type PaillierPrivateKey struct {
	PublicKey *PaillierPublicKey
	Lambda    *big.Int
	Mu        *big.Int
}

var (
	paillierOne = big.NewInt(1)
)

func GeneratePaillierKeyWithReader(bits int, reader io.Reader) (*PaillierPrivateKey, error) {
	if bits < 2048 {
		return nil, errors.New("paillier key size too small")
	}
	if reader == nil {
		reader = rand.Reader
	}
	p, err := readPrime(bits/2, reader)
	if err != nil {
		return nil, err
	}
	q, err := readPrime(bits/2, reader)
	if err != nil {
		return nil, err
	}
	for p.Cmp(q) == 0 {
		q, err = readPrime(bits/2, reader)
		if err != nil {
			return nil, err
		}
	}

	n := new(big.Int).Mul(p, q)
	n2 := new(big.Int).Mul(n, n)
	g := new(big.Int).Add(n, paillierOne)

	pm1 := new(big.Int).Sub(p, paillierOne)
	qm1 := new(big.Int).Sub(q, paillierOne)
	lambda := lcm(pm1, qm1)

	u := new(big.Int).Exp(g, lambda, n2)
	l := paillierL(u, n)
	mu := new(big.Int).ModInverse(l, n)
	if mu == nil {
		return nil, errors.New("failed to invert paillier L value")
	}

	return &PaillierPrivateKey{
		PublicKey: &PaillierPublicKey{N: n, NSquare: n2, G: g},
		Lambda:    lambda,
		Mu:        mu,
	}, nil
}

func (pk *PaillierPublicKey) Encrypt(m *big.Int) (*big.Int, error) {
	if pk == nil || pk.N == nil {
		return nil, errors.New("nil paillier public key")
	}
	if m.Sign() < 0 || m.Cmp(pk.N) >= 0 {
		return nil, errors.New("plaintext out of range")
	}
	r, err := sampleCoprime(rand.Reader, pk.N)
	if err != nil {
		return nil, err
	}
	return pk.EncryptWithRandom(m, r)
}

func (pk *PaillierPublicKey) EncryptWithRandom(m, r *big.Int) (*big.Int, error) {
	if pk == nil || pk.N == nil {
		return nil, errors.New("nil paillier public key")
	}
	if m.Sign() < 0 || m.Cmp(pk.N) >= 0 {
		return nil, errors.New("plaintext out of range")
	}
	if r == nil || r.Sign() <= 0 || r.Cmp(pk.N) >= 0 {
		return nil, errors.New("paillier randomness out of range")
	}
	if new(big.Int).GCD(nil, nil, r, pk.N).Cmp(paillierOne) != 0 {
		return nil, errors.New("paillier randomness not coprime")
	}
	gm := new(big.Int).Exp(pk.G, m, pk.NSquare)
	rn := new(big.Int).Exp(r, pk.N, pk.NSquare)
	c := new(big.Int).Mul(gm, rn)
	c.Mod(c, pk.NSquare)
	return c, nil
}

func (sk *PaillierPrivateKey) Decrypt(c *big.Int) (*big.Int, error) {
	if sk == nil || sk.PublicKey == nil {
		return nil, errors.New("nil paillier private key")
	}
	if c.Sign() <= 0 || c.Cmp(sk.PublicKey.NSquare) >= 0 {
		return nil, errors.New("ciphertext out of range")
	}
	u := new(big.Int).Exp(c, sk.Lambda, sk.PublicKey.NSquare)
	l := paillierL(u, sk.PublicKey.N)
	m := new(big.Int).Mul(l, sk.Mu)
	m.Mod(m, sk.PublicKey.N)
	return m, nil
}

func lcm(a, b *big.Int) *big.Int {
	g := new(big.Int).GCD(nil, nil, a, b)
	ab := new(big.Int).Mul(a, b)
	return ab.Div(ab, g)
}

func paillierL(u, n *big.Int) *big.Int {
	out := new(big.Int).Sub(u, paillierOne)
	return out.Div(out, n)
}

func sampleCoprime(reader io.Reader, n *big.Int) (*big.Int, error) {
	max := new(big.Int).Sub(n, paillierOne)
	for i := 0; i < 128; i++ {
		r, err := rand.Int(reader, max)
		if err != nil {
			return nil, err
		}
		r.Add(r, paillierOne)
		if new(big.Int).GCD(nil, nil, r, n).Cmp(paillierOne) == 0 {
			return r, nil
		}
	}
	return nil, errors.New("failed to sample paillier randomness")
}

func readPrime(bits int, reader io.Reader) (*big.Int, error) {
	if bits < 2 {
		return nil, errors.New("prime bits too small")
	}
	byteLen := (bits + 7) / 8
	buf := make([]byte, byteLen)
	topBit := uint((bits - 1) % 8)
	mask := byte((1 << (topBit + 1)) - 1)
	p := new(big.Int)
	two := big.NewInt(2)

	for attempts := 0; attempts < 1<<20; attempts++ {
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		buf[0] &= mask
		buf[0] |= 1 << topBit
		buf[len(buf)-1] |= 1
		p.SetBytes(buf)
		if p.BitLen() != bits {
			continue
		}
		if p.ProbablyPrime(64) {
			return new(big.Int).Set(p), nil
		}
		// Deterministic odd walk preserves reproducibility for deterministic readers.
		for i := 0; i < 4096; i++ {
			p.Add(p, two)
			if p.BitLen() != bits {
				break
			}
			if p.ProbablyPrime(64) {
				return new(big.Int).Set(p), nil
			}
		}
	}
	return nil, errors.New("failed to generate prime")
}
