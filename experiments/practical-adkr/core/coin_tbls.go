package core

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
)

func coinSelectThreshold(sid string, decided []int, kappa int, f int) ([]int, error) {
	if len(decided) == 0 {
		return nil, fmt.Errorf("empty decided set")
	}
	if kappa <= 0 || kappa > len(decided) {
		return nil, fmt.Errorf("invalid kappa=%d for decided set size=%d", kappa, len(decided))
	}
	if kappa == len(decided) {
		out := append([]int(nil), decided...)
		sort.Ints(out)
		return out, nil
	}
	canonical := append([]int(nil), decided...)
	sort.Ints(canonical)
	h := sha256.New()
	h.Write([]byte("PADKR-THRESHOLD-COIN|"))
	h.Write([]byte(sid))
	h.Write([]byte("|f="))
	h.Write([]byte(strconv.Itoa(f)))
	h.Write([]byte("|decided="))
	for _, id := range canonical {
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(id))
		h.Write(buf[:])
	}
	var seed [32]byte
	copy(seed[:], h.Sum(nil))
	return shuffleBySeed(canonical, kappa, seed), nil
}

func shuffleBySeed(in []int, kappa int, seed [32]byte) []int {
	cp := make([]int, len(in))
	copy(cp, in)
	for i := len(cp) - 1; i > 0; i-- {
		var mix [8]byte
		binary.BigEndian.PutUint64(mix[:], uint64(i))
		h := sha256.New()
		h.Write(seed[:])
		h.Write(mix[:])
		sum := sha256.Sum256(h.Sum(nil))
		j := int(binary.BigEndian.Uint64(sum[:8]) % uint64(i+1))
		cp[i], cp[j] = cp[j], cp[i]
	}
	out := append([]int(nil), cp[:kappa]...)
	sort.Ints(out)
	return out
}
