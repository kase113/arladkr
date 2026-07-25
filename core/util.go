package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

func hashBytes(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		_, _ = h.Write(p)
	}
	return h.Sum(nil)
}

func hashString(parts ...string) []byte {
	raw := make([][]byte, 0, len(parts))
	for _, p := range parts {
		raw = append(raw, []byte(p))
	}
	return hashBytes(raw...)
}

func encodeInts(v []int) []byte {
	out := make([]byte, 8*len(v))
	for i, n := range v {
		binary.BigEndian.PutUint64(out[i*8:(i+1)*8], uint64(n))
	}
	return out
}

func sortedCopy(v []int) []int {
	cp := append([]int(nil), v...)
	sort.Ints(cp)
	return cp
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func stableFirst(v []int, k int) []int {
	if k <= 0 {
		return nil
	}
	cp := sortedCopy(v)
	if len(cp) > k {
		cp = cp[:k]
	}
	return cp
}

func takeFirst(v []int, k int) []int {
	if k <= 0 {
		return nil
	}
	if len(v) <= k {
		return append([]int(nil), v...)
	}
	return append([]int(nil), v[:k]...)
}

func localOldNodes(cfg Config) []int {
	local := filterNodeIDs(cfg.LocalNodeIDs, cfg.OldCommittee)
	if len(local) == 0 {
		return sortedUnique(cfg.OldCommittee)
	}
	return local
}

func nodeSet(ids []int) map[int]struct{} {
	out := make(map[int]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}

func bytesEq(a, b []byte) bool {
	return bytes.Equal(a, b)
}

func cloneSigMap(in map[int][]byte) map[int][]byte {
	if len(in) == 0 {
		return nil
	}
	out := make(map[int][]byte, len(in))
	for id, sig := range in {
		out[id] = append([]byte(nil), sig...)
	}
	return out
}

func cloneBytesMap(in map[int][]byte) map[int][]byte {
	if len(in) == 0 {
		return nil
	}
	out := make(map[int][]byte, len(in))
	for id, raw := range in {
		out[id] = append([]byte(nil), raw...)
	}
	return out
}

func sortedUnique(v []int) []int {
	cp := sortedCopy(v)
	if len(cp) <= 1 {
		return cp
	}
	out := make([]int, 0, len(cp))
	last := cp[0] - 1
	for _, id := range cp {
		if len(out) == 0 || id != last {
			out = append(out, id)
			last = id
		}
	}
	return out
}

func collectEraseBuffers(maps ...map[int][]byte) [][]byte {
	out := make([][]byte, 0)
	for _, m := range maps {
		for _, v := range m {
			out = append(out, append([]byte(nil), v...))
		}
	}
	return out
}

func zeroBytes(v []byte) {
	for i := range v {
		v[i] = 0
	}
}
