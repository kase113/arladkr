package core

import "testing"

func TestCoinSelectFallbackSet_Deterministic(t *testing.T) {
	setByDigest := map[string][]int{
		"aa": []int{0, 2, 3},
		"bb": []int{1, 2, 4},
		"cc": []int{0, 1, 5},
	}
	universe := []int{0, 1, 2, 3, 4, 5}
	a := coinSelectFallbackSet("sid", 1, 2, setByDigest, 3, universe)
	b := coinSelectFallbackSet("sid", 1, 2, setByDigest, 3, universe)
	if !sameIntSet(a, b) {
		t.Fatalf("coin selection should be deterministic: %v vs %v", a, b)
	}
	if len(a) != 3 {
		t.Fatalf("unexpected selected size: %d", len(a))
	}
}
