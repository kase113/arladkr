package core

// ListBackedAggregateTranscript binds a canonical dealer set to the digests
// of the exact received contributions. It is a provider-neutral prototype
// container, not a compact homomorphic aggregate ciphertext.
type ListBackedAggregateTranscript struct {
	Dealers             []int
	ContributionDigests map[int][]byte
	AggregateDigest     []byte
	Trusted             bool
}

func cloneListBackedAggregateTranscript(in *ListBackedAggregateTranscript) *ListBackedAggregateTranscript {
	if in == nil {
		return nil
	}
	out := &ListBackedAggregateTranscript{
		Dealers:             append([]int(nil), in.Dealers...),
		ContributionDigests: make(map[int][]byte, len(in.ContributionDigests)),
		AggregateDigest:     append([]byte(nil), in.AggregateDigest...),
		Trusted:             in.Trusted,
	}
	for dealer, digest := range in.ContributionDigests {
		out.ContributionDigests[dealer] = append([]byte(nil), digest...)
	}
	return out
}
