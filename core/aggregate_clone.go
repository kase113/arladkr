package core

import bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

func cloneBlsPVSSDealerTranscript(in *BlsPVSSDealerTranscript) *BlsPVSSDealerTranscript {
	if in == nil {
		return nil
	}
	out := &BlsPVSSDealerTranscript{
		SID:             in.SID,
		Epoch:           in.Epoch,
		ReceiverOrder:   append([]int(nil), in.ReceiverOrder...),
		Dealer:          in.Dealer,
		Commitments:     append([]bls12381.G1Affine(nil), in.Commitments...),
		EncryptedShares: append([]bls12381.G2Affine(nil), in.EncryptedShares...),
		Zeta:            in.Zeta,
	}
	if in.NIZKProof != nil {
		proof := *in.NIZKProof
		out.NIZKProof = &proof
	}
	return out
}

func cloneBlsPVSSAggregateTranscript(in *BlsPVSSAggregateTranscript) *BlsPVSSAggregateTranscript {
	if in == nil {
		return nil
	}
	out := &BlsPVSSAggregateTranscript{
		Dealers:                   append([]int(nil), in.Dealers...),
		AggregatedCommitments:     append([]bls12381.G1Affine(nil), in.AggregatedCommitments...),
		AggregatedEncryptedShares: append([]bls12381.G2Affine(nil), in.AggregatedEncryptedShares...),
		AggregatedZeta:            in.AggregatedZeta,
		PerDealer:                 make(map[int]*BlsPVSSDealerTranscript, len(in.PerDealer)),
	}
	for dealer, tx := range in.PerDealer {
		out.PerDealer[dealer] = cloneBlsPVSSDealerTranscript(tx)
	}
	return out
}

func cloneAPVSSAggregate(in *APVSSAggregate) *APVSSAggregate {
	if in == nil {
		return nil
	}
	return &APVSSAggregate{
		Provider:          in.Provider,
		Dealers:           append([]int(nil), in.Dealers...),
		AggregateDigest:   append([]byte(nil), in.AggregateDigest...),
		ListTranscript:    cloneListBackedAggregateTranscript(in.ListTranscript),
		BlsPVSSTranscript: cloneBlsPVSSAggregateTranscript(in.BlsPVSSTranscript),
	}
}

func cloneAggRLO(in *AggRLO) *AggRLO {
	if in == nil {
		return nil
	}
	return &AggRLO{
		Header: AggHeader{
			SID:             in.Header.SID,
			Epoch:           in.Header.Epoch,
			Dealers:         append([]int(nil), in.Header.Dealers...),
			AggregateDigest: append([]byte(nil), in.Header.AggregateDigest...),
			PayloadDigest:   append([]byte(nil), in.Header.PayloadDigest...),
			FreshShardRoot:  append([]byte(nil), in.Header.FreshShardRoot...),
			MetadataHash:    append([]byte(nil), in.Header.MetadataHash...),
		},
		Lock: AggLock{
			Threshold:       in.Lock.Threshold,
			Holders:         append([]int(nil), in.Lock.Holders...),
			ShareSignatures: cloneSigMap(in.Lock.ShareSignatures),
			Certificate:     append([]byte(nil), in.Lock.Certificate...),
		},
		Aggregate: *cloneAPVSSAggregate(&in.Aggregate),
		Digest:    append([]byte(nil), in.Digest...),
	}
}
