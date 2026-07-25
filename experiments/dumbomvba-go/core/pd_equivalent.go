package core

import (
	"bytes"
	"context"
	"fmt"
)

type pdOutcome struct {
	store *rcStoreMsg
	lock  *pdLockMsg
	done  *pdDoneMsg
}

func (m *DumboMVBA) runPDInstance(
	ctx context.Context,
	sid string,
	leader int,
	input []byte,
	recv <-chan ReceivedMessage,
) (*pdOutcome, error) {
	n := m.cfg.N
	f := m.cfg.F
	threshold := n - f
	k := n - 2*f

	sendPD := func(to int, body interface{}) {
		_ = m.net.Send(to, ProtocolMessage{
			Tag:    TagMVBAPD,
			Round:  0,
			Leader: leader,
			Body:   body,
		})
	}
	broadcastPD := func(body interface{}) {
		for i := 0; i < n; i++ {
			sendPD(i, body)
		}
	}

	out := &pdOutcome{}
	storedShares := make(map[int][]byte, n)
	lockedShares := make(map[int][]byte, n)
	seenStored := make(map[int]struct{}, n)
	seenLocked := make(map[int]struct{}, n)
	seenStoreFromLeader := false
	seenLockFromLeader := false

	if m.cfg.ID == leader {
		stripes, err := erasureEncodeValue(input, k, n)
		if err != nil {
			return nil, err
		}
		root, branches := buildMerkle(stripes)
		for i := 0; i < n; i++ {
			sendPD(i, pdStoreMsg{
				SID:    sid,
				Root:   root,
				Stripe: append([]byte(nil), stripes[i]...),
				Branch: merkleBranch{
					Index:    branches[i].Index,
					Siblings: cloneSiblings(branches[i].Siblings),
				},
			})
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case in := <-recv:
			switch msg := in.Msg.Body.(type) {
			case pdStoreMsg:
				if msg.SID != sid || in.From != leader || seenStoreFromLeader {
					continue
				}
				if !verifyMerkle(msg.Stripe, msg.Root, msg.Branch) {
					continue
				}
				seenStoreFromLeader = true
				out.store = &rcStoreMsg{
					SID:    sid,
					Root:   append([]byte(nil), msg.Root...),
					From:   m.cfg.ID,
					Stripe: append([]byte(nil), msg.Stripe...),
					Branch: merkleBranch{
						Index:    msg.Branch.Index,
						Siblings: cloneSiblings(msg.Branch.Siblings),
					},
				}
				dig := digestDomain("PD_STORED", sid, msg.Root)
				share, err := m.signer.Sign("PD_STORED", dig)
				if err != nil {
					return nil, err
				}
				sendPD(leader, pdStoredMsg{
					SID:   sid,
					Root:  append([]byte(nil), msg.Root...),
					Share: append([]byte(nil), share...),
				})
				if m.cfg.ID != leader && out.lock != nil {
					return out, nil
				}
			case pdStoredMsg:
				if msg.SID != sid || m.cfg.ID != leader {
					continue
				}
				if _, seen := seenStored[in.From]; seen {
					continue
				}
				dig := digestDomain("PD_STORED", sid, msg.Root)
				if !m.signer.Verify(in.From, "PD_STORED", dig, msg.Share) {
					continue
				}
				seenStored[in.From] = struct{}{}
				storedShares[in.From] = append([]byte(nil), msg.Share...)
				if len(storedShares) >= threshold {
					proof := collectShares(storedShares, threshold)
					broadcastPD(pdLockMsg{
						SID:   sid,
						Root:  append([]byte(nil), msg.Root...),
						Proof: cloneShares(proof),
					})
				}
			case pdLockMsg:
				if msg.SID != sid || in.From != leader || seenLockFromLeader {
					continue
				}
				dig := digestDomain("PD_STORED", sid, msg.Root)
				if !verifyShareSet(m.signer, "PD_STORED", dig, msg.Proof, threshold) {
					continue
				}
				seenLockFromLeader = true
				out.lock = &pdLockMsg{
					SID:   sid,
					Root:  append([]byte(nil), msg.Root...),
					Proof: cloneShares(msg.Proof),
				}
				dig2 := digestDomain("PD_LOCKED", sid, msg.Root)
				share, err := m.signer.Sign("PD_LOCKED", dig2)
				if err != nil {
					return nil, err
				}
				sendPD(leader, pdLockedMsg{
					SID:   sid,
					Root:  append([]byte(nil), msg.Root...),
					Share: append([]byte(nil), share...),
				})
				if m.cfg.ID != leader && out.store != nil {
					return out, nil
				}
			case pdLockedMsg:
				if msg.SID != sid || m.cfg.ID != leader {
					continue
				}
				if _, seen := seenLocked[in.From]; seen {
					continue
				}
				dig := digestDomain("PD_LOCKED", sid, msg.Root)
				if !m.signer.Verify(in.From, "PD_LOCKED", dig, msg.Share) {
					continue
				}
				seenLocked[in.From] = struct{}{}
				lockedShares[in.From] = append([]byte(nil), msg.Share...)
				if len(lockedShares) >= threshold {
					proof := collectShares(lockedShares, threshold)
					done := &pdDoneMsg{
						SID:   sid,
						Root:  append([]byte(nil), msg.Root...),
						Proof: cloneShares(proof),
					}
					out.done = done
					broadcastPD(*done)
					return out, nil
				}
			case pdDoneMsg:
				if msg.SID != sid {
					continue
				}
				// keep listening; done is consumed by quitPD phase.
			default:
				continue
			}
		}
	}
}

func cloneShares(in []SigShare) []SigShare {
	out := make([]SigShare, len(in))
	for i := range in {
		out[i].Signer = in[i].Signer
		if len(in[i].Sig) > 0 {
			out[i].Sig = append([]byte(nil), in[i].Sig...)
		}
	}
	return out
}

func cloneSiblings(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = append([]byte(nil), in[i]...)
	}
	return out
}

func sameRoot(a []byte, b []byte) bool {
	return bytes.Equal(a, b)
}

func proofKey(root []byte) string {
	return fmt.Sprintf("%x", root)
}
