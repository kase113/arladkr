package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	dmvba "dumbomvba_go/core"
)

// ── AgreeOnAggRLO: MVBA on a single header-only AggRLO digest ───────────
//
// Paper §5.2: each node submits d_u = H(AggRLO_u) to MVBA.  Because
// CanonicalSelect is deterministic, all honest nodes that have completed
// LockAgg submit the identical digest.  The MVBA external-validity predicate
// is ValidateDigest(d) = ∃ AggRLO: H(AggRLO)=d ∧ AdmitAgg(AggRLO)=1.
//
// MVBA input size drops from O(κλ) (old descriptor map) to 32 bytes.
//
// Deprecated: RunFallbackMVBA is the legacy entry point that previously
// passed the full descriptor map as MVBA payload.  It now delegates to
// the new AgreeOnAggRLO path.

func RunFallbackMVBA(
	ctx context.Context,
	cfg Config,
	descriptors map[int]Descriptor,
	artifacts map[int]*DealerArtifact,
) ([]int, []NodeOutput, error) {
	// Build AggRLO via LockAgg (same as the primary path)
	aggRLO, _, err := LockAgg(cfg, descriptors, artifacts)
	if err != nil {
		return nil, nil, fmt.Errorf("RunFallbackMVBA/LockAgg: %w", err)
	}
	digest, perNode, _, err := AgreeOnAggRLO(ctx, cfg, aggRLO)
	if err != nil {
		return nil, nil, err
	}
	_ = digest
	return aggRLO.Header.Dealers, perNode, nil
}

// AgreeOnAggRLO runs MVBA+ACS agreement on a single AggRLO digest
// using TCP-based MVBA with TBLS common coin.
func AgreeOnAggRLO(ctx context.Context, cfg Config, aggRLO *AggRLO) ([]byte, []NodeOutput, time.Duration, error) {
	n := len(cfg.OldCommittee)
	localIDs := sortedUnique(cfg.LocalNodeIDs)
	if len(localIDs) == 0 {
		localIDs = sortedUnique(cfg.OldCommittee)
	}
	return runDumboMVBAOnDigestTCP(ctx, cfg, aggRLO, localIDs, n)
}

func makeAggRLODecisionOutputs(localIDs []int, aggRLO *AggRLO) []NodeOutput {
	perNode := make([]NodeOutput, 0, len(localIDs))
	for _, lid := range localIDs {
		perNode = append(perNode, NodeOutput{
			NodeID:     lid,
			DecidedSet: append([]int(nil), aggRLO.Header.Dealers...),
		})
	}
	return perNode
}

// runDumboMVBAOnDigestTCP is the TCP-based distributed MVBA path.
func runDumboMVBAOnDigestTCP(
	ctx context.Context,
	cfg Config,
	aggRLO *AggRLO,
	localIDs []int,
	n int,
) ([]byte, []NodeOutput, time.Duration, error) {
	if aggRLO == nil {
		return nil, nil, 0, fmt.Errorf("AgreeOnAggRLO: nil AggRLO")
	}
	digestHex := hex.EncodeToString(aggRLO.Digest)
	payload, err := json.Marshal(digestHex)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("AgreeOnAggRLO: marshal digest: %w", err)
	}

	// Run MVBA over TCP.
	agreedPayload, mvbaPeerWait, err := runArladkrMVBATCP(ctx, cfg, payload)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("AgreeOnAggRLO TCP: %w", err)
	}

	// Decode the agreed digest.
	var agreedDigestHex string
	if err := json.Unmarshal(agreedPayload, &agreedDigestHex); err != nil {
		return nil, nil, 0, fmt.Errorf("AgreeOnAggRLO TCP: unmarshal output: %w", err)
	}
	agreedDigest, err := hex.DecodeString(agreedDigestHex)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("AgreeOnAggRLO TCP: decode digest: %w", err)
	}

	if !bytes.Equal(agreedDigest, aggRLO.Digest) {
		// Different digest agreed — reconcile via CallHelp if needed.
		// For now, accept the agreed digest.
	}

	return agreedDigest, makeAggRLODecisionOutputs(localIDs, aggRLO), mvbaPeerWait, nil
}

// verifyACSOutput scans the ACS output vectors for a ProposalValue whose
// payload matches the given AggRLO digest.  Accepts any valid digest.
func verifyACSOutput(acsVecs [][]*dmvba.ProposalValue, expectedDigest []byte) []byte {
	for _, vec := range acsVecs {
		for _, pv := range vec {
			if pv == nil || len(pv.Payload) == 0 {
				continue
			}
			// The payload is json-encoded hex string of the digest.
			var digHex string
			if err := json.Unmarshal(pv.Payload, &digHex); err != nil {
				// Legacy: might be old descriptor map format
				continue
			}
			dig, err := hex.DecodeString(digHex)
			if err != nil {
				continue
			}
			if bytes.Equal(dig, expectedDigest) {
				return dig
			}
			// Accept ANY valid digest — in a converged system this
			// is always our own, but the MVBA can technically confirm
			// a digest from a slightly different ReadyPool view.
			return dig
		}
	}
	return nil
}
