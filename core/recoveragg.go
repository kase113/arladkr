package core

import (
	"context"
	"fmt"
	"time"
)

type RecoverAggOutput struct {
	AggRLO                    *AggRLO
	Recovered                 *APVSSRecovered
	AggFragResponses          []AggFragResponse
	AggRLOReadyLatency        time.Duration
	RecoverVerifyLatency      time.Duration
	RecoverCollectLatency     time.Duration
	RecoverVerifyOnlyLatency  time.Duration
	RecoverMaterializeLatency time.Duration
}

// RecoverAgg materializes recoverable aggregate state from a validated
// header-only AggRLO. The lock object itself only certifies the obligation;
// this stage performs the actual aggregate verification/recovery path.
func RecoverAgg(
	cfg Config,
	lockedSet []int,
	artifacts map[int]*DealerArtifact,
) (*RecoverAggOutput, error) {
	rlo, _, err := buildAggRLOForDealers(cfg, lockedSet, artifacts)
	if err != nil {
		return nil, err
	}
	return RecoverAggFromAggRLO(cfg, rlo, artifacts)
}

func RecoverAggFromAggRLO(
	cfg Config,
	rlo *AggRLO,
	artifacts map[int]*DealerArtifact,
) (*RecoverAggOutput, error) {
	start := time.Now()
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	if c.runtime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}
	if rlo == nil {
		return nil, fmt.Errorf("nil AggRLO")
	}
	apvss := newAPVSSFromConfig(c)
	if err := AdmitAgg(c, rlo, apvss, artifacts); err != nil {
		return nil, err
	}
	readyLatency := time.Since(start)
	verifyStart := time.Now()
	collectStart := time.Now()
	responses, err := CollectAggFragResponses(context.Background(), c, rlo, artifacts)
	if err != nil {
		return nil, err
	}
	collectLatency := time.Since(collectStart)
	verifyOnlyStart := time.Now()
	if err := VerifyAggFragResponses(c, rlo, responses, artifacts); err != nil {
		return nil, err
	}
	verifyOnlyLatency := time.Since(verifyOnlyStart)
	verifyLatency := time.Since(verifyStart)
	materializeStart := time.Now()
	var rec *APVSSRecovered
	if rlo.Aggregate.Provider == "optrand" {
		rec, err = RecoverOptrandFromVerifiedAggregate(&rlo.Aggregate)
	} else {
		rec, err = apvss.Rec(c, &rlo.Aggregate, artifacts)
	}
	if err != nil {
		return nil, err
	}
	return &RecoverAggOutput{
		AggRLO:                    rlo,
		Recovered:                 rec,
		AggFragResponses:          responses,
		AggRLOReadyLatency:        readyLatency,
		RecoverVerifyLatency:      verifyLatency,
		RecoverCollectLatency:     collectLatency,
		RecoverVerifyOnlyLatency:  verifyOnlyLatency,
		RecoverMaterializeLatency: time.Since(materializeStart),
	}, nil
}

func RecoverAgreedAggRLO(
	cfg Config,
	rlo *AggRLO,
	artifacts map[int]*DealerArtifact,
) (*RecoverAggOutput, error) {
	admitStart := time.Now()
	c := cfg
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	if c.runtime == nil {
		return nil, fmt.Errorf("runtime not initialized")
	}
	if rlo == nil {
		return nil, fmt.Errorf("nil AggRLO")
	}
	apvss := newAPVSSFromConfig(c)
	if !c.runtime.hasValidatedAggRLO(rlo.Digest, fingerprintAggRLO(rlo)) {
		if err := AdmitAgg(c, rlo, apvss, artifacts); err != nil {
			return nil, err
		}
	}
	readyLatency := time.Since(admitStart)
	if !bytesEq(rlo.Header.AggregateDigest, rlo.Aggregate.AggregateDigest) {
		return nil, fmt.Errorf("AggRLO aggregate digest mismatch")
	}
	verifyStart := time.Now()
	collectStart := time.Now()
	responses, err := CollectAggFragResponses(context.Background(), c, rlo, artifacts)
	if err != nil {
		return nil, err
	}
	collectLatency := time.Since(collectStart)
	verifyOnlyStart := time.Now()
	if err := VerifyAggFragResponses(c, rlo, responses, artifacts); err != nil {
		return nil, err
	}
	verifyOnlyLatency := time.Since(verifyOnlyStart)
	verifyLatency := time.Since(verifyStart)
	materializeStart := time.Now()
	var rec *APVSSRecovered
	if rlo.Aggregate.Provider == "optrand" {
		// Current aggregate-mode shortcut consumes a verified aggregate object
		// that remains bound to the header-only AggRLO digest. If we later move
		// to explicit signer-response / VerifyAggFrag, that extension belongs
		// here rather than in LockAgg.
		rec, err = RecoverOptrandFromVerifiedAggregate(&rlo.Aggregate)
	} else {
		rec, err = apvss.Rec(c, &rlo.Aggregate, artifacts)
	}
	if err != nil {
		return nil, err
	}
	return &RecoverAggOutput{
		AggRLO:                    rlo,
		Recovered:                 rec,
		AggFragResponses:          responses,
		AggRLOReadyLatency:        readyLatency,
		RecoverVerifyLatency:      verifyLatency,
		RecoverCollectLatency:     collectLatency,
		RecoverVerifyOnlyLatency:  verifyOnlyLatency,
		RecoverMaterializeLatency: time.Since(materializeStart),
	}, nil
}
