package core

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
)

var cvPerfCountersEnabled = strings.TrimSpace(os.Getenv("RLADKR_CV_PERF_COUNTERS")) != ""

var cvPerfCounters struct {
	leafVerifyCalls                 atomic.Uint64
	leafVerifySuccesses             atomic.Uint64
	sharingVerifyCalls              atomic.Uint64
	chunkingVerifyCalls             atomic.Uint64
	exactRangeVerifyCalls           atomic.Uint64
	aggCalls                        atomic.Uint64
	aggVerifiedCalls                atomic.Uint64
	averCalls                       atomic.Uint64
	averVerifiedCalls               atomic.Uint64
	averSuccesses                   atomic.Uint64
	aggregateOffers                 atomic.Uint64
	aggregateOfferAVers             atomic.Uint64
	verifiedLeafCacheHits           atomic.Uint64
	verifiedLeafCacheMiss           atomic.Uint64
	verifiedAggregateOfferCacheHits atomic.Uint64
	verifiedAggregateOfferCacheMiss atomic.Uint64
}

type cvPerfSnapshot struct {
	leafVerifyCalls                 uint64
	leafVerifySuccesses             uint64
	sharingVerifyCalls              uint64
	chunkingVerifyCalls             uint64
	exactRangeVerifyCalls           uint64
	aggCalls                        uint64
	aggVerifiedCalls                uint64
	averCalls                       uint64
	averVerifiedCalls               uint64
	averSuccesses                   uint64
	aggregateOffers                 uint64
	aggregateOfferAVers             uint64
	verifiedLeafCacheHits           uint64
	verifiedLeafCacheMiss           uint64
	verifiedAggregateOfferCacheHits uint64
	verifiedAggregateOfferCacheMiss uint64
}

func cvPerfSnapshotNow() cvPerfSnapshot {
	if !cvPerfCountersEnabled {
		return cvPerfSnapshot{}
	}
	return cvPerfSnapshot{
		leafVerifyCalls:                 cvPerfCounters.leafVerifyCalls.Load(),
		leafVerifySuccesses:             cvPerfCounters.leafVerifySuccesses.Load(),
		sharingVerifyCalls:              cvPerfCounters.sharingVerifyCalls.Load(),
		chunkingVerifyCalls:             cvPerfCounters.chunkingVerifyCalls.Load(),
		exactRangeVerifyCalls:           cvPerfCounters.exactRangeVerifyCalls.Load(),
		aggCalls:                        cvPerfCounters.aggCalls.Load(),
		aggVerifiedCalls:                cvPerfCounters.aggVerifiedCalls.Load(),
		averCalls:                       cvPerfCounters.averCalls.Load(),
		averVerifiedCalls:               cvPerfCounters.averVerifiedCalls.Load(),
		averSuccesses:                   cvPerfCounters.averSuccesses.Load(),
		aggregateOffers:                 cvPerfCounters.aggregateOffers.Load(),
		aggregateOfferAVers:             cvPerfCounters.aggregateOfferAVers.Load(),
		verifiedLeafCacheHits:           cvPerfCounters.verifiedLeafCacheHits.Load(),
		verifiedLeafCacheMiss:           cvPerfCounters.verifiedLeafCacheMiss.Load(),
		verifiedAggregateOfferCacheHits: cvPerfCounters.verifiedAggregateOfferCacheHits.Load(),
		verifiedAggregateOfferCacheMiss: cvPerfCounters.verifiedAggregateOfferCacheMiss.Load(),
	}
}

func (end cvPerfSnapshot) subtract(start cvPerfSnapshot) cvPerfSnapshot {
	return cvPerfSnapshot{
		leafVerifyCalls:                 end.leafVerifyCalls - start.leafVerifyCalls,
		leafVerifySuccesses:             end.leafVerifySuccesses - start.leafVerifySuccesses,
		sharingVerifyCalls:              end.sharingVerifyCalls - start.sharingVerifyCalls,
		chunkingVerifyCalls:             end.chunkingVerifyCalls - start.chunkingVerifyCalls,
		exactRangeVerifyCalls:           end.exactRangeVerifyCalls - start.exactRangeVerifyCalls,
		aggCalls:                        end.aggCalls - start.aggCalls,
		aggVerifiedCalls:                end.aggVerifiedCalls - start.aggVerifiedCalls,
		averCalls:                       end.averCalls - start.averCalls,
		averVerifiedCalls:               end.averVerifiedCalls - start.averVerifiedCalls,
		averSuccesses:                   end.averSuccesses - start.averSuccesses,
		aggregateOffers:                 end.aggregateOffers - start.aggregateOffers,
		aggregateOfferAVers:             end.aggregateOfferAVers - start.aggregateOfferAVers,
		verifiedLeafCacheHits:           end.verifiedLeafCacheHits - start.verifiedLeafCacheHits,
		verifiedLeafCacheMiss:           end.verifiedLeafCacheMiss - start.verifiedLeafCacheMiss,
		verifiedAggregateOfferCacheHits: end.verifiedAggregateOfferCacheHits - start.verifiedAggregateOfferCacheHits,
		verifiedAggregateOfferCacheMiss: end.verifiedAggregateOfferCacheMiss - start.verifiedAggregateOfferCacheMiss,
	}
}

func traceCVPerfCounters(node int, start cvPerfSnapshot) {
	if !cvPerfCountersEnabled {
		return
	}
	delta := cvPerfSnapshotNow().subtract(start)
	fmt.Fprintf(os.Stderr,
		"CV_PERF_COUNTERS node=%d leaf_verify_calls=%d leaf_verify_successes=%d sharing_verify_calls=%d chunking_verify_calls=%d exact_range_verify_calls=%d agg_calls=%d agg_verified_calls=%d aver_calls=%d aver_verified_calls=%d aver_successes=%d aggregate_offers=%d aggregate_offer_avers=%d verified_leaf_cache_hits=%d verified_leaf_cache_misses=%d verified_aggregate_offer_cache_hits=%d verified_aggregate_offer_cache_misses=%d\n",
		node, delta.leafVerifyCalls, delta.leafVerifySuccesses, delta.sharingVerifyCalls,
		delta.chunkingVerifyCalls, delta.exactRangeVerifyCalls, delta.aggCalls, delta.aggVerifiedCalls,
		delta.averCalls, delta.averVerifiedCalls, delta.averSuccesses, delta.aggregateOffers,
		delta.aggregateOfferAVers, delta.verifiedLeafCacheHits, delta.verifiedLeafCacheMiss,
		delta.verifiedAggregateOfferCacheHits, delta.verifiedAggregateOfferCacheMiss,
	)
}
