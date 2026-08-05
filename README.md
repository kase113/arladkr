# ARL-ADKR Go Prototype

This repository contains one ARL-ADKR research path built around the
scalar-output CV-sAPVSS construction. It does not expose interchangeable PVSS
providers or legacy agreement/recovery modes.

## Protocol path

```text
CV-sAPVSS ACK/I leaf
-> component RS shard availability lock
-> ReadyCert + optimistic primary + deterministic FirstKValid
-> holder-local aggregate verification and fresh RS dispersal
-> recovered ARC certificate
-> one predicate-capable common-subset MVBA
-> one aggregate recovery
-> scalar shares and public receipts
```

The APVSS transcript keeps every receiver ciphertext so the agreed aggregate
is self-contained. Receivers that acknowledge a lane bind a signed statement;
the complement set `I` carries an exact-lane proof or the experimental compact
batch proof. The compact backend remains behind `-allow-experimental-apvss`
pending proof alignment and independent cryptographic review.

Component descriptors and aggregate locks carry recovered threshold
certificates only. Individual signature shares stay at the collector and are
discarded after certificate recovery. The final agreement object is a compact,
materialized `AggRLO`; there is no fastlane/fallback agreement selector and no
second MVBA.

## Build and test

The module expects its MVBA dependency as a sibling checkout because `go.mod`
contains `replace dumbomvba_go => ../dumbomvba-go`.

```sh
go test ./... -run '^$' -count=1
go test ./core -count=1 -timeout=10m
go test ./cmd/rladkrbench -count=1 -timeout=5m
go test -race ./core -run 'Ready|AggregateManifest|LocalARC' -count=1 -timeout=5m
go build -buildvcs=false -o bin/rladkrbench ./cmd/rladkrbench
```

Run a local multi-process TCP cluster:

```sh
./scripts/run_cv_cluster.sh 4 1 /tmp/arladkr-cv 20000
```

Relevant benchmark controls are `-f-old`, `-f-new`, `-kappa`, `-apvss-mode`,
`-apvss-full-proof-profile`, `-apvss-fallback-profile`, `-apvss-forced-fallback-count`,
`-apvss-wait-all-acks`, network timeouts, and CV key/store directories.
`RLADKR_LEAF_VERIFY_WORKERS` independently bounds ordered leaf
retrieval/verification (default: reserve one scheduler slot, cap at four).
The local multi-process harness divides logical CPUs across node processes;
the effective worker count is recorded through the benchmark environment and
should be fixed explicitly for cross-machine comparisons.
Benchmark output fixes the architecture labels to
`agreement_path=single-mvba`, `apvss_provider=cv-sapvss`,
`arc_mode=materialized`, and `derive_mode=scalar`.

Aggregate candidate materialization rotates one deterministic primary per
epoch. Other nodes independently verify its manifest, persist their fresh
shard, and reuse the recovered ARC-certified AggRLO. If the primary does not
complete, they activate the existing ReadyCert/reselection path after
their local `FirstKValid` prewarm completes and
`RLADKR_CV_PRIMARY_GRACE_MS` (default `10000`) then expires. Benchmark output records
`cv_candidate_mode` and the effective grace. The primary waits up to
`RLADKR_CV_PRIMARY_POOL_GRACE_MS` (default `250`) for an in-flight canonical
prefix update, but starts immediately after all `n_o` certified descriptors
arrive. This second timer only coalesces normal-network reselections.

## Security boundary

- Static corruption is the current target; dynamic corruption and forward-secure
  encryption are outside this implementation scope.
- Fallback `compact-batch`, full-public `compact-batch`, and full-public
  `field-congruent` are experimental. The full profiles use separate
  all-receiver statement scopes. `field-congruent` binds the decrypted radix
  value modulo the scalar field and intentionally omits the canonical-integer
  comparator. None may be reported as production-ready or used for headline
  results before their stated proof obligations and independent review close.
- Component RS plus Merkle membership is a retrievability prototype, not a full
  Byzantine codeword proof. Recovered payload, leaf digest, and APVSS validity
  are still checked before aggregation.
- The optimistic primary gives one candidate in a healthy timely execution;
  it is not an asynchronous proof that only one header can exist. After the
  bounded grace, ReadyCert reselection may materialize multiple valid
  candidates. Safety, ARC thresholds, and the single final MVBA do not depend
  on the timer or primary being honest.
