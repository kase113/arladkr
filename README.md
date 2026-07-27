# ARL-ADKR Go Prototype

This repository contains one ARL-ADKR research path built around the
scalar-output CV-sAPVSS construction. It does not expose interchangeable PVSS
providers or legacy agreement/recovery modes.

## Protocol path

```text
CV-sAPVSS ACK/I leaf
-> component RS shard availability lock
-> ReadyCert + deterministic FirstKValid
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

Relevant benchmark controls are `-f-old`, `-f-new`, `-kappa`,
`-apvss-fallback-profile`, `-apvss-forced-fallback-count`,
`-apvss-wait-all-acks`, network timeouts, and CV key/store directories.
Benchmark output fixes the architecture labels to
`agreement_path=single-mvba`, `apvss_provider=cv-sapvss`,
`arc_mode=materialized`, and `derive_mode=scalar`.

## Security boundary

- Static corruption is the current target; dynamic corruption and forward-secure
  encryption are outside this implementation scope.
- `compact-batch` is experimental. It must not be reported as production-ready.
- Component RS plus Merkle membership is a retrievability prototype, not a full
  Byzantine codeword proof. Recovered payload, leaf digest, and APVSS validity
  are still checked before aggregation.
- ReadyCert plus reselection does not prove that only one candidate header can
  exist. The protocol keeps one final MVBA but may materialize multiple valid
  candidates before agreement.
