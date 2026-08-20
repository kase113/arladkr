# ARL-ADKR Go Prototype

This repository contains one ARL-ADKR research path built around the
scalar-output CV-sAPVSS construction. It does not expose interchangeable PVSS
providers or legacy agreement/recovery modes.

## Protocol path

```text
scalar/group CV-sAPVSS V2 ACK/fallback leaf
-> component APDB lock and verified catalog
-> eligibility coin and sampled proposer/validator sets
-> Pool/PoolCert and contributor-coin aggregate
-> aggregate APDB lock and sampled VCert
-> one direct predicate-bearing MVBA
-> DecCert handoff and new-committee aggregate recovery
-> persist scalar shares, exchange proofs, interpolate public key
```

For each receiver, the V2 transcript contains radix ciphertexts for one scalar
share and one group ElGamal ciphertext for its Pedersen blinding. ACK receivers
provide an identity-bound ownership statement; the complement set carries the
fixed aggregated range/link evidence. Aggregation combines ciphertexts and
commitments homomorphically but never aggregates component proofs: every
selected leaf is decoded and verified again.

The agreement object binds the canonical Pool, selected contributors,
aggregate APDB reference and VCert. Threshold-signature shares remain local to
their collectors; only recovered certificates enter the public transcript.
There is one V2 MVBA decision and one authorized aggregate recovery.

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

Relevant experiment controls are `-f-old`, `-f-new`, `-kappa`,
`-cv-proposer-sample`, `-cv-validator-sample`, the explicit failure target,
network timeouts, and V2 key/store directories. `-cv-failure-target original`
uses the paper's total budget `Delta=1e-10`; `high-assurance` uses
`Delta=2^-64/525600`. The solver allocates `Delta/2` to proposer and validator
sampling separately and chooses the smallest samples from the exact
finite-population bounds for the configured `n,f`. Benchmark output labels the network path as
`cv-sapvss-v2-scalar-group` / `single-mvba-v2`; `cmd/cvv2ref` uses a distinct
reference-only label.

`cmd/cvv2ref` emits one `arladkr-cvv2-reference-report-v1` JSON object with a
stable parameter-derived experiment ID, sampling manifest, ordered raw runs,
and mean timing/size metrics. Smoke runs are labeled `functional-smoke` and
carry no negligible-failure claim. Secure sampling points can be validated
without executing a very large cryptographic reference epoch:

```sh
go run ./cmd/cvv2ref -old-n 4 -old-f 1 -new-n 4 -new-f 1 -runs 1
go run ./cmd/cvv2ref -manifest-only -old-n 128 -old-f 42 \
  -new-n 128 -new-f 42 -failure-target original
go run ./cmd/cvv2ref -matrix-file experiments/cvv2_reference_matrix_v1.json \
  -matrix-manifest-only
```

The versioned pilot matrix contains three executable functional reference
points and ten secure sampling-only points covering both paper profiles at
`n=32,48,64,96,128`. Omitting `-matrix-manifest-only`
runs only the functional points; secure points never trigger large-committee
cryptographic execution.

## Security boundary

- Static corruption is the current target; dynamic corruption and forward-secure
  encryption are outside this implementation scope.
- The fixed V2 fallback adapter is research code. This repository tests its
  canonical statement, range/link binding and cross-domain rejection; it does
  not replace the paper's security proof or an independent implementation
  review.
- Component RS plus Merkle membership is a retrievability prototype, not a full
  Byzantine codeword proof. Recovered payload, leaf digest, and APVSS validity
  are still checked before aggregation.
- The current experiment is a fresh single epoch with co-located old/new roles.
  Physical role separation, multi-epoch key rotation and incomplete-epoch
  restart are outside the claimed experimental boundary. Both `rladkrbench`
  and `run_cv_cluster.sh` reject any `runs`/`epochs` shape other than `1/1`.
