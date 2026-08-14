# Reproducible protocol experiments

`practical-adkr/` is a vendored snapshot of the PracticalADKR experiment used
for comparisons against the ARL-ADKR implementation. It is intentionally a
separate Go module so its dependencies and protocol assumptions do not alter
the ARL-ADKR build.

The local `dumbomvba-go/` module is included because the Practical benchmark's
`go.mod` uses a relative replacement. The launcher defaults to the
seven-process loopback benchmark:

```bash
cd experiments/practical-adkr
./scripts/run_practical_multiprocess_n7.sh
```

The historical filename is retained for compatibility. A matched n=16 run is:

```bash
PRACTICAL_MP_N=16 \
PRACTICAL_MP_F=5 \
PRACTICAL_MP_KAPPA=6 \
PRACTICAL_MP_TIMEOUT=900s \
./scripts/run_practical_multiprocess_n7.sh
```

The launcher uses strict TCP, one process per old-committee node, a shared
artifact cache, and a common deterministic setup seed. It excludes generated
executables and runtime artifact directories from the repository.

On the 2026-07-26 local 32-CPU host, the n=16 command completed on all 16
processes in one run. Per-process total latency was 4.05--4.40 seconds (mean
4.19 seconds), including a 0.35-second mean setup and 3.84-second mean online
protocol phase. This is a reproducibility snapshot, not a statistical claim.

The ARL-ADKR comparison run is launched from the repository root with:

```bash
./scripts/run_cv_cluster.sh 7 2 /tmp/arladkr-cv-n7
```

This launcher uses the scalar/group CV-sAPVSS V2 network path: component APDB,
Pool/PoolCert, contributor sampling, aggregate APDB, sampled VCert, one direct
Dumbo-MVBA, DecCert handoff, aggregate recovery, and scalar-share proofs. It is
a fresh single-epoch experiment and rejects multi-run rotation or resume.

The local academic reference pilot is defined by
`cvv2_reference_matrix_v1.json`. Validate every point without generating keys
or proofs:

```bash
go run ./cmd/cvv2ref \
  -matrix-file experiments/cvv2_reference_matrix_v1.json \
  -matrix-manifest-only
```

The three `reference-crypto` points are functional smoke measurements with
three independent fresh runs each. The four secure points are
`manifest-only`; they record fixed-fraction sampling parameters and must not be
reported as measured cryptographic performance. This file is a pilot reference
matrix, not the separate multi-process network comparison matrix.
