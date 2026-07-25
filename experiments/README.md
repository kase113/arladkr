# Reproducible protocol experiments

`practical-adkr/` is a vendored snapshot of the PracticalADKR experiment used
for comparisons against the ARL-ADKR implementation. It is intentionally a
separate Go module so its dependencies and protocol assumptions do not alter
the ARL-ADKR build.

The local `dumbomvba-go/` module is included because the Practical benchmark's
`go.mod` uses a relative replacement. The seven-process loopback benchmark is:

```bash
cd experiments/practical-adkr
./scripts/run_practical_multiprocess_n7.sh
```

The launcher uses strict TCP, one process per old-committee node, a shared
artifact cache, and a common deterministic setup seed. It excludes generated
executables and runtime artifact directories from the repository.

The ARL-ADKR comparison run is launched from the repository root with:

```bash
./scripts/run_cv_cluster.sh 7 2 /tmp/arladkr-cv-n7
```

This launcher uses the single-path CV-sAPVSS network path: certificate-only
component descriptors, `CV_AGG_MANIFEST` references, collector-directed ARC
shares, compact ARC certificate broadcast, and the certificate-only AggRLO
MVBA witness. The removed retired full-offer wire is not available as a benchmark
fallback.
