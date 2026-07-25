# dumbomvba-go

Go reproduction of the `dumbomvba/core` protocol path, extracted from:

- `/home/yzc/project/dumbomvba/dumbomvba/core`

## Structure

- `core/types.go`: protocol and interface definitions
- `core/signer_tbls.go`: TBLS signer based on `go.dedis.ch/kyber/v3/sign/tbls`
- `core/signer_ed25519.go`: ed25519 fallback signer (compat tests)
- `core/mvba.go`: Dumbo-MVBA entry + minimal SPBC path (compat)
- `core/mvba_equivalent.go`: equivalent dumbomvba core path (`PD -> quitPD -> coin/ABA -> RC`)
- `core/pd_equivalent.go`, `core/rc_equivalent.go`: PD/RC state machines
- `core/coin_equivalent.go`, `core/aba_equivalent.go`: coin and ABA
- `core/acs_vacs.go`: ACS/VACS (`mvbacommonsubset`) path
- `core/equivalent_utils.go`: reed-solomon + merkle helpers
- `core/*_test.go`: unit tests
- `REPRODUCTION.md`: migration log, crypto substitutions, and verification records

## Quick Check

```bash
cd /home/yzc/project/RLADKR/dumbomvba-go
go test ./...
```
