# ARL-ADKR Go Prototype

This repository is a research prototype for evaluating the ARL-ADKR protocol
pipeline. Its main contribution boundary is the distributed protocol and its
recovery-lock integration. PVSS is a replaceable component behind the `APVSS`
provider interface; this code does not claim a new stand-alone PVSS primitive.

## APVSS providers and security boundary

| Provider | Recovered output | Received transcript / aggregate-input checks | Security profile | Scalar threshold-key output |
|---|---|---|---|---:|
| `optrand` | digest (`emulated`) | protocol-emulator checks | `protocol-emulator` | no |
| `bls-pvss` | digest of verified BLS12-381 share material (`group-element`) | yes | `group-element-prototype` | no |
| `scalar-shamir` | degree-`F` Edwards25519 scalar shares and matching public key (`scalar`) | received artifact, list aggregate, decrypted share, and recovered-output checks | `functional-scalar-prototype` | yes |
| `paillier-scalar` | scalar candidate | not wired into this Go prototype | unavailable | no |

The BLS provider encodes `SID`, epoch, dealer, receiver order, commitments,
encrypted shares, and its Schnorr proof in a canonical transcript. `Ver` and
`Agg` consume and verify received artifacts. Recover-time fragment responses
carry that canonical transcript and a separately domain-separated digest.

The BLS dealer samples fresh polynomial coefficients. Runtime/setup keys are
still deterministically generated for this prototype, so the provider does not
advertise production randomness. Its Schnorr proof establishes knowledge of
`DLOG_G1(zeta)`; it is not described as a cross-group Chaum-Pedersen equality
proof. The sharing polynomial currently has degree `n-f-1`, which is distinct
from the degree-`f` scalar-output construction considered in the paper design.

`scalar-shamir` uses threshold `F+1` and polynomial degree `F`. Its list-backed
aggregate binds the exact received dealer artifacts; Recover decrypts and
verifies every receiver share, adds the scalars, and returns the aggregate
shares and matching constant-term public commitment directly. It is a
functional integration provider, not a compact homomorphic APVSS: ciphertext
correctness is not publicly proved before receiver decryption, runtime
randomness/setup remain prototype-only, and IND2/ZK/ROM security is not closed.

Wire versions are provider-local. Legacy Optrand uses schema-v1 with an omitted
provider field; scalar Shamir uses `(provider=scalar-shamir, schema=1)` in its
transcript, share packet, and VE binding. Paillier would own a separate
`(paillier-scalar, schema=1)` codec; there is no global Edwards-v1/Paillier-v2
mapping.

`--derive-mode=scalar` fails closed unless a provider explicitly advertises all
scalar-output, received-input verification, verifiable-share, and threshold-key
capabilities. In this prototype only `scalar-shamir` satisfies that functional
gate. The default `--derive-mode=aggregate` remains an explicit hash-derived
protocol emulator; it must not be reported as a deployed scalar PVSS
key-derivation path.

## Provider boundary

- `core/apvss_iface.go` contains only shared types, the interface, and provider selection.
- `core/apvss_optrand_provider.go` adapts the protocol emulator.
- `core/apvss_bls_provider.go` adapts the BLS12-381 group-element prototype.
- `core/apvss_scalar_shamir_provider.go` implements the functional scalar path.
- `core/apvss_list_aggregate.go` contains the provider-neutral list-backed container.
- `core/apvss_capabilities.go` is the capability gate used by recovery and benchmarks.

Benchmark output includes `apvss_provider`, `apvss_output`, `security_profile`,
and `derive_mode`, preventing results from silently mixing emulator, BLS, and
functional scalar runs.

## Build and test

The module currently expects its MVBA dependency as a sibling checkout because
`go.mod` contains `replace dumbomvba_go => ../dumbomvba-go`.

```sh
go test ./...
go test -race ./core ./cmd/rladkrbench
go vet ./core ./cmd/rladkrbench
go build -buildvcs=false -o /tmp/arladkr-rladkrbench ./cmd/rladkrbench
```

Example benchmark flags:

```sh
go run ./cmd/rladkrbench --apvss-provider=optrand --derive-mode=aggregate
go run ./cmd/rladkrbench --apvss-provider=bls-pvss --derive-mode=aggregate
go run ./cmd/rladkrbench --apvss-provider=scalar-shamir --derive-mode=scalar
```

Current scalar-provider ledger:

```text
functional degree-F scalar provider wired into Go = true
real threshold shares/public key returned = true
compact scalar APVSS = false
Paillier scalar provider = false
production setup/randomness = false
formal IND2/ZK/ROM closure = false
bare.tex modified = false
```
