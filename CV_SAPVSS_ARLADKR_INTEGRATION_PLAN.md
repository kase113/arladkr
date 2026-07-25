# CV-sAPVSS ARL-ADKR Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use test-driven development for every task. The workspace is not a Git repository, so worktrees and per-task commits are unavailable; keep each patch independently buildable instead.

**Goal:** Replace the benchmark execution path with a complete, cross-process CV-sAPVSS ARL-ADKR flow under static corruption: component availability, common dealer selection, materialized aggregate ARC, \(n_o-2f_o\)-shard recovery, receipt verification, and scalar threshold-key output.

**Architecture:** Keep the existing CV algebra/proofs, TCP transport, threshold signer, Reed--Solomon library, and Dumbomvba ACS/MVBA. Add one CV-specific orchestration path called by `RunEpoch`; do not force receipt-bearing material through the legacy `APVSS` interface. Only a materialized AggRLO is proposed to MVBA, and the semantic decision remains its canonical digest.

**Tech stack:** Go standard library, gnark-crypto BLS12-381/fr, klauspost/reedsolomon, existing `agreementTransport`, existing TBLS signer, existing Dumbomvba common-subset runner.

**Status (2026-07-24):** Tasks 1--6 and the single-AggRLO-MVBA follow-up are implemented. Full CV
tests and real `n=4`/`n=7` loopback TCP E2E pass. Task 7 removed all legacy runtime selection and the
standalone `arl-pvss/` tree; compile-coupled Go legacy sources remain until caller analysis permits
physical deletion.

---

## File map

- `core/cv_sapvss_codec.go`: strict decoders/encoders for leaf proof, leaf, receipt, fresh shard, candidate bundle, and materialized AggRLO witness.
- `core/cv_sapvss_keys.go`, `core/cv_sapvss_lock_keys.go`: public registries plus local-only receiver and old-lock secret loading/key generation.
- `core/cv_sapvss_component_service.go`, `core/cv_sapvss_aggregate_service.go`: component dispersal/retrieval, fresh shard/ARC collection, ARC-holder recovery, and receipt exchange.
- `core/cv_sapvss_router.go`: exactly one `RecvChan` consumer per local old node and bounded tag demultiplexing for the whole epoch.
- `core/cv_sapvss_store.go`: holder-local atomic shard persistence keyed by `(sid, epoch, header digest, holder)`.
- `core/cv_sapvss_epoch.go`: CV-only `RunEpoch` orchestration and result construction.
- `core/cv_sapvss_m4.go`: deterministic per-candidate fresh nonce entry point and helpers reused by the network path.
- `core/mvba_tcp.go`: optional external-validity predicate and instance-domain parameter; old caller remains a thin wrapper.
- `core/config.go`, `core/types.go`, `core/epoch.go`: CV constraints, result fields, and dispatch.
- `cmd/rladkrbench/main.go`: CV defaults/keygen flags and truthful labels.
- `scripts/run_cv_cluster.sh`: portable one-process-per-old-node launcher.

## Task 1: Canonical codecs and key material

**Tests:** focused cases live in the CV codec, key, component, service, store, router and epoch test files.

- [x] Write `TestCVLeafCodecRoundTripAndRejectsTrailingBytes`; run it and confirm failure because `cvDecodeLeaf` is missing.
- [x] Implement bounded vector/scalar readers and `cvDecodeLeafProof`, mirroring `cvLeafProofCanonicalBytes`; every count is checked against context-derived exact sizes before allocation.
- [x] Implement `cvDecodeLeaf(wire, expectedContext)` and finish by re-encoding byte-for-byte plus `cvVerifyLeaf`.
- [x] Write receipt round-trip/tamper test; implement `cvDecodeReceipt` with canonical re-encoding and aggregate/receiver binding checks.
- [x] Write key-registry test; implement JSON `version`, ordered `(receiver_id, public_key)` entries, and per-receiver scalar files. Strict-network loading reads only `LocalReceiverIDs`; each scalar must canonically decode and reproduce its registry public key.
- [x] Add key generation using `crypto/rand`, registry mode `0644`, secret mode `0600`; no new dependency.
- [x] Generate an independent random old-lock threshold polynomial; publish every verification share but load only the local old-node scalar in strict runtime.
- [x] Run only the named codec/key tests.

## Task 2: Component availability and local candidate collection

**Protocol messages:** `CV_COMPONENT_INIT`, `CV_COMPONENT_ACK`, `CV_COMPONENT_CERT`, `CV_COMPONENT_GET`, `CV_COMPONENT_LEAF`, `CV_COMPONENT_READY`.

- [x] Write a failing state-machine test showing a node that receives a valid component certificate but missed INIT retrieves the leaf from a certified holder.
- [x] Add random dealer construction: sample degree-\(f_n\) scalar/blinding coefficients and shared Groth coins, then call the existing `cvReferenceDeal`.
- [x] Dealer broadcasts canonical leaf. A holder decodes and runs `VerifyLeaf`, stores the leaf, and only then signs `RL_LOCK` for a header binding `(sid, epoch, dealer, context digest, leaf digest)`.
- [x] Dealer collects distinct valid ACKs, recovers an \(n_o-f_o\) component certificate, and broadcasts the descriptor. Missing recipients request the leaf from `Descriptor.Lock.Holders` and verify digest/context/proof before admitting it.
- [x] Broadcast each certified descriptor and retain the first valid descriptor per dealer in an epoch-local bounded registry.
- [x] Wait for \(n_o-f_o\) valid descriptors, sort the local view by dealer, and select exactly \(K=f_o+1\). This is candidate collection, not agreement; asynchronous views may yield different valid candidates.
- [x] Retrieve every missing selected leaf from that descriptor's certified holders, then canonical-decode and run full `VerifyLeaf` before materialization.
- [x] Do not run a component MVBA. Candidate safety comes from the descriptor certificate; final agreement is exclusively on materialized AggRLO witnesses.
- [x] Reuse the already verified/stored local leaf to synthesize the local holder ACK and omit self-INIT, while preserving the \(n_o-f_o\) certificate threshold.
- [x] Run only component/candidate tests.

The router starts before component dispersal and remains the sole reader until receipt finalization. Unknown, oversized, stale-session, and stale-epoch messages are rejected rather than consumed by a later phase.

## Task 3: Fresh aggregate dispersal and real ARC shares

**Protocol messages:** `CV_AGG_MANIFEST`, `CV_ARC_SHARE`, `CV_ARC_CERTIFICATE`.

The aggregate path is single-path: `CV_AGG_MANIFEST` carries the aggregate header
and component-set root. Holders rebuild the aggregate and their deterministic
fresh shard from the locally cached, certificate-only component descriptors;
the retired full aggregate-offer wire is not accepted.

- [x] Write a failing test that an ARC share is produced only after the holder has verified and stored its own fresh shard.
- [x] Derive `nonce = H("ARL-CV-sAPVSS/fresh-nonce", contextDigest, aggregateDigest)`; it is unique to the decided epoch/candidate and makes all honest materializers produce the same RS codeword/root.
- [x] Run `VerifyLeaf -> Agg -> AVer`, serialize the aggregate transcript, and use existing `(n_o,n_o-2f_o)` RS/Merkle helpers.
- [ ] Limit materialization to a safe proposer subset. The current implementation lets every process materialize its locally selected candidate; limiting it requires a leader/proposer schedule and RLO help dissemination that preserves liveness for the single AggRLO MVBA.
- [x] Holder recomputes expected aggregate/root, verifies membership/index, atomically stores the shard in a holder-local directory, signs the common `AggHeader`, and broadcasts one `CV_ARC_SHARE` from its own local identity. Same-key/same-bytes retry is idempotent; same-key/different-bytes is rejected.
- [x] Verify sender/holder equality, membership, digest, and TBLS share; collect any \(n_o-f_o\) distinct shares and recover the certificate.
- [x] Encode the complete materialized AggRLO as the MVBA help witness. Run the protocol's only predicate-bearing MVBA instance; validate the decided witness and expose `AggRLO.Digest` as the semantic decision.
- [x] Run only aggregate/ARC tests.

## Task 4: Recover from ARC holders

**Protocol messages:** `CV_RECOVER_GET`, `CV_RECOVER_SHARD`, `CV_RECOVER_DONE`.

- [x] Write a failing test where only \(n_o-2f_o\) of the decided ARC holders respond and recovery succeeds without dealer responses.
- [x] Request the decided root from `AggRLO.Lock.Holders`. A holder responds only if its locally stored shard matches the decided root and holder-to-index mapping.
- [x] Accept distinct authenticated indices only; verify Merkle branch/root/header before counting.
- [x] Stop after \(n_o-2f_o\) valid shards, reconstruct with existing RS code, check payload digest and aggregate digest, then canonical-decode the aggregate transcript.
- [x] Broadcast DONE and keep servicing requests until \(n_o-f_o\) DONE notices or context cancellation, preventing early successful nodes from starving peers.
- [x] Run only recovery tests.

## Task 5: Receipts and scalar threshold key

**Protocol messages:** `CV_RECEIPT`, `CV_RECEIPT_DONE`.

- [x] Write a failing test that two/three valid receipt subsets interpolate the identical threshold public key, while a tampered receipt is rejected.
- [x] For each local receiver secret call existing `cvDecShare`, immediately call `cvVerifyShare`, store canonical 32-byte `fr` share, and broadcast canonical receipt.
- [x] Decode and verify every remote receipt against the recovered aggregate; count each receiver once.
- [x] Interpolate any \(f_n+1\) verified `receipt.publicScalar` values at zero in BLS12-381 G1. Return compressed canonical G1 as `NewPublicKey`; return only locally held scalar shares in `NewShares`.
- [x] Add canonical receipts and verified count to `EpochResult`; do not hash recovered bytes into a fake key.
- [x] Run only receipt/key tests.

## Task 6: `RunEpoch`, CLI, launcher, and metrics

- [x] Write config tests requiring `cv-sapvss + materialized + scalar`; strict network additionally requires key directory, predicate-capable agreement kernel, and exactly one local old node per process.
- [x] In strict CV mode load only local old-node TBLS secret shares from the key directory while retaining all public verification shares. `SignShare` must fail for a non-local holder; deterministic all-secret runtime generation remains available only to non-strict unit fixtures.
- [x] Dispatch `RunEpoch` to `runCVEpoch` after common runtime/transport setup. Fill existing phase timings and add component-ready, ARC-holder, recovered-shard, and verified-receipt counts.
- [x] Make CLI defaults `cv-sapvss`, `materialized`, `scalar`, `comm-metrics=true`; expose CV key directory/local receiver IDs and keygen-only mode.
- [x] Pass actual mode/ARC/provider fields into formatter. Use phase labels `component_disperse`, `common_candidate`, `aggregate_disperse`, `arc_share`, `recover_shard`, and `receipt`; remove hard-coded `header-only` output.
- [x] Add `scripts/run_cv_cluster.sh`: generate keys once, construct protocol/MVBA address maps, assign one old node and receiver per process, start processes, prefix logs, wait, and propagate failure.
- [x] Compile packages and run only CLI/config formatter tests; do not run full `RunEpoch` or multiprocess E2E without explicit user approval.

## Task 7: Legacy cleanup and documentation

- [x] Remove old providers from CLI/config runtime selection after CV path compiles; retain only shared ARL transport/MVBA/threshold-signature/state helpers.
- [ ] Delete compile-coupled legacy Go provider files/tests only when `rg` proves they have no remaining shared callers. The standalone `arl-pvss/` prototype is already deleted; historical documents and CV reference tests remain.
- [x] Update the Phase 1 authority document: mark codec/network/common-candidate/ARC/recovery/receipt gates with exact component-test status; keep full E2E/benchmark status open until actually run.
- [x] Run `gofmt`, `go test` only for the named component tests, and `go test` compile-only selection where possible. Record commands and outcomes; never claim E2E success from component checks.
