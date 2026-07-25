# ADKR Review Notes

Reviewed target: `/home/RLADKR/practical-adkr/core/adkr.go`

Scope:
- `core/adkr.go`
- `core/apdb.go`
- `core/pvss_dxt.go`
- `core/recover_erasure.go`
- `core/mvba_dumbo_adapter.go`
- `core/types.go`
- `core/netdelay.go`

Focus:
- Distributed correctness
- Runtime behavior under up to 256 nodes
- Design and implementation risks

Overall assessment: `REQUEST_CHANGES`

## Findings

### P1-1 `APDB` certificate threshold is set to `2f`, which weakens the protocol quorum

Location:
- `/home/RLADKR/practical-adkr/core/apdb.go:38`
- `/home/RLADKR/practical-adkr/core/apdb.go:281`
- `/home/RLADKR/practical-adkr/core/adkr.go:358`
- `/home/RLADKR/practical-adkr/core/adkr.go:686`

What is happening:
- The code builds APDB certificates with `threshold := 2 * cfg.F`.
- In a `n = 3f + 1` Byzantine setting, the usual quorum needed for dispersal certificates is `2f + 1`, not `2f`.
- `verifyAPDBCertificate` only checks signature validity and uniqueness; it does not enforce a minimum certificate size on verification.

Why this matters:
- With 256 nodes and `f = 85`, the current code can accept certificates backed by only 170 receipts, while the safety quorum should be 171.
- That reduces quorum intersection guarantees and makes it easier for two conflicting certificates to exist without enough honest overlap.
- Because the same reduced threshold is reused in fallback certificate synthesis, this issue is systematic rather than incidental.

Suggested fix:
- Change every APDB certificate construction threshold to `2*cfg.F + 1`.
- Enforce the same lower bound inside `verifyAPDBCertificate`, so malformed or legacy undersized certificates are rejected on read as well as write.

### P1-2 The code silently fabricates remote progress using local private keys, so distributed runs can appear healthy when the network path is broken

Location:
- `/home/RLADKR/practical-adkr/core/pvss_dxt.go:322`
- `/home/RLADKR/practical-adkr/core/pvss_dxt.go:344`
- `/home/RLADKR/practical-adkr/core/adkr.go:328`
- `/home/RLADKR/practical-adkr/core/adkr.go:412`

What is happening:
- In `DXTBackend.Deal`, if network ack collection is incomplete, the dealer synthesizes recipient acknowledgements locally by signing with `recipientSignPriv`.
- In APDB, if the distributed path fails or yields no valid set, the code marks every dealer valid for every node and synthesizes certificates by signing with `dealerEDPriv[nodeID]`.
- In agreement, if MVBA fails, it falls back to `localQuorumDealerSet`, which is also process-local.

Why this matters:
- This is acceptable for a single-process simulator, but it masks the exact failures that matter in real deployments: node reachability, listener binding bugs, split deployments, partial partitions, and key placement mistakes.
- If you run up to 256 nodes across multiple hosts, a process that happens to hold many private keys can generate progress that would be impossible in a real distributed system.
- The result is a false sense of liveness and correctness: benchmarks may pass while actual distributed execution would stall.

Suggested fix:
- Introduce an explicit mode split:
  - `simulation/dev`: allow local synthetic fallback.
  - `distributed/strict`: disable all private-key-based local synthesis and fail hard on missing remote acknowledgements/certificates/agreement.
- Gate these paths behind config, not environment convention.
- Surface which fallback path was taken in the returned `Result`, logs, and metrics as a first-class failure signal.

### P1-3 Recast recovery has O(selected * old * new) control traffic and very large buffered channels, which is likely to break down around 256 nodes

Location:
- `/home/RLADKR/practical-adkr/core/adkr.go:833`
- `/home/RLADKR/practical-adkr/core/adkr.go:837`
- `/home/RLADKR/practical-adkr/core/adkr.go:1247`
- `/home/RLADKR/practical-adkr/core/adkr.go:1292`
- `/home/RLADKR/practical-adkr/core/adkr.go:1455`

What is happening:
- `storeSeenCh` and `fetchRespCh` are sized as `len(selectedIDs) * len(old) * len(newC)`.
- Every local holder sends a `store_batch` to every new-committee recipient.
- Once holder threshold is reached, each recipient fans fetch requests out to many holders, with default fanout `erasureK + f`.

Why this matters at 256 nodes:
- With old committee = new committee = 256 and `f = 85`, a single phase can easily create buffers on the order of 16M message slots if `selectedIDs` is large.
- Even if actual traffic is lower, the preallocated channel capacities alone can explode memory usage.
- The send pattern also creates a large number of goroutines and short-lived TCP connections, which raises scheduler pressure, fd pressure, and retransmission tail latency.

Suggested fix:
- Stop sizing channels from the full Cartesian product. Use bounded worker queues sized from concurrency limits.
- Batch by dealer windows or recipient windows instead of all selected dealers at once.
- Replace per-send goroutines with a fixed worker pool and connection reuse.
- Add load-shedding and backpressure metrics so saturation is visible before timeout.

### P1-4 The recast ready barrier is persisted only by `old-%d.ready` filenames and is not namespaced by run identity, so stale files can contaminate future runs

Location:
- `/home/RLADKR/practical-adkr/core/adkr.go:734`
- `/home/RLADKR/practical-adkr/core/adkr.go:759`
- `/home/RLADKR/practical-adkr/core/adkr.go:769`

What is happening:
- The barrier writes files under `<cache>/recast-ready/old-<id>.ready`.
- It does not include `SID`, committee hash, PID, timestamp, or run UUID.
- The wait condition is simply “number of matching files >= len(old)”.

Why this matters:
- A previous crashed or completed run can leave enough ready files behind to immediately satisfy the barrier for a later, unrelated run.
- In distributed setups this can cause one run to proceed before all listeners of the current run are actually ready.
- That kind of stale artifact bug is especially painful because it appears nondeterministically under repeated benchmark loops.

Suggested fix:
- Namespace barrier state by a run identifier derived from `SID` plus committee/config hash.
- Clear or expire old barrier directories before use.
- Consider replacing filesystem rendezvous with an in-protocol readiness handshake if this path is intended for multi-host execution.

### P2-1 `adkr.go` has grown into a protocol god-file and mixes orchestration, crypto plumbing, network transport, retries, caching, and artifact coordination

Location:
- `/home/RLADKR/practical-adkr/core/adkr.go:135`
- `/home/RLADKR/practical-adkr/core/adkr.go:781`
- `/home/RLADKR/practical-adkr/core/adkr.go:1690`

What is happening:
- `RunPracticalADKR` and helpers own end-to-end workflow, timing, networking, fallback behavior, persistence, and recovery.
- `runRecastRecovery` alone contains transport setup, admission control, verification, resend policy, thresholds, and completion logic.

Why this matters:
- At this size, changing one runtime behavior risks changing protocol behavior at the same time.
- It makes it difficult to test safety properties in isolation.
- For distributed systems, tangled control and transport logic slows down incident debugging because it is unclear whether failures are semantic or infrastructural.

Suggested fix:
- Split into modules with narrow responsibilities:
  - protocol orchestration
  - APDB certificate/dispersal engine
  - agreement adapter
  - recast transport
  - recast verifier/state machine
  - cache/artifact coordination
- Keep state transitions explicit and serializable so they can be tested independently.

### P2-2 `validateConfig` only checks the old committee size and leaves several distributed invariants unchecked

Location:
- `/home/RLADKR/practical-adkr/core/adkr.go:1565`

Missing checks:
- `len(NewCommittee) >= 3f + 1` if the new committee is expected to tolerate the same fault model.
- Uniqueness of node IDs across each committee.
- Whether old and new committee overlap is allowed or forbidden.
- Whether every node mentioned in the committee has a configured transport address in strict distributed mode.
- Whether local node IDs are a subset of configured node IDs.

Why this matters:
- Invalid committee layouts become runtime failures much later in the protocol.
- At 256 nodes, late failure is expensive and much harder to debug.

Suggested fix:
- Add a stronger config validator with committee uniqueness, address completeness, and strict-mode key/address placement checks.

### P2-3 `loadOrComputeDXTCache` can wait forever on a stale lock file

Location:
- `/home/RLADKR/practical-adkr/core/adkr.go:1724`
- `/home/RLADKR/practical-adkr/core/adkr.go:1751`

What is happening:
- The cache lock uses `O_CREATE|O_EXCL`.
- If a process dies after creating the lock and before removing it, every later process waits until context cancellation.
- There is no owner metadata, heartbeat, age check, or stale lock reclamation.

Why this matters:
- In repeated benchmark or multi-process runs, one interrupted job can poison future executions.
- This becomes more likely as node count and wall-clock duration increase.

Suggested fix:
- Write owner metadata into the lock file and reclaim stale locks based on age and liveness.
- Or switch to a lock implementation with lease semantics.

### P2-4 The APDB transport verifies the whole transcript on every receipt request, which is expensive and amplifies startup load

Location:
- `/home/RLADKR/practical-adkr/core/apdb.go:113`
- `/home/RLADKR/practical-adkr/core/apdb.go:155`
- `/home/RLADKR/practical-adkr/core/pvss_dxt.go:433`

What is happening:
- Each APDB receipt request carries the full `DXTTranscript`.
- Each receiver runs `dxt.VerifyTranscript` before issuing a receipt.

Why this matters at scale:
- This duplicates transcript serialization and signature verification work at every recipient for every dealer.
- With 256 dealers and 256 recipients, this becomes a heavy N^2 verification burst before agreement even starts.

Suggested fix:
- Separate transcript dissemination from receipt attestation.
- Have APDB attest a content-addressed root or chunk proof, not a full transcript object on every request.
- Cache transcript verification results by `(dealer, root)` per node.

## Open Questions

1. Is this code intended to support true multi-host deployment, or is the primary target still local process simulation?
2. In your deployment model, does one OS process ever hold private keys for multiple logical nodes? If yes, strict-vs-sim mode becomes urgent.
3. Is `selectedIDs` expected to be close to `n` in your experiments? If yes, the recast phase likely needs redesign before 256-node runs.

## Recommended Follow-up Order

1. Fix APDB quorum thresholds and verifier enforcement.
2. Add a strict distributed mode that disables all synthetic local progress.
3. Redesign recast recovery flow control and queue sizing before large-scale runs.
4. Namespace and harden all filesystem rendezvous and cache locks.
5. Refactor `adkr.go` into smaller protocol/runtime components so further fixes are safer.

## Review Method

This review was based on static analysis of the code paths above plus an attempted repository test run. It focused on correctness and runtime risk rather than style.

## 2026-06-29 Local Proc-Sim Repair Tracking

Environment:
- Current work is limited to local single-machine `proc-sim`.
- Linux ephemeral port range on this host is `32768-60999`, so proc-sim base ports must keep effective protocol ports outside that range.

Applied fixes:
- Added proc-sim preflight guard in `deployment/docker/run_proc_sim.py` to reject port plans that overlap Linux ephemeral ports.
- Hardened `recover` retry behavior in `core/adkr.go`:
  - wider initial fetch fanout
  - periodic recipient-side retry dispatch
  - deterministic holder rotation per recipient to avoid low-index holder hotspots
  - default fetch stall interval reduced from `2s` to `1s`

Verification:
- `go build -o /home/RLADKR/practical-adkr/bin/bench_latency ./cmd/bench_latency`
- `go test ./core -run 'Test(BoundedQueueSize|RecoverInitialFetchFanout|RecoverRetryStep)$' -count=1`

Proc-sim benchmark snapshots:
- `n=64`, out dir `/tmp/practical-opt4-n64`
  - result: `64/64` success
- `n=96`, older valid baseline `/tmp/practical-seq2-n96`
  - result: `70/96` success
- `n=96`, before latest holder rotation `/tmp/practical-opt6-n96`
  - result: `64/96` success, `32/96` fail
  - average success metrics:
    - latency `157631.29 ms`
    - mvba `52191.18 ms`
    - recover `71078.85 ms`
    - fetch req `1396.22`
    - fetch resp `839.84`
- `n=96`, after holder rotation and faster retry `/tmp/practical-opt7-n96`
  - result: `69/96` success, `27/96` fail
  - average success metrics:
    - latency `154040.55 ms`
    - mvba `51217.68 ms`
    - recover `69752.57 ms`
    - fetch req `1232.64`
    - fetch resp `833.04`
  - remaining explicit recast timeout sample:
    - one node stalled with `dealer=2,3,4,9,11,15,23,30,32,40,46,57,63,66,68,71,77,83,85,86,89,90,92`
    - all of those dealers had `holders=96` but `recipients=0`

## 2026-06-29 Follow-up Runtime Tuning

Applied code changes:
- `core/mvba_dumbo_adapter.go`
  - Added env-overridable local MVBA defaults:
    - `PRACTICAL_MVBA_MAX_ROUNDS`
    - `PRACTICAL_MVBA_WAIT_SPBC_MS`
    - `PRACTICAL_MVBA_ROUTE_TIMEOUT_MS`
- `core/adkr.go`
  - Increased direct transcript carriers in recast from exactly `erasureK` to a bounded redundant set:
    - default `erasureK + min(f, max(1, f/4))`
    - override `PRACTICAL_RECOVER_DIRECT_TR_CARRIERS`
  - Short-circuited recover processing for dealers/recipients already completed locally, to avoid repeated transcript verification and unnecessary shard decode work.

Verification:
- `gofmt -w core/mvba_dumbo_adapter.go core/adkr.go`
- `go test ./core -run 'Test(APDBCertificateThreshold|VerifyAPDBCertificateRejectsUndersizedQuorum|PracticalRunIDUsesEnvOverride|PracticalRunIDStableWithoutEnv|CacheLockStale|BoundedQueueSize|RecoverInitialFetchFanout|RecoverRetryStep|APDBProposalUsesFinishedPDQuorumOnly)$' -count=1`
- `go build -o /home/RLADKR/practical-adkr/bin/bench_latency ./cmd/bench_latency`

Local proc-sim experiment:
- out dir `/tmp/practical-localtight-n127-r1`
- launcher env:
  - `PROC_SIM_BASE_PORT=27000`
  - `PRACTICAL_MVBA_WAIT_SPBC_MS=12000`
  - `PRACTICAL_MVBA_ROUTE_TIMEOUT_MS=3000`
  - `PRACTICAL_MVBA_PEER_WAIT_MS=2000`
  - `PRACTICAL_MVBA_MAX_ROUNDS=12`
- result: `127/127` success

Observed averages across 127 node logs:
- mean latency `169923.76 ms`
- mean online protocol `162665.20 ms`
- mean APDB dispersal `13232.08 ms`
- mean MVBA agree `72558.79 ms`
- mean recover `76775.21 ms`
- mean decided set `85.00`
- mean selected count `26.00`
- mean verified count `26.00`
- mean recover fetch req sent `479.32`
- mean recover fetch resp recv `194.07`
- mean recover recipient seen `26.00`

Interpretation:
- Tightening local MVBA waits did not hurt liveness in local proc-sim; `127/127` still succeeds.
- However, total latency did not materially improve versus `/tmp/practical-directrc-n127`.
- The phase cost now shows a clearer tradeoff pattern:
  - some nodes finish MVBA much faster (`~61-67s`) but then spend `~82-90s` in recover
  - others spend `~127-133s` in MVBA and then only `~15-25s` in recover
- This suggests the main remaining gap to the paper is no longer just timeout conservatism; it is likely the total amount of online work and/or overlap structure between MVBA completion and recast completion.

Next likely directions:
- Inspect why MVBA completion remains highly skewed across nodes under fully local conditions.
- Revisit whether one process should wait for all local recipient recoveries before reporting local completion, or whether the paper-comparable metric should stop at the first committee-level decision boundary instead.
- Further reduce recover store traffic volume rather than only reducing fallback fetches.

## 2026-06-29 Recover Store Subset Cut

Applied code changes:
- `core/adkr.go`
  - Added deterministic per-recipient active store-holder selection:
    - helper `recoverStoreHolderPosition(...)`
    - only a bounded holder subset now proactively sends `store_batch` to each recipient
  - Default active sender count:
    - `max(requiredHolders, directCarrierCount)`
    - override `PRACTICAL_RECOVER_STORE_HOLDERS`
  - Direct transcript senders are now chosen from that recipient-specific active subset, instead of every holder broadcasting to every recipient.
- `core/adkr_test.go`
  - added `TestRecoverStoreHolderPosition`

Verification:
- `gofmt -w core/adkr.go core/adkr_test.go`
- `go test ./core -run 'Test(APDBCertificateThreshold|VerifyAPDBCertificateRejectsUndersizedQuorum|PracticalRunIDUsesEnvOverride|PracticalRunIDStableWithoutEnv|CacheLockStale|BoundedQueueSize|RecoverInitialFetchFanout|RecoverRetryStep|RecoverStoreHolderPosition|APDBProposalUsesFinishedPDQuorumOnly)$' -count=1`
- `go build -o /home/RLADKR/practical-adkr/bin/bench_latency ./cmd/bench_latency`

Local proc-sim experiment:
- out dir `/tmp/practical-storecut-n127-r1`
- launcher env:
  - `PROC_SIM_BASE_PORT=27000`
  - `PRACTICAL_MVBA_WAIT_SPBC_MS=12000`
  - `PRACTICAL_MVBA_ROUTE_TIMEOUT_MS=3000`
  - `PRACTICAL_MVBA_PEER_WAIT_MS=2000`
  - `PRACTICAL_MVBA_MAX_ROUNDS=12`
- result: `127/127` success

Comparison vs `/tmp/practical-localtight-n127-r1`:
- previous:
  - mean latency `169923.76 ms`
  - mean online protocol `162665.20 ms`
  - mean MVBA agree `72558.79 ms`
  - mean recover `76775.21 ms`
  - mean recover store seen `1406.78`
  - mean recover fetch req sent `479.32`
  - mean recover fetch resp recv `194.07`
  - mean recover sent bytes `76380445.82`
  - mean recover recv bytes `76198908.72`
- current:
  - mean latency `157100.07 ms`
  - mean online protocol `150070.20 ms`
  - mean MVBA agree `73117.59 ms`
  - mean recover `63656.47 ms`
  - mean recover store seen `26.06`
  - mean recover fetch req sent `0.00`
  - mean recover fetch resp recv `0.00`
  - mean recover sent bytes `44464900.83`
  - mean recover recv bytes `42551698.08`

Interpretation:
- This is a real improvement, not just a phase tradeoff shuffle.
- The recast path is now almost entirely satisfied by the targeted proactive store/direct-transcript path.
- The fetch fallback path effectively disappeared at `n=127` in local proc-sim.
- Recover online cost dropped by about `13.1s`, and total mean latency dropped by about `12.8s`.
- MVBA remains the dominant unresolved bottleneck.

## 2026-06-29 Internal Delay 50-100ms Trial

Launcher change:
- Added `global50_100` latency profile to `deployment/docker/run_proc_sim.py`
  - pairwise delay sampled deterministically in `[50ms, 100ms]`

Experiment:
- out dir `/tmp/practical-internal50-100-n127-r1`
- command used internal delay mode:
  - `--latency-mode internal`
  - `--latency-profile global50_100`
- env:
  - `PROC_SIM_BASE_PORT=27000`
  - `PRACTICAL_MVBA_WAIT_SPBC_MS=12000`
  - `PRACTICAL_MVBA_ROUTE_TIMEOUT_MS=3000`
  - `PRACTICAL_MVBA_PEER_WAIT_MS=2000`
  - `PRACTICAL_MVBA_MAX_ROUNDS=12`

Result:
- process exit status: `127/127` exited cleanly
- protocol success: `0/127`
- all node logs report `success_runs=0`

Observed failure mode:
- failures are concentrated in MVBA, not recover
- representative errors:
  - `dumbo-mvba agreement failed: mvba node 0 failed: pd[0] failed: context deadline exceeded`
  - `dumbo-mvba agreement failed: mvba node 1 failed: quitpd failed: context deadline exceeded`
- this suggests the current tightened local MVBA timeout profile is too aggressive for `n=127` when internal delay injection is enabled, even at `50-100ms`.

Takeaway:
- Lowering simulated delay from `100-200ms` to `50-100ms` does not automatically make the run easier under the current MVBA parameterization.
- For internal-delay experiments, MVBA timeout defaults likely need a separate tuning track from the zero-delay local proc-sim settings.

Follow-up trial:
- out dir `/tmp/practical-internal50-100-n127-r2`
- relaxed MVBA env:
  - `PRACTICAL_MVBA_WAIT_SPBC_MS=60000`
  - `PRACTICAL_MVBA_ROUTE_TIMEOUT_MS=12000`
  - `PRACTICAL_MVBA_PEER_WAIT_MS=12000`
- benchmark timeout raised to `420s`

Result:
- protocol success still `0/127`
- representative failures remain MVBA-specific:
  - `quitpd failed: context deadline exceeded`
  - `pd[0] failed: context deadline exceeded`

Updated takeaway:
- At `n=127` with internal `50-100ms` delay, the current MVBA implementation/path is not rescued by simply restoring conservative timeout values.
- The remaining issue is likely protocol-path behavior under internal injected delay, not just timeout calibration.

## 2026-06-29 MVBA Internal-Delay Trace Diagnosis

Instrumentation:
- Added `DUMBO_TRACE_NODE_IDS` filter support inside local `../dumbomvba-go` trace points:
  - `DUMBO_MVBA_TIMING`
  - `DUMBO_MVBA_EQ_TRACE`
  - `DUMBO_PD_TRACE`
  - `DUMBO_QUITPD_TRACE`
  - `DUMBO_ACS_TRACE`

Diagnostic run:
- out dir `/tmp/practical-internal50-100-trace0-n127`
- traced only node `0`
- env:
  - `DUMBO_TRACE_NODE_IDS=0`
  - `DUMBO_MVBA_TIMING=1`
  - `DUMBO_MVBA_EQ_TRACE=1`
  - `DUMBO_PD_TRACE=1`
  - `DUMBO_QUITPD_TRACE=1`
  - `DUMBO_ACS_TRACE=1`
  - `PRACTICAL_MVBA_WAIT_SPBC_MS=60000`
  - `PRACTICAL_MVBA_ROUTE_TIMEOUT_MS=12000`
  - `PRACTICAL_MVBA_PEER_WAIT_MS=12000`
- latency mode:
  - `internal`
  - `global50_100`

Key observation from node `0`:
- Local PD for leader `0` completes successfully:
  - `locked_progress count=85/85`
  - `done_broadcast count=85/85`
  - `eq_pd_all ms=21279.79`
- The failure happens after PD, inside `quitPD`:
  - `ctx_done provens=40/85 ready=0/43 finish=0 err=context deadline exceeded`
- So node `0` sees only `40` valid `pdDone` proofs from the network, far below the `n-f = 85` threshold needed to start `ready`.

Interpretation:
- Under internal `50-100ms` delay, the bottleneck is specifically the `quitPD` admission step, not:
  - local dealer PD completion
  - recast/recover
  - APDB
- The equivalent-path MVBA currently fails because too few leader-side PD instances make it through to the globally visible `done` stage in time.

Most likely next direction:
- Focus on `quitPD` / PD dissemination in `../dumbomvba-go/core/mvba_equivalent.go` and `pd_equivalent.go`.
- In particular, investigate whether:
  - every leader reliably reaches `done_broadcast`
  - `TagMVBAPDFinish` routing/backlog is dropping effective progress under internal delay
  - `runEquivalent` should overlap or relax the all-PD wait before entering `quitPD`

## 2026-06-29 PD Lock Rebroadcast Fix

Applied change:
- `../dumbomvba-go/core/pd_equivalent.go`
  - leaders now periodically rebroadcast `pdLockMsg` after the first `lock_broadcast`, until `done` is reached
  - default interval: `2s`
  - override: `DUMBO_PD_LOCK_REBROADCAST_MS`

Why this was targeted:
- Trace showed local leader `0` could finish its own PD, but `quitPD` stalled at:
  - `provens=40/85 ready=0/43 finish=0`
- This strongly suggested many remote leaders were not reliably driving their PD instances from `lock` to `done` under internal delay.

Diagnostic validation:
- out dir `/tmp/practical-internal50-100-trace0-lockrebroadcast-n127`
- still traced only node `0`
- internal delay:
  - `global50_100`
- MVBA env:
  - `PRACTICAL_MVBA_WAIT_SPBC_MS=60000`
  - `PRACTICAL_MVBA_ROUTE_TIMEOUT_MS=12000`
  - `PRACTICAL_MVBA_PEER_WAIT_MS=12000`

Trace outcome for node `0`:
- `lock_rebroadcast locked=63/85` is observed
- `quitPD` now progresses fully:
  - `provens=85/85`
  - `ready_broadcast provens=85/85`
  - `ready_progress ready=43/43`
  - `finish_broadcast ready=43/43`
  - `finish_complete ...`
- MVBA then completes:
  - `eq_quitpd ms=25583.22`
  - `eq_rc_prepare ms=10803.25`
  - `eq_aba ms=408.50`
  - `eq_rc_sub ms=14294.28`
  - `eq_total ms=74044.37`

Full-run result:
- `127/127` success under internal `50-100ms`
- all 127 node logs report `success_runs=1`
- aggregate means across all nodes:
  - mean latency `235024.36 ms`
  - mean MVBA agree `74974.68 ms`
  - mean recover `10024.42 ms`

Interpretation:
- The internal-delay failure was primarily caused by insufficient reliability of the leader-side `PD lock -> done` progression.
- Periodic `lock` rebroadcast is enough to restore liveness at `n=127` under internal `50-100ms`.
- Recover remains cheap in this scenario; the dominant cost is again MVBA / pre-recover online work.

Current read:
- Latest local fix materially improved `n=96` and nearly recovered the previous `70/96` baseline.
- Residual failures are still concentrated in tail `recover` convergence rather than certificate or shard-verification rejection.
- The failure signature `holders=96, recipients=0` suggests remaining bottlenecks are still in recipient-side fetch/response scheduling or end-to-end deadline pressure, not holder admission.

## 2026-06-29 Paper Alignment Repair

Alignment conclusions:
- The paper's `n=127 -> k=26` parameter pair matches the hypergeometric derivation only when `n` is interpreted as the committee size, not the total old+new participant count.
- Therefore, the benchmark flag `-n` should remain the committee size, while logs should explicitly print total logical participants to avoid ambiguity.

Code changes:
- `cmd/bench_latency/main.go`
  - kept `-n` as committee size
  - added `committee_size` and `total_logical_participants` to `E2E_BENCH_RESULT`
  - prewarms recipient Paillier/VE keys before online timing begins
- `core/adkr.go`
  - added shared/cache-backed recipient Paillier key loading so key generation is removed from the online hot path
  - changed APDB-derived MVBA proposals to `stableFirst(valid, 2f+1)` so Agree operates on a `2f+1` finished-PD/lock set instead of the entire valid dealer set

Validation:
- `go test ./core -run 'Test(APDBCertificateThreshold|VerifyAPDBCertificateRejectsUndersizedQuorum|PracticalRunIDUsesEnvOverride|PracticalRunIDStableWithoutEnv|CacheLockStale|BoundedQueueSize|RecoverInitialFetchFanout|RecoverRetryStep|APDBProposalUsesFinishedPDQuorumOnly)$' -count=1`
- `go build -o /home/RLADKR/practical-adkr/bin/bench_latency ./cmd/bench_latency`

Smoke check:
- `n=64`, out dir `/tmp/practical-papercheck-n64`
  - result: `64/64` success
  - sample metrics:
    - `committee_size=64`
    - `total_logical_participants=128`
    - `setup 1611.66 ms`
    - `mean_decided_set=43`

Updated `n=127` benchmark:
- out dir `/tmp/practical-paperfix-n127`
- result: `80/127` success, `47/127` fail
- failure mode:
  - `47` explicit `recast recovery timeout`
  - `0` outer `context deadline exceeded`
- average successful metrics:
  - latency `170933.63 ms`
  - setup `7036.63 ms`
  - mvba `63618.42 ms`
  - recover `87046.72 ms`
  - mean decided set `85.0`
  - selected count `26.0`
  - verified count `26.0`

Comparison against the previous `n=127` run `/tmp/practical-opt7-n127`:
- success rate improved from `73/127` to `80/127`
- average latency improved from `202338.30 ms` to `170933.63 ms`
- setup improved from about `29978.57 ms` to `7036.63 ms`
- mvba improved from about `77817.11 ms` to `63618.42 ms`
- mean decided set dropped from `127` to `85`, which now matches the intended `2f+1` committee-size semantics for `f=42`

Current read after paper-alignment fixes:
- The benchmark semantics are now clearer and consistent with the paper's `k` table.
- Removing recipient VE key generation from the online path materially reduced setup overhead.
- Restricting Agree input to a `2f+1` finished set brought MVBA behavior closer to the paper and improved both latency and success rate.
- The dominant remaining gap with the paper is now concentrated in `recover`, not in setup semantics or MVBA input inflation.

## 2026-06-29 Setup / Recover Follow-up

Statistics interpretation:
- `setup` should not be treated as the primary paper-comparison latency anymore.
- The more meaningful comparison fields for the paper path are:
  - `mean_online_protocol_ms`
  - `mean_total_phase_ms`
- `mean_setup_ms` is still exported as a diagnostic field, but it now mostly reflects local prewarm/cache/bootstrap overhead rather than the intended online protocol body.

Recover debugging result:
- On `/tmp/practical-paperfix-n127`, failures are now highly concentrated:
  - `47/47` failing nodes end with `recast recovery timeout`
  - timeout details overwhelmingly show `holders=127, recipients=0`
- This means holder-side admission and store visibility are already complete; the bottleneck is the final recipient-side recovery path, not PD/APDB admission.

Attempted recast optimization:
- I tried a more aggressive push-style recover variant where holders proactively pushed shard batches to recipients once holder admission was sufficient.
- Benchmark: `/tmp/practical-pushfix-n127`
  - result regressed to `67/127` success from `80/127`
  - average latency regressed to `186167.73 ms`
  - `recast recovery timeout` increased to `60`
- Conclusion:
  - naive proactive shard pushing is heavier than the current request-driven path in this local proc-sim implementation
  - this did not reproduce the paper's lighter RC semantics and should not be kept

Current best local baseline after rollback:
- `/tmp/practical-paperfix-n127`
  - `80/127` success
  - `mean_latency_ms=170933.63`
  - `mean_setup_ms=7036.63`
  - `mean_mvba_agree_ms=63618.42`
  - `mean_recover_ms=87046.72`

Updated read:
- The paper-alignment fixes for benchmark semantics, Paillier prewarm, and MVBA input were all net-positive and should remain.
- The remaining performance gap is now sharply localized to the current recover/RC realization.
- The next useful step should be a more faithful redesign of RC semantics, not additional brute-force fanout or shard pushing.

## 2026-06-29 Direct-RC Recover Redesign

Recover redesign:
- I changed the recast path so that a small designated subset of old-committee holders directly includes the full transcript in `store_batch` for each selected dealer, while the remaining holders still send only the lightweight store/cert/attestation metadata.
- The designated subset is the first `erasureK = n-2f` holders, which is enough to cover recovery for every selected dealer without waiting for the tail fetch path to assemble shards.
- Recipients now fast-path transcript recovery directly from the authenticated `store_batch` payload when the transcript is present and verifies against the dealer root.

Why this helped:
- Previous failing runs already had `holders=n` but `recipients=0`, meaning admission/store visibility was complete and only the final per-recipient transcript reconstruction was stuck.
- This redesign removes most of the request/response orchestration from the critical path and makes recast closer to the paper's intuition that old-committee parties help receivers directly recover the transcript.

Validation:
- `go test ./core -run 'Test(APDBCertificateThreshold|VerifyAPDBCertificateRejectsUndersizedQuorum|PracticalRunIDUsesEnvOverride|PracticalRunIDStableWithoutEnv|CacheLockStale|BoundedQueueSize|RecoverInitialFetchFanout|RecoverRetryStep|APDBProposalUsesFinishedPDQuorumOnly)$' -count=1`
- `go build -o /home/RLADKR/practical-adkr/bin/bench_latency ./cmd/bench_latency`

New `n=127` benchmark:
- out dir `/tmp/practical-directrc-n127`
- result: `127/127` success
- `0` recast recovery timeout
- average successful metrics:
  - latency `168832.49 ms`
  - setup `7081.17 ms`
  - mvba `71446.85 ms`
  - recover `77045.36 ms`
  - mean decided set `85.0`
  - fetch req `568.50`
  - fetch resp `254.54`
  - recipient seen `26.23`

Sample single-node successful line:
- `mean_latency_ms=175215.65`
- `mean_online_protocol_ms=168385.64`
- `mean_mvba_agree_ms=65525.93`
- `mean_recover_ms=88677.59`
- `mean_recover_fetch_req_sent=45`
- `mean_recover_fetch_resp_recv=4`
- `mean_recover_recipient_seen=26`

Comparison against the previous best `/tmp/practical-paperfix-n127`:
- success improved from `80/127` to `127/127`
- recast timeout dropped from `47` to `0`
- average latency improved from `170933.63 ms` to `168832.49 ms`
- recover fetch traffic dropped substantially:
  - req from about `1449.49` to `568.50`
  - resp from about `1183.29` to `254.54`

Current read:
- This is the first local `n=127` run that fully eliminates recast timeout tails.
- The dominant gap with the paper is no longer correctness/liveness of recover, but raw phase cost, especially MVBA and the still-heavy recover body.

## 2026-06-29 Internal 50-100ms Monitored `n=127`

Monitored run:
- out dir `/tmp/practical-internal50-100-monitor-n127`
- latency mode:
  - `internal`
  - `global50_100`
- result:
  - `127/127` success
  - `0` timeout

Host baseline before run:
- host: `9gpu-com`
- CPU:
  - `160` vCPU
  - `AMD EPYC 9754`
- memory:
  - `196 GiB` RAM
  - idle available memory about `192 GiB`
- swap:
  - `37 GiB`, unused
- file descriptor limit:
  - `ulimit -n = 1048576`

Observed runtime state during run:
- load average snapshots reached about:
  - `71.77`
  - `79.51`
  - `82.71`
  - `89.20`
- CPU user utilization snapshots reached about:
  - `76.8%`
  - `79.2%`
- memory used stayed around:
  - `18.5 GiB` to `18.9 GiB`
- free memory stayed around:
  - `177 GiB` to `178 GiB`
- swap remained:
  - `0`

Aggregate benchmark means across all `127` node logs:
- latency `235139.43 ms`
- setup `136734.57 ms`
- online protocol `98404.44 ms`
- APDB dispersal `13203.44 ms`
- MVBA `76108.27 ms`
- recover `8986.84 ms`

Read:
- This run is not memory-bound.
- It is also not close to exhausting swap or file descriptors.
- The host is busy, but the dominant online cost is still protocol time, especially `MVBA`, not `recover`.

## 2026-06-29 Why `50-100ms` Did Not Drop Online Latency Much

Important comparison note:
- The currently available `internal/global100_200` `n=127` samples on disk are the older pre-fix runs:
  - `deployment/docker-artifacts/retest20260629-practical-n127-global100_200-internal-recoververify-r1`
  - `deployment/docker-artifacts/retest20260629-practical-n127-global100_200-internal-recoververify-r2-mvbafix`
- Those runs failed in `MVBA/PD` and are not a clean apples-to-apples success comparison against the new `global50_100` run.

Why the improvement is still limited:
- `online protocol` is now dominated by:
  - `MVBA ~= 76.1s`
  - `APDB ~= 13.2s`
  - `recover ~= 9.0s`
- Only part of that cost scales linearly with per-link delay.
- A large remaining fraction is from:
  - many serialized rounds and quorum waits inside `PD/MVBA`
  - goroutine scheduling across `127` local processes
  - local TCP/socket backlog and kernel wakeup overhead
  - repeated cryptographic verification and message handling
  - tail waiting for the slowest quorum members rather than the mean link delay

More concrete interpretation:
- Halving the injected one-way delay from roughly `100-200ms` to `50-100ms` does not halve the dominant `MVBA` wall-clock, because `MVBA` is currently governed more by round barriers and tail progress than by raw per-hop transit time.
- After the `PD lock` rebroadcast fix, the protocol became live, but it still spends most of the online path waiting for enough parties to finish each logical step.
- In this local proc-sim setting, host scheduling noise and connection fanout flatten the benefit of reducing the synthetic delay range.

Practical conclusion:
- The small drop is not strong evidence that the delay injector is wrong.
- It is stronger evidence that the present bottleneck at `n=127` is `MVBA/PD` round structure and local runtime overhead, so reducing injected network latency alone yields only a second-order improvement.
- The next fair measurement should be a fresh successful `internal/global100_200` rerun on the current code path, then compare it directly against `/tmp/practical-internal50-100-monitor-n127`.

## 2026-06-29 MVBA / PD Hotspot Breakdown at `n=127`

Goal:
- Break the current `mean_mvba_agree_ms ~= 76s` into subphases and identify the true hot sections.

Data sources:
- single-node detailed trace:
  - `/tmp/practical-internal50-100-trace0-lockrebroadcast-n127`
- all-node timing-only rerun:
  - `/tmp/practical-internal50-100-mvba-timing-n127`
- common settings:
  - `n=127`
  - `f=42`
  - `internal/global50_100`
  - `PRACTICAL_MVBA_WAIT_SPBC_MS=60000`
  - `PRACTICAL_MVBA_ROUTE_TIMEOUT_MS=12000`
  - `PRACTICAL_MVBA_PEER_WAIT_MS=12000`

Aggregate benchmark result from the timing-only rerun:
- `127/127` success
- `mean_mvba_agree_ms = 75761.29`

Mean equivalent-path phase timings across all `127` nodes:
- `eq_total = 74038.87 ms`
- `eq_pd_all = 21599.62 ms`
- `eq_quitpd = 21319.05 ms`
- `eq_perm_coin = 1087.97 ms`
- `eq_rc_prepare = 13222.39 ms`
- `eq_aba = 2171.79 ms`
- `eq_rc_sub = 14214.66 ms`

Share of `eq_total`:
- `eq_pd_all`: `29.17%`
- `eq_quitpd`: `28.79%`
- `eq_rc_prepare`: `17.86%`
- `eq_rc_sub`: `19.20%`
- `eq_perm_coin`: `1.47%`
- `eq_aba`: `2.93%`

Interpretation:
- The biggest cost is not the coin or ABA logic.
- The dominant body is the PD/RC envelope:
  - `PD all` plus `quitPD` together already take about `50.9%`
  - adding `RC prepare` and `RC sub` brings the structured non-ABA body to about `95%`
- So the current `~76s` is overwhelmingly a:
  - PD completion problem
  - quitPD quorum progression problem
  - RC admission / transcript-subprotocol problem
- It is not primarily a shared-coin or ABA problem.

Tail behavior across nodes:
- `eq_total`
  - mean `74038.87 ms`
  - p50 `74431.04 ms`
  - p95 `77753.60 ms`
  - max `79031.62 ms`
- `eq_pd_all`
  - p95 `23734.66 ms`
  - max `25696.44 ms`
- `eq_quitpd`
  - p95 `25701.49 ms`
  - max `26040.80 ms`
- `eq_rc_prepare`
  - p95 `16183.02 ms`
  - max `16685.58 ms`
- `eq_rc_sub`
  - p95 `16850.46 ms`
  - max `17427.75 ms`

Important tail read:
- The heaviest and most stable long-tail block is now `quitPD`.
- `eq_quitpd` is both large on average and tightly clustered near `25-26s` in the slowest nodes.
- This means the previous liveness fix solved the outright stall, but `quitPD` is still one of the two largest steady-state costs.

Slowest total MVBA samples:
- node `87`
  - `eq_total 79031.62`
  - `pd_all 21955.26`
  - `quitpd 25495.17`
  - `rc_prepare 15749.91`
  - `rc_sub 14688.28`
- node `32`
  - `eq_total 78891.02`
  - `pd_all 20519.12`
  - `quitpd 25683.03`
  - `rc_prepare 16685.58`
  - `rc_sub 14831.97`
- node `72`
  - `eq_total 78705.98`
  - `pd_all 24387.03`
  - `quitpd 25563.49`
  - `rc_prepare 12907.81`
  - `rc_sub 14682.84`

Representative single-node detailed trace:
- node `0` in `/tmp/practical-internal50-100-trace0-lockrebroadcast-n127`
  - `eq_pd_all = 22202.83 ms`
  - `eq_quitpd = 25583.22 ms`
  - `eq_perm_coin = 330.40 ms`
  - `eq_rc_prepare = 10803.25 ms`
  - `eq_aba = 408.50 ms`
  - `eq_rc_sub = 14294.28 ms`
  - `eq_total = 74044.37 ms`
- This is very close to the all-node mean and is therefore representative rather than an outlier.

Why `mean_mvba_agree_ms` is still slightly above `eq_total`:
- `mean_mvba_agree_ms = 75761.29`
- `mean_eq_total = 74038.87`
- delta is about `1722.42 ms`
- This residual gap is consistent with wrapper overhead outside the equivalent core timing span:
  - ACS-side diffuse / packaging
  - adapter glue / serialization
  - measurement boundary mismatch between exported benchmark timing and inner `eq_total`

Current conclusion:
- The next optimization target should be ordered as:
  1. reduce `quitPD` round cost and quorum-tail waiting
  2. reduce `PD all` completion time
  3. compress `RC prepare` and `RC sub`
  4. deprioritize coin / ABA for now
- If the goal is to approach the paper's `n=127` latency, the highest-yield protocol work is in the PD-to-quitPD path, not in recover and not in the coin/ABA components.

## 2026-06-29 `quitPD` focused diagnosis and optimization

Status:
- current local best-known safe version is the `opt4` line described in this section
- unless a later note explicitly overrides it, all subsequent local proc-sim comparisons for `practical-adkr` should treat `opt4` as the active baseline

Goal:
- Refine the `quitPD` diagnosis, try targeted optimizations, and validate them under:
  - `n=127`
  - `f=42`
  - `internal/global50_100`
  - `PRACTICAL_MVBA_WAIT_SPBC_MS=60000`
  - `PRACTICAL_MVBA_ROUTE_TIMEOUT_MS=12000`
  - `PRACTICAL_MVBA_PEER_WAIT_MS=12000`

### Diagnosis summary

Code paths:
- `quitPD`: `/home/RLADKR/dumbomvba-go/core/mvba_equivalent.go`
- `PD`: `/home/RLADKR/dumbomvba-go/core/pd_equivalent.go`

Observed structure before optimization:
- `runEquivalent` waited for all `PD` goroutines to finish before starting effective `quitPD` progress.
- `quitPD` then verified up to `n-f = 85` `pdDoneMsg` proofs, each proof itself being a high-threshold `PD_LOCKED` share-set.
- This made `quitPD` both a serialization barrier and a heavy CPU verification stage.

Key hotspot evidence:
- top-line baseline:
  - `127/127` success
  - `mean_online_protocol_ms = 98578.77`
  - `mean_mvba_agree_ms = 75761.29`
- inner timing baseline:
  - `eq_total = 74038.87 ms`
  - `eq_pd_all = 21599.62 ms`
  - `eq_quitpd = 21319.05 ms`
- overlap analysis on slow nodes showed `eq_quitpd` had the strongest concentration among the worst total MVBA tails.

Interpretation:
- `quitPD` was not just correlated noise.
- It was a real tail driver, and a good first target.

### Optimization attempt 1: overlap `quitPD` with PD completion

Applied changes:
- start `runQuitPD(...)` immediately instead of after the full `PD all` barrier
- as each PD instance reaches `out.done`, immediately broadcast its `pdDoneMsg` into `TagMVBAPDFinish`
- remove the old post-`wg.Wait()` bulk rebroadcast loop
- reuse the precomputed `PD_QUIT_READY` digest
- drop redundant late `pdDone` / `quitReady` processing once thresholds are already satisfied

Result:
- out dir: `/tmp/practical-internal50-100-quitpd-opt1-n127`
- `127/127` success
- top-line improvement versus baseline:
  - `mean_online_protocol_ms`: `98578.77 -> 91284.99` ms
  - `mean_mvba_agree_ms`: `75761.29 -> 68225.84` ms
  - `mean_latency_ms`: `234787.68 -> 227586.14` ms

Important note:
- after this refactor, `eq_quitpd` can no longer be compared literally to baseline timing because it now overlaps with `PD all`
- after this point, the trustworthy comparison metrics are:
  - `mean_mvba_agree_ms`
  - `mean_online_protocol_ms`
  - `eq_total`

Conclusion:
- keep this optimization
- it is safe and gives a clear real-world latency win

### Optimization attempt 2: local finish threshold returns immediately

Attempted change:
- after collecting `f+1` `quitReady` shares locally, broadcast `quitFinishMsg` and return immediately without waiting for any remote `quitFinish`

Observed result:
- this variant caused systemic failure
- logs showed many nodes timing out later with:
  - `waiting for recast ready barrier: context deadline exceeded`
  - some nodes also failed inside MVBA with `pd[...] failed: context deadline exceeded`

Root cause:
- returning immediately let `runQuitPD` stop consuming `TagMVBAPDFinish`
- the router / channel path still needed to absorb late `pdDone`, `quitReady`, and `quitFinish` traffic
- the premature local exit changed system behavior from “latency optimization” into “message-drain violation”

Conclusion:
- this optimization is unsafe
- it was reverted

### Optimization attempt 3: compact proof shortcut

Attempted idea:
- replace some share-list proofs with recovered threshold signatures to cut both message size and verification cost

Observed result:
- performance looked dramatically better in one run, but the approach was rejected

Why it was rejected:
- `practical-adkr` currently wires MVBA with `NewBLS12381Signer(..., threshold=f+1)`
- `PD_STORED` / `PD_LOCKED` in the equivalent path require `n-f` semantics
- so a naive recovered-signature shortcut would accidentally downgrade an `n-f` proof into an `f+1` proof

Conclusion:
- this was a protocol-invalid optimization
- it must not be used as evidence or kept in production logic

### Optimization attempt 4: safe `quitPD` parallel verification

Applied safe changes:
- keep optimization attempt 1
- keep the compact-proof helper only behind a strict threshold guard:
  - recovered-signature fast path is allowed only if signer threshold `>=` required protocol threshold
  - for current `practical-adkr` MVBA wiring, `PD` / `quitPD` safely fall back to share-set verification
- add a bounded worker pool inside `runQuitPD`
  - `pdDoneMsg` proof checks are verified in parallel
  - the main loop only advances quorum counters after verified results return
  - once `n-f` proved `pdDone` messages are reached, verification intake is closed

Result:
- out dir: `/tmp/practical-internal50-100-quitpd-opt4-n127`
- `127/127` success
- top-line metrics:
  - `mean_online_protocol_ms = 37051.98`
  - `mean_mvba_agree_ms = 6267.88`
  - `mean_recover_ms = 17666.19`
  - `mean_latency_ms = 172888.35`
- inner timing:
  - `eq_total = 4774.81 ms`
  - `eq_pd_all = 2233.47 ms`
  - `eq_quitpd = 2732.02 ms`
  - `eq_rc_prepare = 119.00 ms`
  - `eq_aba = 427.77 ms`
  - `eq_rc_sub = 993.79 ms`

Comparison versus original baseline:
- `mean_online_protocol_ms`: `98578.77 -> 37051.98` ms
- `mean_mvba_agree_ms`: `75761.29 -> 6267.88` ms
- `mean_latency_ms`: `234787.68 -> 172888.35` ms

Interpretation:
- the big gain is real and safe only for `opt4`, not for the rejected compact-proof shortcut
- the current dominant online cost has shifted:
  - MVBA is no longer the main bottleneck
  - recovery has become relatively larger again
- `quitPD` is still visible, but no longer the catastrophic tail source it was in the baseline

### Open-source directions worth borrowing from

Useful implementation families to study for the next round:
- `erlang-hbbft`
  - classic HoneyBadgerBFT-style RBC / ACS decomposition
  - good reference for how broadcast termination is kept explicit without adding unnecessary post-threshold barriers
- `poanetwork/hbbft`
  - Rust implementation with modular RBC / ACS components
  - useful for queueing and subprotocol isolation ideas
- AlephBFT reliable broadcast design notes
  - useful conceptual reference for compact terminal proofs / multisignature-style confirmation rather than repeated large proof propagation

What is relevant from these references:
- avoid terminal phases that require extra waiting after the local threshold condition is already protocol-safe
- isolate broadcast progress from later-stage routing so late traffic does not poison unrelated phases
- prefer compact, verifiable terminal evidence when the signer model actually supports the required quorum threshold

### Current recommendation

Keep:
- optimization attempt 1
- optimization attempt 4

Do not keep:
- optimization attempt 2
- optimization attempt 3

Next priority after this fix set:
1. profile `recover` again, because it is now the larger remaining online component
2. if continuing on MVBA, target:
   - batch verification or lower-allocation verification in `quitPD`
   - routing separation for `TagMVBAPDFinish`
   - safer compact terminal proofs only if signer wiring is upgraded to match protocol thresholds

## 2026-06-29 Current Local Baseline Status

Current local best-known Practical ADKR version:

- active baseline: `opt4`
- benchmark environment: local single-machine `proc-sim`
- current comparison profile for stressed runs:
  - `n=127`
  - internal delay `50-100ms`

Working rule going forward:

- unless a later entry explicitly supersedes this note, all local Practical ADKR comparisons should treat `opt4` as the pinned best-known baseline
- this means subsequent work may compare new ARL/other variants against:
  - `mean_online_protocol_ms`
  - `mean_mvba_agree_ms`
  - `mean_recover_ms`
  from `opt4`, rather than against older pre-fix Practical samples

Reason for pinning:

- `opt4` is the latest version in this local line that both:
  - preserves protocol-safe `quitPD` verification semantics
  - and restores `127/127` success under internal `50-100ms`
