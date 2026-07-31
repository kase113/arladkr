#!/usr/bin/env bash
set -euo pipefail

# Run one strict-TCP PracticalADKR process per old-committee node.
# The benchmark itself uses deterministic setup keys. The artifact directory
# remains shared for the DXT/Paillier paths. Strict APDB
# uses TCP; its per-holder RS shard files are local durable stores, not barriers.

# The historical filename is retained for compatibility.  Override these
# values for a matched committee experiment, e.g. n=16/f=5/kappa=6.
N="${PRACTICAL_MP_N:-7}"
F="${PRACTICAL_MP_F:-2}"
KAPPA="${PRACTICAL_MP_KAPPA:-3}"
if (( N <= 0 || F < 0 || KAPPA <= 0 || KAPPA > 2 * F + 1 || N < 3 * F + 1 )); then
  printf 'invalid committee parameters: n=%s f=%s kappa=%s\n' "${N}" "${F}" "${KAPPA}" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run_dir_template="/tmp/practical-adkr-mp-n${N}.XXXXXX"
RUN_DIR="${PRACTICAL_MP_RUN_DIR:-$(mktemp -d "${run_dir_template}")}"
CACHE_DIR="${RUN_DIR}/artifacts"
LOG_DIR="${RUN_DIR}/logs"
BIN="${ROOT_DIR}/bin/bench_latency"
SUMMARY_AWK="${ROOT_DIR}/../../scripts/summarize_cluster_bench.awk"
RESULTS_FILE="${RUN_DIR}/cluster-results.log"
if [[ -d "${RUN_DIR}" && -n "$(find "${RUN_DIR}" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
  printf 'run directory must be empty to avoid stale benchmark artifacts: %s\n' "${RUN_DIR}" >&2
  exit 2
fi
mkdir -p "${CACHE_DIR}" "${LOG_DIR}"
mkdir -p "${RUN_DIR}/epoch-barrier"
touch "${RESULTS_FILE}"

cleanup() {
  status=$?
  if [[ "${KEEP_PRACTICAL_MP_RUN:-0}" != "1" && "${RUN_DIR}" == "/tmp/practical-adkr-mp-n${N}."* ]]; then
    rm -rf -- "${RUN_DIR}"
  else
    printf 'PRACTICAL_MP_RUN_DIR=%s\n' "${RUN_DIR}" >&2
  fi
  exit "${status}"
}
trap cleanup EXIT INT TERM

if [[ ! -x "${BIN}" || "${REBUILD_PRACTICAL_MP:-1}" == "1" ]]; then
  (cd "${ROOT_DIR}" && go build -o "${BIN}" ./cmd/bench_latency)
fi

mvba_addrs=""
proto_addrs=""
coin_addrs=""
for id in $(seq 0 $((N - 1))); do
  [[ -z "${mvba_addrs}" ]] || mvba_addrs+=","
  mvba_addrs+="${id}=127.0.0.1:$((23000 + id))"
  [[ -z "${proto_addrs}" ]] || proto_addrs+=","
	proto_addrs+="${id}=127.0.0.1:$((24000 + id))"
	[[ -z "${coin_addrs}" ]] || coin_addrs+=","
	coin_addrs+="${id}=127.0.0.1:$((18000 + id))"
done
for id in $(seq 0 $((N - 1))); do
  new_id=$((N + id))
  proto_addrs+=",${new_id}=127.0.0.1:$((24000 + new_id))"
done

pids=()
for id in $(seq 0 $((N - 1))); do
  log="${LOG_DIR}/node-${id}.log"
  PRACTICAL_ARTIFACT_CACHE_DIR="${CACHE_DIR}" \
  PRACTICAL_LOCAL_STATE_DIR="${RUN_DIR}/local/node-${id}" \
	PRACTICAL_EPOCH_BARRIER_DIR="${RUN_DIR}/epoch-barrier" \
  RLADKR_RANDOM_SEED="${RLADKR_RANDOM_SEED:-practical-adkr-multiprocess-n${N}}" \
  PRACTICAL_STRICT_NETWORK=1 \
  PRACTICAL_DELAY_ENABLE="${PRACTICAL_DELAY_ENABLE:-0}" \
  "${BIN}" \
    -n "${N}" -f "${F}" -kappa "${KAPPA}" -runs "${PRACTICAL_MP_RUNS:-1}" \
    -timeout "${PRACTICAL_MP_TIMEOUT:-120s}" \
    -paillier-bits "${PRACTICAL_MP_PAILLIER_BITS:-2048}" \
    -mvba-network tcp \
    -mvba-addrs "${mvba_addrs}" -mvba-local-ids "${id}" \
	-proto-addrs "${proto_addrs}" -proto-local-ids "${id},$((N + id))" \
	-coin-addrs "${coin_addrs}" \
    -strict-network=true -comm-metrics=true \
    >"${log}" 2>&1 &
  pids+=("$!")
done

status=0
for i in $(seq 0 $((N - 1))); do
  if ! wait "${pids[$i]}"; then
    status=1
  fi
done

printf 'PRACTICAL_MP_RUN_DIR=%s\n' "${RUN_DIR}"
printf 'PRACTICAL_MP_LOG_DIR=%s\n' "${LOG_DIR}"
for id in $(seq 0 $((N - 1))); do
  log="${LOG_DIR}/node-${id}.log"
  result=$(rg '^E2E_BENCH_RESULT ' "${log}" | tail -n 1 || true)
  if [[ -n "${result}" ]]; then
    printf '%s\n' "${result}" >>"${RESULTS_FILE}"
    printf 'NODE_%s %s\n' "${id}" "${result}"
  else
    printf 'NODE_%s NO_RESULT\n' "${id}"
    tail -n 8 "${log}" >&2 || true
  fi
done
awk -v protocol=PRACTICAL-ADKR -v expected_nodes="${N}" -v faults="${F}" \
  -f "${SUMMARY_AWK}" "${RESULTS_FILE}"
exit "${status}"
