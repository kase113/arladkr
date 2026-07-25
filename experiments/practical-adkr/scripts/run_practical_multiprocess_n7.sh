#!/usr/bin/env bash
set -euo pipefail

# Run one strict-TCP PracticalADKR process per old-committee node.
# The benchmark itself uses deterministic setup keys, while the artifact
# directory is shared so DXT/APDB/Paillier barriers can exchange outputs.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${PRACTICAL_MP_RUN_DIR:-$(mktemp -d /tmp/practical-adkr-mp-n7.XXXXXX)}"
CACHE_DIR="${RUN_DIR}/artifacts"
LOG_DIR="${RUN_DIR}/logs"
BIN="${ROOT_DIR}/bin/bench_latency"
mkdir -p "${CACHE_DIR}" "${LOG_DIR}"

cleanup() {
  status=$?
  if [[ "${KEEP_PRACTICAL_MP_RUN:-0}" != "1" && "${RUN_DIR}" == /tmp/practical-adkr-mp-n7.* ]]; then
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
for id in $(seq 0 6); do
  [[ -z "${mvba_addrs}" ]] || mvba_addrs+=","
  mvba_addrs+="${id}=127.0.0.1:$((23000 + id))"
  [[ -z "${proto_addrs}" ]] || proto_addrs+=","
  proto_addrs+="${id}=127.0.0.1:$((24000 + id))"
done
for id in $(seq 0 6); do
  new_id=$((7 + id))
  proto_addrs+=",${new_id}=127.0.0.1:$((24000 + new_id))"
done

pids=()
for id in $(seq 0 6); do
  log="${LOG_DIR}/node-${id}.log"
  PRACTICAL_ARTIFACT_CACHE_DIR="${CACHE_DIR}" \
  RLADKR_RANDOM_SEED="${RLADKR_RANDOM_SEED:-practical-adkr-multiprocess-n7}" \
  PRACTICAL_STRICT_NETWORK=1 \
  PRACTICAL_DELAY_ENABLE="${PRACTICAL_DELAY_ENABLE:-0}" \
  "${BIN}" \
    -n 7 -f 2 -kappa 3 -runs "${PRACTICAL_MP_RUNS:-1}" \
    -timeout "${PRACTICAL_MP_TIMEOUT:-120s}" \
    -paillier-bits "${PRACTICAL_MP_PAILLIER_BITS:-2048}" \
    -mvba-network tcp \
    -mvba-addrs "${mvba_addrs}" -mvba-local-ids "${id}" \
    -proto-addrs "${proto_addrs}" -proto-local-ids "${id},$((7 + id))" \
    -strict-network=true -comm-metrics=true \
    >"${log}" 2>&1 &
  pids+=("$!")
done

status=0
for i in $(seq 0 6); do
  if ! wait "${pids[$i]}"; then
    status=1
  fi
done

printf 'PRACTICAL_MP_RUN_DIR=%s\n' "${RUN_DIR}"
printf 'PRACTICAL_MP_LOG_DIR=%s\n' "${LOG_DIR}"
for id in $(seq 0 6); do
  log="${LOG_DIR}/node-${id}.log"
  result=$(rg '^E2E_BENCH_RESULT ' "${log}" | tail -n 1 || true)
  if [[ -n "${result}" ]]; then
    printf 'NODE_%s %s\n' "${id}" "${result}"
  else
    printf 'NODE_%s NO_RESULT\n' "${id}"
    tail -n 8 "${log}" >&2 || true
  fi
done
exit "${status}"
