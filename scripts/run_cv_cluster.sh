#!/usr/bin/env bash
set -euo pipefail

n="${1:-4}"
f="${2:-1}"
if (( $# >= 3 )); then
  root="$3"
else
  root="$(mktemp -d "/tmp/arladkr-cv-n${n}.XXXXXX")"
fi
base_port="${4:-20000}"
epoch_timeout="${RLADKR_CV_EPOCH_TIMEOUT:-90s}"
wait_spbc_timeout="${RLADKR_CV_WAIT_SPBC_TIMEOUT:-}"
route_send_timeout="${RLADKR_CV_ROUTE_SEND_TIMEOUT:-}"
apvss_fallback_profile="${RLADKR_APVSS_FALLBACK_PROFILE:-exact-lane}"
allow_experimental_apvss="${RLADKR_ALLOW_EXPERIMENTAL_APVSS:-false}"
apvss_forced_fallback_count="${RLADKR_APVSS_FORCED_FALLBACK_COUNT:-0}"
apvss_wait_all_acks="${RLADKR_APVSS_WAIT_ALL_ACKS:-false}"
epochs="${RLADKR_CV_EPOCHS:-1}"
runs="${RLADKR_CV_RUNS:-1}"
# All n node processes share one host in this harness. Keep the default at one
# crypto worker per process so the benchmark does not oversubscribe the host;
# callers can still set RLADKR_CRYPTO_WORKERS explicitly.
crypto_workers="${RLADKR_CRYPTO_WORKERS:-1}"
# ACK decryption has its own bounded queue. Two workers per process use the
# 32 logical CPUs of the n=16 local harness without widening proof workers.
lane_workers="${RLADKR_LANE_WORKERS:-2}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="$repo_dir/bin/rladkrbench"
summary_awk="$repo_dir/scripts/summarize_cluster_bench.awk"
public_dir="$root/keys/public"
generated_secret_dir="$root/keys/generated-private"
log_dir="$root/logs"
results_file="$root/cluster-results.log"

if (( n <= 0 || f < 0 || n < 3 * f + 1 || epochs <= 0 || runs <= 0 )); then
  printf 'invalid committee parameters: n=%s f=%s\n' "$n" "$f" >&2
  exit 2
fi
component_last_port=$((base_port + 2 * n - 1))
mvba_base_port=$((base_port + 2 * n + 100))
mvba_last_port=$((mvba_base_port + n - 1))
if (( base_port <= 0 || mvba_last_port > 65535 )); then
  printf 'invalid cluster port ranges: component=%s-%s mvba=%s-%s\n' \
    "$base_port" "$component_last_port" "$mvba_base_port" "$mvba_last_port" >&2
  exit 2
fi
read -r ephemeral_low ephemeral_high < /proc/sys/net/ipv4/ip_local_port_range
if (( (base_port <= ephemeral_high && component_last_port >= ephemeral_low) ||
      (mvba_base_port <= ephemeral_high && mvba_last_port >= ephemeral_low) )); then
  printf 'cluster listener range overlaps ephemeral ports %s-%s: component=%s-%s mvba=%s-%s\n' \
    "$ephemeral_low" "$ephemeral_high" "$base_port" "$component_last_port" \
    "$mvba_base_port" "$mvba_last_port" >&2
  exit 2
fi
if [[ -d "$root" && -n "$(find "$root" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
  printf 'run directory must be empty to avoid stale keys, readiness markers, and shards: %s\n' "$root" >&2
  exit 2
fi

mkdir -p "$repo_dir/bin" "$public_dir" "$generated_secret_dir" "$root/ready" "$log_dir"
mkdir -p "$root/epoch-barrier"
touch "$results_file"
bench_timeout_args=()
if [[ -n "$wait_spbc_timeout" ]]; then
  bench_timeout_args+=( -wait-spbc-timeout "$wait_spbc_timeout" )
fi
if [[ -n "$route_send_timeout" ]]; then
  bench_timeout_args+=( -route-send-timeout "$route_send_timeout" )
fi
(cd "$repo_dir" && go build -buildvcs=false -o "$binary" ./cmd/rladkrbench)
"$binary" -n "$n" -f "$f" -runs 1 -cv-keygen-only \
  -cv-public-key-dir "$public_dir" -cv-local-secret-dir "$generated_secret_dir"

for ((i=0; i<n; i++)); do
  node_secret_dir="$root/node-$i/private"
  mkdir -p "$node_secret_dir"
  chmod 700 "$node_secret_dir"
  mv "$generated_secret_dir/old-node-$i-lock.scalar" "$node_secret_dir/"
  mv "$generated_secret_dir/receiver-$((n+i)).scalar" "$node_secret_dir/"
done
rmdir "$generated_secret_dir"

node_addrs=""
mvba_addrs=""
for ((i=0; i<n; i++)); do
  [[ -z "$node_addrs" ]] || node_addrs+=","
  [[ -z "$mvba_addrs" ]] || mvba_addrs+=","
  node_addrs+="$i=127.0.0.1:$((base_port+i))"
  mvba_addrs+="$i=127.0.0.1:$((mvba_base_port+i))"
done

printf 'ARLADKR_CV_PORTS component=%s-%s mvba=%s-%s ephemeral=%s-%s\n' \
  "$base_port" "$component_last_port" "$mvba_base_port" "$mvba_last_port" \
  "$ephemeral_low" "$ephemeral_high"

start_at="$(( $(date +%s) + 3 ))"
pids=()
for ((i=0; i<n; i++)); do
  mkdir -p "$root/node-$i/store"
  node_secret_dir="$root/node-$i/private"
  log="$log_dir/node-$i.log"
  (
    export RLADKR_LOCAL_NODE_IDS="$i"
    export RLADKR_LOCAL_RECEIVER_IDS="$((n+i))"
    export RLADKR_NODE_ADDRS="$node_addrs"
    export RLADKR_MVBA_NODE_ADDRS="$mvba_addrs"
    export RLADKR_ARTIFACT_CACHE_DIR="$root/node-$i/store"
		export RLADKR_STATE_CHAIN_DIR="$root/node-$i/state-chain"
    export RLADKR_LISTENER_READY_DIR="$root/ready"
    export RLADKR_LISTENER_READY_NODE_COUNT="$n"
		export RLADKR_EPOCH_BARRIER_DIR="$root/epoch-barrier"
    export RLADKR_CV_DEBUG="${RLADKR_CV_DEBUG:-1}"
    export RLADKR_CV_PERF_COUNTERS="${RLADKR_CV_PERF_COUNTERS:-1}"
    export RLADKR_CRYPTO_WORKERS="$crypto_workers"
    export RLADKR_LANE_WORKERS="$lane_workers"
    "$binary" -n "$n" -f "$f" -runs "$runs" -epochs "$epochs" \
      -transport tcp-distributed \
      -bind-host 127.0.0.1 -base-port "$base_port" -start-at "$start_at" -timeout "$epoch_timeout" \
			"${bench_timeout_args[@]}" \
      -apvss-fallback-profile "$apvss_fallback_profile" \
      -allow-experimental-apvss="$allow_experimental_apvss" \
      -apvss-forced-fallback-count "$apvss_forced_fallback_count" \
      -apvss-wait-all-acks="$apvss_wait_all_acks" \
      -comm-metrics=true -strict-network=true \
      -cv-public-key-dir "$public_dir" -cv-local-secret-dir "$node_secret_dir" \
      -cv-local-receiver-ids "$((n+i))"
  ) >"$log" 2>&1 &
  pids+=("$!")
done

status=0
for pid in "${pids[@]}"; do
  wait "$pid" || status=1
done

printf 'ARLADKR_CV_RUN_DIR=%s\n' "$root"
printf 'ARLADKR_CV_LOG_DIR=%s\n' "$log_dir"
for ((i=0; i<n; i++)); do
  log="$log_dir/node-$i.log"
  result="$(rg '^E2E_BENCH_RESULT ' "$log" | tail -n 1 || true)"
  if [[ -n "$result" ]]; then
    printf '%s\n' "$result" >>"$results_file"
    printf 'NODE_%s %s\n' "$i" "$result"
  else
    status=1
    printf 'NODE_%s NO_RESULT\n' "$i"
    tail -n 12 "$log" >&2 || true
  fi
done
awk -v protocol=ARLADKR-GO -v expected_nodes="$n" -v faults="$f" \
  -f "$summary_awk" "$results_file"
exit "$status"
