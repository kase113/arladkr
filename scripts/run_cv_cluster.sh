#!/usr/bin/env bash
set -euo pipefail

n="${1:-4}"
f="${2:-1}"
root="${3:-$(pwd)/cv-run}"
base_port="${4:-41000}"
epoch_timeout="${RLADKR_CV_EPOCH_TIMEOUT:-90s}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary="$repo_dir/bin/rladkrbench"
public_dir="$root/keys/public"
generated_secret_dir="$root/keys/generated-private"

mkdir -p "$repo_dir/bin" "$public_dir" "$generated_secret_dir" "$root/ready"
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
  mvba_addrs+="$i=127.0.0.1:$((base_port+1000+i))"
done

start_at="$(( $(date +%s) + 3 ))"
pids=()
for ((i=0; i<n; i++)); do
  mkdir -p "$root/node-$i/store"
  node_secret_dir="$root/node-$i/private"
  (
    export RLADKR_LOCAL_NODE_IDS="$i"
    export RLADKR_LOCAL_RECEIVER_IDS="$((n+i))"
    export RLADKR_NODE_ADDRS="$node_addrs"
    export RLADKR_MVBA_NODE_ADDRS="$mvba_addrs"
    export RLADKR_ARTIFACT_CACHE_DIR="$root/node-$i/store"
    export RLADKR_LISTENER_READY_DIR="$root/ready"
    export RLADKR_LISTENER_READY_NODE_COUNT="$n"
    "$binary" -n "$n" -f "$f" -runs 1 -epochs 1 \
      -transport tcp-distributed -agreement-kernel commonsubset-tcp \
      -bind-host 127.0.0.1 -base-port "$base_port" -start-at "$start_at" -timeout "$epoch_timeout" \
      -apvss-provider cv-sapvss -arc-mode materialized -derive-mode scalar \
      -comm-metrics=true -strict-network=true \
      -cv-public-key-dir "$public_dir" -cv-local-secret-dir "$node_secret_dir" \
      -cv-local-receiver-ids "$((n+i))" 2>&1 | sed -u "s/^/[node-$i] /"
  ) &
  pids+=("$!")
done

status=0
for pid in "${pids[@]}"; do
  wait "$pid" || status=1
done
exit "$status"
