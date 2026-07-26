#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
summary_awk="$repo_dir/scripts/summarize_cluster_bench.awk"
fixture="$(mktemp /tmp/arladkr-cluster-summary.XXXXXX)"
trap 'rm -f "$fixture"' EXIT

printf '%s\n' \
  'E2E_BENCH_RESULT runs=1 success_runs=1 mean_latency_ms=100 mean_all_latency_ms=100 mean_setup_ms=10 mean_total_sent_bytes=1000 mean_total_recv_bytes=2000 consensus_hash=abc' \
  'E2E_BENCH_RESULT runs=1 success_runs=1 mean_latency_ms=120 mean_all_latency_ms=120 mean_setup_ms=20 mean_total_sent_bytes=1200 mean_total_recv_bytes=2200 consensus_hash=abc' \
  'E2E_BENCH_RESULT runs=1 success_runs=1 mean_latency_ms=110 mean_all_latency_ms=110 mean_setup_ms=30 mean_total_sent_bytes=1400 mean_total_recv_bytes=2400 consensus_hash=abc' \
  'E2E_BENCH_RESULT runs=1 success_runs=0 mean_latency_ms=0 mean_all_latency_ms=900 mean_setup_ms=0 mean_total_sent_bytes=0 mean_total_recv_bytes=0 consensus_hash=none' \
  >"$fixture"

result="$(awk -v protocol=TEST -v expected_nodes=4 -v faults=1 -f "$summary_awk" "$fixture")"
for token in \
  'result_nodes=4' \
  'successful_nodes=3' \
  'quorum=3' \
  'quorum_success=1' \
  'all_success=0' \
  'quorum_latency_ms=120.00' \
  'all_nodes_latency_ms=-1.00' \
  'mean_node_latency_ms=110.00' \
  'max_attempt_latency_ms=900.00' \
  'mean_setup_ms=20.00' \
  'mean_sent_bytes_per_node=1200' \
  'mean_recv_bytes_per_node=2200' \
  'consensus_hashes=1'; do
  if [[ "$result" != *"$token"* ]]; then
    printf 'missing %s in summary:\n%s\n' "$token" "$result" >&2
    exit 1
  fi
done

printf 'cluster summary regression test passed\n'
