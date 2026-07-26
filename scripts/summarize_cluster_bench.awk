function value(name, fallback,    i, pair) {
    for (i = 1; i <= NF; i++) {
        split($i, pair, "=")
        if (pair[1] == name) {
            return pair[2]
        }
    }
    return fallback
}

$1 == "E2E_BENCH_RESULT" {
    result_nodes++
    runs = value("runs", 0) + 0
    success_runs = value("success_runs", 0) + 0
    attempt = value("mean_all_latency_ms", 0) + 0
    if (attempt > max_attempt_latency) {
        max_attempt_latency = attempt
    }
    if (runs <= 0 || success_runs < runs) {
        next
    }

    successful_nodes++
    latency[successful_nodes] = value("mean_latency_ms", 0) + 0
    latency_sum += latency[successful_nodes]
    setup_sum += value("mean_setup_ms", 0) + 0
    sent_sum += value("mean_total_sent_bytes", 0) + 0
    recv_sum += value("mean_total_recv_bytes", 0) + 0
    hash = value("consensus_hash", "")
    if (hash != "" && hash != "none") {
        consensus[hash] = 1
    }
}

END {
    for (i = 1; i <= successful_nodes; i++) {
        for (j = i + 1; j <= successful_nodes; j++) {
            if (latency[j] < latency[i]) {
                tmp = latency[i]
                latency[i] = latency[j]
                latency[j] = tmp
            }
        }
    }

    quorum = expected_nodes - faults
    quorum_success = successful_nodes >= quorum ? 1 : 0
    all_success = successful_nodes >= expected_nodes ? 1 : 0
    quorum_latency = quorum_success ? latency[quorum] : -1
    all_latency = all_success ? latency[expected_nodes] : -1
    mean_latency = successful_nodes > 0 ? latency_sum / successful_nodes : 0
    mean_setup = successful_nodes > 0 ? setup_sum / successful_nodes : 0
    mean_sent = successful_nodes > 0 ? sent_sum / successful_nodes : 0
    mean_recv = successful_nodes > 0 ? recv_sum / successful_nodes : 0
    consensus_hashes = 0
    for (hash in consensus) {
        consensus_hashes++
    }

    printf("CLUSTER_BENCH_RESULT protocol=%s expected_nodes=%d result_nodes=%d successful_nodes=%d quorum=%d quorum_success=%d all_success=%d quorum_latency_ms=%.2f all_nodes_latency_ms=%.2f mean_node_latency_ms=%.2f max_attempt_latency_ms=%.2f mean_setup_ms=%.2f mean_sent_bytes_per_node=%.0f mean_recv_bytes_per_node=%.0f consensus_hashes=%d\n",
        protocol, expected_nodes, result_nodes, successful_nodes, quorum,
        quorum_success, all_success, quorum_latency, all_latency, mean_latency,
        max_attempt_latency, mean_setup, mean_sent, mean_recv, consensus_hashes)
}
