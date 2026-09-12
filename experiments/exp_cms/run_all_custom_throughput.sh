#!/usr/bin/env bash
set -euo pipefail

DEV="enp94s0f0np0"

RUNS=10
WINDOW=10
GAP=5
WARMUP=20

BASE_PIN="/sys/fs/bpf/cms_custom"
NATIVE_PIN="/sys/fs/bpf/cms_native_custom_rdpmc"
KFUNC_PIN="/sys/fs/bpf/cms_kfunc_custom_rdpmc"

get_id() {
    sudo bpftool prog show pinned "$1" |
        awk -F: 'NR==1 {gsub(/^[ \t]+|[ \t]+$/, "", $1); print $1}'
}

attach_prog() {

    local label="$1"
    local pin="$2"

    local id
    id=$(get_id "$pin")

    echo
    echo "========================================"
    echo "Attaching $label"
    echo "Program ID: $id"
    echo "========================================"

    sudo ip link set dev "$DEV" xdp off 2>/dev/null || true

    sudo bpftool net attach \
        xdp id "$id" dev "$DEV"

    sudo bpftool net

    echo "$id"
}

sudo sysctl -w kernel.bpf_stats_enabled=1 >/dev/null

# ---------------------------------------------------------

id=$(attach_prog "BASELINE" "$BASE_PIN" | tail -1)

./run_throughput_auto.sh \
    "$id" "$RUNS" "$WINDOW" "$GAP" "$WARMUP" \
    cms_custom_throughput.csv

# ---------------------------------------------------------

id=$(attach_prog "NATIVE RDPMC" "$NATIVE_PIN" | tail -1)

./run_throughput_auto.sh \
    "$id" "$RUNS" "$WINDOW" "$GAP" "$WARMUP" \
    cms_native_custom_throughput.csv

# ---------------------------------------------------------

id=$(attach_prog "KFUNC RDPMC" "$KFUNC_PIN" | tail -1)

./run_throughput_auto.sh \
    "$id" "$RUNS" "$WINDOW" "$GAP" "$WARMUP" \
    cms_kfunc_custom_throughput.csv

echo
echo "All throughput tests completed."
