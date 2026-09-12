#!/usr/bin/env bash
set -euo pipefail

DEV="enp94s0f0np0"

RUNS=10
TIMEOUT_MS=10000
GAP=5
WARMUP=20

BASE_PIN="/sys/fs/bpf/cms_custom"
NATIVE_PIN="/sys/fs/bpf/cms_native_custom_rdpmc"
KFUNC_PIN="/sys/fs/bpf/cms_kfunc_custom_rdpmc"

get_id() {
    sudo bpftool prog show pinned "$1" |
        awk -F: 'NR==1 {gsub(/^[ \t]+|[ \t]+$/, "", $1); print $1}'
}

run_variant() {

    local label="$1"
    local pin="$2"
    local out="$3"

    local id
    id=$(get_id "$pin")

    echo
    echo "========================================"
    echo "$label"
    echo "Program ID: $id"
    echo "========================================"

    sudo ip link set dev "$DEV" xdp off 2>/dev/null || true

    sudo bpftool net attach \
        xdp id "$id" dev "$DEV"

    sudo bpftool net

    ./run_instructions_auto.sh \
        "$id" \
        "$RUNS" \
        "$TIMEOUT_MS" \
        "$GAP" \
        "$WARMUP" \
        "$out"
}

echo 0 | sudo tee /proc/sys/kernel/nmi_watchdog >/dev/null

run_variant \
    "BASELINE" \
    "$BASE_PIN" \
    cms_custom_instructions.csv

run_variant \
    "NATIVE RDPMC" \
    "$NATIVE_PIN" \
    cms_native_custom_instructions.csv

run_variant \
    "KFUNC RDPMC" \
    "$KFUNC_PIN" \
    cms_kfunc_custom_instructions.csv

echo
echo "All instruction tests completed."
