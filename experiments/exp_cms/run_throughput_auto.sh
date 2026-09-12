#!/usr/bin/env bash
set -euo pipefail

PROG_ID="${1:-}"
RUNS="${2:-10}"
WINDOW="${3:-10}"
GAP="${4:-5}"
WARMUP="${5:-20}"
OUT="${6:-throughput_results.csv}"

if [[ -z "$PROG_ID" ]]; then
    echo "Usage:"
    echo "  $0 <prog_id> [runs] [window_s] [gap_s] [warmup_s] [output.csv]"
    exit 1
fi

get_run_cnt() {
    sudo bpftool prog show id "$PROG_ID" |
        sed -n 's/.*run_cnt \([0-9][0-9]*\).*/\1/p'
}

get_run_time_ns() {
    sudo bpftool prog show id "$PROG_ID" |
        sed -n 's/.*run_time_ns \([0-9][0-9]*\).*/\1/p'
}

echo "run,prog_id,run_cnt_before,run_cnt_after,delta_run_cnt,run_time_ns_before,run_time_ns_after,delta_run_time_ns,elapsed_s,mpps,ns_per_pkt" > "$OUT"

echo "Program ID       : $PROG_ID"
echo "Runs             : $RUNS"
echo "Measurement      : ${WINDOW}s"
echo "Gap              : ${GAP}s"
echo "Warm-up          : ${WARMUP}s"
echo "Output           : $OUT"
echo
echo "Make sure TRex is already running continuously."
echo
echo "Warm-up for ${WARMUP}s..."
sleep "$WARMUP"

for i in $(seq 1 "$RUNS"); do
    echo
    echo "========================================"
    echo "Run $i / $RUNS"
    echo "========================================"

    before_cnt=$(get_run_cnt)
    before_ns=$(get_run_time_ns)

    if [[ -z "$before_cnt" || -z "$before_ns" ]]; then
        echo "ERROR: could not read BPF statistics"
        exit 1
    fi

    t0=$(date +%s.%N)

    sleep "$WINDOW"

    t1=$(date +%s.%N)

    after_cnt=$(get_run_cnt)
    after_ns=$(get_run_time_ns)

    if [[ -z "$after_cnt" || -z "$after_ns" ]]; then
        echo "ERROR: could not read BPF statistics"
        exit 1
    fi

    delta_cnt=$((after_cnt - before_cnt))
    delta_ns=$((after_ns - before_ns))

    elapsed=$(awk -v a="$t0" -v b="$t1" \
        'BEGIN { printf "%.9f", b-a }')

    mpps=$(awk -v d="$delta_cnt" -v e="$elapsed" \
        'BEGIN { printf "%.6f", d/e/1000000.0 }')

    ns_per_pkt=$(awk -v n="$delta_ns" -v d="$delta_cnt" \
        'BEGIN {
            if (d > 0)
                printf "%.6f", n/d;
            else
                printf "nan";
        }')

    echo "run_cnt before    : $before_cnt"
    echo "run_cnt after     : $after_cnt"
    echo "delta run_cnt     : $delta_cnt"
    echo "elapsed           : $elapsed s"
    echo "throughput        : $mpps Mpps"
    echo "delta run_time_ns : $delta_ns"
    echo "ns/pkt            : $ns_per_pkt"

    echo "$i,$PROG_ID,$before_cnt,$after_cnt,$delta_cnt,$before_ns,$after_ns,$delta_ns,$elapsed,$mpps,$ns_per_pkt" >> "$OUT"

    if [[ "$i" -lt "$RUNS" ]]; then
        echo "Gap ${GAP}s..."
        sleep "$GAP"
    fi
done

echo
echo "========================================"
echo "Summary"
echo "========================================"

python3 - "$OUT" <<'PY'
import csv
import statistics
import sys

path = sys.argv[1]

mpps = []
ns = []

with open(path) as f:
    for row in csv.DictReader(f):
        mpps.append(float(row["mpps"]))
        ns.append(float(row["ns_per_pkt"]))

def report(name, values):
    print(f"{name}:")
    print(f"  n      = {len(values)}")
    print(f"  mean   = {statistics.mean(values):.6f}")
    print(f"  median = {statistics.median(values):.6f}")
    if len(values) > 1:
        print(f"  stdev  = {statistics.stdev(values):.6f}")
    print(f"  min    = {min(values):.6f}")
    print(f"  max    = {max(values):.6f}")

report("Throughput [Mpps]", mpps)
print()
report("Runtime [ns/pkt]", ns)
PY
