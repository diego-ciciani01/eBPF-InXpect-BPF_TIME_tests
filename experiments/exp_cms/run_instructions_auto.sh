#!/usr/bin/env bash
set -euo pipefail

PROG_ID="${1:-}"
RUNS="${2:-10}"
TIMEOUT_MS="${3:-10000}"
GAP="${4:-5}"
WARMUP="${5:-20}"
OUT="${6:-instructions_results.csv}"

if [[ -z "$PROG_ID" ]]; then
    echo "Usage:"
    echo "  $0 <prog_id> [runs] [timeout_ms] [gap_s] [warmup_s] [output.csv]"
    exit 1
fi

get_run_cnt() {
    sudo bpftool prog show id "$PROG_ID" |
        sed -n 's/.*run_cnt \([0-9][0-9]*\).*/\1/p'
}

echo "run,prog_id,run_cnt_before,run_cnt_after,delta_run_cnt,instructions,instructions_per_pkt" > "$OUT"

echo "Program ID : $PROG_ID"
echo "Runs       : $RUNS"
echo "Timeout    : ${TIMEOUT_MS} ms"
echo "Gap        : ${GAP}s"
echo "Warm-up    : ${WARMUP}s"
echo "Output     : $OUT"
echo
echo "TRex should already be running at the fixed rate."
echo

sleep "$WARMUP"

for i in $(seq 1 "$RUNS"); do
    echo "========================================"
    echo "Run $i / $RUNS"
    echo "========================================"

    before=$(get_run_cnt)

    if [[ -z "$before" ]]; then
        echo "ERROR: cannot read run_cnt"
        exit 1
    fi

    tmp=$(mktemp)

    sudo perf stat \
        -x, \
        -e instructions \
        -b "$PROG_ID" \
        --timeout "$TIMEOUT_MS" \
        2> "$tmp"

    after=$(get_run_cnt)

    if [[ -z "$after" ]]; then
        echo "ERROR: cannot read run_cnt after perf"
        rm -f "$tmp"
        exit 1
    fi

    delta=$((after - before))

    instructions=$(awk -F',' '
        $3 == "instructions" {
            gsub(/[[:space:]]/, "", $1)
            print $1
            exit
        }
    ' "$tmp")

    if [[ -z "$instructions" || "$instructions" == "<notcounted>" || "$instructions" == "<notsupported>" ]]; then
        echo "ERROR: perf did not return a valid instruction count"
        cat "$tmp"
        rm -f "$tmp"
        exit 1
    fi

    ipp=$(awk -v ins="$instructions" -v pkt="$delta" '
        BEGIN {
            if (pkt > 0)
                printf "%.6f", ins / pkt
            else
                printf "nan"
        }')

    echo "run_cnt before : $before"
    echo "run_cnt after  : $after"
    echo "delta packets  : $delta"
    echo "instructions   : $instructions"
    echo "instr/pkt      : $ipp"

    echo "$i,$PROG_ID,$before,$after,$delta,$instructions,$ipp" >> "$OUT"

    rm -f "$tmp"

    if [[ "$i" -lt "$RUNS" ]]; then
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

vals = []

with open(sys.argv[1]) as f:
    for row in csv.DictReader(f):
        vals.append(float(row["instructions_per_pkt"]))

print(f"n      = {len(vals)}")
print(f"mean   = {statistics.mean(vals):.6f} instr/pkt")
print(f"median = {statistics.median(vals):.6f} instr/pkt")
if len(vals) > 1:
    print(f"stdev  = {statistics.stdev(vals):.6f}")
print(f"min    = {min(vals):.6f}")
print(f"max    = {max(vals):.6f}")
PY
