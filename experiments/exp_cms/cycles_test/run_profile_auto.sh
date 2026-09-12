#!/usr/bin/env bash
set -euo pipefail

PROG_ID="${1:?Usage: $0 PROG_ID [runs] [duration] [gap] [warmup] [output.csv]}"
RUNS="${2:-10}"
DURATION="${3:-10}"
GAP="${4:-5}"
WARMUP="${5:-20}"
OUT="${6:-profile_results.csv}"

echo "run,prog_id,run_cnt,cycles,instructions,cycles_per_pkt,instructions_per_pkt,ipc,cpi" > "$OUT"

echo "Program ID : $PROG_ID"
echo "Runs       : $RUNS"
echo "Duration   : ${DURATION}s"
echo "Gap        : ${GAP}s"
echo "Warm-up    : ${WARMUP}s"
echo "Output     : $OUT"
echo

sleep "$WARMUP"

for i in $(seq 1 "$RUNS"); do
    echo "========================================"
    echo "Run $i / $RUNS"
    echo "========================================"

    tmp=$(mktemp)

    sudo bpftool prog profile \
        id "$PROG_ID" \
        duration "$DURATION" \
        cycles instructions > "$tmp"

    cat "$tmp"

    run_cnt=$(awk '$2=="run_cnt" {print $1}' "$tmp")
    cycles=$(awk '$2=="cycles" {print $1}' "$tmp")
    instructions=$(awk '$2=="instructions" {print $1}' "$tmp")

    if [[ -z "$run_cnt" || -z "$cycles" || -z "$instructions" ]]; then
        echo "ERROR: failed to parse profile output"
        cat "$tmp"
        rm -f "$tmp"
        exit 1
    fi

    read cpp ipp ipc cpi <<< "$(awk \
        -v r="$run_cnt" \
        -v c="$cycles" \
        -v ins="$instructions" \
        'BEGIN {
            printf "%.6f %.6f %.6f %.6f",
                c/r,
                ins/r,
                ins/c,
                c/ins
        }')"

    echo "cycles/pkt       : $cpp"
    echo "instructions/pkt : $ipp"
    echo "IPC              : $ipc"
    echo "CPI              : $cpi"

    echo "$i,$PROG_ID,$run_cnt,$cycles,$instructions,$cpp,$ipp,$ipc,$cpi" >> "$OUT"

    rm -f "$tmp"

    if [[ "$i" -lt "$RUNS" ]]; then
        sleep "$GAP"
    fi
done

echo
python3 - "$OUT" <<'PY'
import csv
import statistics
import sys

rows = list(csv.DictReader(open(sys.argv[1])))

for field, label in [
    ("cycles_per_pkt", "cycles/pkt"),
    ("instructions_per_pkt", "instructions/pkt"),
    ("ipc", "IPC"),
]:
    x = [float(r[field]) for r in rows]

    print(label)
    print(f"  mean   = {statistics.mean(x):.6f}")
    print(f"  median = {statistics.median(x):.6f}")
    print(f"  stdev  = {statistics.stdev(x):.6f}")
    print(f"  min    = {min(x):.6f}")
    print(f"  max    = {max(x):.6f}")
    print()
PY
