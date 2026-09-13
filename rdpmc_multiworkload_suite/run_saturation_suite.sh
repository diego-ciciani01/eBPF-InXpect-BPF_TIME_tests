#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    exec sudo -E "$0" "$@"
fi

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${1:-$(pwd)}"
ROOT="$(cd "$ROOT" && pwd)"
SELECT="${2:-all}"
IFACE="${IFACE:-enp94s0f0np0}"
RUNS="${RUNS:-10}"
WINDOW="${WINDOW:-10}"
GAP="${GAP:-5}"
WARMUP="${WARMUP:-20}"
BUILD="$ROOT/build_rdpmc"
RESULTS="${RESULTS:-$ROOT/results_rdpmc_multiworkload}"
ROUTE_MAPS="$ROOT/experiments/exp_routing/mappe"

mkdir -p "$RESULTS"

if [[ ! -x "$BUILD/suite_loader" ]]; then
    echo "ERROR: $BUILD/suite_loader missing. Run build_rdpmc_suite.sh first." >&2
    exit 1
fi

if [[ ! -d /sys/fs/bpf ]]; then
    echo "ERROR: bpffs not mounted at /sys/fs/bpf" >&2
    exit 1
fi

sysctl -q -w kernel.bpf_stats_enabled=1

echo "============================================================"
echo "RDPMC multi-workload SATURATION benchmark"
echo "Interface : $IFACE"
echo "Runs      : $RUNS"
echo "Window    : ${WINDOW}s"
echo "Gap       : ${GAP}s"
echo "Warmup    : ${WARMUP}s"
echo "Results   : $RESULTS"
echo "Selection : $SELECT"
echo "============================================================"
echo "IMPORTANT: TRex must already be running at 100% offered load."
echo

get_field() {
    local id="$1" key="$2"
    bpftool prog show id "$id" | awk -v key="$key" '
        {
            for (i = 1; i <= NF; i++) {
                if (!found && $i == key) {
                    print $(i + 1)
                    found = 1
                }
            }
        }
        END { if (!found) exit 1 }
    '
}

wait_ready() {
    local log="$1" pid="$2"
    for _ in $(seq 1 600); do
        if grep -q '^READY ' "$log" 2>/dev/null; then return 0; fi
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "ERROR: loader exited before READY" >&2
            cat "$log" >&2 || true
            return 1
        fi
        sleep 0.2
    done
    echo "ERROR: timeout waiting for loader READY" >&2
    cat "$log" >&2 || true
    return 1
}

run_variant() {
    local workload="$1" variant="$2"
    local obj="$BUILD/$workload/${variant}.bpf.o"
    local csv="$RESULTS/${workload}_${variant}_saturation.csv"
    local log="$RESULTS/${workload}_${variant}_loader.log"

    if [[ ! -f "$obj" ]]; then
        echo "ERROR: missing $obj" >&2
        exit 1
    fi

    : > "$log"
    echo
    echo "=== $workload / $variant ==="

    if [[ "$workload" == "routing" ]]; then
        "$BUILD/suite_loader" "$workload" "$obj" "$IFACE" "$ROUTE_MAPS" >"$log" 2>&1 &
    else
        "$BUILD/suite_loader" "$workload" "$obj" "$IFACE" >"$log" 2>&1 &
    fi
    local lpid=$!

    trap 'kill -TERM '"$lpid"' 2>/dev/null || true; wait '"$lpid"' 2>/dev/null || true' EXIT
    wait_ready "$log" "$lpid"
    cat "$log"

    local id
    id=$(sed -n 's/^READY .*prog_id=\([0-9][0-9]*\).*/\1/p' "$log" | tail -1)
    if [[ -z "$id" ]]; then
        echo "ERROR: could not parse prog_id" >&2
        return 1
    fi

    echo "Attached prog id: $id"
    bpftool net

    if [[ "$variant" == "native_rdpmc" ]]; then
        local nrdpmc
        nrdpmc=$(bpftool prog dump jited id "$id" 2>/dev/null | grep -cw 'rdpmc' || true)
        echo "JIT rdpmc count: $nrdpmc"
        if [[ "$nrdpmc" -ne 2 ]]; then
            echo "ERROR: expected exactly 2 rdpmc in native JIT" >&2
            return 1
        fi
    fi

    echo "Warm-up ${WARMUP}s..."
    sleep "$WARMUP"

    echo "run,workload,variant,prog_id,elapsed_s,delta_run_cnt,mpps,delta_run_time_ns,ns_per_pkt" > "$csv"

    for i in $(seq 1 "$RUNS"); do
        local c0 c1 r0 r1 t0 t1 elapsed
        c0=$(get_field "$id" run_cnt)
        r0=$(get_field "$id" run_time_ns)
        t0=$(date +%s%N)
        sleep "$WINDOW"
        t1=$(date +%s%N)
        c1=$(get_field "$id" run_cnt)
        r1=$(get_field "$id" run_time_ns)

        read -r elapsed dc mpps dr nspp <<<"$(python3 - <<PY
c0=$c0; c1=$c1; r0=$r0; r1=$r1; t0=$t0; t1=$t1
elapsed=(t1-t0)/1e9
dc=c1-c0
dr=r1-r0
mpps=(dc/elapsed)/1e6 if elapsed>0 else float('nan')
nspp=(dr/dc) if dc>0 else float('nan')
print(f'{elapsed:.6f} {dc} {mpps:.6f} {dr} {nspp:.6f}')
PY
)"
        echo "$i,$workload,$variant,$id,$elapsed,$dc,$mpps,$dr,$nspp" >> "$csv"
        printf 'run %2d: %8.4f Mpps  %9.3f ns/pkt  packets=%s\n' "$i" "$mpps" "$nspp" "$dc"
        if [[ "$i" -lt "$RUNS" ]]; then sleep "$GAP"; fi
    done

    python3 - "$csv" <<'PY'
import csv, statistics, sys
rows=list(csv.DictReader(open(sys.argv[1])))
for field,label in [('mpps','Mpps'),('ns_per_pkt','ns/pkt')]:
    x=[float(r[field]) for r in rows]
    sd=statistics.stdev(x) if len(x) > 1 else 0.0
    print(f'{label}: mean={statistics.mean(x):.6f}  median={statistics.median(x):.6f}  stdev={sd:.6f}')
PY

    kill -TERM "$lpid" 2>/dev/null || true
    wait "$lpid" 2>/dev/null || true
    trap - EXIT
    sleep 2
}

case "$SELECT" in
    all) WORKLOAD_LIST="drop nat routing tunnel" ;;
    drop|nat|routing|tunnel) WORKLOAD_LIST="$SELECT" ;;
    *) echo "ERROR: second argument must be all|drop|nat|routing|tunnel" >&2; exit 2 ;;
esac

for workload in $WORKLOAD_LIST; do
    run_variant "$workload" baseline
    run_variant "$workload" native_rdpmc
    run_variant "$workload" kfunc_rdpmc
done

python3 "$SUITE_DIR/summarize_saturation.py" "$RESULTS"

echo
echo "[DONE] Results in $RESULTS"

