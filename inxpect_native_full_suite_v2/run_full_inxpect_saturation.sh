#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "ERROR: run with sudo -E"; exit 1; fi
WORKLOAD="${1:?Usage: $0 <drop|cms|nat|routing|tunnel> [repo-root]}"
ROOT="$(realpath "${2:-.}")"
BUILD="$ROOT/build_inxpect_native"
IFACE="${IFACE:-enp94s0f0np0}"
RUNS="${RUNS:-10}"
WINDOW="${WINDOW:-10}"
GAP="${GAP:-5}"
WARMUP="${WARMUP:-20}"
MODE="${MODE:-full}"              # full | sampled
SAMPLE_EXP="${SAMPLE_EXP:-4}"    # sampled => 2^4 = 16 packets
COUNTER="${COUNTER:-0}"
INXPECT_BIN="${INXPECT_BIN:-$ROOT/inxpect/inxpect}"
RESULTS="$ROOT/results_inxpect_native_full"
mkdir -p "$RESULTS"

[[ "$MODE" == full || "$MODE" == sampled ]] || { echo "ERROR: MODE must be full or sampled"; exit 1; }
[[ -x "$BUILD/full_loader" ]] || { echo "ERROR: build suite first"; exit 1; }
[[ -x "$BUILD/verify_inxpect_map" ]] || { echo "ERROR: verifier missing"; exit 1; }
[[ -x "$INXPECT_BIN" ]] || { echo "ERROR: InXpect binary not found/executable: $INXPECT_BIN"; exit 1; }
[[ -d /sys/fs/bpf ]] || { echo "ERROR: bpffs not mounted"; exit 1; }

if pgrep -x enable_cycles >/dev/null 2>&1; then
  echo "ERROR: enable_cycles is still running. Stop it first: InXpect must allocate PMC$COUNTER itself."
  exit 1
fi
if pgrep -x inxpect >/dev/null 2>&1; then
  echo "ERROR: another inxpect process is already running. Stop it first."
  exit 1
fi

ROUTE_DIR="$BUILD/routing_maps/mappe"
get_field() {
  local id="$1" key="$2"
  bpftool prog show id "$id" | awk -v key="$key" '{for(i=1;i<=NF;i++) if(!found && $i==key){print $(i+1); found=1}} END{if(!found) exit 1}'
}
cleanup_pair() {
  local ipid="${1:-}" lpid="${2:-}"
  if [[ -n "$ipid" ]] && kill -0 "$ipid" 2>/dev/null; then kill -TERM "$ipid" 2>/dev/null || true; wait "$ipid" 2>/dev/null || true; fi
  if [[ -n "$lpid" ]] && kill -0 "$lpid" 2>/dev/null; then kill -TERM "$lpid" 2>/dev/null || true; wait "$lpid" 2>/dev/null || true; fi
  rm -f /sys/fs/bpf/multiplexed_output /sys/fs/bpf/percpu_output 2>/dev/null || true
}

run_variant() {
  local variant="$1" obj="$2"
  local llog="$RESULTS/${WORKLOAD}_${MODE}_${variant}_loader.log"
  local ilog="$RESULTS/${WORKLOAD}_${MODE}_${variant}_inxpect.log"
  local csv="$RESULTS/${WORKLOAD}_${MODE}_${variant}.csv"
  : > "$llog"; : > "$ilog"
  echo "run,workload,mode,variant,prog_id,elapsed_s,delta_run_cnt,mpps,delta_run_time_ns,ns_per_pkt" > "$csv"

  local loader_args=("$BUILD/full_loader" "$WORKLOAD" "$obj" "$IFACE")
  if [[ "$WORKLOAD" == routing ]]; then loader_args+=("$ROUTE_DIR"); fi
  "${loader_args[@]}" >"$llog" 2>&1 & local lpid=$!
  local ready=""
  for _ in $(seq 1 100); do
    ready="$(grep '^READY ' "$llog" | tail -1 || true)"
    [[ -n "$ready" ]] && break
    kill -0 "$lpid" 2>/dev/null || { cat "$llog"; echo "ERROR: loader died"; return 1; }
    sleep 0.1
  done
  [[ -n "$ready" ]] || { cat "$llog"; cleanup_pair "" "$lpid"; echo "ERROR: no READY"; return 1; }
  echo "$ready"
  local id prog
  id="$(sed -n 's/.*prog_id=\([0-9][0-9]*\).*/\1/p' <<<"$ready")"
  prog="$(sed -n 's/.*prog_name=\([^ ]*\).*/\1/p' <<<"$ready")"

  if [[ "$variant" == native ]]; then
    local dump nrd
    dump="$(bpftool prog dump jited id "$id" 2>/dev/null || true)"
    nrd="$(grep -c '\<rdpmc\>' <<<"$dump" || true)"
    echo "JIT rdpmc sites: $nrd"
    [[ "$nrd" -ge 2 ]] || { cleanup_pair "" "$lpid"; echo "ERROR: expected >=2 native rdpmc sites"; return 1; }
  fi

  local inx_args=("$INXPECT_BIN" -n "$prog" -e cycles -a -d 3600)
  if [[ "$MODE" == sampled ]]; then inx_args+=( -s "$SAMPLE_EXP" ); fi
  "${inx_args[@]}" >"$ilog" 2>&1 & local ipid=$!
  sleep 2
  if ! kill -0 "$ipid" 2>/dev/null; then cat "$ilog"; cleanup_pair "" "$lpid"; echo "ERROR: InXpect exited early"; return 1; fi
  if ! "$BUILD/verify_inxpect_map" "$COUNTER"; then
    echo "--- InXpect log ---"; cat "$ilog"
    cleanup_pair "$ipid" "$lpid"
    echo "ERROR: PMC allocation/section activation mismatch. Stop stale profilers or reload mykperf, then retry."
    return 1
  fi

  echo "Warm-up ${WARMUP}s with full InXpect active..."
  sleep "$WARMUP"
  if ! "$BUILD/verify_inxpect_map" "$COUNTER" require-runs; then
    echo "--- InXpect log ---"; cat "$ilog"
    cleanup_pair "$ipid" "$lpid"
    echo "ERROR: InXpect section is active but run_cnt is zero."
    return 1
  fi

  for r in $(seq 1 "$RUNS"); do
    local c0 t0 c1 t1 start end elapsed delta mpps ns
    c0="$(get_field "$id" run_cnt)"; t0="$(get_field "$id" run_time_ns)"
    start="$(date +%s.%N)"; sleep "$WINDOW"; end="$(date +%s.%N)"
    c1="$(get_field "$id" run_cnt)"; t1="$(get_field "$id" run_time_ns)"
    read -r elapsed delta mpps ns <<<"$(python3 - "$start" "$end" "$c0" "$c1" "$t0" "$t1" <<'PY'
import sys
s,e,c0,c1,t0,t1=sys.argv[1:]
elapsed=float(e)-float(s); d=int(c1)-int(c0); dt=int(t1)-int(t0)
print(f"{elapsed:.6f} {d} {d/elapsed/1e6:.6f} {dt/d if d else 0:.6f}")
PY
)"
    printf 'run %2d: %8.4f Mpps  %9.3f ns/pkt  packets=%s\n' "$r" "$mpps" "$ns" "$delta"
    echo "$r,$WORKLOAD,$MODE,$variant,$id,$elapsed,$delta,$mpps,$((t1-t0)),$ns" >> "$csv"
    [[ "$r" -lt "$RUNS" ]] && sleep "$GAP"
  done

  # Stop profiler first so it can disable the PMU while maps/program still exist.
  kill -TERM "$ipid" 2>/dev/null || true; wait "$ipid" 2>/dev/null || true
  echo "InXpect final report ($variant):"
  tail -20 "$ilog" || true
  kill -TERM "$lpid" 2>/dev/null || true; wait "$lpid" 2>/dev/null || true
  rm -f /sys/fs/bpf/multiplexed_output /sys/fs/bpf/percpu_output 2>/dev/null || true
}

trap 'rm -f /sys/fs/bpf/multiplexed_output /sys/fs/bpf/percpu_output 2>/dev/null || true' EXIT
KOBJ="$BUILD/$WORKLOAD/kfunc_${MODE}.bpf.o"
NOBJ="$BUILD/$WORKLOAD/native_${MODE}.bpf.o"
[[ -f "$KOBJ" && -f "$NOBJ" ]] || { echo "ERROR: objects missing for $WORKLOAD/$MODE"; exit 1; }

echo "============================================================"
echo "Full InXpect: KFUNC RDPMC vs NATIVE RDPMC"
echo "workload=$WORKLOAD mode=$MODE iface=$IFACE runs=$RUNS window=${WINDOW}s"
[[ "$MODE" == sampled ]] && echo "sampling interval = 2^$SAMPLE_EXP packets"
echo "IMPORTANT: TRex must already be running; do NOT run enable_cycles."
echo "============================================================"


echo; echo "=== $WORKLOAD / InXpect native ==="; run_variant native "$NOBJ"
echo; echo "=== $WORKLOAD / InXpect kfunc ==="; run_variant kfunc "$KOBJ"


python3 - "$RESULTS/${WORKLOAD}_${MODE}_kfunc.csv" "$RESULTS/${WORKLOAD}_${MODE}_native.csv" <<'PY'
import csv,statistics,sys
for p in sys.argv[1:]:
    rows=list(csv.DictReader(open(p)))
    v=rows[0]['variant'] if rows else p
    m=[float(r['mpps']) for r in rows]; n=[float(r['ns_per_pkt']) for r in rows]
    sd=lambda x: statistics.stdev(x) if len(x)>1 else 0.0
    print(f"{v:7s}: {statistics.mean(m):.6f} ± {sd(m):.6f} Mpps; {statistics.mean(n):.6f} ± {sd(n):.6f} ns/pkt")
k=list(csv.DictReader(open(sys.argv[1]))); n=list(csv.DictReader(open(sys.argv[2])))
km=statistics.mean(float(r['mpps']) for r in k); nm=statistics.mean(float(r['mpps']) for r in n)
kn=statistics.mean(float(r['ns_per_pkt']) for r in k); nn=statistics.mean(float(r['ns_per_pkt']) for r in n)
print(f"Native vs kfunc throughput: {(nm/km-1)*100:+.2f}%")
print(f"Native vs kfunc ns/pkt:     {(nn/kn-1)*100:+.2f}% ({nn-kn:+.3f} ns/pkt)")
PY

echo "[DONE] CSV/logs in $RESULTS"
