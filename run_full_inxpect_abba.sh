#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run with sudo -E"
  exit 1
fi

WORKLOAD="${1:?Usage: $0 <drop|cms|nat|routing|tunnel> [repo-root]}"
ROOT="$(realpath "${2:-.}")"
BUILD="$ROOT/build_inxpect_native"

IFACE="${IFACE:-enp94s0f0np0}"
WINDOW="${WINDOW:-10}"
GAP="${GAP:-3}"
WARMUP="${WARMUP:-5}"
BLOCKS="${BLOCKS:-5}"            # 5 blocks => 10 native + 10 kfunc measurements
MODE="${MODE:-full}"             # full | sampled
SAMPLE_EXP="${SAMPLE_EXP:-4}"
COUNTER="${COUNTER:-0}"
INXPECT_BIN="${INXPECT_BIN:-$ROOT/inxpect/inxpect}"

RESULTS="$ROOT/results_inxpect_native_abba"
mkdir -p "$RESULTS"

[[ "$MODE" == full || "$MODE" == sampled ]] || {
  echo "ERROR: MODE must be full or sampled"
  exit 1
}
[[ -x "$BUILD/full_loader" ]] || {
  echo "ERROR: build suite first"
  exit 1
}
[[ -x "$BUILD/verify_inxpect_map" ]] || {
  echo "ERROR: verifier missing"
  exit 1
}
[[ -x "$INXPECT_BIN" ]] || {
  echo "ERROR: InXpect binary not found/executable: $INXPECT_BIN"
  exit 1
}
[[ -d /sys/fs/bpf ]] || {
  echo "ERROR: bpffs not mounted"
  exit 1
}

if pgrep -x enable_cycles >/dev/null 2>&1; then
  echo "ERROR: enable_cycles is still running. Stop it first."
  exit 1
fi

if pgrep -x inxpect >/dev/null 2>&1; then
  echo "ERROR: another inxpect process is already running. Stop it first."
  exit 1
fi

# Catch stale loaders from the previous bare-RDPMC suite.
if pgrep -f "$ROOT/build_rdpmc/suite_loader" >/dev/null 2>&1; then
  echo "ERROR: stale build_rdpmc/suite_loader process detected."
  pgrep -af "$ROOT/build_rdpmc/suite_loader" || true
  echo "Stop it before benchmarking."
  exit 1
fi

ROUTE_DIR="$BUILD/routing_maps/mappe"

KOBJ="$BUILD/$WORKLOAD/kfunc_${MODE}.bpf.o"
NOBJ="$BUILD/$WORKLOAD/native_${MODE}.bpf.o"

[[ -f "$KOBJ" && -f "$NOBJ" ]] || {
  echo "ERROR: objects missing for $WORKLOAD/$MODE"
  exit 1
}

KCSV="$RESULTS/${WORKLOAD}_${MODE}_kfunc_abba.csv"
NCSV="$RESULTS/${WORKLOAD}_${MODE}_native_abba.csv"
ALLCSV="$RESULTS/${WORKLOAD}_${MODE}_sequence_abba.csv"

HEADER="seq,block,position,workload,mode,variant,prog_id,elapsed_s,delta_run_cnt,mpps,delta_run_time_ns,ns_per_pkt,inxpect_cycles_per_pkt,inxpect_total_cycles,inxpect_run_cnt"
echo "$HEADER" > "$KCSV"
echo "$HEADER" > "$NCSV"
echo "$HEADER" > "$ALLCSV"

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
    END {
      if (!found) exit 1
    }
  '
}

CURRENT_IPID=""
CURRENT_LPID=""

cleanup_current() {
  if [[ -n "${CURRENT_IPID:-}" ]] && kill -0 "$CURRENT_IPID" 2>/dev/null; then
    kill -TERM "$CURRENT_IPID" 2>/dev/null || true
    wait "$CURRENT_IPID" 2>/dev/null || true
  fi
  if [[ -n "${CURRENT_LPID:-}" ]] && kill -0 "$CURRENT_LPID" 2>/dev/null; then
    kill -TERM "$CURRENT_LPID" 2>/dev/null || true
    wait "$CURRENT_LPID" 2>/dev/null || true
  fi
  CURRENT_IPID=""
  CURRENT_LPID=""
  rm -f /sys/fs/bpf/multiplexed_output /sys/fs/bpf/percpu_output 2>/dev/null || true
}

trap cleanup_current EXIT INT TERM HUP

run_one() {
  local variant="$1"
  local obj="$2"
  local seq="$3"
  local block="$4"
  local pos="$5"

  cleanup_current

  local tag
  printf -v tag "%02d_%s" "$seq" "$variant"

  local llog="$RESULTS/${WORKLOAD}_${MODE}_${tag}_loader.log"
  local ilog="$RESULTS/${WORKLOAD}_${MODE}_${tag}_inxpect.log"

  : > "$llog"
  : > "$ilog"

  echo
  echo "----------------------------------------------------------------"
  echo "seq=$seq block=$block pos=$pos variant=$variant"
  echo "----------------------------------------------------------------"

  local loader_args=("$BUILD/full_loader" "$WORKLOAD" "$obj" "$IFACE")
  if [[ "$WORKLOAD" == routing ]]; then
    loader_args+=("$ROUTE_DIR")
  fi

  "${loader_args[@]}" >"$llog" 2>&1 &
  CURRENT_LPID=$!

  local ready=""
  for _ in $(seq 1 100); do
    ready="$(grep '^READY ' "$llog" | tail -1 || true)"
    [[ -n "$ready" ]] && break

    if ! kill -0 "$CURRENT_LPID" 2>/dev/null; then
      cat "$llog"
      echo "ERROR: loader died"
      return 1
    fi
    sleep 0.1
  done

  if [[ -z "$ready" ]]; then
    cat "$llog"
    echo "ERROR: no READY from loader"
    return 1
  fi

  echo "$ready"

  local id prog
  id="$(sed -n 's/.*prog_id=\([0-9][0-9]*\).*/\1/p' <<<"$ready")"
  prog="$(sed -n 's/.*prog_name=\([^ ]*\).*/\1/p' <<<"$ready")"

  if [[ "$variant" == native ]]; then
    local dump nrd
    dump="$(bpftool prog dump jited id "$id" 2>/dev/null || true)"
    nrd="$(grep -c '\<rdpmc\>' <<<"$dump" || true)"
    echo "JIT rdpmc sites: $nrd"
    if [[ "$nrd" -lt 2 ]]; then
      echo "ERROR: expected >=2 native rdpmc sites"
      return 1
    fi
  fi

  local inx_args=("$INXPECT_BIN" -n "$prog" -e cycles -a -d 3600)
  if [[ "$MODE" == sampled ]]; then
    inx_args+=( -s "$SAMPLE_EXP" )
  fi

  "${inx_args[@]}" >"$ilog" 2>&1 &
  CURRENT_IPID=$!

  sleep 2

  if ! kill -0 "$CURRENT_IPID" 2>/dev/null; then
    cat "$ilog"
    echo "ERROR: InXpect exited early"
    return 1
  fi

  if ! "$BUILD/verify_inxpect_map" "$COUNTER"; then
    echo "--- InXpect log ---"
    cat "$ilog"
    echo "ERROR: PMC allocation/section activation mismatch"
    return 1
  fi

  echo "Warm-up ${WARMUP}s..."
  sleep "$WARMUP"

  if ! "$BUILD/verify_inxpect_map" "$COUNTER" require-runs; then
    echo "--- InXpect log ---"
    cat "$ilog"
    echo "ERROR: section active but run_cnt is zero"
    return 1
  fi

  local c0 t0 c1 t1 start end elapsed delta mpps ns
  c0="$(get_field "$id" run_cnt)"
  t0="$(get_field "$id" run_time_ns)"

  start="$(date +%s.%N)"
  sleep "$WINDOW"
  end="$(date +%s.%N)"

  c1="$(get_field "$id" run_cnt)"
  t1="$(get_field "$id" run_time_ns)"

  read -r elapsed delta mpps ns <<<"$(python3 - "$start" "$end" "$c0" "$c1" "$t0" "$t1" <<'PY'
import sys
s,e,c0,c1,t0,t1=sys.argv[1:]
elapsed=float(e)-float(s)
d=int(c1)-int(c0)
dt=int(t1)-int(t0)
print(f"{elapsed:.6f} {d} {d/elapsed/1e6:.6f} {dt/d if d else 0:.6f}")
PY
)"

  printf 'MEASURED: %8.4f Mpps  %9.3f ns/pkt  packets=%s\n' "$mpps" "$ns" "$delta"

  # Stop InXpect first so it prints its final report and disables the PMU
  # while the map and BPF program are still alive.
  kill -TERM "$CURRENT_IPID" 2>/dev/null || true
  wait "$CURRENT_IPID" 2>/dev/null || true
  CURRENT_IPID=""

  echo "InXpect final report ($variant, seq=$seq):"
  tail -20 "$ilog" || true

  local cyc_pp total_cyc inx_runs
  cyc_pp="$(awk '
    /cycles:/ {
      x=$3
      gsub("/pkt","",x)
      v=x
    }
    END { if (v != "") print v; else print "nan" }
  ' "$ilog")"

  total_cyc="$(awk '
    /cycles:/ { v=$2 }
    END { if (v != "") print v; else print "0" }
  ' "$ilog")"

  inx_runs="$(awk '
    /cycles:/ { v=$5 }
    END { if (v != "") print v; else print "0" }
  ' "$ilog")"

  local row
  row="$seq,$block,$pos,$WORKLOAD,$MODE,$variant,$id,$elapsed,$delta,$mpps,$((t1-t0)),$ns,$cyc_pp,$total_cyc,$inx_runs"

  echo "$row" >> "$ALLCSV"
  if [[ "$variant" == native ]]; then
    echo "$row" >> "$NCSV"
  else
    echo "$row" >> "$KCSV"
  fi

  kill -TERM "$CURRENT_LPID" 2>/dev/null || true
  wait "$CURRENT_LPID" 2>/dev/null || true
  CURRENT_LPID=""

  rm -f /sys/fs/bpf/multiplexed_output /sys/fs/bpf/percpu_output 2>/dev/null || true
}

echo "============================================================"
echo "Full InXpect balanced ABBA benchmark"
echo "workload=$WORKLOAD mode=$MODE iface=$IFACE"
echo "blocks=$BLOCKS -> $((BLOCKS * 2)) measurements/variant"
echo "window=${WINDOW}s warmup=${WARMUP}s gap=${GAP}s"
echo "Pattern alternates:"
echo "  odd blocks : Native Kfunc Kfunc Native"
echo "  even blocks: Kfunc Native Native Kfunc"
[[ "$MODE" == sampled ]] && echo "sampling interval = 2^$SAMPLE_EXP packets"
echo "IMPORTANT: TRex must already be running; do NOT run enable_cycles."
echo "============================================================"

seqno=0

for block in $(seq 1 "$BLOCKS"); do
  if (( block % 2 == 1 )); then
    pattern=(native kfunc kfunc native)
  else
    pattern=(kfunc native native kfunc)
  fi

  echo
  echo "================ BLOCK $block / $BLOCKS ================"

  pos=0
  for variant in "${pattern[@]}"; do
    seqno=$((seqno + 1))
    pos=$((pos + 1))

    if [[ "$variant" == native ]]; then
      run_one native "$NOBJ" "$seqno" "$block" "$pos"
    else
      run_one kfunc "$KOBJ" "$seqno" "$block" "$pos"
    fi

    if ! (( block == BLOCKS && pos == 4 )); then
      sleep "$GAP"
    fi
  done
done

echo
echo "================ FINAL SUMMARY ================"

python3 - "$KCSV" "$NCSV" "$ALLCSV" <<'PY'
import csv
import math
import statistics
import sys
from collections import defaultdict

kfile, nfile, allfile = sys.argv[1:]

def rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))

k = rows(kfile)
n = rows(nfile)
allrows = rows(allfile)

def vals(rs, key):
    out=[]
    for r in rs:
        try:
            x=float(r[key])
            if math.isfinite(x):
                out.append(x)
        except Exception:
            pass
    return out

def sd(x):
    return statistics.stdev(x) if len(x) > 1 else 0.0

def describe(name, rs):
    m=vals(rs,"mpps")
    t=vals(rs,"ns_per_pkt")
    c=vals(rs,"inxpect_cycles_per_pkt")
    print(
        f"{name:7s}: "
        f"{statistics.mean(m):.6f} ± {sd(m):.6f} Mpps; "
        f"{statistics.mean(t):.6f} ± {sd(t):.6f} ns/pkt; "
        f"{statistics.mean(c):.3f} ± {sd(c):.3f} InXpect cycles/pkt"
    )

describe("kfunc", k)
describe("native", n)

km=statistics.mean(vals(k,"mpps"))
nm=statistics.mean(vals(n,"mpps"))
kt=statistics.mean(vals(k,"ns_per_pkt"))
nt=statistics.mean(vals(n,"ns_per_pkt"))
kc=statistics.mean(vals(k,"inxpect_cycles_per_pkt"))
nc=statistics.mean(vals(n,"inxpect_cycles_per_pkt"))

print()
print(f"Native vs kfunc throughput: {(nm/km-1)*100:+.2f}%")
print(f"Native vs kfunc ns/pkt:     {(nt/kt-1)*100:+.2f}% ({nt-kt:+.3f} ns/pkt)")
print(f"Native vs kfunc PMC cycles: {(nc/kc-1)*100:+.2f}% ({nc-kc:+.3f} cycles/pkt)")

# Paired ABBA/BAAB block analysis: average the two observations of each
# variant inside each four-measurement block, then compare within block.
byblock=defaultdict(lambda: defaultdict(list))
for r in allrows:
    byblock[int(r["block"])][r["variant"]].append(r)

d_mpps=[]
d_ns=[]
d_cyc=[]

print()
print("Per-block paired comparison:")
for b in sorted(byblock):
    kr=byblock[b]["kfunc"]
    nr=byblock[b]["native"]

    bk=statistics.mean(vals(kr,"mpps"))
    bn=statistics.mean(vals(nr,"mpps"))
    bkt=statistics.mean(vals(kr,"ns_per_pkt"))
    bnt=statistics.mean(vals(nr,"ns_per_pkt"))
    bkc=statistics.mean(vals(kr,"inxpect_cycles_per_pkt"))
    bnc=statistics.mean(vals(nr,"inxpect_cycles_per_pkt"))

    dm=(bn/bk-1)*100
    dt=(bnt/bkt-1)*100
    dc=(bnc/bkc-1)*100

    d_mpps.append(dm)
    d_ns.append(dt)
    d_cyc.append(dc)

    print(
        f"  block {b:2d}: throughput {dm:+.2f}% | "
        f"ns/pkt {dt:+.2f}% | PMC cycles {dc:+.2f}%"
    )

print()
print(
    "Paired-block mean: "
    f"throughput {statistics.mean(d_mpps):+.2f}% ± {sd(d_mpps):.2f} pp | "
    f"ns/pkt {statistics.mean(d_ns):+.2f}% ± {sd(d_ns):.2f} pp | "
    f"PMC cycles {statistics.mean(d_cyc):+.2f}% ± {sd(d_cyc):.2f} pp"
)
PY

echo
echo "[DONE]"
echo "Sequence CSV: $ALLCSV"
echo "Kfunc CSV   : $KCSV"
echo "Native CSV  : $NCSV"
echo "Logs        : $RESULTS"
