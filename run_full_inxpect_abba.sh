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
WARMUP="${WARMUP:-10}"
BLOCKS="${BLOCKS:-5}"
MODE="${MODE:-full}"                 # full | sampled
SAMPLE_EXP="${SAMPLE_EXP:-4}"
COUNTER="${COUNTER:-0}"
INXPECT_BIN="${INXPECT_BIN:-$ROOT/inxpect/inxpect}"

# Optional reproducibility controls.
# If PIN_CPU is set, IRQs whose /proc/interrupts line contains both IFACE
# and "TxRx" are pinned to that CPU. Stop irqbalance before using this.
PIN_CPU="${PIN_CPU:-}"
STRICT_SINGLE_CPU="${STRICT_SINGLE_CPU:-0}"

RESULTS="$ROOT/results_inxpect_native_abba_v2"
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
	  echo "ERROR: verifier missing: $BUILD/verify_inxpect_map"
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

if pgrep -f "$ROOT/build_rdpmc/suite_loader" >/dev/null 2>&1; then
	  echo "ERROR: stale build_rdpmc/suite_loader process detected."
	    pgrep -af "$ROOT/build_rdpmc/suite_loader" || true
	      exit 1
fi

ROUTE_DIR="$BUILD/routing_maps/mappe"

KOBJ="$BUILD/$WORKLOAD/kfunc_${MODE}.bpf.o"
NOBJ="$BUILD/$WORKLOAD/native_${MODE}.bpf.o"

[[ -f "$KOBJ" && -f "$NOBJ" ]] || {
	  echo "ERROR: objects missing for $WORKLOAD/$MODE"
  exit 1
}

# ---------------------------------------------------------------------------
# Optional IRQ pinning.
# ---------------------------------------------------------------------------
pin_irqs_if_requested() {
	  [[ -n "$PIN_CPU" ]] || return 0

	    if systemctl is-active --quiet irqbalance 2>/dev/null; then
		        echo "ERROR: irqbalance is active, but PIN_CPU=$PIN_CPU was requested."
			    echo "Run: sudo systemctl stop irqbalance"
			        echo "Then rerun this benchmark."
				    exit 1
				      fi

				        mapfile -t irqs < <(
					    awk -v iface="$IFACE" '
					          index($0, iface) && $0 ~ /TxRx/ {
						          gsub(":", "", $1)
							          print $1
								        }
									    ' /proc/interrupts
									      )

									        if (( ${#irqs[@]} == 0 )); then
											    echo "ERROR: could not find a TxRx IRQ for $IFACE in /proc/interrupts"
											        grep -i "$IFACE" /proc/interrupts || true
												    exit 1
												      fi

												        echo "Pinning $IFACE TxRx IRQ(s) to CPU $PIN_CPU:"
													  for irq in "${irqs[@]}"; do
														      echo "$PIN_CPU" > "/proc/irq/$irq/smp_affinity_list"
														          printf '  IRQ %s -> ' "$irq"
															      cat "/proc/irq/$irq/smp_affinity_list"
															        done
															}

															pin_irqs_if_requested

															KCSV="$RESULTS/${WORKLOAD}_${MODE}_kfunc_abba_v2.csv"
															NCSV="$RESULTS/${WORKLOAD}_${MODE}_native_abba_v2.csv"
															ALLCSV="$RESULTS/${WORKLOAD}_${MODE}_sequence_abba_v2.csv"

															HEADER="seq,block,position,workload,mode,variant,prog_id,elapsed_s,bpf_delta_run_cnt,mpps,bpf_delta_run_time_ns,ns_per_pkt,pmc_pre_runs,pmc_post_runs,pmc_delta_runs,pmc_pre_value,pmc_post_value,pmc_delta_value,pmc_cycles_per_run,pmc_run_ratio,window_cpu_count,window_cpus,cpu_valid,pmc_valid,cumulative_final_cycles_per_pkt"
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

																												    get_total_field() {
																													      local file="$1" key="$2"
																													        awk -v key="$key" '
																														    /TOTAL_RUNS=/ {
																														          for (i = 1; i <= NF; i++) {
																																          split($i, a, "=")
																																	          if (a[1] == key) v=a[2]
																																			        }
																																				    }
																																				        END {
																																					      if (v == "") exit 1
																																						            print v
																																							        }
																																								  ' "$file"
																																							  }

																																							  # Compare per-CPU run0 values from two verify_inxpect_map snapshots.
																																							  # Prints: "<count> <cpu-list>", where cpu-list uses ";" as separator.
																																							  window_cpu_delta() {
																																								    local pre="$1" post="$2"
																																								      python3 - "$pre" "$post" <<'PY'
import re
import sys

def parse(path):
    d = {}
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = re.search(r"\bcpu=(\d+)\b.*\brun0=(\d+)\b", line)
            if m:
                d[int(m.group(1))] = int(m.group(2))
    return d

a = parse(sys.argv[1])
b = parse(sys.argv[2])
active = []
for cpu in sorted(set(a) | set(b)):
    if b.get(cpu, 0) - a.get(cpu, 0) > 0:
        active.append(cpu)

print(len(active), ";".join(map(str, active)) if active else "none")
PY
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
									    local premap="$RESULTS/${WORKLOAD}_${MODE}_${tag}_map_pre.txt"
									      local postmap="$RESULTS/${WORKLOAD}_${MODE}_${tag}_map_post.txt"

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

																																			    # Allow event setup / map activation to complete before the actual warm-up.
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

																																										        # -----------------------------------------------------------------------
																																											  # NEW IN V2:
																																											    # snapshot InXpect's aggregation map *after* warm-up, before measurement.
																																											      # This discards startup/transient values from the primary PMC metric.
																																											        # -----------------------------------------------------------------------
																																												  if ! "$BUILD/verify_inxpect_map" "$COUNTER" require-runs >"$premap"; then
																																													      cat "$premap" || true
																																													          echo "--- InXpect log ---"
																																														      cat "$ilog"
																																														          echo "ERROR: pre-window InXpect map snapshot failed"
																																															      return 1
																																															        fi

																																																  local pmc_pre_runs pmc_pre_value
																																																    pmc_pre_runs="$(get_total_field "$premap" TOTAL_RUNS)"
																																																      pmc_pre_value="$(get_total_field "$premap" TOTAL_VALUE)"

																																																        echo "PMC PRE : runs=$pmc_pre_runs value=$pmc_pre_value"

																																																	  local c0 t0 c1 t1 start end elapsed delta mpps ns
																																																	    c0="$(get_field "$id" run_cnt)"
																																																	      t0="$(get_field "$id" run_time_ns)"

																																																	        start="$(date +%s.%N)"
																																																		  sleep "$WINDOW"
																																																		    end="$(date +%s.%N)"

																																																		      c1="$(get_field "$id" run_cnt)"
																																																		        t1="$(get_field "$id" run_time_ns)"

																																																			  # Snapshot immediately after the benchmark window, while InXpect and
																																																			    # the BPF program are still alive.
																																																			      if ! "$BUILD/verify_inxpect_map" "$COUNTER" require-runs >"$postmap"; then
																																																				          cat "$postmap" || true
																																																					      echo "--- InXpect log ---"
																																																					          cat "$ilog"
																																																						      echo "ERROR: post-window InXpect map snapshot failed"
																																																						          return 1
																																																							    fi

																																																							      local pmc_post_runs pmc_post_value
																																																							        pmc_post_runs="$(get_total_field "$postmap" TOTAL_RUNS)"
																																																								  pmc_post_value="$(get_total_field "$postmap" TOTAL_VALUE)"

																																																								    echo "PMC POST: runs=$pmc_post_runs value=$pmc_post_value"

																																																								      read -r elapsed delta mpps ns <<<"$(python3 - "$start" "$end" "$c0" "$c1" "$t0" "$t1" <<'PY'
import sys
s,e,c0,c1,t0,t1=sys.argv[1:]
elapsed=float(e)-float(s)
d=int(c1)-int(c0)
dt=int(t1)-int(t0)
print(f"{elapsed:.6f} {d} {d/elapsed/1e6:.6f} {dt/d if d else 0:.6f}")
PY
)"

  local pmc_delta_runs pmc_delta_value pmc_cpr pmc_ratio pmc_valid
    read -r pmc_delta_runs pmc_delta_value pmc_cpr pmc_ratio pmc_valid <<<"$(
        python3 - "$pmc_pre_runs" "$pmc_post_runs" \
		              "$pmc_pre_value" "$pmc_post_value" "$delta" <<'PY'
import sys
r0,r1,v0,v1,bpf = map(int, sys.argv[1:])
dr = r1-r0
dv = v1-v0
valid = int(dr > 0 and dv >= 0 and bpf > 0)
cpr = (dv/dr) if dr > 0 and dv >= 0 else float("nan")
ratio = (dr/bpf) if bpf > 0 else float("nan")
print(dr, dv, f"{cpr:.6f}", f"{ratio:.6f}", valid)
PY
  )"

    local cpu_count cpu_list cpu_valid
      read -r cpu_count cpu_list <<<"$(window_cpu_delta "$premap" "$postmap")"

        cpu_valid=1
	  if [[ -n "$PIN_CPU" ]]; then
		      if [[ "$cpu_count" != "1" || "$cpu_list" != "$PIN_CPU" ]]; then
			            cpu_valid=0
				        fi
					  elif [[ "$STRICT_SINGLE_CPU" == "1" && "$cpu_count" != "1" ]]; then
						      cpu_valid=0
						        fi

							  printf 'MEASURED: %8.4f Mpps  %9.3f ns/pkt  packets=%s\n' "$mpps" "$ns" "$delta"
							    printf 'PMC WINDOW: %.3f cycles/run  delta_runs=%s  delta_value=%s  run_ratio=%.4f  CPUs=%s\n' \
								        "$pmc_cpr" "$pmc_delta_runs" "$pmc_delta_value" "$pmc_ratio" "$cpu_list"

							      if [[ "$MODE" == "full" ]]; then
								          python3 - "$pmc_ratio" <<'PY'
import sys
x=float(sys.argv[1])
if not (0.90 <= x <= 1.10):
    print(f"WARNING: InXpect delta_run_cnt / BPF delta_run_cnt = {x:.4f}; expected about 1.0 in full mode.")
PY
  fi

    if [[ "$cpu_valid" != "1" ]]; then
	        echo "WARNING: CPU validation failed: count=$cpu_count cpus=$cpu_list expected=${PIN_CPU:-single-CPU}"
		    if [[ "$STRICT_SINGLE_CPU" == "1" ]]; then
			          echo "ERROR: STRICT_SINGLE_CPU=1; rejecting this measurement."
				        return 1
					    fi
					      fi

					        # Stop InXpect after the post-window snapshot. Its cumulative final report
						  # is kept only as a diagnostic; it is NOT the primary PMC metric anymore.
						    kill -TERM "$CURRENT_IPID" 2>/dev/null || true
						      wait "$CURRENT_IPID" 2>/dev/null || true
						        CURRENT_IPID=""

							  echo "InXpect cumulative final report ($variant, seq=$seq) [diagnostic only]:"
							    tail -20 "$ilog" || true

							      local cumulative_final_cyc
							        cumulative_final_cyc="$(awk '
								    /cycles:/ {
								          x=$3
									        gsub("/pkt","",x)
										      v=x
										          }
											      END { if (v != "") print v; else print "nan" }
											        ' "$ilog")"

												  local row
												    row="$seq,$block,$pos,$WORKLOAD,$MODE,$variant,$id,$elapsed,$delta,$mpps,$((t1-t0)),$ns,$pmc_pre_runs,$pmc_post_runs,$pmc_delta_runs,$pmc_pre_value,$pmc_post_value,$pmc_delta_value,$pmc_cpr,$pmc_ratio,$cpu_count,$cpu_list,$cpu_valid,$pmc_valid,$cumulative_final_cyc"

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
																    echo "Full InXpect balanced ABBA benchmark V2"
																    echo "workload=$WORKLOAD mode=$MODE iface=$IFACE"
																    echo "blocks=$BLOCKS -> $((BLOCKS * 2)) measurements/variant"
																    echo "window=${WINDOW}s warmup=${WARMUP}s gap=${GAP}s"
																    echo "Primary PMC metric: delta(TOTAL_VALUE)/delta(TOTAL_RUNS)"
																    echo "                    over the benchmark window only"
																    echo "Pattern alternates:"
																    echo "  odd blocks : Native Kfunc Kfunc Native"
																    echo "  even blocks: Kfunc Native Native Kfunc"
																    [[ "$MODE" == sampled ]] && echo "sampling interval = 2^$SAMPLE_EXP packets"
																    [[ -n "$PIN_CPU" ]] && echo "IRQ pinning requested: CPU $PIN_CPU"
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

def vals(rs, key, valid_only=False):
    out=[]
    for r in rs:
        if valid_only and r.get("pmc_valid") != "1":
            continue
        try:
            x=float(r[key])
            if math.isfinite(x):
                out.append(x)
        except Exception:
            pass
    return out

def sd(x):
    return statistics.stdev(x) if len(x) > 1 else 0.0

def mean_or_nan(x):
    return statistics.mean(x) if x else float("nan")

def describe(name, rs):
    m=vals(rs,"mpps")
    t=vals(rs,"ns_per_pkt")
    c=vals(rs,"pmc_cycles_per_run", valid_only=True)
    print(
        f"{name:7s}: "
        f"{mean_or_nan(m):.6f} ± {sd(m):.6f} Mpps; "
        f"{mean_or_nan(t):.6f} ± {sd(t):.6f} ns/pkt; "
        f"{mean_or_nan(c):.3f} ± {sd(c):.3f} PMC cycles/run"
    )

describe("kfunc", k)
describe("native", n)

km=mean_or_nan(vals(k,"mpps"))
nm=mean_or_nan(vals(n,"mpps"))
kt=mean_or_nan(vals(k,"ns_per_pkt"))
nt=mean_or_nan(vals(n,"ns_per_pkt"))
kc=mean_or_nan(vals(k,"pmc_cycles_per_run", valid_only=True))
nc=mean_or_nan(vals(n,"pmc_cycles_per_run", valid_only=True))

print()
print(f"Native vs kfunc throughput: {(nm/km-1)*100:+.2f}%")
print(f"Native vs kfunc ns/pkt:     {(nt/kt-1)*100:+.2f}% ({nt-kt:+.3f} ns/pkt)")
print(f"Native vs kfunc PMC window: {(nc/kc-1)*100:+.2f}% ({nc-kc:+.3f} cycles/run)")

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

    bk=mean_or_nan(vals(kr,"mpps"))
    bn=mean_or_nan(vals(nr,"mpps"))
    bkt=mean_or_nan(vals(kr,"ns_per_pkt"))
    bnt=mean_or_nan(vals(nr,"ns_per_pkt"))
    bkc=mean_or_nan(vals(kr,"pmc_cycles_per_run", valid_only=True))
    bnc=mean_or_nan(vals(nr,"pmc_cycles_per_run", valid_only=True))

    dm=(bn/bk-1)*100
    dt=(bnt/bkt-1)*100
    dc=(bnc/bkc-1)*100

    d_mpps.append(dm)
    d_ns.append(dt)
    d_cyc.append(dc)

    print(
        f"  block {b:2d}: throughput {dm:+.2f}% | "
        f"ns/pkt {dt:+.2f}% | PMC-window {dc:+.2f}%"
    )

print()
print(
    "Paired-block mean: "
    f"throughput {statistics.mean(d_mpps):+.2f}% ± {sd(d_mpps):.2f} pp | "
    f"ns/pkt {statistics.mean(d_ns):+.2f}% ± {sd(d_ns):.2f} pp | "
    f"PMC-window {statistics.mean(d_cyc):+.2f}% ± {sd(d_cyc):.2f} pp"
)

bad_cpu=[r for r in allrows if r.get("cpu_valid") != "1"]
bad_pmc=[r for r in allrows if r.get("pmc_valid") != "1"]

print()
print(f"Validation: {len(bad_cpu)} CPU-warning measurement(s); {len(bad_pmc)} structurally invalid PMC measurement(s).")
if bad_cpu:
    print("CPU warnings:")
    for r in bad_cpu:
        print(f"  seq={r['seq']} variant={r['variant']} CPUs={r['window_cpus']}")
PY

echo
echo "[DONE]"
echo "Sequence CSV: $ALLCSV"
echo "Kfunc CSV   : $KCSV"
echo "Native CSV  : $NCSV"
echo "Logs/maps   : $RESULTS"

