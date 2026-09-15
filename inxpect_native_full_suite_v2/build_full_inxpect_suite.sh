#!/usr/bin/env bash
set -euo pipefail
ROOT="$(realpath "${1:-.}")"
SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN="$ROOT/generated_inxpect_native"
BUILD="$ROOT/build_inxpect_native"
COUNTER="${COUNTER:-0}"
BUILD_MODE="${BUILD_MODE:-full}"   # full | sampled | all
CLANG_BPF="${CUSTOM_CLANG:-$HOME/llvm-project/build/bin/clang}"
CC="${CC:-clang}"

[[ -x "$CLANG_BPF" ]] || { echo "ERROR: custom clang not found: $CLANG_BPF"; exit 1; }
[[ -f "$ROOT/inxpect/kperf_/mykperf_module.h" ]] || { echo "ERROR: missing InXpect headers"; exit 1; }
mkdir -p "$GEN" "$BUILD"
[[ "$BUILD_MODE" == full || "$BUILD_MODE" == sampled || "$BUILD_MODE" == all ]] || { echo "ERROR: BUILD_MODE must be full, sampled, or all"; exit 1; }
python3 "$SUITE_DIR/generate_native_inxpect.py" "$ROOT" "$GEN" --counter "$COUNTER"

echo "[INFO] compiling BPF variants with the SAME custom LLVM: $CLANG_BPF"
echo "[INFO] BUILD_MODE=$BUILD_MODE"
: > "$BUILD/program_names.tsv.tmp"
tail -n +2 "$GEN/manifest.tsv" | while IFS=$'\t' read -r workload mode srcdir ksrc nsrc kprog nprog; do
    if [[ "$BUILD_MODE" != all && "$mode" != "$BUILD_MODE" ]]; then
        continue
    fi
    out="$BUILD/$workload"; mkdir -p "$out"
    common=( -target bpf -g -w -O2 -c -I "$GEN/include" -I "$srcdir" -I "$ROOT/inxpect/kperf_" -I /usr/include/x86_64-linux-gnu )
    echo "[BUILD] $workload/$mode kfunc ($kprog)"
    "$CLANG_BPF" "${common[@]}" "$ksrc" -o "$out/kfunc_${mode}.bpf.o"
    echo "[BUILD] $workload/$mode native unpatched ($nprog)"
    "$CLANG_BPF" "${common[@]}" "$nsrc" -o "$out/native_${mode}_unpatched.bpf.o"
    python3 "$SUITE_DIR/patch_all_rdpmc_elf.py" \
        "$out/native_${mode}_unpatched.bpf.o" "$out/native_${mode}.bpf.o" \
        --counter "$COUNTER" --min-expected 2
    echo -e "$workload\t$mode\t$kprog\t$nprog" >> "$BUILD/program_names.tsv.tmp"
done
{
  echo -e "workload\tmode\tkfunc_prog\tnative_prog"
  [[ -f "$BUILD/program_names.tsv.tmp" ]] && cat "$BUILD/program_names.tsv.tmp"
} > "$BUILD/program_names.tsv"
rm -f "$BUILD/program_names.tsv.tmp"

if [[ -f "$ROOT/experiments/exp_routing/mappe.zip" ]]; then
  rm -rf "$BUILD/routing_maps"
  mkdir -p "$BUILD/routing_maps"
  unzip -oq "$ROOT/experiments/exp_routing/mappe.zip" -d "$BUILD/routing_maps"
fi

echo "[BUILD] full_loader"
$CC -O2 -Wall -Wextra "$SUITE_DIR/full_loader.c" \
    -I "$ROOT/experiments/exp_tunnel" -o "$BUILD/full_loader" \
    -l:libbpf.so.1 -lelf -lz

echo "[BUILD] verify_inxpect_map"
$CC -O2 -Wall -Wextra "$SUITE_DIR/verify_inxpect_map.c" \
    -o "$BUILD/verify_inxpect_map" -l:libbpf.so.1 -lelf -lz

echo
 echo "[OK] Full-InXpect native suite built in $BUILD (BUILD_MODE=$BUILD_MODE)"
 echo "[IMPORTANT] Native objects are fixed to PMC index $COUNTER."
 echo "            Do NOT keep enable_cycles running; InXpect itself must program cycles."
