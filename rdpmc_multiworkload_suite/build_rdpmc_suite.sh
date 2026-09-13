#!/usr/bin/env bash
set -euo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${1:-$(pwd)}"
ROOT="$(cd "$ROOT" && pwd)"
CLANG="${CLANG:-$HOME/llvm-project/build/bin/clang}"
COUNTER="${COUNTER:-0}"
GEN="$ROOT/generated_rdpmc"
BUILD="$ROOT/build_rdpmc"

if [[ ! -x "$CLANG" ]]; then
    echo "ERROR: custom clang not found/executable: $CLANG" >&2
    exit 1
fi

python3 "$SUITE_DIR/generate_rdpmc_suite.py" \
    --root "$ROOT" --out "$GEN" --counter "$COUNTER"

rm -rf "$BUILD"
mkdir -p "$BUILD"

compile_one() {
    local workload="$1" src="$2" out="$3" srcdir="$4"
    mkdir -p "$(dirname "$out")"
    echo "[BUILD] $workload: $(basename "$out")"
    "$CLANG" -target bpf -O2 -g -w -c "$src" -o "$out" \
        -I "$srcdir" \
        -I "$ROOT/inxpect/kperf_" \
        -I /usr/include/x86_64-linux-gnu
}

for workload in drop nat routing tunnel; do
    case "$workload" in
        drop)    srcdir="$ROOT/experiments/exp_drop" ;;
        nat)     srcdir="$ROOT/experiments/exp_nat" ;;
        routing) srcdir="$ROOT/experiments/exp_routing" ;;
        tunnel)  srcdir="$ROOT/experiments/exp_tunnel" ;;
    esac

    outdir="$BUILD/$workload"
    mkdir -p "$outdir"

    compile_one "$workload" "$GEN/$workload/baseline.bpf.c" \
        "$outdir/baseline.bpf.o" "$srcdir"
    compile_one "$workload" "$GEN/$workload/kfunc_rdpmc.bpf.c" \
        "$outdir/kfunc_rdpmc.bpf.o" "$srcdir"
    compile_one "$workload" "$GEN/$workload/native_rdpmc.bpf.c" \
        "$outdir/native_unpatched.bpf.o" "$srcdir"

    python3 "$SUITE_DIR/patch_rdpmc_elf.py" \
        "$outdir/native_unpatched.bpf.o" \
        "$outdir/native_rdpmc.bpf.o" \
        --counter "$COUNTER" --expected 2

done

# The routing loader expects the map files. Extract the authors' archive if needed.
ROUTE_DIR="$ROOT/experiments/exp_routing/mappe"
ROUTE_ZIP="$ROOT/experiments/exp_routing/mappe.zip"
if [[ ! -d "$ROUTE_DIR" && -f "$ROUTE_ZIP" ]]; then
    echo "[PREP] extracting routing tables from mappe.zip"
    (cd "$ROOT/experiments/exp_routing" && unzip -q -o mappe.zip)
fi

# Generic libbpf loader used by the benchmark runner.
clang -O2 -Wall -Wextra \
   "$SUITE_DIR/suite_loader.c" \
   -I "$ROOT/experiments/exp_tunnel" \
   -o "$BUILD/suite_loader" \
   -l:libbpf.so.1 -lelf -lz


echo
echo "[OK] Build complete: $BUILD"
echo "Objects:"
find "$BUILD" -maxdepth 2 -name '*.bpf.o' -print | sort
