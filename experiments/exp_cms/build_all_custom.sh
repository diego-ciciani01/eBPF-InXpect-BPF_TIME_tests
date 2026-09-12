#!/usr/bin/env bash
set -euo pipefail

CLANG="${CLANG:-$HOME/llvm-project/build/bin/clang}"
OBJCOPY="${OBJCOPY:-$HOME/llvm-project/build/bin/llvm-objcopy}"
OBJDUMP="${OBJDUMP:-$HOME/llvm-project/build/bin/llvm-objdump}"

COUNTER="${COUNTER:-0}"

CFLAGS=(
    -target bpf
    -g
    -w
    -O2
    -I ../../inxpect/kperf_
    -I /usr/include/x86_64-linux-gnu
)

echo "========================================"
echo "Compiler: $CLANG"
echo "RDPMC counter: $COUNTER"
echo "========================================"

# ---------------------------------------------------------
# 1. Baseline
# ---------------------------------------------------------

echo
echo "[1/3] Building baseline CMS..."

"$CLANG" "${CFLAGS[@]}" \
    -c cms.bpf.c \
    -o cms_custom.bpf.o

# ---------------------------------------------------------
# 2. Kfunc RDPMC
# ---------------------------------------------------------

echo
echo "[2/3] Building kfunc CMS..."

"$CLANG" "${CFLAGS[@]}" \
    -c cms_kfunc_bare_rdpmc.bpf.c \
    -o cms_kfunc_custom_rdpmc.bpf.o

# ---------------------------------------------------------
# 3. Native RDPMC
# ---------------------------------------------------------

echo
echo "[3/3] Building native CMS..."

"$CLANG" "${CFLAGS[@]}" \
    -c cms_native_rdpmc.bpf.c \
    -o cms_native_custom_unpatched.bpf.o

echo
echo "BPF_TIME instructions before patch:"

"$OBJDUMP" -d cms_native_custom_unpatched.bpf.o |
    grep 'f7 ' || true

"$OBJCOPY" \
    --dump-section xdp=/tmp/cms_native_custom_xdp.bin \
    cms_native_custom_unpatched.bpf.o

python3 - "$COUNTER" <<'PY'
from pathlib import Path
import struct
import sys

counter = int(sys.argv[1])

src = Path("/tmp/cms_native_custom_xdp.bin")
dst = Path("/tmp/cms_native_custom_xdp_rdpmc.bin")

data = bytearray(src.read_bytes())

if len(data) % 8:
    raise RuntimeError(
        f"XDP section size {len(data)} is not a multiple of 8"
    )

patched = []

for i in range(0, len(data), 8):

    code = data[i]

    if code != 0xf7:
        continue

    regs = data[i + 1]
    off = struct.unpack_from("<h", data, i + 2)[0]
    imm = struct.unpack_from("<i", data, i + 4)[0]

    print(
        f"found BPF_TIME: insn={i//8}, "
        f"regs=0x{regs:02x}, off={off}, imm={imm}"
    )

    if off != 0 or imm != 0:
        raise RuntimeError(
            f"Unexpected BPF_TIME encoding at instruction {i//8}"
        )

    # BPF_TIME_RDTSC -> BPF_TIME_RDPMC
    struct.pack_into("<h", data, i + 2, 1)

    # PMC selector
    struct.pack_into("<i", data, i + 4, counter)

    patched.append(i // 8)

if len(patched) != 2:
    raise RuntimeError(
        f"Expected exactly 2 BPF_TIME instructions; found {len(patched)}"
    )

dst.write_bytes(data)

print()
print("Patched instructions:", patched)
print("PMC counter:", counter)
PY

cp \
    cms_native_custom_unpatched.bpf.o \
    cms_native_custom_rdpmc.bpf.o

"$OBJCOPY" \
    --update-section \
    xdp=/tmp/cms_native_custom_xdp_rdpmc.bin \
    cms_native_custom_rdpmc.bpf.o


# ---------------------------------------------------------
# Validate native object
# ---------------------------------------------------------

"$OBJCOPY" \
    --dump-section xdp=/tmp/check_native_custom.bin \
    cms_native_custom_rdpmc.bpf.o

python3 - "$COUNTER" <<'PY'
from pathlib import Path
import struct
import sys

expected_counter = int(sys.argv[1])
data = Path("/tmp/check_native_custom.bin").read_bytes()

found = []

for i in range(0, len(data), 8):

    if data[i] != 0xf7:
        continue

    off = struct.unpack_from("<h", data, i + 2)[0]
    imm = struct.unpack_from("<i", data, i + 4)[0]

    print(
        f"validated BPF_TIME: "
        f"insn={i//8}, off={off}, imm={imm}"
    )

    if off != 1:
        raise RuntimeError("BPF_TIME is not RDPMC")

    if imm != expected_counter:
        raise RuntimeError(
            f"Wrong PMC: expected {expected_counter}, got {imm}"
        )

    found.append(i // 8)

if len(found) != 2:
    raise RuntimeError(
        f"Expected 2 patched instructions, found {len(found)}"
    )

print("Native object validation OK")
PY


echo
echo "========================================"
echo "Build complete"
echo "========================================"

ls -lh \
    cms_custom.bpf.o \
    cms_native_custom_rdpmc.bpf.o \
    cms_kfunc_custom_rdpmc.bpf.o
