#!/usr/bin/env bash
set -euo pipefail

BPFFS=/sys/fs/bpf

BASE_PIN="$BPFFS/cms_custom"
NATIVE_PIN="$BPFFS/cms_native_custom_rdpmc"
KFUNC_PIN="$BPFFS/cms_kfunc_custom_rdpmc"

sudo rm -f \
    "$BASE_PIN" \
    "$NATIVE_PIN" \
    "$KFUNC_PIN"

echo "Loading baseline..."
sudo bpftool prog load \
    cms_custom.bpf.o \
    "$BASE_PIN"

echo "Loading native RDPMC..."
sudo bpftool prog load \
    cms_native_custom_rdpmc.bpf.o \
    "$NATIVE_PIN"

echo "Loading kfunc RDPMC..."
sudo bpftool prog load \
    cms_kfunc_custom_rdpmc.bpf.o \
    "$KFUNC_PIN"

echo
echo "========================================"
echo "Loaded programs"
echo "========================================"

echo
echo "[BASELINE]"
sudo bpftool prog show pinned "$BASE_PIN"

echo
echo "[NATIVE]"
sudo bpftool prog show pinned "$NATIVE_PIN"

echo
echo "[KFUNC]"
sudo bpftool prog show pinned "$KFUNC_PIN"

echo
echo "Native JIT RDPMC count:"
sudo bpftool prog dump jited pinned "$NATIVE_PIN" |
    grep -c rdpmc || true

echo
echo "Native JIT relevant instructions:"
sudo bpftool prog dump jited pinned "$NATIVE_PIN" |
    grep -E 'rdpmc|lfence' || true
