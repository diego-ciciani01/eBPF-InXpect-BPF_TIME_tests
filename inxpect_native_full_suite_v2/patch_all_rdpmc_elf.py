#!/usr/bin/env python3
"""Patch every custom BPF_TIME/RDTSC instruction in one BPF ELF section to RDPMC.

Unpatched instruction: code=0xf7, off=0, imm=0
Patched instruction:   code=0xf7, off=1, imm=<counter>

Unlike the earlier bare benchmark patcher, this intentionally patches all call
sites because full InXpect sources can have more than one END_TRACE expansion.
"""
from __future__ import annotations
import argparse, pathlib, struct, sys
ELF64_SHDR = struct.Struct('<IIQQQQIIQQ')

def cstr(blob: bytes, off: int) -> str:
    end = blob.find(b'\0', off)
    if end < 0: end = len(blob)
    return blob[off:end].decode('utf-8', errors='replace')

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('output')
    ap.add_argument('--section', default='xdp')
    ap.add_argument('--counter', type=int, default=0)
    ap.add_argument('--min-expected', type=int, default=2)
    args = ap.parse_args()
    data = bytearray(pathlib.Path(args.input).read_bytes())
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        raise RuntimeError('Expected ELF64 little-endian object')
    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
    shdrs = [ELF64_SHDR.unpack_from(data, e_shoff + i*e_shentsize) for i in range(e_shnum)]
    shstr = shdrs[e_shstrndx]
    names = bytes(data[shstr[4]:shstr[4]+shstr[5]])
    target = None
    for sh in shdrs:
        if cstr(names, sh[0]) == args.section:
            target = sh; break
    if target is None:
        raise RuntimeError(f"Section {args.section!r} not found")
    sec_off, sec_size = target[4], target[5]
    matches = []
    for rel in range(0, sec_size, 8):
        p = sec_off + rel
        code = data[p]
        off16 = struct.unpack_from('<h', data, p+2)[0]
        imm32 = struct.unpack_from('<i', data, p+4)[0]
        if code == 0xF7 and off16 == 0 and imm32 == 0:
            matches.append((p, rel, bytes(data[p:p+8])))
    if len(matches) < args.min_expected:
        raise RuntimeError(f"Expected at least {args.min_expected} BPF_TIME sites, found {len(matches)}")
    for p, rel, before in matches:
        struct.pack_into('<h', data, p+2, 1)
        struct.pack_into('<i', data, p+4, args.counter)
        print(f"patch xdp+0x{rel:x}: {before.hex(' ')} -> {bytes(data[p:p+8]).hex(' ')}")
    pathlib.Path(args.output).write_bytes(data)
    print(f"[OK] wrote {args.output}; patched={len(matches)} counter={args.counter}")
    return 0

if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise
