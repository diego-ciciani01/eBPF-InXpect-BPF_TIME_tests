#!/usr/bin/env python3
"""Patch exactly N custom BPF_TIME/RDTSC insns in an ELF section to RDPMC.

Expected unpatched custom instruction encoding (8-byte eBPF insn):
  code=0xf7, off=0, imm=0
Patched encoding:
  code=0xf7, off=1, imm=<counter>

No pyelftools dependency is required.
"""
from __future__ import annotations
import argparse
import pathlib
import struct
import sys

ELF64_SHDR = struct.Struct('<IIQQQQIIQQ')


def cstr(blob: bytes, off: int) -> str:
    end = blob.find(b'\0', off)
    if end < 0:
        end = len(blob)
    return blob[off:end].decode('utf-8', errors='replace')


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('input')
    ap.add_argument('output')
    ap.add_argument('--section', default='xdp')
    ap.add_argument('--counter', type=int, default=0)
    ap.add_argument('--expected', type=int, default=2)
    args = ap.parse_args()

    if not 0 <= args.counter <= 0x7fffffff:
        ap.error('counter must fit signed BPF imm32')

    data = bytearray(pathlib.Path(args.input).read_bytes())
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1:
        raise RuntimeError('Expected ELF64 little-endian object')

    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
    if e_shentsize < ELF64_SHDR.size:
        raise RuntimeError('Unexpected section-header size')

    shdrs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        shdrs.append(ELF64_SHDR.unpack_from(data, off))

    shstr = shdrs[e_shstrndx]
    shstr_off, shstr_size = shstr[4], shstr[5]
    names = bytes(data[shstr_off:shstr_off + shstr_size])

    target = None
    for sh in shdrs:
        name = cstr(names, sh[0])
        if name == args.section:
            target = sh
            break
    if target is None:
        available = [cstr(names, sh[0]) for sh in shdrs]
        raise RuntimeError(f'Section {args.section!r} not found. Sections: {available}')

    sec_off, sec_size = target[4], target[5]
    if sec_size % 8:
        raise RuntimeError(f'Section size {sec_size} is not a multiple of 8')

    matches = []
    for rel in range(0, sec_size, 8):
        p = sec_off + rel
        code = data[p]
        off16 = struct.unpack_from('<h', data, p + 2)[0]
        imm32 = struct.unpack_from('<i', data, p + 4)[0]
        if code == 0xF7 and off16 == 0 and imm32 == 0:
            matches.append((p, rel, bytes(data[p:p+8])))

    if len(matches) != args.expected:
        raise RuntimeError(
            f'Expected exactly {args.expected} BPF_TIME/RDTSC instructions in '
            f'{args.section!r}, found {len(matches)}. Refusing to patch.'
        )

    for p, rel, before in matches:
        struct.pack_into('<h', data, p + 2, 1)              # off = RDPMC sub-op
        struct.pack_into('<i', data, p + 4, args.counter)   # imm = PMC index
        after = bytes(data[p:p+8])
        print(f'patch section+0x{rel:x}: {before.hex(" ")} -> {after.hex(" ")}')

    pathlib.Path(args.output).write_bytes(data)
    print(f'[OK] wrote {args.output}; patched={len(matches)}, counter={args.counter}')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f'ERROR: {e}', file=sys.stderr)
        raise
