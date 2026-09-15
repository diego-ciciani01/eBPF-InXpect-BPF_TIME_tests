#!/usr/bin/env python3
from __future__ import annotations
import argparse, pathlib, re, shutil, sys

WORKLOADS = {
    "drop": {
        "dir": "experiments/exp_drop",
        "full": "drop_kfunc.bpf.c",
        "sampled": "drop_sr.bpf.c",
        "native_full_name": "drop_ninx",
        "native_sampled_name": "drop_nsr",
    },
    "cms": {
        "dir": "experiments/exp_cms",
        "full": "cms_kfunc.bpf.c",
        "sampled": "cms_sr.bpf.c",
        "native_full_name": "cms_ninx",
        "native_sampled_name": "cms_nsr",
    },
    "nat": {
        "dir": "experiments/exp_nat",
        "full": "xdp_nat_kfunc.bpf.c",
        "sampled": "xdp_nat_sr.bpf.c",
        "native_full_name": "nat_ninx",
        "native_sampled_name": "nat_nsr",
    },
    "routing": {
        "dir": "experiments/exp_routing",
        "full": "lpmtrie_kfunc.bpf.c",
        "sampled": "lpmtrie_sr.bpf.c",
        "native_full_name": "route_ninx",
        "native_sampled_name": "route_nsr",
    },
    "tunnel": {
        "dir": "experiments/exp_tunnel",
        "full": "tunnel_kfunc.bpf.c",
        "sampled": "tunnel_sr.bpf.c",
        "native_full_name": "tunnel_ninx",
        "native_sampled_name": "tunnel_nsr",
    },
}

XDP_RE = re.compile(r'(SEC\("xdp"\)\s*\n\s*int\s+)([A-Za-z_][A-Za-z0-9_]*)(\s*\()')


def generate_header(root: pathlib.Path, out: pathlib.Path, counter: int) -> pathlib.Path:
    src = root / "inxpect/kperf_/mykperf_module.h"
    if not src.exists():
        raise FileNotFoundError(src)
    text = src.read_text()

    # Remove only the kfunc declaration embedded in BPF_MYKPERF_INIT_TRACE().
    lines = text.splitlines(keepends=True)
    new_lines = []
    removed = 0
    for line in lines:
        if "bpf_mykperf__rdpmc" in line and "__ksym" in line:
            removed += 1
            continue
        new_lines.append(line)
    if removed != 1:
        raise RuntimeError(f"Expected to remove exactly one rdpmc __ksym declaration, removed={removed}")
    text = "".join(new_lines)

    marker = "#include <linux/if_link.h>"
    if marker not in text:
        raise RuntimeError(f"Could not find header insertion marker in {src}")
    native = f'''\n\n/* Native-RDPMC InXpect specialization.\n * The current BPF_TIME_RDPMC prototype encodes the PMC selector in the\n * instruction immediate, so this header is intentionally single-counter.\n * Userspace still configures/activates the InXpect section and programs the\n * PMU; the benchmark runner verifies that InXpect allocated PMC{counter}.\n */\n#define MYKPERF_NATIVE_FIXED_COUNTER {counter}\n#define bpf_mykperf__rdpmc(counter_ignored) __builtin_readcyclecounter()\n'''
    text = text.replace(marker, marker + native, 1)
    dst = out / "include/mykperf_module_native.h"
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(text)
    return dst


def xdp_name(text: str) -> str:
    m = XDP_RE.search(text)
    if not m:
        raise RuntimeError("Unable to find SEC(\"xdp\") program function")
    return m.group(2)


def native_source(text: str, new_name: str) -> tuple[str, str]:
    if '#include "mykperf_module.h"' not in text:
        raise RuntimeError('Source does not include "mykperf_module.h"')
    old = xdp_name(text)
    text = text.replace('#include "mykperf_module.h"', '#include "mykperf_module_native.h"', 1)
    text, n = XDP_RE.subn(lambda m: m.group(1) + new_name + m.group(3), text, count=1)
    if n != 1:
        raise RuntimeError(f"Failed to rename XDP function {old} -> {new_name}")
    return text, old


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", help="eBPF-InXpect-BPF_TIME_tests repository root")
    ap.add_argument("out", help="generated source directory")
    ap.add_argument("--counter", type=int, default=0)
    args = ap.parse_args()
    root = pathlib.Path(args.root).resolve()
    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    generate_header(root, out, args.counter)

    manifest = ["workload\tmode\tsrcdir\tkfunc_src\tnative_src\tkfunc_prog\tnative_prog"]
    built = 0
    for workload, cfg in WORKLOADS.items():
        srcdir = root / cfg["dir"]
        if not srcdir.exists():
            print(f"[SKIP] {workload}: {srcdir} missing")
            continue
        wout = out / workload
        wout.mkdir(parents=True, exist_ok=True)
        for mode, key, nkey in [
            ("full", "full", "native_full_name"),
            ("sampled", "sampled", "native_sampled_name"),
        ]:
            src = srcdir / cfg[key]
            if not src.exists():
                print(f"[SKIP] {workload}/{mode}: {src.name} missing")
                continue
            original = src.read_text()
            kfunc_prog = xdp_name(original)
            kdst = wout / f"kfunc_{mode}.bpf.c"
            kdst.write_text(original)
            ntext, _ = native_source(original, cfg[nkey])
            ndst = wout / f"native_{mode}.bpf.c"
            ndst.write_text(ntext)
            manifest.append("\t".join([
                workload, mode, str(srcdir), str(kdst), str(ndst),
                kfunc_prog, cfg[nkey]
            ]))
            print(f"[OK] {workload:8s}/{mode:7s}: {kfunc_prog} -> {cfg[nkey]}")
            built += 1

    (out / "manifest.tsv").write_text("\n".join(manifest) + "\n")
    print(f"Generated {built} mode/workload pairs in {out}")
    print(f"Native fixed PMC index: {args.counter}")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise
