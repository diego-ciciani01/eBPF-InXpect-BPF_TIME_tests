#!/usr/bin/env python3
"""
r bare-RDPMC variants from the authors' baseline XDP sources.

For each workload, this script creates:
  * a native source using __builtin_readcyclecounter() at entry/exit; the
    resulting BPF_TIME instructions are patched to RDPMC by patch_rdpmc_elf.py;
  * a kfunc source using two direct bpf_mykperf__rdpmc(counter) calls.

Both variants are derived from the *same baseline source*. Existing *_kfunc.bpf.c
files are intentionally not used because they include the full InXpect macro
infrastructure and, for some workloads, instrument different control-flow
regions.
"""

from __future__ import annotations
import argparse
import pathlib
import re
import sys

WORKLOADS = {
    "drop": {
        "src": "experiments/exp_drop/drop.bpf.c",
        "entry": "drop",
        "native_entry": "drop_nrdpmc",
        "kfunc_entry": "drop_krdpmc",
    },
    "nat": {
        "src": "experiments/exp_nat/xdp_nat.bpf.c",
        "entry": "xdp_nat",
        "native_entry": "nat_nrdpmc",
        "kfunc_entry": "nat_krdpmc",
    },
    "routing": {
        "src": "experiments/exp_routing/lpmtrie.bpf.c",
        "entry": "lpmtrie",
        "native_entry": "route_nrdpmc",
        "kfunc_entry": "route_krdpmc",
    },
    "tunnel": {
        "src": "experiments/exp_tunnel/tunnel.bpf.c",
        "entry": "tunnel",
        "native_entry": "tun_nrdpmc",
        "kfunc_entry": "tun_krdpmc",
    },
}


def rename_xdp_entry_to_inline_body(src: str, entry: str) -> tuple[str, str]:
    # These source files all have a single XDP entry with a struct xdp_md * arg.
    pat = re.compile(
        r'SEC\s*\(\s*"xdp"\s*\)\s*'
        r'int\s+' + re.escape(entry) + r'\s*\(\s*'
        r'struct\s+xdp_md\s*\*\s*(?P<arg>[A-Za-z_]\w*)\s*\)',
        re.MULTILINE,
    )
    m = pat.search(src)
    if not m:
        raise RuntimeError(f'Cannot find XDP entry function {entry!r}')
    if len(pat.findall(src)) != 1:
        raise RuntimeError(f'Expected exactly one XDP entry function {entry!r}')

    arg = m.group('arg')
    body_name = f"{entry}__rdpmc_body"
    replacement = f"static __always_inline int {body_name}(struct xdp_md *{arg})"
    out = src[:m.start()] + replacement + src[m.end():]
    return out, body_name


def insert_before_license(src: str, text: str) -> str:
    # Handles char LICENSE[] and char _license[].
    matches = list(re.finditer(
        r'(?m)^\s*char\s+[A-Za-z_]\w*\s*\[\s*\]\s*SEC\s*\(\s*"license"\s*\)',
        src,
    ))
    if not matches:
        raise RuntimeError('Cannot find SEC("license") declaration')
    pos = matches[-1].start()
    return src[:pos] + text.rstrip() + "\n\n" + src[pos:]



def make_baseline(src: str, entry: str) -> str:
    """Generate a control baseline with the same wrapper/body structure as
    native and kfunc variants. This avoids source-structure/codegen differences
    from confounding baseline-vs-instrumented comparisons.
    """
    src, body_name = rename_xdp_entry_to_inline_body(src, entry)
    wrapper = f'''\
/* AUTO-GENERATED: wrapped baseline control.
 * The original XDP body is forced inline into a thin XDP wrapper, matching the
 * source structure used by the native and kfunc RDPMC variants.
 */
SEC("xdp")
int {entry}(struct xdp_md *ctx)
{{
    return {body_name}(ctx);
}}
'''
    return insert_before_license(src, wrapper)

def make_native(src: str, entry: str, wrapper_name: str) -> str:
    src, body_name = rename_xdp_entry_to_inline_body(src, entry)
    wrapper = f'''\
/* AUTO-GENERATED: native bare RDPMC test.
 * __builtin_readcyclecounter() is first emitted by the custom LLVM as BPF_TIME
 * with off=0; patch_rdpmc_elf.py changes exactly these two instructions to
 * BPF_TIME_RDPMC (off=1, imm=<PMC index>).
 */
SEC("xdp")
int {wrapper_name}(struct xdp_md *ctx)
{{
    __u64 __rdpmc_start = __builtin_readcyclecounter();
    int __rdpmc_ret = {body_name}(ctx);
    __u64 __rdpmc_end = __builtin_readcyclecounter();

    /* Keep both counter reads live. This branch should never be taken for a
     * running cycles counter, and matches the CMS bare-RDPMC methodology. */
    if (__rdpmc_end == __rdpmc_start)
        return XDP_ABORTED;

    return __rdpmc_ret;
}}
'''
    return insert_before_license(src, wrapper)


def make_kfunc(src: str, entry: str, wrapper_name: str, counter: int) -> str:
    src, body_name = rename_xdp_entry_to_inline_body(src, entry)
    wrapper = f'''\
/* AUTO-GENERATED: kfunc bare RDPMC test.
 * Directly invokes the same InXpect kfunc used by the CMS comparison, without
 * InXpect maps/multiplexing/sampling, so the only mechanism difference versus
 * native is kfunc-call path vs native BPF_TIME_RDPMC.
 */
__u64 bpf_mykperf__rdpmc(__u8 counter) __ksym;

#define RDPMC_TEST_COUNTER {counter}

SEC("xdp")
int {wrapper_name}(struct xdp_md *ctx)
{{
    __u64 __rdpmc_start = bpf_mykperf__rdpmc(RDPMC_TEST_COUNTER);
    int __rdpmc_ret = {body_name}(ctx);
    __u64 __rdpmc_end = bpf_mykperf__rdpmc(RDPMC_TEST_COUNTER);

    if (__rdpmc_end == __rdpmc_start)
        return XDP_ABORTED;

    return __rdpmc_ret;
}}
'''
    return insert_before_license(src, wrapper)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default='.', help='Root of eBPF-InXpect-BPF_TIME_tests')
    ap.add_argument('--out', default='generated_rdpmc', help='Output directory')
    ap.add_argument('--counter', type=int, default=0, help='Programmable PMC index (default: 0)')
    args = ap.parse_args()

    if not 0 <= args.counter <= 5:
        ap.error('--counter must be in [0,5] for the current verifier implementation')

    root = pathlib.Path(args.root).resolve()
    out = pathlib.Path(args.out)
    if not out.is_absolute():
        out = root / out
    out.mkdir(parents=True, exist_ok=True)

    for workload, cfg in WORKLOADS.items():
        src_path = root / cfg['src']
        if not src_path.exists():
            raise FileNotFoundError(src_path)
        original = src_path.read_text()

        wout = out / workload
        wout.mkdir(parents=True, exist_ok=True)
        (wout / 'native_rdpmc.bpf.c').write_text(
            make_native(original, cfg['entry'], cfg['native_entry'])
        )
        (wout / 'kfunc_rdpmc.bpf.c').write_text(
            make_kfunc(original, cfg['entry'], cfg['kfunc_entry'], args.counter)
        )
        # Generate a wrapped baseline control so all three variants have the
        # same body/wrapper source structure and compiler optimization context.
        (wout / 'baseline.bpf.c').write_text(
            make_baseline(original, cfg['entry'])
        )
        print(f"[OK] {workload:8s}: {src_path.relative_to(root)} -> {wout}")

    print(f"\nGenerated sources in: {out}")
    print(f"RDPMC counter index: {args.counter}")
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise

