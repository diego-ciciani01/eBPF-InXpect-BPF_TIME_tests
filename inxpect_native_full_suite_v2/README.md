# Native RDPMC inside the full InXpect pipeline

This suite replaces **only InXpect's two `bpf_mykperf__rdpmc()` accesses** with the custom native `BPF_TIME_RDPMC` instruction, while retaining the rest of the InXpect path: section activation, PMU setup from userspace, sampling logic, map lookup, aggregation into `multiplexed_output`, userspace polling, and the existing `bpf_mykperf__fence()` call.

## Important limitation

The current thesis ISA prototype encodes the RDPMC selector as a BPF immediate (`off=1, imm=PMC index`). InXpect normally supports runtime-selected/multiplexed counters. Therefore this integration is intentionally a **single-event specialization**. The default build uses **PMC0**, and the runner aborts unless `./inxpect -e cycles` actually allocated PMC0. This is appropriate for the current cycles experiment, but it is not yet a drop-in replacement for arbitrary runtime multiplexing. A future `BPF_TIME_RDPMC | BPF_X` form could remove this limitation.

Do **not** run the separate `enable_cycles` helper during these tests. InXpect itself must program the cycles event.

## Build

From the repository root:

```bash
cd ~/eBPF-InXpect-BPF_TIME_tests

# Copy/extract this suite as ./inxpect_native_full_suite first.
COUNTER=0 ./inxpect_native_full_suite/build_full_inxpect_suite.sh .
```

It compiles both kfunc and native BPF variants with the same custom LLVM (`~/llvm-project/build/bin/clang` by default), patches every generated BPF_TIME site to RDPMC, builds a generic XDP loader, and builds a map verifier.

Make sure the existing InXpect userspace binary exists:

```bash
ls -lh inxpect/inxpect
```

If needed, build it with your already-fixed local InXpect tree.

## First smoke test: Drop, no sampling

Node1/TRex: use your validated 2M-flow profile at 100%.

Node0:

```bash
cd ~/eBPF-InXpect-BPF_TIME_tests
RUNS=1 WINDOW=5 GAP=1 WARMUP=5 \
IFACE=enp94s0f0np0 MODE=full \
sudo -E ./inxpect_native_full_suite/run_full_inxpect_saturation.sh drop .
```

The runner will:
1. load/attach the full InXpect kfunc object;
2. launch `inxpect -e cycles` so the `main` section is really active;
3. verify that PMC0 was allocated and that InXpect's own `run_cnt` becomes non-zero;
4. measure throughput and `bpf_stats` ns/pkt;
5. repeat with the native RDPMC object;
6. print the direct Native-vs-Kfunc improvement.

If this smoke test is clean, use:

```bash
RUNS=10 WINDOW=10 GAP=5 WARMUP=20 IFACE=enp94s0f0np0 MODE=full \
sudo -E ./inxpect_native_full_suite/run_full_inxpect_saturation.sh drop .
```

Then repeat for `cms`, `routing`, `tunnel`, and `nat`. For NAT use the validated **40k-flow** TRex profile so the 100k-entry NAT table stays at ~80k entries.

## Sampling experiment (optional but already supported)

The suite also generates native versions from the original `*_sr.bpf.c` sources. For one sample every 16 packets:

```bash
RUNS=10 WINDOW=10 GAP=5 WARMUP=20 \
IFACE=enp94s0f0np0 MODE=sampled SAMPLE_EXP=4 \
sudo -E ./inxpect_native_full_suite/run_full_inxpect_saturation.sh drop .
```

This compares the original InXpect kfunc sampling pipeline against the same pipeline with native RDPMC.

## Summarize all completed workloads

```bash
python3 ./inxpect_native_full_suite/summarize_full_inxpect.py \
    results_inxpect_native_full --mode full
```

For sampled results use `--mode sampled`.
