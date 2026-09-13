# Multi-workload native-RDPMC vs kfunc-RDPMC suite

This suite extends the CMS methodology to the four other InXpect paper workloads:
**Drop, NAT, Router (LPM trie), and Tunnel**.

## Methodological choice

Do **not** benchmark the repository's existing `*_kfunc.bpf.c` files against the
native variant for this experiment. Those sources contain the full InXpect
macro/multiplexing/map infrastructure and some instrument a different region of
the program. Instead, this suite derives both instrumented variants from the
same original baseline source:

- baseline: authors' source, unchanged, compiled with the same custom LLVM;
- native: two `BPF_TIME_RDPMC` reads around the whole XDP entry;
- kfunc: two direct `bpf_mykperf__rdpmc(0)` calls around the same XDP entry.

The native and kfunc variants use the same anti-DCE check as the CMS bare test.
The InXpect kfunc already executes `lfence; rdpmc; lfence`, and the custom native
JIT is expected to emit the same fenced sequence.

## 1. Copy/extract this directory into the repository

Example repository root:

```bash
cd ~/eBPF-InXpect-BPF_TIME_tests
```

Assume this suite directory is available as `rdpmc_multiworkload_suite/`.

## 2. Keep the cycles event enabled

Use the same `enable_cycles` setup used for the CMS comparison and keep it alive.
It must configure **PMC0** for CPU cycles and report counter index `0`.

The generated objects default to `COUNTER=0`.

## 3. Build

```bash
cd ~/eBPF-InXpect-BPF_TIME_tests

./rdpmc_multiworkload_suite/build_rdpmc_suite.sh .
```

If needed:

```bash
CLANG=~/llvm-project/build/bin/clang COUNTER=0 \
  ./rdpmc_multiworkload_suite/build_rdpmc_suite.sh .
```

Outputs are placed in:

```text
build_rdpmc/drop/
build_rdpmc/nat/
build_rdpmc/routing/
build_rdpmc/tunnel/
```

Each contains `baseline.bpf.o`, `native_rdpmc.bpf.o`, and
`kfunc_rdpmc.bpf.o`. The build aborts unless exactly **two** custom BPF_TIME
instructions are found and patched in every native object.

## 4. Smoke test first

On the traffic-generator node, start the same 2M-flow UDP profile at 100%:

```text
start -f rand_udp_2m.py -m 100% -p 0 -d 1200
```

On the DUT, for a very quick validation you can temporarily run the full suite
with one 5-second window:

```bash
RUNS=1 WINDOW=5 GAP=1 WARMUP=5 \
IFACE=enp94s0f0np0 \
sudo -E ./rdpmc_multiworkload_suite/run_one_saturation.sh drop .
```

The native variant is automatically rejected if the JIT dump does not contain
exactly two `rdpmc` instructions.

## 5. Final saturation experiment

For the final data I recommend one workload at a time (restart TRex for each), e.g.:

```bash
RUNS=10 WINDOW=10 GAP=5 WARMUP=20 \
IFACE=enp94s0f0np0 \
sudo -E ./rdpmc_multiworkload_suite/run_one_saturation.sh drop .

RUNS=10 WINDOW=10 GAP=5 WARMUP=20 \
IFACE=enp94s0f0np0 \
sudo -E ./rdpmc_multiworkload_suite/run_one_saturation.sh routing .
```

Replace `drop` with `nat` or `tunnel` as needed. To run all four in one go, use
`run_saturation_suite.sh . all` and give TRex a much longer duration (at least
about one hour, because each workload has three variants and routing-map setup
also takes time).

The script runs, for every workload:

```text
baseline -> native RDPMC -> kfunc RDPMC
```

and records both maximum processed Mpps and `bpf_stats` ns/pkt. Results go to:

```text
results_rdpmc_multiworkload/
```

The final aggregate table is `summary_saturation.csv`.

## Workload map setup

The generic loader reproduces the setup present in the authors' userspace
loaders:

- Drop: no map setup;
- NAT: fresh NAT maps per loaded object;
- Routing: loads `experiments/exp_routing/mappe/{1..32}.txt`; `mappe.zip` is
  automatically extracted by the build script if needed;
- Tunnel: initializes key 0 of `vip2tnl` using the values from the authors'
  `tunnel.c` loader.

## Important NAT caveat

The supplied NAT program has `DEFAULT_MAX_ENTRIES_NAT_TABLE=100000`, whereas the
common synthetic workload uses 2M flows. A long warm-up can therefore drive the
NAT table to capacity and make later packets follow the map-update-failure path.
This affects all three variants equally when they are started from a fresh map,
but before using NAT as a strong thesis claim, inspect its return-path behavior
under the chosen trace. The suite intentionally does not silently change the
authors' NAT source or map size.

## Why Router/Tunnel are safer immediately

Router and Tunnel have explicit map initialization in the authors' loaders and
the suite reproduces it. Drop requires none. These three are therefore the best
first validation after CMS.
