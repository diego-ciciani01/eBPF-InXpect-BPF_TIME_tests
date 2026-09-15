V2 build fix
============
The original build script compiled full and sampled variants in manifest order.
On the supplied repository, experiments/exp_nat/xdp_nat_sr.bpf.c contains three
pointer-to-integer assignments involving free_port_p, so a modern custom Clang
stops while compiling NAT/sampled. Because the script uses `set -e`, helper
binaries full_loader and verify_inxpect_map were never reached.

For the end-to-end no-sampling experiment, sampled objects are unnecessary.
V2 therefore adds BUILD_MODE=full|sampled|all and defaults to BUILD_MODE=full.

Recommended now:
  COUNTER=0 BUILD_MODE=full ./inxpect_native_full_suite_v2/build_full_inxpect_suite.sh .

This compiles all five full variants and the helper binaries while leaving the
original experiment sources untouched.
