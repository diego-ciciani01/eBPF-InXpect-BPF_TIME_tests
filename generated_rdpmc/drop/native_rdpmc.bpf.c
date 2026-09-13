#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

static __always_inline int drop__rdpmc_body(struct xdp_md *ctx)
{
    return XDP_DROP;
}
/* AUTO-GENERATED: native bare RDPMC test.
 * __builtin_readcyclecounter() is first emitted by the custom LLVM as BPF_TIME
 * with off=0; patch_rdpmc_elf.py changes exactly these two instructions to
 * BPF_TIME_RDPMC (off=1, imm=<PMC index>).
 */
SEC("xdp")
int drop_nrdpmc(struct xdp_md *ctx)
{
    __u64 __rdpmc_start = __builtin_readcyclecounter();
    int __rdpmc_ret = drop__rdpmc_body(ctx);
    __u64 __rdpmc_end = __builtin_readcyclecounter();

    /* Keep both counter reads live. This branch should never be taken for a
     * running cycles counter, and matches the CMS bare-RDPMC methodology. */
    if (__rdpmc_end == __rdpmc_start)
        return XDP_ABORTED;

    return __rdpmc_ret;
}


char _license[] SEC("license") = "GPL";