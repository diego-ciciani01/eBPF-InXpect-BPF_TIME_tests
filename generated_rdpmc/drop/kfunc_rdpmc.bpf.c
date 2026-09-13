#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

static __always_inline int drop__rdpmc_body(struct xdp_md *ctx)
{
    return XDP_DROP;
}
/* AUTO-GENERATED: kfunc bare RDPMC test.
 * Directly invokes the same InXpect kfunc used by the CMS comparison, without
 * InXpect maps/multiplexing/sampling, so the only mechanism difference versus
 * native is kfunc-call path vs native BPF_TIME_RDPMC.
 */
__u64 bpf_mykperf__rdpmc(__u8 counter) __ksym;

#define RDPMC_TEST_COUNTER 0

SEC("xdp")
int drop_krdpmc(struct xdp_md *ctx)
{
    __u64 __rdpmc_start = bpf_mykperf__rdpmc(RDPMC_TEST_COUNTER);
    int __rdpmc_ret = drop__rdpmc_body(ctx);
    __u64 __rdpmc_end = bpf_mykperf__rdpmc(RDPMC_TEST_COUNTER);

    if (__rdpmc_end == __rdpmc_start)
        return XDP_ABORTED;

    return __rdpmc_ret;
}


char _license[] SEC("license") = "GPL";