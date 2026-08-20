#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int drop_native(struct xdp_md *ctx)
{
    __u64 ts = __builtin_readcyclecounter();

    if (ts == 0)
        return XDP_ABORTED;

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
