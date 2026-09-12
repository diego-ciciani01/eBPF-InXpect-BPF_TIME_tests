#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

extern __u64 bpf_mykperf__rdpmc(__u64 counter) __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} delta_map SEC(".maps");

SEC("xdp")
int rdpmc_kfunc_min(struct xdp_md *ctx)
{
    __u64 start;
    __u64 end;
    __u64 delta;
    __u32 key = 0;

    start = bpf_mykperf__rdpmc(0);
    end   = bpf_mykperf__rdpmc(0);

    delta = end - start;

    bpf_map_update_elem(&delta_map, &key, &delta, BPF_ANY);

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
