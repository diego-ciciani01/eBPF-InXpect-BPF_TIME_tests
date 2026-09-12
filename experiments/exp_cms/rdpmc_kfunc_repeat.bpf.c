#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define COUNTER 0

extern __u64 bpf_mykperf__rdpmc(__u64 counter) __ksym;

SEC("socket")
int rdpmc_kfunc_repeat(struct __sk_buff *skb)
{
    __u64 v0, v1, v2, v3;
    __u64 v4, v5, v6, v7;
    __u64 v8, v9, v10, v11;
    __u64 v12, v13, v14, v15;
    __u64 guard;

    v0  = bpf_mykperf__rdpmc(COUNTER);
    v1  = bpf_mykperf__rdpmc(COUNTER);
    v2  = bpf_mykperf__rdpmc(COUNTER);
    v3  = bpf_mykperf__rdpmc(COUNTER);
    v4  = bpf_mykperf__rdpmc(COUNTER);
    v5  = bpf_mykperf__rdpmc(COUNTER);
    v6  = bpf_mykperf__rdpmc(COUNTER);
    v7  = bpf_mykperf__rdpmc(COUNTER);
    v8  = bpf_mykperf__rdpmc(COUNTER);
    v9  = bpf_mykperf__rdpmc(COUNTER);
    v10 = bpf_mykperf__rdpmc(COUNTER);
    v11 = bpf_mykperf__rdpmc(COUNTER);
    v12 = bpf_mykperf__rdpmc(COUNTER);
    v13 = bpf_mykperf__rdpmc(COUNTER);
    v14 = bpf_mykperf__rdpmc(COUNTER);
    v15 = bpf_mykperf__rdpmc(COUNTER);

    /*
     * Force LLVM to keep all intermediate kfunc calls/results.
     */
    guard =
        v1 ^ v2 ^ v3 ^ v4 ^
        v5 ^ v6 ^ v7 ^ v8 ^
        v9 ^ v10 ^ v11 ^ v12 ^
        v13 ^ v14;

    /*
     * Artificial dependency so guard cannot simply disappear.
     * This branch should practically never be taken.
     */
    if (guard == 0xffffffffffffffffULL)
        return 0;

    /*
     * 16 reads -> 15 inter-read intervals.
     */
    return (__u32)(v15 - v0);
}

char LICENSE[] SEC("license") = "GPL";
