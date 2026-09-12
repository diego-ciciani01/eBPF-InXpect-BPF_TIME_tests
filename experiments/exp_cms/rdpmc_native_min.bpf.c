#include <linux/bpf.h>




#define BPF_TIME_RDTSC 0
#define BPF_TIME_RDPMC 1

#define RDPMC_INSN(dst, counter)                  \
    ((struct bpf_insn){                           \
        .code = BPF_ALU64 | BPF_TIME | BPF_K,    \
        .dst_reg = (dst),                         \
        .src_reg = BPF_REG_0,                     \
        .off = BPF_TIME_RDPMC,                    \
        .imm = (counter),                         \
    })

struct bpf_insn prog[] = {
    /* #1 */
    RDPMC_INSN(BPF_REG_6, COUNTER),

    /* #2 - #15 */
    RDPMC_INSN(BPF_REG_7, COUNTER),
    RDPMC_INSN(BPF_REG_7, COUNTER),
    RDPMC_INSN(BPF_REG_7, COUNTER),
    RDPMC_INSN(BPF_REG_7, COUNTER),
    RDPMC_INSN(BPF_REG_7, COUNTER),
    RDPMC_INSN(BPF_REG_7, COUNTER),
    RDPMC_INSN(BPF_REG_7, COUNTER),
    RDPMC_INSN(BPF_REG_7, COUNTER),
    RDPMC_INSN(BPF_REG_7, COUNTER),
    RDPMC_INSN(BPF_REG_7, COUNTER),
    RDPMC_INSN(BPF_REG_7, COUNTER),
    RDPMC_INSN(BPF_REG_7, COUNTER),
    RDPMC_INSN(BPF_REG_7, COUNTER),
    RDPMC_INSN(BPF_REG_7, COUNTER),

    /* #16 */
    RDPMC_INSN(BPF_REG_0, COUNTER),

    /* R0 = read16 - read1 */
    {
        .code = BPF_ALU64 | BPF_SUB | BPF_X,
        .dst_reg = BPF_REG_0,
        .src_reg = BPF_REG_6,
    },

    {
        .code = BPF_JMP | BPF_EXIT,
    },
};

/* SEC("xdp") */
/* int rdpmc_native_min(struct xdp_md *ctx) */
/* { */
/*     __u64 start = __builtin_bpf_rdpmc(0);   /\* oppure il tuo builtin/opcode *\/ */
/*     __u64 end   = __builtin_bpf_rdpmc(0); */

/*     if (end == start) */
/*         return XDP_ABORTED; */

/*     return XDP_DROP; */
/* } */

/* char LICENSE[] SEC("license") = "GPL"; */
