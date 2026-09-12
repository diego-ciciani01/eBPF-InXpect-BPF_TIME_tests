#define _GNU_SOURCE

#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * Custom opcode from your kernel:
 *
 *   BPF_ALU64 | BPF_TIME | BPF_K
 *
 * BPF_TIME = 0xf0 -> final opcode 0xf7
 */
#ifndef BPF_TIME
#define BPF_TIME 0xf0
#endif

#define BPF_TIME_RDTSC 0
#define BPF_TIME_RDPMC 1

/*
 * After reboot enable_cycles returned:
 *
 *   RDPMC counter index = 1
 */
#define COUNTER 0

#define PIN_PATH "/sys/fs/bpf/rdpmc_native_repeat"

#define RDPMC_INSN(dst, counter)                \
    ((struct bpf_insn){                         \
        .code = BPF_ALU64 | BPF_TIME | BPF_K,   \
        .dst_reg = (dst),                       \
        .src_reg = BPF_REG_0,                   \
        .off = BPF_TIME_RDPMC,                  \
        .imm = (counter),                       \
    })

static struct bpf_insn prog[] = {
    /*
     * Read #1.
     *
     * Keep the first measurement in R6 so that it survives
     * all the following reads.
     */
    RDPMC_INSN(BPF_REG_6, COUNTER),

    /*
     * Reads #2 ... #15.
     *
     * Their values are intentionally discarded by repeatedly
     * overwriting R7. The instructions themselves remain in
     * the raw BPF instruction stream.
     */
    RDPMC_INSN(BPF_REG_7, COUNTER), /* #2  */
    RDPMC_INSN(BPF_REG_7, COUNTER), /* #3  */
    RDPMC_INSN(BPF_REG_7, COUNTER), /* #4  */
    RDPMC_INSN(BPF_REG_7, COUNTER), /* #5  */
    RDPMC_INSN(BPF_REG_7, COUNTER), /* #6  */
    RDPMC_INSN(BPF_REG_7, COUNTER), /* #7  */
    RDPMC_INSN(BPF_REG_7, COUNTER), /* #8  */
    RDPMC_INSN(BPF_REG_7, COUNTER), /* #9  */
    RDPMC_INSN(BPF_REG_7, COUNTER), /* #10 */
    RDPMC_INSN(BPF_REG_7, COUNTER), /* #11 */
    RDPMC_INSN(BPF_REG_7, COUNTER), /* #12 */
    RDPMC_INSN(BPF_REG_7, COUNTER), /* #13 */
    RDPMC_INSN(BPF_REG_7, COUNTER), /* #14 */
    RDPMC_INSN(BPF_REG_7, COUNTER), /* #15 */

    /*
     * Read #16 goes directly into R0.
     */
    RDPMC_INSN(BPF_REG_0, COUNTER),

    /*
     * R0 = read_16 - read_1
     *
     * Therefore the returned delta spans 15 inter-read intervals.
     */
    {
        .code = BPF_ALU64 | BPF_SUB | BPF_X,
        .dst_reg = BPF_REG_0,
        .src_reg = BPF_REG_6,
        .off = 0,
        .imm = 0,
    },

    {
        .code = BPF_JMP | BPF_EXIT,
        .dst_reg = 0,
        .src_reg = 0,
        .off = 0,
        .imm = 0,
    },
};

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int load_program(void)
{
    static char verifier_log[1024 * 1024];

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;

    attr.insn_cnt = sizeof(prog) / sizeof(prog[0]);
    attr.insns = (uint64_t)(uintptr_t)prog;

    attr.license = (uint64_t)(uintptr_t)"GPL";

    attr.log_buf = (uint64_t)(uintptr_t)verifier_log;
    attr.log_size = sizeof(verifier_log);
    attr.log_level = 1;

    printf("first insn: code=0x%x dst=%u src=%u off=%d imm=%d\n",
       prog[0].code,
       prog[0].dst_reg,
       prog[0].src_reg,
       prog[0].off,
       prog[0].imm);
    
    int fd = sys_bpf(BPF_PROG_LOAD, &attr);

    if (fd < 0) {
        fprintf(stderr,
                "BPF_PROG_LOAD failed: %s\n",
                strerror(errno));

        fprintf(stderr,
                "\n------ verifier log ------\n%s\n"
                "--------------------------\n",
                verifier_log);

        return -1;
    }

    printf("BPF program loaded successfully\n");
    printf("program fd: %d\n", fd);
    printf("instructions: %zu\n",
           sizeof(prog) / sizeof(prog[0]));
    printf("RDPMC reads: 16\n");
    printf("RDPMC counter: %d\n", COUNTER);

    return fd;
}

static int pin_program(int fd, const char *path)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.pathname = (uint64_t)(uintptr_t)path;
    attr.bpf_fd = fd;

    if (sys_bpf(BPF_OBJ_PIN, &attr) < 0) {
        fprintf(stderr,
                "BPF_OBJ_PIN(%s) failed: %s\n",
                path,
                strerror(errno));
        return -1;
    }

    return 0;
}

int main(void)
{
    int fd;

    printf("Native RDPMC repeat microbenchmark\n");
    printf("counter = %d\n", COUNTER);
    printf("reads   = 16\n");
    printf("intervals = 15\n\n");

    fd = load_program();
    if (fd < 0)
        return EXIT_FAILURE;

    if (pin_program(fd, PIN_PATH) < 0) {
        fprintf(stderr,
                "\nIf the pin already exists, remove it first with:\n"
                "  sudo rm -f %s\n",
                PIN_PATH);

        close(fd);
        return EXIT_FAILURE;
    }

    printf("Pinned at:\n  %s\n", PIN_PATH);

    close(fd);

    /*
     * Closing the fd is fine: the bpffs pin keeps the BPF
     * program alive.
     */

    return EXIT_SUCCESS;
}
