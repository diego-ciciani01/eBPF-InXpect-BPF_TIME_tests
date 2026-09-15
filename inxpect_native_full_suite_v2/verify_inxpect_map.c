#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PIN_MULTI "/sys/fs/bpf/multiplexed_output"
struct record {
    char name[16];
    __u64 run_cnts[4];
    __u64 values[4];
    __u32 counters[4];
} __attribute__((aligned(64)));

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <expected_counter> [require-runs]\n", argv[0]); return 2; }
    int expected = atoi(argv[1]);
    int require_runs = argc >= 3 && !strcmp(argv[2], "require-runs");
    int fd = bpf_obj_get(PIN_MULTI);
    if (fd < 0) { perror("bpf_obj_get(multiplexed_output)"); return 2; }
    int ncpu = libbpf_num_possible_cpus();
    struct record *v = calloc(ncpu, sizeof(*v));
    if (!v) return 2;
    __u32 key = 0;
    if (bpf_map_lookup_elem(fd, &key, v)) { perror("bpf_map_lookup_elem"); free(v); return 2; }
    unsigned long long total_runs = 0, total_value = 0; int active = 0, mismatch = 0;
    for (int cpu = 0; cpu < ncpu; cpu++) {
        if (!v[cpu].name[0]) continue;
        active++;
        total_runs += v[cpu].run_cnts[0];
        total_value += v[cpu].values[0];
        if ((int)v[cpu].counters[0] != expected) mismatch = 1;
        if (v[cpu].run_cnts[0])
            printf("cpu=%d name=%.*s counter0=%u run0=%llu value0=%llu\n",
                   cpu, 15, v[cpu].name, v[cpu].counters[0],
                   (unsigned long long)v[cpu].run_cnts[0],
                   (unsigned long long)v[cpu].values[0]);
    }
    free(v);
    printf("ACTIVE_CPUS=%d EXPECTED_COUNTER=%d TOTAL_RUNS=%llu TOTAL_VALUE=%llu\n",
           active, expected, total_runs, total_value);
    if (!active) { fprintf(stderr, "ERROR: InXpect section is not activated\n"); return 3; }
    if (mismatch) { fprintf(stderr, "ERROR: InXpect allocated a different PMC index\n"); return 4; }
    if (require_runs && total_runs == 0) { fprintf(stderr, "ERROR: profiling run_cnt is still zero\n"); return 5; }
    return 0;
}
