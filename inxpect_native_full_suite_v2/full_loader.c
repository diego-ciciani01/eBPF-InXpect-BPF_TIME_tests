#define _GNU_SOURCE
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tunnel_common.h"

#define PIN_MULTI "/sys/fs/bpf/multiplexed_output"
#define PIN_ARRAY "/sys/fs/bpf/percpu_output"

struct ipv4_lpm_key { __u32 prefixlen; __u32 data; };
static volatile sig_atomic_t stop;
static int g_ifindex = -1;
static bool g_attached;
static struct bpf_object *g_obj;

static void on_signal(int sig) { (void)sig; stop = 1; }
static void unpin_profiler_maps(void) { unlink(PIN_MULTI); unlink(PIN_ARRAY); }
static void cleanup(void) {
    if (g_attached && g_ifindex > 0) bpf_xdp_detach(g_ifindex, 0, NULL);
    unpin_profiler_maps();
    if (g_obj) bpf_object__close(g_obj);
}

static int set_pin_path(struct bpf_object *obj, const char *name, const char *path) {
    struct bpf_map *m = bpf_object__find_map_by_name(obj, name);
    if (!m) { fprintf(stderr, "ERROR: profiler map %s not found\n", name); return -1; }
    int err = bpf_map__set_pin_path(m, path);
    if (err) { fprintf(stderr, "ERROR: set pin path %s: %d\n", path, err); return -1; }
    return 0;
}
static int ensure_pin(struct bpf_object *obj, const char *name, const char *path) {
    if (access(path, F_OK) == 0) return 0;
    struct bpf_map *m = bpf_object__find_map_by_name(obj, name);
    if (!m) return -1;
    int err = bpf_map__pin(m, path);
    if (err && errno != EEXIST) { perror("bpf_map__pin"); return -1; }
    return 0;
}

static int populate_tunnel(struct bpf_object *obj) {
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "vip2tnl");
    if (!map) { fprintf(stderr, "ERROR: tunnel map vip2tnl not found\n"); return -1; }
    int fd = bpf_map__fd(map); __u8 key = 0; struct iptnl_info tnl = {};
    tnl.saddr.v4 = inet_addr("10.10.1.2");
    tnl.daddr.v4 = inet_addr("10.10.1.1");
    tnl.family = AF_INET;
    memset(tnl.dmac, 0, sizeof(tnl.dmac));
    if (bpf_map_update_elem(fd, &key, &tnl, BPF_ANY)) { perror("vip2tnl update"); return -1; }
    return 0;
}

static int populate_routing(struct bpf_object *obj, const char *maps_dir) {
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "lpm");
    if (!map) { fprintf(stderr, "ERROR: routing map lpm not found\n"); return -1; }
    int fd = bpf_map__fd(map); unsigned long long total = 0;
    for (unsigned prefix = 0; prefix <= 32; prefix++) {
        char path[4096]; snprintf(path, sizeof(path), "%s/%u.txt", maps_dir, prefix);
        FILE *fp = fopen(path, "r");
        if (!fp) { if (errno == ENOENT) continue; perror(path); return -1; }
        char *line = NULL; size_t cap = 0; ssize_t n;
        while ((n = getline(&line, &cap, fp)) >= 0) {
            while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = 0;
            if (!n) continue;
            struct ipv4_lpm_key key = { .prefixlen = prefix, .data = inet_addr(line) };
            __u8 value = (__u8)prefix;
            if (bpf_map_update_elem(fd, &key, &value, BPF_ANY)) {
                fprintf(stderr, "ERROR: LPM update %s: %s\n", line, strerror(errno));
                free(line); fclose(fp); return -1;
            }
            total++;
        }
        free(line); fclose(fp);
    }
    fprintf(stderr, "[MAP] routing LPM ready: %llu entries\n", total);
    return 0;
}

static void usage(const char *p) {
    fprintf(stderr, "Usage: %s <workload> <object.bpf.o> <ifname> [routing_maps_dir]\n", p);
}

int main(int argc, char **argv) {
    if (argc < 4) { usage(argv[0]); return 2; }
    const char *workload = argv[1], *obj_path = argv[2], *ifname = argv[3];
    const char *route_maps = argc >= 5 ? argv[4] : NULL;
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    g_ifindex = if_nametoindex(ifname);
    if (!g_ifindex) { fprintf(stderr, "ERROR: if_nametoindex(%s)\n", ifname); return 1; }
    bpf_xdp_detach(g_ifindex, 0, NULL);
    unpin_profiler_maps();

    g_obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(g_obj)) { g_obj = NULL; fprintf(stderr, "ERROR: open %s\n", obj_path); return 1; }
    if (set_pin_path(g_obj, "multiplexed_output", PIN_MULTI) ||
        set_pin_path(g_obj, "percpu_output", PIN_ARRAY)) { cleanup(); return 1; }
    if (bpf_object__load(g_obj)) { fprintf(stderr, "ERROR: load %s failed\n", obj_path); cleanup(); return 1; }
    if (ensure_pin(g_obj, "multiplexed_output", PIN_MULTI) ||
        ensure_pin(g_obj, "percpu_output", PIN_ARRAY)) { cleanup(); return 1; }

    struct bpf_program *prog = bpf_object__next_program(g_obj, NULL);
    if (!prog) { fprintf(stderr, "ERROR: no BPF program\n"); cleanup(); return 1; }

    if (!strcmp(workload, "routing")) {
        if (!route_maps || populate_routing(g_obj, route_maps)) { cleanup(); return 1; }
    } else if (!strcmp(workload, "tunnel")) {
        if (populate_tunnel(g_obj)) { cleanup(); return 1; }
    } else if (strcmp(workload, "drop") && strcmp(workload, "cms") && strcmp(workload, "nat")) {
        fprintf(stderr, "ERROR: unknown workload %s\n", workload); cleanup(); return 1;
    }

    int pfd = bpf_program__fd(prog);
    if (bpf_xdp_attach(g_ifindex, pfd, 0, NULL)) { perror("bpf_xdp_attach"); cleanup(); return 1; }
    g_attached = true;
    struct bpf_prog_info info = {}; __u32 len = sizeof(info);
    if (bpf_obj_get_info_by_fd(pfd, &info, &len)) { perror("prog info"); cleanup(); return 1; }
    signal(SIGINT, on_signal); signal(SIGTERM, on_signal);
    printf("READY workload=%s prog_id=%u prog_name=%s pin=%s\n", workload, info.id, info.name, PIN_MULTI);
    fflush(stdout);
    while (!stop) pause();
    cleanup();
    return 0;
}
