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

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

static volatile sig_atomic_t stop;
static int g_ifindex = -1;
static bool g_attached;
static struct bpf_object *g_obj;

static void on_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static void cleanup(void)
{
    if (g_attached && g_ifindex > 0)
        bpf_xdp_detach(g_ifindex, 0, NULL);
    if (g_obj)
        bpf_object__close(g_obj);
}

static int populate_tunnel(struct bpf_object *obj)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "vip2tnl");
    if (!map) {
        fprintf(stderr, "ERROR: tunnel map vip2tnl not found\n");
        return -1;
    }
    int fd = bpf_map__fd(map);
    __u8 key = 0;
    struct iptnl_info tnl = {};
    tnl.saddr.v4 = inet_addr("10.10.1.2");
    tnl.daddr.v4 = inet_addr("10.10.1.1");
    tnl.family = AF_INET;
    memset(tnl.dmac, 0, sizeof(tnl.dmac));
    if (bpf_map_update_elem(fd, &key, &tnl, BPF_ANY)) {
        perror("bpf_map_update_elem(vip2tnl)");
        return -1;
    }
    fprintf(stderr, "[MAP] tunnel vip2tnl initialized\n");
    return 0;
}

static int populate_routing(struct bpf_object *obj, const char *maps_dir)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "lpm");
    if (!map) {
        fprintf(stderr, "ERROR: routing map lpm not found\n");
        return -1;
    }
    int fd = bpf_map__fd(map);
    unsigned long long total = 0;

    for (unsigned prefix = 1; prefix <= 32; prefix++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/%u.txt", maps_dir, prefix);
        FILE *fp = fopen(path, "r");
        if (!fp) {
            if (errno == ENOENT)
                continue;
            perror(path);
            return -1;
        }
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        unsigned long long count = 0;
        while ((n = getline(&line, &cap, fp)) >= 0) {
            while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r'))
                line[--n] = '\0';
            if (n == 0)
                continue;
            struct ipv4_lpm_key key = {
                .prefixlen = prefix,
                .data = inet_addr(line),
            };
            __u8 value = (__u8)prefix;
            if (bpf_map_update_elem(fd, &key, &value, BPF_ANY)) {
                fprintf(stderr, "ERROR: LPM update failed at %s: %s\n",
                        line, strerror(errno));
                free(line);
                fclose(fp);
                return -1;
            }
            count++;
            total++;
        }
        free(line);
        fclose(fp);
        if (count)
            fprintf(stderr, "[MAP] /%u: %llu entries (total=%llu)\n",
                    prefix, count, total);
    }
    fprintf(stderr, "[MAP] routing LPM ready: %llu entries\n", total);
    return 0;
}

static void usage(const char *p)
{
    fprintf(stderr,
        "Usage: %s <workload> <object.bpf.o> <ifname> [routing_maps_dir]\n"
        "  workload: drop | nat | routing | tunnel\n", p);
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        usage(argv[0]);
        return 2;
    }
    const char *workload = argv[1];
    const char *obj_path = argv[2];
    const char *ifname = argv[3];
    const char *route_maps = argc >= 5 ? argv[4] : NULL;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    g_ifindex = if_nametoindex(ifname);
    if (!g_ifindex) {
        fprintf(stderr, "ERROR: if_nametoindex(%s): %s\n", ifname, strerror(errno));
        return 1;
    }

    /* Make repeated benchmark switching deterministic. */
    bpf_xdp_detach(g_ifindex, 0, NULL);

    g_obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(g_obj)) {
        fprintf(stderr, "ERROR: bpf_object__open_file(%s)\n", obj_path);
        g_obj = NULL;
        return 1;
    }
    if (bpf_object__load(g_obj)) {
        fprintf(stderr, "ERROR: bpf_object__load(%s) failed\n", obj_path);
        cleanup();
        return 1;
    }

    struct bpf_program *prog = bpf_object__next_program(g_obj, NULL);
    if (!prog) {
        fprintf(stderr, "ERROR: no BPF program in object\n");
        cleanup();
        return 1;
    }

    if (!strcmp(workload, "routing")) {
        if (!route_maps) {
            fprintf(stderr, "ERROR: routing_maps_dir is required for routing\n");
            cleanup();
            return 1;
        }
        if (populate_routing(g_obj, route_maps)) {
            cleanup();
            return 1;
        }
    } else if (!strcmp(workload, "tunnel")) {
        if (populate_tunnel(g_obj)) {
            cleanup();
            return 1;
        }
    } else if (strcmp(workload, "drop") && strcmp(workload, "nat")) {
        fprintf(stderr, "ERROR: unknown workload %s\n", workload);
        cleanup();
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (bpf_xdp_attach(g_ifindex, prog_fd, 0, NULL)) {
        fprintf(stderr, "ERROR: bpf_xdp_attach(%s): %s\n", ifname, strerror(errno));
        cleanup();
        return 1;
    }
    g_attached = true;

    struct bpf_prog_info info = {};
    __u32 len = sizeof(info);
    if (bpf_obj_get_info_by_fd(prog_fd, &info, &len)) {
        perror("bpf_obj_get_info_by_fd");
        cleanup();
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    printf("READY workload=%s prog_id=%u prog_name=%s\n",
           workload, info.id, info.name);
    fflush(stdout);

    while (!stop)
        pause();

    cleanup();
    return 0;
}
