#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/icmp.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>

#include "common.h"
#include "fasthash.h"

#define _SEED_HASHFN 77
#define _COUNT_PACKETS
struct vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};
#define htons(x) (((((unsigned short)(x) & 0xFF00) >> 8) | (((unsigned short)(x) & 0x00FF) << 8)))

#define HASHFN_N _CS_ROWS
#define COLUMNS _CS_COLUMNS

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

struct countmin
{
    __u8 values[HASHFN_N][COLUMNS];
};

struct pkt_5tuple
{
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    uint8_t proto;
} __attribute__((packed));

struct pkt_md
{
#ifdef _COUNT_PACKETS
    uint64_t drop_cnt;
#else
    uint64_t bytes_cnt;
#endif
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pkt_md);
} dropcnt SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct countmin);
} countmin SEC(".maps");

static void FORCE_INLINE countmin_add(struct countmin *cm, void *element, __u64 len)
{
    // Calcola un solo hash e lo riusa per aggiornare/interrogare lo sketch
    uint64_t h = fasthash64(element, len, _SEED_HASHFN);

    uint16_t hashes[4];
    hashes[0] = (h & 0xFFFF);
    hashes[1] = h >> 16 & 0xFFFF;
    hashes[2] = h >> 32 & 0xFFFF;
    hashes[3] = h >> 48 & 0xFFFF;

    _Static_assert(ARRAY_SIZE(hashes) == HASHFN_N, "Missing hash function");

    for (int i = 0; i < ARRAY_SIZE(hashes); i++)
    {
        __u32 target_idx = hashes[i] & (COLUMNS - 1);
        NO_TEAR_ADD(cm->values[i][target_idx], 1);
    }

    return;
}

SEC("xdp")
int cms_native(struct xdp_md *ctx)
{
    __u64 start = __builtin_readcyclecounter();

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    uint64_t nh_off = 0;
    struct eth_hdr *eth = data;
    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        goto DROP;

    uint16_t h_proto = eth->proto;

// parse double vlans
#pragma unroll
    for (int i = 0; i < 2; i++)
    {
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD))
        {
            struct vlan_hdr *vhdr;
            vhdr = data + nh_off;
            nh_off += sizeof(struct vlan_hdr);
            if (data + nh_off > data_end)
                goto DROP;
            h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    switch (h_proto)
    {
    case htons(ETH_P_IP):
        break;
    default:
        goto DROP;
    }

    struct pkt_5tuple pkt;

    struct iphdr *ip = data + nh_off;
    if ((void *)&ip[1] > data_end)
        goto DROP;

    pkt.src_ip = ip->saddr;
    pkt.dst_ip = ip->daddr;
    pkt.proto = ip->protocol;

    switch (ip->protocol)
    {
    case IPPROTO_TCP: {
        struct tcp_hdr *tcp = NULL;
        tcp = data + nh_off + sizeof(*ip);
        if (data + nh_off + sizeof(*ip) + sizeof(*tcp) > data_end)
            goto DROP;
        pkt.src_port = tcp->source;
        pkt.dst_port = tcp->dest;
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *udp = NULL;
        udp = data + nh_off + sizeof(*ip);
        if (data + nh_off + sizeof(*ip) + sizeof(*udp) > data_end)
            goto DROP;
        pkt.src_port = udp->source;
        pkt.dst_port = udp->dest;
        break;
    }
    default:
        goto DROP;
    }

    uint32_t zero = 0;
    struct countmin *cm;

    cm = bpf_map_lookup_elem(&countmin, &zero);
    if (!cm)
        goto DROP;

    countmin_add(cm, &pkt, sizeof(pkt));

    struct pkt_md *md;
    uint32_t index = 0;

    md = bpf_map_lookup_elem(&dropcnt, &index);
    if (md)
    {
#ifdef _COUNT_PACKETS
        NO_TEAR_INC(md->drop_cnt);
#else
        uint16_t pkt_len = (uint16_t)(data_end - data);
        NO_TEAR_ADD(md->bytes_cnt, pkt_len);
#endif
    }

DROP:
    {
        __u64 end = __builtin_readcyclecounter();
        // impedisce al compilatore di eliminare le due letture come dead-code
        if (end == start)
            return XDP_ABORTED;
    }
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
