#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

static __always_inline int drop__rdpmc_body(struct xdp_md *ctx)
{
    return XDP_DROP;
}
/* AUTO-GENERATED: wrapped baseline control.
 * The original XDP body is forced inline into a thin XDP wrapper, matching the
 * source structure used by the native and kfunc RDPMC variants.
 */
SEC("xdp")
int drop(struct xdp_md *ctx)
{
    return drop__rdpmc_body(ctx);
}


char _license[] SEC("license") = "GPL";