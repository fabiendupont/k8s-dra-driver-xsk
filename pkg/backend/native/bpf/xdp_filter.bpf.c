/* SPDX-License-Identifier: Apache-2.0 */
/*
 * xdp_xsk_filter — EtherType-filtered XSK redirect.
 *
 * Frames whose EtherType appears in xsk_ethertypes are redirected to
 * the AF_XDP socket bound to the receiving queue (XSKMAP lookup by
 * rx_queue_index); everything else is passed up the kernel stack.
 *
 * Verified at the bytecode level with PREVAIL (see xdp-graph-lib
 * scripts/prevail-check.sh; same object shape as xgl nodes).
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u16);
	__type(value, __u8);
} xsk_ethertypes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);
} xsk_map SEC(".maps");

SEC("xdp")
int xdp_xsk_filter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__u16 ethertype;
	__u8 *hit;

	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	ethertype = __bpf_ntohs(eth->h_proto); /* wire is big-endian;
		* map keys are host-order as installed by the driver */
	hit = bpf_map_lookup_elem(&xsk_ethertypes, &ethertype);
	if (!hit)
		return XDP_PASS;

	return bpf_redirect_map(&xsk_map, ctx->rx_queue_index, XDP_PASS);
}

char LICENSE[] SEC("license") = "Dual BSD-2-Clause/GPL";
