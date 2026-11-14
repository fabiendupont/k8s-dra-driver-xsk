/* SPDX-License-Identifier: Apache-2.0 */
/*
 * redbox — node-local RedBox plumbing for HSR/PRP stream delivery.
 *
 * Composes the xdp-hsr-prp graph extension nodes with the DRA
 * driver's XSK filter. The intended dataplane (all in the node
 * network namespace):
 *
 *   RX:  ring port XDP
 *          redbox_root (alloc xgl_meta) -> node_eth_dispatch
 *                        (generic L2 dispatch, from xdp-nodes —
 *                         replaces this repo's own eth-input shim)
 *          xnodes_l2_table[0x892F] -> node_hsr_ingress
 *                        (dedup + tag strip, from xdp-hsr-prp)
 *          node_hsr_ingress re-enters via egl_prog_array[ETH_INPUT]
 *          -> rb_delivery: EtherType -> claim veth peer, bpf_redirect
 *          -> frame arrives on claim veth (XSK side), where the
 *             driver's xdp_xsk_filter redirects into the pod's XSK.
 *
 *   TX:  pod XSK transmit -> claim veth peer RX (TC ingress)
 *          rb_uplink: bpf_redirect to ring port A egress
 *          node_hsr_egress (TC egress, from xdp-hsr-prp): insert HSR
 *          tag, clone to ring port B (clone patches path field).
 *
 * The xgl_meta layout must match xdp-graph-lib's XGL_META_VERSION 1
 * (52 bytes, packed, aligned 4) so node_hsr_ingress's XGL_META_GET
 * succeeds. It is duplicated here rather than vendored; the comment
 * on RB_XGL_META_VERSION tracks the upstream version.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD-2-Clause/GPL";

/* Mirror of xdp-graph-lib XGL_META_VERSION 1 (xgl/xgl_meta.h).
 * node_hsr_ingress drops frames whose metadata version mismatches,
 * so bumping the upstream version must be reflected here. */
#define RB_XGL_META_VERSION 1
#define RB_XGL_SCRATCH_SIZE 32

struct rb_xgl_meta {
	__u8  version;
	__u8  flags;
	__u16 l2_proto;
	__u16 l3_offset;
	__u16 next_node;
	__u32 ingress_ifindex;
	__u64 timestamp_ns;
	__u8  scratch[RB_XGL_SCRATCH_SIZE];
} __attribute__((packed, aligned(4)));

_Static_assert(sizeof(struct rb_xgl_meta) == 52,
	       "rb_xgl_meta must match xgl_meta (52 bytes)");

/* The root tail-calls xdp-nodes' node_eth_dispatch, which lives in
 * its own object; index 0 per the xnodes registry (XNODE_IDX_XGL
 * base — the root is the composition's dispatch entry point). The
 * HSR ingress node is reached via the xnodes object's own
 * egl_prog_array, keyed by xnodes_l2_table (populated from Go),
 * so rb_pa carries only the root's single tail-call target. */
#define RB_IDX_ETH_DISPATCH 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u32);
} rb_pa SEC(".maps");

/* EtherType -> ifindex of the claim veth peer (delivery target). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u16);
	__type(value, __u32);
} rb_streams SEC(".maps");

/* Ring port A ifindex for the TX uplink redirect. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} rb_uplink_ifindex SEC(".maps");

SEC("xdp")
int redbox_root(struct xdp_md *ctx)
{
	struct rb_xgl_meta *meta;

	if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct rb_xgl_meta)))
		return XDP_PASS;

	meta = (void *)(long)ctx->data_meta;
	if ((void *)(meta + 1) > (void *)(long)ctx->data)
		return XDP_PASS;

	/* Zero the metadata (XGL_META_ALLOC semantics). */
	__builtin_memset(meta, 0, sizeof(*meta));
	meta->version = RB_XGL_META_VERSION;
	meta->ingress_ifindex = ctx->ingress_ifindex;
	meta->timestamp_ns = bpf_ktime_get_ns();
	meta->next_node = RB_IDX_ETH_DISPATCH;

	/* Tail-call into xdp-nodes' node_eth_dispatch (foreign fd,
	 * installed by the Go manager): EtherType-driven L2 dispatch
	 * via xnodes_l2_table, with 0x892F routed to the HSR ingress
	 * node. */
	bpf_tail_call(ctx, &rb_pa, RB_IDX_ETH_DISPATCH);
	return XDP_PASS;
}

/* ETH_INPUT re-entry target: delivers the deduplicated, untagged
 * frame to the claim veth peer that owns its EtherType. Attached to
 * node_hsr_ingress's egl_prog_array from userspace. */
SEC("xdp")
int rb_delivery(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__u16 ethertype;
	__u32 *ifindex;

	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	ethertype = bpf_ntohs(eth->h_proto);
	ifindex = bpf_map_lookup_elem(&rb_streams, &ethertype);
	if (!ifindex)
		return XDP_PASS;

	return bpf_redirect(*ifindex, 0);
}

/* TC ingress on the claim veth peer: pod TX frames are steered to
 * ring port A's egress, where node_hsr_egress tags and clones. */
SEC("tc")
int rb_uplink(struct __sk_buff *skb)
{
	__u32 key = 0;
	__u32 *ifindex = bpf_map_lookup_elem(&rb_uplink_ifindex, &key);

	if (!ifindex)
		return TC_ACT_OK;

	return bpf_redirect(*ifindex, 0);
}
