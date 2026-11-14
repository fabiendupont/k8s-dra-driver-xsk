package hsrprp

import (
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

// Role indices from xdp-hsr-prp hsr_prp_node_ids.h. The config map
// maps roles to PROG_ARRAY indices; we choose the indices.
const (
	roleEthInput   = 0 // tail-call target after dedup/tag-strip
	roleHSRIngress = 1 // self index of node_hsr_ingress (stats)
)

// Composition indices per the xnodes registry (xdp-nodes
// include/xnodes/xnodes_registry.h). The HSR ingress node is
// installed in the xnodes object's egl_prog_array at the
// XNODE_IDX_HSR_PRP base (64); rb_delivery stays in the hsr
// object's own egl_prog_array at a scratch index inside the
// reserved dynamic range.
const (
	xnodesIdxHSRIngress = 64  // XNODE_IDX_HSR_PRP_BASE
	deliveryIdx         = 160 // XNODE_IDX_DYNAMIC_FIRST
	// xnodes_node_config roles (xdp-nodes registry).
	xnodesRoleEthDispatch = 0
)

// Manager owns the node-local RedBox dataplane for the configured
// groups: the XDP root/dispatch shims, the xdp-hsr-prp ingress node,
// the TC egress tagging/cloning on ring ports, and per-claim veth
// plumbing. It is layout-compatible with the native backend's XSK
// machinery: each claim veth gets an XSK via the backend's Add, and
// this manager wires the redundant stream into that veth.
type Manager struct {
	objDir string

	mu      sync.Mutex
	groups  map[string]*groupState  // group name -> state
	streams map[string]*streamState // claim UID -> state
}

type groupState struct {
	cfg       Group
	rb        *ebpf.Collection // redbox shims (root, eth_input, delivery, uplink)
	ingress   *ebpf.Collection // node_hsr_ingress (+ its maps)
	egress    *ebpf.Collection // node_hsr_egress (+ tc_ring_config, seq_counters)
	rootLinks []link.Link      // XDP links on the two ring ports
	egLinks   []link.Link      // TC egress links on the two ring ports
	xnodes    *ebpf.Collection // xdp-nodes generic nodes (eth dispatch)
	portIdx   [2]int           // ring port ifindexes at attach time
}

type streamState struct {
	claimUID  string
	group     string
	ethertype uint16
	vethHost  string // XSK side: xdp_xsk_filter attached, XSK bound (queue 0)
	vethPeer  string // delivery target + TC uplink side
	peerIdx   int
	uplink    link.Link
}

// NewManager creates a RedBox manager. objDir is the directory
// containing the xdp-hsr-prp BPF objects (node_hsr_ingress.bpf.o,
// node_hsr_egress.bpf.o).
func NewManager(objDir string) *Manager {
	return &Manager{
		objDir:  objDir,
		groups:  make(map[string]*groupState),
		streams: make(map[string]*streamState),
	}
}

// Groups returns the configured group names (caller supplies the
// Config; the driver publishes devices from it directly).
//
// SetupGroup initializes the dataplane for one group. Idempotent,
// and self-healing: if the ring ports were re-created (new ifindex,
// e.g. a test re-wiring veths), the old attachments are dead — tear
// down and set up again.
func (m *Manager) SetupGroup(cfg Group) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if gs, ok := m.groups[cfg.Name]; ok {
		if gs.linksAlive() {
			return nil
		}
		klog.InfoS("HSR/PRP group links are down; re-setting up",
			"group", cfg.Name)
		gs.close()
		delete(m.groups, cfg.Name)
		// NOTE: existing streams' delivery entries lived in the old
		// collection; their claims must be re-prepared (pod restart)
		// to re-register. Acceptable while group config is static
		// and ring re-wiring is a test-only event.
	}
	if cfg.Mode != "hsr" {
		return fmt.Errorf("group %q: mode %q not supported", cfg.Name, cfg.Mode)
	}

	portA, err := netlink.LinkByName(cfg.Ports[0])
	if err != nil {
		return fmt.Errorf("group %q: ring port %s: %w", cfg.Name, cfg.Ports[0], err)
	}
	portB, err := netlink.LinkByName(cfg.Ports[1])
	if err != nil {
		return fmt.Errorf("group %q: ring port %s: %w", cfg.Name, cfg.Ports[1], err)
	}

	// Load the redbox shims.
	rbSpec, err := loadRedbox()
	if err != nil {
		return fmt.Errorf("group %q: loading redbox spec: %w", cfg.Name, err)
	}
	rb, err := ebpf.NewCollection(rbSpec)
	if err != nil {
		return fmt.Errorf("group %q: loading redbox: %w", cfg.Name, err)
	}

	// Load node_hsr_ingress from the xdp-hsr-prp build.
	ingSpec, err := ebpf.LoadCollectionSpec(m.objDir + "/node_hsr_ingress.bpf.o")
	if err != nil {
		rb.Close()
		return fmt.Errorf("group %q: opening ingress spec: %w", cfg.Name, err)
	}
	ingress, err := ebpf.NewCollection(ingSpec)
	if err != nil {
		rb.Close()
		return fmt.Errorf("group %q: loading ingress: %w", cfg.Name, err)
	}

	// Load node_hsr_egress (TC).
	egSpec, err := ebpf.LoadCollectionSpec(m.objDir + "/node_hsr_egress.bpf.o")
	if err != nil {
		rb.Close()
		ingress.Close()
		return fmt.Errorf("group %q: opening egress spec: %w", cfg.Name, err)
	}
	egress, err := ebpf.NewCollection(egSpec)
	if err != nil {
		rb.Close()
		ingress.Close()
		return fmt.Errorf("group %q: loading egress: %w", cfg.Name, err)
	}

	// Load node_eth_dispatch (xdp-nodes): generic L2 dispatch that
	// replaces this repo's former rb_eth_input shim.
	xnSpec, err := ebpf.LoadCollectionSpec(m.objDir + "/node_eth_dispatch.bpf.o")
	if err != nil {
		rb.Close(); ingress.Close(); egress.Close()
		return fmt.Errorf("group %q: opening xnodes eth_dispatch spec: %w", cfg.Name, err)
	}
	xnodes, err := ebpf.NewCollection(xnSpec)
	if err != nil {
		rb.Close(); ingress.Close(); egress.Close()
		return fmt.Errorf("group %q: loading xnodes eth_dispatch: %w", cfg.Name, err)
	}

	gs := &groupState{cfg: cfg, rb: rb, ingress: ingress, egress: egress, xnodes: xnodes,
		portIdx: [2]int{portA.Attrs().Index, portB.Attrs().Index}}
	attach := func() error {
		// rb_pa[0] = node_eth_dispatch (xdp-nodes, foreign fd) —
		// the root's single tail-call target.
		pa := rb.Maps["rb_pa"]
		if err := pa.Put(uint32(0), uint32(xnodes.Programs["node_eth_dispatch"].FD())); err != nil {
			return fmt.Errorf("populating rb_pa[eth_dispatch]: %w", err)
		}
		// xnodes composition: L2 table routes 0x892F to the HSR
		// ingress node, installed in the xnodes object's own
		// prog array; the node's config map carries its self
		// index for statistics.
		xnPa := xnodes.Maps["egl_prog_array"]
		if err := xnPa.Put(uint32(xnodesIdxHSRIngress), uint32(ingress.Programs["node_hsr_ingress"].FD())); err != nil {
			return fmt.Errorf("populating xnodes egl_prog_array[hsr_ingress]: %w", err)
		}
		l2t := xnodes.Maps["xnodes_l2_table"]
		if err := l2t.Put(uint16(0x892F), uint32(xnodesIdxHSRIngress)); err != nil {
			return fmt.Errorf("populating xnodes_l2_table[0x892F]: %w", err)
		}
		xnCfg := xnodes.Maps["xnodes_node_config"]
		if err := xnCfg.Put(uint32(xnodesRoleEthDispatch), uint32(32)); err != nil {
			return fmt.Errorf("populating xnodes_node_config[eth_dispatch]: %w", err)
		}
		// hsr_prp_node_config: self index for stats + delivery index.
		nc := ingress.Maps["hsr_prp_node_config"]
		if err := nc.Put(uint32(roleHSRIngress), uint32(xnodesIdxHSRIngress)); err != nil {
			return fmt.Errorf("populating node_config[hsr_ingress]: %w", err)
		}
		if err := nc.Put(uint32(roleEthInput), uint32(deliveryIdx)); err != nil {
			return fmt.Errorf("populating node_config[eth_input]: %w", err)
		}
		// hsr egl_prog_array[deliveryIdx] = rb_delivery.
		egl := ingress.Maps["egl_prog_array"]
		if err := egl.Put(uint32(deliveryIdx), uint32(rb.Programs["rb_delivery"].FD())); err != nil {
			return fmt.Errorf("populating egl_prog_array[delivery]: %w", err)
		}

		// TC ring config: local ifindex -> {peer ifindex, path id}.
		type ringPortConfig struct {
			PeerIfindex uint32
			PathID      uint8
			_           [3]uint8
		}
		tc := egress.Maps["tc_ring_config"]
		if err := tc.Put(uint32(portA.Attrs().Index), ringPortConfig{PeerIfindex: uint32(portB.Attrs().Index), PathID: 0}); err != nil {
			return fmt.Errorf("populating tc_ring_config[A]: %w", err)
		}
		if err := tc.Put(uint32(portB.Attrs().Index), ringPortConfig{PeerIfindex: uint32(portA.Attrs().Index), PathID: 1}); err != nil {
			return fmt.Errorf("populating tc_ring_config[B]: %w", err)
		}

		// XDP root on both ring ports (driver mode first, generic
		// fallback — mirrors the native backend's attach policy).
		for _, p := range []netlink.Link{portA, portB} {
			l, err := link.AttachXDP(link.XDPOptions{
				Interface: p.Attrs().Index,
				Program:   rb.Programs["redbox_root"],
				Flags:     link.XDPDriverMode,
			})
			if err != nil {
				l, err = link.AttachXDP(link.XDPOptions{
					Interface: p.Attrs().Index,
					Program:   rb.Programs["redbox_root"],
					Flags:     link.XDPGenericMode,
				})
			}
			if err != nil {
				return fmt.Errorf("attaching redbox_root to %s: %w", p.Attrs().Name, err)
			}
			gs.rootLinks = append(gs.rootLinks, l)
		}

		// TC egress tagging/clone on both ring ports.
		for _, p := range []netlink.Link{portA, portB} {
			l, err := link.AttachTCX(link.TCXOptions{
				Interface: p.Attrs().Index,
				Program:   egress.Programs["node_hsr_egress"],
				Attach:    ebpf.AttachTCXEgress,
			})
			if err != nil {
				return fmt.Errorf("attaching node_hsr_egress to %s: %w", p.Attrs().Name, err)
			}
			gs.egLinks = append(gs.egLinks, l)
		}

		// TX uplink target: ring port A (egress there tags + clones
		// to B via tc_ring_config).
		up := rb.Maps["rb_uplink_ifindex"]
		if err := up.Put(uint32(0), uint32(portA.Attrs().Index)); err != nil {
			return fmt.Errorf("populating rb_uplink_ifindex: %w", err)
		}
		return nil
	}
	if err := attach(); err != nil {
		gs.close()
		return fmt.Errorf("group %q: %w", cfg.Name, err)
	}

	m.groups[cfg.Name] = gs
	return nil
}

// TeardownGroup removes a group's dataplane.
func (m *Manager) TeardownGroup(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if gs, ok := m.groups[name]; ok {
		gs.close()
		delete(m.groups, name)
	}
}

func (gs *groupState) close() {
	for _, l := range gs.rootLinks {
		l.Close()
	}
	for _, l := range gs.egLinks {
		l.Close()
	}
	gs.rb.Close()
	gs.ingress.Close()
	gs.egress.Close()
	if gs.xnodes != nil {
		gs.xnodes.Close()
	}
}

// linksAlive reports whether the ring ports still carry our XDP
// program. Ifindex alone is insufficient: deleting and re-creating a
// veth can reuse the same ifindex, leaving a dead attachment behind.
func (gs *groupState) linksAlive() bool {
	for _, name := range gs.cfg.Ports {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return false
		}
		if xdp := l.Attrs().Xdp; xdp == nil || !xdp.Attached {
			return false
		}
	}
	return true
}

// AddStream creates the per-claim veth plumbing for one stream:
// a veth pair whose host side carries the XSK (the native backend
// attaches xdp_xsk_filter there) and whose peer side is the delivery
// target + TX uplink. Returns the host-side ifname and ifindex for
// backend.Add.
//
// The caller must still call backend.Add(vethHost, ifindex, 0, ...) to
// create the XSK; this only wires the redundant path to the veth.
func (m *Manager) AddStream(claimUID, groupName string, ethertype uint16) (ifname string, ifindex int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	gs, ok := m.groups[groupName]
	if !ok {
		return "", -1, fmt.Errorf("unknown group %q", groupName)
	}
	if _, exists := m.streams[claimUID]; exists {
		// Idempotent for kubelet retries.
		s := m.streams[claimUID]
		return s.vethHost, s.peerIdx, nil
	}

	// veth names: IFNAMSIZ is 16 with trailing NUL.
	base := "xskh-" + trimUID(claimUID)
	host, peer := base+"n", base+"p"

	la := netlink.NewLinkAttrs()
	la.Name = host
	veth := &netlink.Veth{LinkAttrs: la, PeerName: peer}
	if err := netlink.LinkAdd(veth); err != nil {
		// A leftover pair from a previous driver process (the
		// in-memory state was lost on restart, so unprepare could
		// not clean it up). Nothing can be using it — the handoff
		// servers died with the old process — so remove and retry.
		if stale, lerr := netlink.LinkByName(host); lerr == nil {
			klog.InfoS("Removing stale stream veth from a previous driver process",
				"veth", host)
			_ = netlink.LinkDel(stale)
		}
		if err2 := netlink.LinkAdd(veth); err2 != nil {
			return "", -1, fmt.Errorf("creating veth pair %s/%s: %w (stale cleanup: %v)",
				host, peer, err, err2)
		}
	}
	cleanupLink := func() { _ = netlink.LinkDel(veth) }

	peerLink, err := netlink.LinkByName(peer)
	if err != nil {
		cleanupLink()
		return "", -1, fmt.Errorf("looking up %s: %w", peer, err)
	}
	for _, l := range []netlink.Link{veth, peerLink} {
		if err := netlink.LinkSetUp(l); err != nil {
			cleanupLink()
			return "", -1, fmt.Errorf("setting %s up: %w", l.Attrs().Name, err)
		}
	}

	// Delivery: EtherType -> veth peer. After node_hsr_ingress
	// strips the tag, rb_delivery redirects to this ifindex; the
	// frame then arrives on the host side, where the backend's
	// xdp_xsk_filter redirects it into the pod's XSK.
	if err := gs.rb.Maps["rb_streams"].Put(ethertype, uint32(peerLink.Attrs().Index)); err != nil {
		cleanupLink()
		return "", -1, fmt.Errorf("populating rb_streams[%#04x]: %w", ethertype, err)
	}

	// TX uplink: TC ingress on the peer side redirects pod TX to
	// ring port A (where node_hsr_egress tags and clones).
	uplink, err := link.AttachTCX(link.TCXOptions{
		Interface: peerLink.Attrs().Index,
		Program:   gs.rb.Programs["rb_uplink"],
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		_ = gs.rb.Maps["rb_streams"].Delete(ethertype)
		cleanupLink()
		return "", -1, fmt.Errorf("attaching rb_uplink to %s: %w", peer, err)
	}

	m.streams[claimUID] = &streamState{
		claimUID:  claimUID,
		group:     groupName,
		ethertype: ethertype,
		vethHost:  host,
		vethPeer:  peer,
		peerIdx:   peerLink.Attrs().Index,
		uplink:    uplink,
	}
	return host, veth.Attrs().Index, nil
}

// DelStream removes the per-claim plumbing. Call after the backend
// has released the XSK on the host side. Idempotent.
func (m *Manager) DelStream(claimUID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.streams[claimUID]
	if !ok {
		return
	}
	delete(m.streams, claimUID)

	s.uplink.Close()
	if gs, ok := m.groups[s.group]; ok {
		_ = gs.rb.Maps["rb_streams"].Delete(s.ethertype)
	}
	if l, err := netlink.LinkByName(s.vethHost); err == nil {
		_ = netlink.LinkDel(l) // removes the pair
	}
}

// StreamVeth reports the host-side veth for a claim (empty if none).
func (m *Manager) StreamVeth(claimUID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.streams[claimUID]; ok {
		return s.vethHost
	}
	return ""
}

// trimUID shortens a claim UID for IFNAMSIZ-safe veth names
// (5 hex chars keep "xskh-XXXXXn/p" within 16 bytes).
func trimUID(uid string) string {
	u := strings.ReplaceAll(uid, "-", "")
	if len(u) > 5 {
		u = u[:5]
	}
	return u
}
