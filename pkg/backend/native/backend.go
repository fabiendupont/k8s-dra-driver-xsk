package native

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend"
)// Backend implements backend.Backend in-process.
//
// One XDP program is attached per interface that has allocations;
// the EtherType set and XSK map are shared across all queues of that
// interface. The xgl_check gate upstream guarantees per-interface
// filter sets are disjoint, so removing a queue's filters on Del
// cannot affect another queue's.
type Backend struct {
	handoffDir string

	mu      sync.Mutex
	spec    *ebpf.CollectionSpec
	coll    *ebpf.Collection
	links   map[string]link.Link // ifname -> XDP link
	allocs  map[string]*alloc     // ifname:queue -> allocation
}

type alloc struct {
	req     *backend.Allocation
	xsk     *XSK
	handoff *handoffServer
}

// New creates the native backend. handoffDir is where the per-queue
// SCM_RIGHTS sockets are created (e.g. /run/xsk).
func New(handoffDir string) *Backend {
	return &Backend{
		handoffDir: handoffDir,
		links:      make(map[string]link.Link),
		allocs:     make(map[string]*alloc),
	}
}

func (b *Backend) Name() string { return "native" }

func allocKey(ifname string, queueID int) string {
	return fmt.Sprintf("%s:%d", ifname, queueID)
}

// ensureLoaded loads the BPF collection (lazily, on first use).
func (b *Backend) ensureLoaded() error {
	if b.coll != nil {
		return nil
	}
	if b.spec == nil {
		spec, err := loadFilter()
		if err != nil {
			return fmt.Errorf("loading BPF spec: %w", err)
		}
		b.spec = spec
	}
	coll, err := ebpf.NewCollection(b.spec)
	if err != nil {
		return fmt.Errorf("creating BPF collection (CAP_BPF/CAP_NET_ADMIN required): %w", err)
	}
	b.coll = coll
	return nil
}

// ensureLink attaches the filter program to the interface. Native
// (driver) mode is preferred, with generic (skb) fallback for
// interfaces whose driver has no XDP support.
func (b *Backend) ensureLink(ifname string, ifindex int) error {
	if _, ok := b.links[ifname]; ok {
		return nil
	}
	prog := b.coll.Programs["xdp_xsk_filter"]
	l, err := link.AttachXDP(link.XDPOptions{
		Interface: ifindex,
		Program:   prog,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		l, err = link.AttachXDP(link.XDPOptions{
			Interface: ifindex,
			Program:   prog,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			return fmt.Errorf("attaching XDP to %s: %w", ifname, err)
		}
	}
	b.links[ifname] = l
	return nil
}

// Exported for reuse by other backends (bpfman).
const (
	DefaultFrameSize = 4096
	DefaultNumFrames = 4096
)

func (b *Backend) Add(ctx context.Context, a *backend.Allocation) (string, error) {
	if len(a.Ethertypes) == 0 {
		return "", fmt.Errorf("no ethertypes in allocation")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.allocs[allocKey(a.Ifname, a.QueueID)]; exists {
		return "", fmt.Errorf("queue %s:%d already allocated", a.Ifname, a.QueueID)
	}

	if err := b.ensureLoaded(); err != nil {
		return "", err
	}
	if err := b.ensureLink(a.Ifname, a.Ifindex); err != nil {
		return "", err
	}

	var frameSize uint32 = DefaultFrameSize
	var numFrames uint32 = DefaultNumFrames
	xsk, err := OpenXSK(a.Ifindex, a.QueueID, frameSize, numFrames, a.Zerocopy)
	if err != nil {
		return "", fmt.Errorf("opening XSK for %s:%d: %w", a.Ifname, a.QueueID, err)
	}

	xskFd, _ := xsk.Fds()
	xskMap := b.coll.Maps["xsk_map"]
	if err := xskMap.Put(uint32(a.QueueID), uint32(xskFd)); err != nil {
		xsk.Close()
		return "", fmt.Errorf("inserting xsk fd into XSKMAP: %w", err)
	}

	etMap := b.coll.Maps["xsk_ethertypes"]
	for _, et := range a.Ethertypes {
		if err := etMap.Put(et, uint8(1)); err != nil {
			b.cleanup(a.Ifname, a.QueueID)
			return "", fmt.Errorf("installing filter %#04x: %w", et, err)
		}
	}

	sockPath := filepath.Join(b.handoffDir, fmt.Sprintf("%s-q%d.sock", a.Ifname, a.QueueID))
	info := HandoffInfo{
		Ifname:     a.Ifname,
		Ifindex:    a.Ifindex,
		QueueID:    a.QueueID,
		FrameSize:  frameSize,
		NumFrames:  numFrames,
		Zerocopy:   xsk.Zerocopy,
		Ethertypes: a.Ethertypes,
	}
	hs, err := StartHandoffServer(sockPath, info, xskFd, xsk.umemFd)
	if err != nil {
		b.cleanup(a.Ifname, a.QueueID)
		return "", fmt.Errorf("starting handoff server: %w", err)
	}

	b.allocs[allocKey(a.Ifname, a.QueueID)] = &alloc{req: a, xsk: xsk, handoff: hs}
	return sockPath, nil
}

func (b *Backend) Del(ctx context.Context, ifname string, queueID int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cleanup(ifname, queueID)
}

// cleanup removes an allocation. Caller holds b.mu.
func (b *Backend) cleanup(ifname string, queueID int) error {
	key := allocKey(ifname, queueID)
	a, ok := b.allocs[key]
	if !ok {
		return fmt.Errorf("no allocation for %s", key)
	}
	delete(b.allocs, key)

	a.handoff.Close()
	etMap := b.coll.Maps["xsk_ethertypes"]
	for _, et := range a.req.Ethertypes {
		if err := etMap.Delete(et); err != nil {
			return fmt.Errorf("removing filter %#04x: %w", et, err)
		}
	}
	if xskMap := b.coll.Maps["xsk_map"]; xskMap != nil {
		_ = xskMap.Delete(uint32(queueID))
	}
	a.xsk.Close()

	// Detach the program when the last queue on this interface is
	// gone.
	if b.ifaceHasAllocs(ifname) {
		return nil
	}
	if l, ok := b.links[ifname]; ok {
		if err := l.Close(); err != nil {
			return fmt.Errorf("detaching XDP from %s: %w", ifname, err)
		}
		delete(b.links, ifname)
	}
	return nil
}

func (b *Backend) ifaceHasAllocs(ifname string) bool {
	for k := range b.allocs {
		if len(k) > len(ifname)+1 && k[:len(ifname)] == ifname && k[len(ifname)] == ':' {
			return true
		}
	}
	return false
}
