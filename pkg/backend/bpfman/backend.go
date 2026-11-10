// Package bpfman implements backend.Backend by delegating XDP
// program loading and attachment to a bpfman daemon (gRPC over its
// Unix socket), while creating AF_XDP sockets in-process.
//
// Complements the native backend: bpfman owns the XDP attach point
// (its dispatcher coexists with other programs on the same
// interface), while the driver keeps the DRA allocation semantics,
// the XSK creation, and the SCM_RIGHTS handoff identical.
//
// The filter program is the same embedded ELF the native backend
// loads; bpfman receives it as a File bytecode location and pins
// its maps, which this backend then opens to insert XSK fds and
// EtherType filters.
package bpfman

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	bpfmanv1 "github.com/bpfman/bpfman/clients/gobpfman/v1"
	"github.com/cilium/ebpf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend"
	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend/native"
)

const (
	// programName must match the XDP program in the embedded ELF.
	programName = "xdp_xsk_filter"
	// defaultElfDir is where the driver writes the embedded ELF
	// for bpfman's File bytecode location.
	defaultElfDir = "/run/xsk/bpfman"
)

// Backend implements backend.Backend via a bpfman daemon.
type Backend struct {
	socketPath string

	mu        sync.Mutex
	conn      *grpc.ClientConn
	client    bpfmanv1.BpfmanClient
	elfDir    string // where the embedded ELF is written for bpfman
	elfPath   string
	programID uint32 // 0 = not loaded
	mapPin    string
	links     map[string]uint32 // ifname -> XDP link id
	allocs    map[string]*alloc
}

type alloc struct {
	req      *backend.Allocation
	xsk      *native.XSK
	handoff  *native.HandoffServer
}

// New creates the bpfman backend. socketPath is the bpfman gRPC
// Unix socket (default /run/bpfman/bpfman.sock).
func New(socketPath string) *Backend {
	return &Backend{
		socketPath: socketPath,
		elfDir:     defaultElfDir,
		links:      make(map[string]uint32),
		allocs:     make(map[string]*alloc),
	}
}

func (b *Backend) Name() string { return "bpfman" }

func allocKey(ifname string, queueID int) string {
	return fmt.Sprintf("%s:%d", ifname, queueID)
}

// dial lazily connects to the bpfman daemon.
func (b *Backend) dial() error {
	if b.client != nil {
		return nil
	}
	conn, err := grpc.NewClient("unix://"+b.socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dialing bpfman at %s: %w", b.socketPath, err)
	}
	b.conn = conn
	b.client = bpfmanv1.NewBpfmanClient(conn)
	return nil
}

// ensureProgram writes the embedded ELF to disk and loads it via
// bpfman exactly once. The response's MapPinPath is where bpfman
// pinned the program's maps.
func (b *Backend) ensureProgram() error {
	if b.programID != 0 {
		return nil
	}
	if err := b.dial(); err != nil {
		return err
	}

	if err := os.MkdirAll(b.elfDir, 0755); err != nil {
		return fmt.Errorf("creating %s: %w", b.elfDir, err)
	}
	elfPath := filepath.Join(b.elfDir, "xdp_filter.bpf.o")
	elfBytes, err := native.FilterELFBytes()
	if err != nil {
		return err
	}
	if err := os.WriteFile(elfPath, elfBytes, 0644); err != nil {
		return fmt.Errorf("writing filter ELF: %w", err)
	}
	b.elfPath = elfPath

	resp, err := b.client.Load(context.Background(), &bpfmanv1.LoadRequest{
		Bytecode: &bpfmanv1.BytecodeLocation{
			Location: &bpfmanv1.BytecodeLocation_File{File: elfPath},
		},
		Metadata: map[string]string{
			"owner": "k8s-dra-driver-xsk",
		},
		Info: []*bpfmanv1.LoadInfo{{
			Name:        programName,
			ProgramType: bpfmanv1.BpfmanProgramType_XDP,
		}},
	})
	if err != nil {
		return fmt.Errorf("bpfman Load: %w", err)
	}
	if len(resp.Programs) == 0 {
		return fmt.Errorf("bpfman Load: no programs in response")
	}
	info := resp.Programs[0]
	if info.KernelInfo == nil {
		return fmt.Errorf("bpfman Load: no kernel info in response")
	}
	b.programID = info.KernelInfo.Id
	b.mapPin = info.Info.GetMapPinPath()
	return nil
}

// ensureLink attaches the loaded program to the interface via
// bpfman (XDP attach with default priority; bpfman's dispatcher
// composes it with other programs on the interface).
func (b *Backend) ensureLink(ifname string) error {
	if _, ok := b.links[ifname]; ok {
		return nil
	}
	resp, err := b.client.Attach(context.Background(), &bpfmanv1.AttachRequest{
		Id: b.programID,
		Attach: &bpfmanv1.AttachInfo{
			Info: &bpfmanv1.AttachInfo_XdpAttachInfo{
				XdpAttachInfo: &bpfmanv1.XDPAttachInfo{
					Iface: ifname,
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("bpfman Attach to %s: %w", ifname, err)
	}
	b.links[ifname] = resp.LinkId
	return nil
}

// openMap opens one of the program's pinned maps by name.
func (b *Backend) openMap(name string) (*ebpf.Map, error) {
	if b.mapPin == "" {
		return nil, fmt.Errorf("program maps not pinned (no MapPinPath)")
	}
	return ebpf.LoadPinnedMap(filepath.Join(b.mapPin, name), nil)
}

func (b *Backend) Add(ctx context.Context, a *backend.Allocation) (string, error) {
	if len(a.Ethertypes) == 0 {
		return "", fmt.Errorf("no ethertypes in allocation")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	key := allocKey(a.Ifname, a.QueueID)
	if _, exists := b.allocs[key]; exists {
		return "", fmt.Errorf("queue %s already allocated", key)
	}

	if err := b.ensureProgram(); err != nil {
		return "", err
	}
	if err := b.ensureLink(a.Ifname); err != nil {
		return "", err
	}

	// XSK creation is program-loader-agnostic: same in-process
	// sockets, same handoff, as the native backend.
	xsk, err := native.OpenXSK(a.Ifindex, a.QueueID,
		native.DefaultFrameSize, native.DefaultNumFrames, a.Zerocopy)
	if err != nil {
		return "", fmt.Errorf("opening XSK for %s: %w", key, err)
	}

	xskMap, err := b.openMap("xsk_map")
	if err != nil {
		xsk.Close()
		return "", fmt.Errorf("opening pinned xsk_map: %w", err)
	}
	defer xskMap.Close()
	xskFd, _ := xsk.Fds()
	if err := xskMap.Put(uint32(a.QueueID), uint32(xskFd)); err != nil {
		xsk.Close()
		return "", fmt.Errorf("inserting xsk fd into xsk_map: %w", err)
	}

	etMap, err := b.openMap("xsk_ethertypes")
	if err != nil {
		xsk.Close()
		return "", fmt.Errorf("opening pinned xsk_ethertypes: %w", err)
	}
	defer etMap.Close()
	for _, et := range a.Ethertypes {
		if err := etMap.Put(et, uint8(1)); err != nil {
			xsk.Close()
			return "", fmt.Errorf("installing filter %#04x: %w", et, err)
		}
	}

	sockPath := filepath.Join(filepath.Dir(b.elfDir),
		fmt.Sprintf("%s-q%d.sock", a.Ifname, a.QueueID))
	info := native.HandoffInfo{
		Ifname:     a.Ifname,
		Ifindex:    a.Ifindex,
		QueueID:    a.QueueID,
		FrameSize:  native.DefaultFrameSize,
		NumFrames:  native.DefaultNumFrames,
		Zerocopy:   xsk.Zerocopy,
		Ethertypes: a.Ethertypes,
	}
	hs, err := native.StartHandoffServer(sockPath, info, xskFd, xsk.UMemFd())
	if err != nil {
		xsk.Close()
		return "", fmt.Errorf("starting handoff server: %w", err)
	}

	b.allocs[key] = &alloc{req: a, xsk: xsk, handoff: hs}
	return sockPath, nil
}

func (b *Backend) Del(ctx context.Context, ifname string, queueID int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cleanup(ctx, ifname, queueID)
}

// cleanup removes an allocation. Caller holds b.mu.
func (b *Backend) cleanup(ctx context.Context, ifname string, queueID int) error {
	key := allocKey(ifname, queueID)
	a, ok := b.allocs[key]
	if !ok {
		return fmt.Errorf("no allocation for %s", key)
	}
	delete(b.allocs, key)

	a.handoff.Close()

	if etMap, err := b.openMap("xsk_ethertypes"); err == nil {
		for _, et := range a.req.Ethertypes {
			_ = etMap.Delete(et)
		}
		etMap.Close()
	}
	if xskMap, err := b.openMap("xsk_map"); err == nil {
		_ = xskMap.Delete(uint32(queueID))
		xskMap.Close()
	}
	a.xsk.Close()

	// Detach the link when the last queue on this interface is
	// gone; unload the program when no allocations remain.
	if !b.ifaceHasAllocs(ifname) {
		if linkID, ok := b.links[ifname]; ok {
			if _, err := b.client.Detach(ctx, &bpfmanv1.DetachRequest{
				LinkId: linkID,
			}); err != nil {
				return fmt.Errorf("bpfman Detach from %s: %w", ifname, err)
			}
			delete(b.links, ifname)
		}
	}
	if len(b.allocs) == 0 && b.programID != 0 {
		if _, err := b.client.Unload(ctx, &bpfmanv1.UnloadRequest{
			Id: b.programID,
		}); err != nil {
			return fmt.Errorf("bpfman Unload: %w", err)
		}
		b.programID = 0
		b.mapPin = ""
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
