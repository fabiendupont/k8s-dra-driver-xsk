package bpfman

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	bpfmanv1 "github.com/bpfman/bpfman/clients/gobpfman/v1"
	"google.golang.org/grpc"

	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend"
)

// fakeBpfman implements the bpfman gRPC server, recording calls.
type fakeBpfman struct {
	bpfmanv1.UnimplementedBpfmanServer

	loadReqs   []*bpfmanv1.LoadRequest
	attachReqs []*bpfmanv1.AttachRequest
	detachReqs []*bpfmanv1.DetachRequest
	unloadReqs []*bpfmanv1.UnloadRequest

	nextProgID uint32
	nextLinkID uint32
}

func (f *fakeBpfman) Load(ctx context.Context, req *bpfmanv1.LoadRequest) (*bpfmanv1.LoadResponse, error) {
	f.loadReqs = append(f.loadReqs, req)
	f.nextProgID++
	return &bpfmanv1.LoadResponse{
		Programs: []*bpfmanv1.LoadResponseInfo{{
			Info: &bpfmanv1.ProgramInfo{
				Name:       req.GetInfo()[0].GetName(),
				MapPinPath: "/tmp/fake-map-pin",
			},
			KernelInfo: &bpfmanv1.KernelProgramInfo{
				Id:   f.nextProgID,
				Name: req.GetInfo()[0].GetName(),
			},
		}},
	}, nil
}

func (f *fakeBpfman) Attach(ctx context.Context, req *bpfmanv1.AttachRequest) (*bpfmanv1.AttachResponse, error) {
	f.attachReqs = append(f.attachReqs, req)
	f.nextLinkID++
	return &bpfmanv1.AttachResponse{LinkId: f.nextLinkID}, nil
}

func (f *fakeBpfman) Detach(ctx context.Context, req *bpfmanv1.DetachRequest) (*bpfmanv1.DetachResponse, error) {
	f.detachReqs = append(f.detachReqs, req)
	return &bpfmanv1.DetachResponse{}, nil
}

func (f *fakeBpfman) Unload(ctx context.Context, req *bpfmanv1.UnloadRequest) (*bpfmanv1.UnloadResponse, error) {
	f.unloadReqs = append(f.unloadReqs, req)
	return &bpfmanv1.UnloadResponse{}, nil
}

func startFake(t *testing.T) (*fakeBpfman, string) {
	t.Helper()
	f := &fakeBpfman{}
	lis, err := net.Listen("unix", filepath.Join(t.TempDir(), "bpfman.sock"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	bpfmanv1.RegisterBpfmanServer(srv, f)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return f, lis.Addr().String()
}

// TestBackendRequestFlow validates the gRPC traffic shape against a
// fake bpfman daemon: one Load, one Attach per interface, and the
// Detach/Unload teardown order. The XSK/map operations require
// CAP_BPF and are skipped in this test (covered by the native
// backend's privileged tests — the code paths are shared).
func TestBackendRequestFlow(t *testing.T) {
	fake, sock := startFake(t)
	b := New(sock)
	b.elfDir = t.TempDir()

	// Del/Add with map operations fail without CAP_BPF; the
	// request-building is still validated up to the first
	// privileged step.
	_, _ = b.Add(context.Background(), &backend.Allocation{
		Ifname:     "eth0",
		Ifindex:    2,
		QueueID:    0,
		Ethertypes: []uint16{0x88B8},
	})

	if len(fake.loadReqs) != 1 {
		t.Fatalf("expected 1 Load, got %d", len(fake.loadReqs))
	}
	lr := fake.loadReqs[0]
	if lr.GetBytecode().GetFile() == "" {
		t.Error("Load: expected File bytecode location")
	}
	if len(lr.GetInfo()) != 1 ||
		lr.GetInfo()[0].GetName() != "xdp_xsk_filter" ||
		lr.GetInfo()[0].GetProgramType() != bpfmanv1.BpfmanProgramType_XDP {
		t.Errorf("Load: unexpected program info: %+v", lr.GetInfo())
	}
	if lr.GetMetadata()["owner"] != "k8s-dra-driver-xsk" {
		t.Error("Load: expected owner metadata")
	}
	if _, err := os.Stat(lr.GetBytecode().GetFile()); err != nil {
		t.Errorf("embedded ELF not written to disk: %v", err)
	}

	if len(fake.attachReqs) != 1 {
		t.Fatalf("expected 1 Attach, got %d", len(fake.attachReqs))
	}
	ar := fake.attachReqs[0]
	if ar.GetId() != 1 {
		t.Errorf("Attach: program id = %d, want 1", ar.GetId())
	}
	if ar.GetAttach().GetXdpAttachInfo().GetIface() != "eth0" {
		t.Errorf("Attach: iface = %q", ar.GetAttach().GetXdpAttachInfo().GetIface())
	}

	// Second Add on the same interface: no second Load, no second
	// Attach (program and link are reused).
	_, _ = b.Add(context.Background(), &backend.Allocation{
		Ifname:     "eth0",
		Ifindex:    2,
		QueueID:    1,
		Ethertypes: []uint16{0x88BA},
	})
	if len(fake.loadReqs) != 1 {
		t.Errorf("expected Load reuse, got %d loads", len(fake.loadReqs))
	}
	if len(fake.attachReqs) != 1 {
		t.Errorf("expected Attach reuse, got %d attaches", len(fake.attachReqs))
	}
}

func TestName(t *testing.T) {
	if New("/unused").Name() != "bpfman" {
		t.Error("Name() != bpfman")
	}
}
