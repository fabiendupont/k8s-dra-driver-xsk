// dra-xsk — DRA kubelet plugin for AF_XDP socket allocation.
//
// Discovers NIC queues, publishes ResourceSlice devices, and
// allocates dedicated RX queues as AF_XDP sockets via
// NodePrepareResources / NodeUnprepareResources. The EtherType
// filter set comes from claim parameters (OpaqueDeviceConfiguration);
// with none set, the legacy IEC 61850 preset applies.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	drav1 "k8s.io/kubelet/pkg/apis/dra/v1"

	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend"
	bpfmanbackend "github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend/bpfman"
	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend/native"
	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/driver"
	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/xsk"
)

var (
	driverName   = flag.String("driver-name", "xsk.dra.io", "DRA driver name")
	nodeName     = flag.String("node-name", "", "Kubernetes node name (required)")
	pluginSock   = flag.String("plugin-socket", "/var/lib/kubelet/plugins/xsk.dra.io/plugin.sock", "kubelet DRA plugin socket path")
	cdiDir       = flag.String("cdi-dir", driver.CDIDir, "CDI spec directory")
	handoffDir   = flag.String("handoff-dir", "/run/xsk", "directory for per-queue SCM_RIGHTS handoff sockets")
	xglCheckBin  = flag.String("xgl-check-bin", os.Getenv("XGL_CHECK_BIN"), "xgl_check binary path (xdp-graph-lib); empty disables the graph validation gate")
	includeVirt  = flag.Bool("include-virtual", false, "include virtual interfaces (veth) in queue discovery — development/testing only")
	registryDir  = flag.String("plugins-registry-dir", "/var/lib/kubelet/plugins_registry", "kubelet plugins_registry directory for the registration socket")
	backendKind  = flag.String("backend", "native", "XSK backend: native (in-process XDP) or bpfman (delegate program loading to a bpfman daemon)")
	bpfmanSock   = flag.String("bpfman-socket", "/run/bpfman/bpfman.sock", "bpfman daemon gRPC Unix socket path (bpfman backend)")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	if *nodeName == "" {
		*nodeName = os.Getenv("NODE_NAME")
	}
	if *nodeName == "" {
		fmt.Fprintln(os.Stderr, "--node-name or NODE_NAME is required")
		os.Exit(1)
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		klog.Fatalf("Building in-cluster config: %v", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		klog.Fatalf("Building Kubernetes client: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *includeVirt {
		xsk.UseVirtualInterfaces()
	}

	var xskBackend backend.Backend
	switch *backendKind {
	case "native":
		xskBackend = native.New(*handoffDir)
	case "bpfman":
		xskBackend = bpfmanbackend.New(*bpfmanSock)
	default:
		klog.Fatalf("unknown backend %q (native or bpfman)", *backendKind)
	}

	// BPF maps pin memory; on kernels < 5.11 this is accounted
	// against MEMLOCK, which defaults to 64 KiB — far too small.
	// Best effort: on 5.11+ (memcg accounting) this is a no-op.
	if err := rlimit.RemoveMemlock(); err != nil {
		klog.V(2).InfoS("could not remove memlock rlimit (ok on 5.11+ kernels)", "err", err)
	}

	d := driver.NewDriver(*driverName, *nodeName, *cdiDir,
		xskBackend, *xglCheckBin, client)

	if err := d.Discover(ctx); err != nil {
		klog.Fatalf("Publishing NIC queue ResourceSlices: %v", err)
	}
	klog.InfoS("NIC queues published to DRA", "driver", *driverName, "node", *nodeName)

	// Start the kubelet DRA plugin gRPC server.
	if err := os.MkdirAll(pluginSocketDir(*pluginSock), 0755); err != nil {
		klog.Fatalf("Creating plugin socket dir: %v", err)
	}
	_ = os.Remove(*pluginSock)

	lis, err := net.Listen("unix", *pluginSock)
	if err != nil {
		klog.Fatalf("Listening on plugin socket %s: %v", *pluginSock, err)
	}

	srv := grpc.NewServer()
	drav1.RegisterDRAPluginServer(srv, d)

	// Kubelet plugin registration: serve the registration API on a
	// socket in plugins_registry; the kubelet watcher discovers it,
	// calls GetInfo, and dials the DRA endpoint above.
	registrar := driver.NewRegistrar(*driverName, *pluginSock)
	go func() {
		if err := registrar.Serve(ctx, *registryDir); err != nil {
			klog.Errorf("Plugin registration server: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		klog.InfoS("Shutting down")
		srv.GracefulStop()
	}()

	klog.InfoS("DRA plugin listening", "socket", *pluginSock)
	if err := srv.Serve(lis); err != nil {
		klog.Fatalf("gRPC server error: %v", err)
	}

	d.Shutdown(context.Background())
}

func pluginSocketDir(sockPath string) string {
	for i := len(sockPath) - 1; i >= 0; i-- {
		if sockPath[i] == '/' {
			return sockPath[:i]
		}
	}
	return "."
}
