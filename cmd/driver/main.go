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

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	drav1 "k8s.io/kubelet/pkg/apis/dra/v1"

	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend"
	bpfmanbackend "github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend/bpfman"
	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend/native"
	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/driver"
	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/hsrprp"
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
	backendKind  = flag.String("backend", "native", "XSK backend: native (in-process XDP) or bpfman (delegate program loading to the bpfman eBPF Manager Operator via CRDs)")
	hsrprpConfig = flag.String("hsrprp-config", "", "HSR/PRP groups config file (YAML); empty disables the RedBox stream pool")
	hsrprpObjDir = flag.String("hsrprp-obj-dir", "/usr/lib/xsk-dra/hsrprp", "directory containing xdp-hsr-prp BPF objects (node_hsr_ingress.bpf.o, node_hsr_egress.bpf.o)")
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
		bp, err := bpfmanbackend.New(*nodeName, cfg)
		if err != nil {
			klog.Fatalf("Creating bpfman backend: %v", err)
		}
		xskBackend = bp
	default:
		klog.Fatalf("unknown backend %q (native or bpfman)", *backendKind)
	}

	// AF_XDP UMEM registration still charges RLIMIT_MEMLOCK even on
	// kernels where BPF maps are memcg-accounted (5.11+): cilium's
	// RemoveMemlock is a no-op there, but the XSK umem (16 MiB by
	// default) exceeds typical 8 MiB container limits. Raise it
	// explicitly; requires CAP_SYS_RESOURCE.
	{
		newLimit := unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}
		if err := unix.Prlimit(0, unix.RLIMIT_MEMLOCK, &newLimit, nil); err != nil {
			klog.InfoS("could not raise memlock rlimit (UMEM allocation may fail)", "err", err)
		}
	}

	// HSR/PRP RedBox stream pool: optional. The manager is created
	// even without a config so stream claims fail with a clear
	// error rather than a nil deref.
	var hsrCfg *hsrprp.Config
	if *hsrprpConfig != "" {
		hsrCfg, err = hsrprp.LoadConfig(*hsrprpConfig)
		if err != nil {
			klog.Fatalf("Loading HSR/PRP config: %v", err)
		}
		klog.InfoS("HSR/PRP groups loaded", "groups", len(hsrCfg.Groups))
	}
	hsrMgr := hsrprp.NewManager(*hsrprpObjDir)

	d := driver.NewDriver(*driverName, *nodeName, *cdiDir,
		xskBackend, *xglCheckBin, client, hsrCfg, hsrMgr)

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
	// Re-publish slices whenever the kubelet (re-)registers us: the
	// kubelet deletes all ResourceSlices when it restarts, before
	// drivers have re-registered.
	registrar.OnRegistered(func() {
		if err := d.Discover(ctx); err != nil {
			klog.ErrorS(err, "Re-publishing ResourceSlices after kubelet registration")
		} else {
			klog.InfoS("Re-published ResourceSlices after kubelet registration")
		}
	})
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
