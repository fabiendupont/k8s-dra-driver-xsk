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

	"google.golang.org/grpc"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	drav1 "k8s.io/kubelet/pkg/apis/dra/v1"

	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/driver"
)

var (
	driverName   = flag.String("driver-name", "xsk.dra.io", "DRA driver name")
	nodeName     = flag.String("node-name", "", "Kubernetes node name (required)")
	pluginSock   = flag.String("plugin-socket", "/var/lib/kubelet/plugins/xsk.dra.io/plugin.sock", "kubelet DRA plugin socket path")
	cdiDir       = flag.String("cdi-dir", driver.CDIDir, "CDI spec directory")
	groutxSocket = flag.String("groutx-socket", "/run/groutx.sock", "groutx daemon Unix socket path")
	xglCheckBin  = flag.String("xgl-check-bin", os.Getenv("XGL_CHECK_BIN"), "xgl_check binary path (xdp-graph-lib); empty disables the graph validation gate")
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

	d := driver.NewDriver(*driverName, *nodeName, *cdiDir, *groutxSocket, *xglCheckBin, client)

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
