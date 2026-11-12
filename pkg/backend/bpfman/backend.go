// Package bpfman implements backend.Backend by delegating XDP
// program loading to the bpfman eBPF Manager Operator through its
// CRD API (BpfApplication), while creating AF_XDP sockets and
// updating maps in-process.
//
// Maps are accessed through a bpfman CSI volume mounted into the
// driver pod (see the DaemonSet spec). The CSI driver re-pins the
// program's maps into our mount namespace, bypassing bpfman's
// container-local bpffs.
//
// The BpfApplication CR (deployments/bpfman-program.yaml) is a
// static resource deployed before the driver DaemonSet, so the
// program is loaded before the CSI volume mount is attempted.
// The driver updates the interface list at runtime via the
// Kubernetes API.
package bpfman

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend"
	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend/native"
)

const (
	// programName must match the XDP program in the embedded ELF.
	programName = "xdp_xsk_filter"

	// elfPath is where the driver writes the embedded ELF for the
	// bpfman agent to read. /run/bpfman is the bpfman operator's
	// runtime hostPath, shared between pods on the same node.
	elfPath = "/run/bpfman/xsk-dra-driver.bpf.o"

	// csiMapDir is where the bpfman CSI driver mounts the
	// program's maps into our pod. The CSI volume is declared in
	// the DaemonSet spec with volumeAttributes matching the
	// BpfApplication's bpfman.io/ProgramName metadata.
	csiMapDir = "/run/xsk/bpfman-maps"

	// crdNamespace is where BpfApplication resources live.
	crdNamespace = "bpfman"

	// appLoadTimeout is how long to wait for the program to be
	// loaded by bpfman (via the pre-deployed BpfApplication).
	appLoadTimeout = 120 * time.Second
)

var (
	bpfAppGVR = schema.GroupVersionResource{
		Group:    "bpfman.io",
		Version:  "v1alpha1",
		Resource: "bpfapplications",
	}
	bpfAppStateGVR = schema.GroupVersionResource{
		Group:    "bpfman.io",
		Version:  "v1alpha1",
		Resource: "bpfapplicationstates",
	}
)

// Backend implements backend.Backend via the bpfman CRD API.
type Backend struct {
	client   dynamic.Interface
	nodeName string

	mu     sync.Mutex
	appName string
	allocs map[string]*alloc
}

type alloc struct {
	req     *backend.Allocation
	xsk     *native.XSK
	handoff *native.HandoffServer
}

// New creates the bpfman CRD backend.
func New(nodeName string, restConfig *rest.Config) (*Backend, error) {
	dyn, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("creating dynamic client: %w", err)
	}
	return &Backend{
		client:   dyn,
		nodeName: nodeName,
		allocs:   make(map[string]*alloc),
	}, nil
}

func (b *Backend) Name() string { return "bpfman" }

func allocKey(ifname string, queueID int) string {
	return fmt.Sprintf("%s:%d", ifname, queueID)
}

// ensureElf writes the embedded ELF to the shared hostPath.
func (b *Backend) ensureElf() error {
	if _, err := os.Stat(elfPath); err == nil {
		return nil // already written
	}
	dir := filepath.Dir(elfPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	elfBytes, err := native.FilterELFBytes()
	if err != nil {
		return err
	}
	if err := os.WriteFile(elfPath, elfBytes, 0644); err != nil {
		return fmt.Errorf("writing filter ELF: %w", err)
	}
	return nil
}

// ensureProgramLoaded waits for the pre-deployed BpfApplication
// to be loaded by bpfman. Checks for a program ID being assigned
// (more stable than appLoadStatus, which fluctuates during
// interface updates).
func (b *Backend) ensureProgramLoaded(ctx context.Context) error {
	b.appName = "xsk-dra-driver"

	deadline := time.Now().Add(appLoadTimeout)
	for time.Now().Before(deadline) {
		states, err := b.client.Resource(bpfAppStateGVR).Namespace(
			crdNamespace).List(ctx, metav1.ListOptions{
			LabelSelector: "bpfman.io/ownedByProgram=xsk-dra-driver",
		})
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		for _, state := range states.Items {
			node, _, _ := unstructured.NestedString(
				state.Object, "status", "node")
			if node != b.nodeName {
				continue
			}
			// Check for a program ID — assigned once bpfman loads
			// the program, regardless of attach state.
			programs, _, _ := unstructured.NestedSlice(
				state.Object, "status", "programs")
			for _, p := range programs {
				prog, ok := p.(map[string]interface{})
				if !ok {
					continue
				}
				name, _, _ := unstructured.NestedString(prog, "name")
				if name != programName {
					continue
				}
				progID, _, _ := unstructured.NestedInt64(prog, "programId")
				if progID > 0 {
					klog.InfoS("bpfman program loaded",
						"app", b.appName, "node", node,
						"programId", progID)
					return nil
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for bpfman program on node %s", b.nodeName)
}

// addInterface updates the BpfApplication to include the given
// interface in its XDP links.
func (b *Backend) addInterface(ctx context.Context, ifname string) error {
	app, err := b.client.Resource(bpfAppGVR).Namespace(
		crdNamespace).Get(ctx, b.appName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting BpfApplication: %w", err)
	}

	// Get the current interface list.
	programs, found, _ := unstructured.NestedSlice(app.Object,
		"spec", "programs")
	if !found || len(programs) == 0 {
		return fmt.Errorf("BpfApplication has no programs")
	}
	prog, ok := programs[0].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid program spec")
	}
	links, _, _ := unstructured.NestedSlice(prog, "xdp", "links")
	if len(links) == 0 {
		return fmt.Errorf("BpfApplication has no XDP links")
	}
	link, ok := links[0].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid link")
	}
	sel, _, _ := unstructured.NestedMap(link, "interfaceSelector")
	ifaces, _, _ := unstructured.NestedStringSlice(sel, "interfaces")

	// Check if already present.
	for _, i := range ifaces {
		if i == ifname {
			return nil
		}
	}

	// Add the new interface.
	newIfaces := append(ifaces, ifname)
	if err := unstructured.SetNestedStringSlice(sel, newIfaces,
		"interfaces"); err != nil {
		return err
	}
	if err := unstructured.SetNestedMap(link, sel,
		"interfaceSelector"); err != nil {
		return err
	}
	links[0] = link
	xdpMap, _, _ := unstructured.NestedMap(prog, "xdp")
	if err := unstructured.SetNestedSlice(xdpMap, links, "links"); err != nil {
		return err
	}
	if err := unstructured.SetNestedMap(prog, xdpMap, "xdp"); err != nil {
		return err
	}
	programs[0] = prog
	if err := unstructured.SetNestedSlice(app.Object, programs,
		"spec", "programs"); err != nil {
		return err
	}

	_, err = b.client.Resource(bpfAppGVR).Namespace(
		crdNamespace).Update(ctx, app, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("updating BpfApplication interfaces: %w", err)
	}

	// Wait for the interface to appear in the BpfApplicationState
	// with a successful link status.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		states, err := b.client.Resource(bpfAppStateGVR).Namespace(
			crdNamespace).List(ctx, metav1.ListOptions{
			LabelSelector: "bpfman.io/ownedByProgram=xsk-dra-driver",
		})
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		for _, state := range states.Items {
			node, _, _ := unstructured.NestedString(
				state.Object, "status", "node")
			if node != b.nodeName {
				continue
			}
			programs, _, _ := unstructured.NestedSlice(
				state.Object, "status", "programs")
			for _, p := range programs {
				prog, ok := p.(map[string]interface{})
				if !ok {
					continue
				}
				xdp, _, _ := unstructured.NestedMap(prog, "xdp")
				links, _, _ := unstructured.NestedSlice(xdp, "links")
				for _, l := range links {
					link, ok := l.(map[string]interface{})
					if !ok {
						continue
					}
					ifName, _, _ := unstructured.NestedString(link, "interfaceName")
					if ifName == ifname {
						status, _, _ := unstructured.NestedString(link, "linkStatus")
						if status == "Attached" || status == "Loaded" {
							klog.InfoS("bpfman interface attached",
								"interface", ifname, "status", status)
							return nil
						}
					}
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for interface %s to attach", ifname)
}

// openMap opens one of the program's maps from the CSI-mounted
// directory. The bpfman CSI driver re-pins the maps into our
// pod's mount namespace.
func (b *Backend) openMap(name string) (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(filepath.Join(csiMapDir, name), nil)
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

	// Ensure the ELF is available and the program is loaded.
	if err := b.ensureElf(); err != nil {
		return "", err
	}
	if err := b.ensureProgramLoaded(ctx); err != nil {
		return "", err
	}

	// If this is a new interface, add it to the BpfApplication.
	if err := b.addInterface(ctx, a.Ifname); err != nil {
		return "", err
	}

	// XSK creation is program-loader-agnostic.
	xsk, err := native.OpenXSK(a.Ifindex, a.QueueID,
		native.DefaultFrameSize, native.DefaultNumFrames, a.Zerocopy)
	if err != nil {
		return "", fmt.Errorf("opening XSK for %s: %w", key, err)
	}

	xskMap, err := b.openMap("xsk_map")
	if err != nil {
		xsk.Close()
		return "", fmt.Errorf("opening xsk_map from CSI mount: %w", err)
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
		return "", fmt.Errorf("opening xsk_ethertypes from CSI mount: %w", err)
	}
	defer etMap.Close()
	for _, et := range a.Ethertypes {
		if err := etMap.Put(et, uint8(1)); err != nil {
			xsk.Close()
			return "", fmt.Errorf("installing filter %#04x: %w", et, err)
		}
	}

	sockPath := filepath.Join(filepath.Dir(csiMapDir),
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

	return nil
}
