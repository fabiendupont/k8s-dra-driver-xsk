// Package bpfman implements backend.Backend by delegating XDP
// program loading to the bpfman eBPF Manager Operator through its
// CRD API (BpfApplication), while creating AF_XDP sockets and
// updating maps in-process.
//
// This uses the CRD API (BpfApplication) for program loading,
// which is the supported external interface for the
// operator-deployed bpfman (its gRPC socket is pod-local).
// Maps are pinned under the shared /run/bpfman hostPath.
//
// KNOWN LIMITATION: the BpfApplication CRD's
// networkNamespaces.pods field (required for XDP links) only
// selects POD network namespaces — there is no host-netns option.
// Program loading succeeds (bpfman assigns a program ID), but XDP
// attachment to host network interfaces fails with
// UpdateAttachInfoError. This is an upstream bpfman CRD design
// limitation: the model targets pod-level network functions, not
// host NIC attachment.
//
// For host-netns XDP attachment through bpfman, use the gRPC API
// with a manually-deployed bpfman daemon that exposes its socket
// on the host. The CRD path would need an upstream bpfman
// enhancement to support host-netns attachment (e.g. a
// networkNamespaces.host option or primaryNodeInterface
// overriding the netns selector).
//
// The filter program is the same embedded ELF the native backend
// loads; it is written to a shared hostPath directory that the
// bpfman agent can read.
package bpfman

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

	// elfDir is where the driver writes the embedded ELF for the
	// bpfman agent to read. Must be a hostPath shared between the
	// driver pod and the bpfman daemon pod. /run/bpfman is the
	// bpfman operator's runtime hostPath.
	elfDir = "/run/bpfman"

	// crdNamespace is where BpfApplication resources are created.
	crdNamespace = "bpfman"

	// mapRoot is where bpfman pins program maps. Under the
	// operator's runtime hostPath.
	mapRoot = "/run/bpfman/fs/maps"

	// loadTimeout is how long to wait for BpfApplicationState
	// to report the program is loaded.
	loadTimeout = 60 * time.Second
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
	client    dynamic.Interface
	nodeName  string

	mu       sync.Mutex
	appName  string // BpfApplication resource name
	elfPath  string
	loaded   bool
	mapDir   string // directory containing pinned maps for our program
	allocs   map[string]*alloc
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

// ensureLoaded writes the embedded ELF, creates the
// BpfApplication CR, and waits for the program to be loaded.
func (b *Backend) ensureLoaded(ctx context.Context, ifname string) error {
	if b.loaded {
		return nil
	}

	// Write the embedded ELF to the shared hostPath.
	if err := os.MkdirAll(elfDir, 0755); err != nil {
		return fmt.Errorf("creating %s: %w", elfDir, err)
	}
	elfPath := filepath.Join(elfDir, "xsk-dra-driver.bpf.o")
	elfBytes, err := native.FilterELFBytes()
	if err != nil {
		return err
	}
	if err := os.WriteFile(elfPath, elfBytes, 0644); err != nil {
		return fmt.Errorf("writing filter ELF: %w", err)
	}
	b.elfPath = elfPath
	b.appName = fmt.Sprintf("xsk-dra-driver-%s", b.nodeName)

	// Create the BpfApplication CR.
	app := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "bpfman.io/v1alpha1",
		"kind":       "BpfApplication",
		"metadata": map[string]interface{}{
			"name":      b.appName,
			"namespace": crdNamespace,
		},
		"spec": map[string]interface{}{
			"byteCode": map[string]interface{}{
				"path": elfPath,
			},
			"nodeSelector": map[string]interface{}{
				"matchLabels": map[string]interface{}{
					"kubernetes.io/hostname": b.nodeName,
				},
			},
			"programs": []interface{}{
				map[string]interface{}{
					"name": programName,
					"type": "XDP",
					"xdp": map[string]interface{}{
						"links": []interface{}{
							map[string]interface{}{
								"interfaceSelector": map[string]interface{}{
									"interfaces": []interface{}{ifname},
								},
								"networkNamespaces": map[string]interface{}{"pods": map[string]interface{}{}},
							},
						},
					},
				},
			},
		},
	}}

	_, err = b.client.Resource(bpfAppGVR).Namespace(crdNamespace).Create(
		ctx, app, metav1.CreateOptions{})
	if err != nil {
		// If it already exists (driver restart), update it.
		existing, getErr := b.client.Resource(bpfAppGVR).Namespace(
			crdNamespace).Get(ctx, b.appName, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("creating BpfApplication: %w (get: %v)", err, getErr)
		}
		app.SetResourceVersion(existing.GetResourceVersion())
		_, err = b.client.Resource(bpfAppGVR).Namespace(crdNamespace).Update(
			ctx, app, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("updating BpfApplication: %w", err)
		}
	}

	// Wait for BpfApplicationState to report loaded.
	if err := b.waitForLoad(ctx); err != nil {
		return err
	}

	b.loaded = true
	klog.InfoS("bpfman program loaded", "app", b.appName,
		"elf", b.elfPath, "interface", ifname)
	return nil
}

// waitForLoad polls the BpfApplicationState until the program is
// loaded, then discovers the map pin directory.
func (b *Backend) waitForLoad(ctx context.Context) error {
	deadline := time.Now().Add(loadTimeout)
	stateName := b.appName

	for time.Now().Before(deadline) {
		state, err := b.client.Resource(bpfAppStateGVR).Namespace(
			crdNamespace).Get(ctx, stateName, metav1.GetOptions{})
		if err != nil {
			// State may not exist yet; retry.
			time.Sleep(2 * time.Second)
			continue
		}

		// Check the overall load status.
		status, found, _ := unstructured.NestedString(
			state.Object, "status", "appLoadStatus")
		if !found {
			time.Sleep(2 * time.Second)
			continue
		}

		if status == "Loaded" || status == "Succeeded" ||
			status == "Complete" {
			// Find the map pin directory. bpfman pins maps under
			// /run/bpfman/fs/maps/<uuid>/ on the host.
			if err := b.discoverMapDir(ctx, state); err != nil {
				return fmt.Errorf("discovering map directory: %w", err)
			}
			return nil
		}

		if strings.Contains(strings.ToLower(status), "fail") ||
			strings.Contains(strings.ToLower(status), "error") {
			// Check conditions for details.
			conditions, _, _ := unstructured.NestedSlice(
				state.Object, "status", "conditions")
			for _, c := range conditions {
				cond, ok := c.(map[string]interface{})
				if !ok {
					continue
				}
				msg, _, _ := unstructured.NestedString(cond, "message")
				if msg != "" {
					return fmt.Errorf("bpfman load failed: %s: %s", status, msg)
				}
			}
			return fmt.Errorf("bpfman load failed: %s", status)
		}

		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("timeout waiting for BpfApplicationState %s", stateName)
}

// discoverMapDir finds the pinned map directory for our program.
// bpfman pins maps under /run/bpfman/fs/maps/<uuid>/ — we look for
// the directory containing our maps.
func (b *Backend) discoverMapDir(ctx context.Context,
	state *unstructured.Unstructured) error {

	// Walk /run/bpfman/fs/maps/ looking for our maps.
	entries, err := os.ReadDir(mapRoot)
	if err != nil {
		return fmt.Errorf("reading %s: %w (is the bpfman runtime "+
			"hostPath mounted?)", mapRoot, err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(mapRoot, e.Name())
		// Check if this directory has our maps.
		if _, err := os.Stat(filepath.Join(dir, "xsk_map")); err == nil {
			b.mapDir = dir
			klog.InfoS("Found bpfman map directory", "dir", dir)
			return nil
		}
	}

	return fmt.Errorf("no map directory with xsk_map under %s", mapRoot)
}

// openMap opens one of the program's pinned maps by name.
func (b *Backend) openMap(name string) (*ebpf.Map, error) {
	if b.mapDir == "" {
		return nil, fmt.Errorf("map directory not discovered")
	}
	return ebpf.LoadPinnedMap(filepath.Join(b.mapDir, name), nil)
}

// updateInterface adds the interface to the BpfApplication's
// XDP links if not already present.
func (b *Backend) updateInterface(ctx context.Context, ifname string) error {
	app, err := b.client.Resource(bpfAppGVR).Namespace(
		crdNamespace).Get(ctx, b.appName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("getting BpfApplication: %w", err)
	}

	programs, found, _ := unstructured.NestedSlice(app.Object,
		"spec", "programs")
	if !found || len(programs) == 0 {
		return fmt.Errorf("BpfApplication has no programs")
	}

	prog, ok := programs[0].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid program spec")
	}

	xdp, found, _ := unstructured.NestedMap(prog, "xdp")
	if !found {
		return fmt.Errorf("no xdp section")
	}

	links, _, _ := unstructured.NestedSlice(xdp, "links")
	for _, l := range links {
		link, ok := l.(map[string]interface{})
		if !ok {
			continue
		}
		ifaces, _, _ := unstructured.NestedStringSlice(link,
			"interfaceSelector", "interfaces")
		for _, i := range ifaces {
			if i == ifname {
				return nil // already present
			}
		}
	}

	// Add the new interface to the first link's selector.
	if len(links) > 0 {
		link, ok := links[0].(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid link")
		}
		sel, _, _ := unstructured.NestedMap(link, "interfaceSelector")
		ifaces, _, _ := unstructured.NestedStringSlice(sel, "interfaces")
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
		if err := unstructured.SetNestedSlice(xdp, links, "links"); err != nil {
			return err
		}
		if err := unstructured.SetNestedMap(prog, xdp, "xdp"); err != nil {
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
	}

	return nil
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

	if err := b.ensureLoaded(ctx, a.Ifname); err != nil {
		return "", err
	}

	// If this is a new interface, add it to the BpfApplication.
	if err := b.updateInterface(ctx, a.Ifname); err != nil {
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

	sockPath := filepath.Join(filepath.Dir(elfDir),
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

	// Delete the BpfApplication when no allocations remain.
	if len(b.allocs) == 0 && b.loaded {
		if err := b.client.Resource(bpfAppGVR).Namespace(
			crdNamespace).Delete(ctx, b.appName,
			metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("deleting BpfApplication: %w", err)
		}
		b.loaded = false
		b.mapDir = ""
		klog.InfoS("Deleted BpfApplication", "name", b.appName)
	}

	return nil
}
