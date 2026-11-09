// Package driver implements the DRA kubelet plugin for AF_XDP socket allocation.
//
// On NodePrepareResources:
//   - Calls groutx.XskAdd() to register an EtherType filter (GOOSE 0x88B8,
//     SV 0x88BA) with the groutx daemon, which loads the XDP pipeline and
//     returns a Unix socket path for the AF_XDP fd handoff.
//   - Writes a CDI spec that injects IEC61850_XSK_SOCKET into the pod.
//
// On NodeUnprepareResources:
//   - Calls groutx.XskDel() to detach the XDP filter and close the socket.
//   - Removes the CDI spec.
package driver

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	drav1 "k8s.io/kubelet/pkg/apis/dra/v1"

	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend"
	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/xglcheck"
	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/xsk"
)

// EtherType constants for the legacy IEC 61850 preset are in
// params.go (defaultEthertypes); the driver itself is
// protocol-neutral and takes its filter set from claim parameters.

// Driver implements drav1.DRAPluginServer.
type Driver struct {
	drav1.UnimplementedDRAPluginServer
	driverName   string
	nodeName     string
	cdiDir       string
	client       kubernetes.Interface
	backend      backend.Backend
	state        *AllocationState
	publisher    *SlicePublisher
	xglCheckBin  string
}

// NewDriver creates a new DRA XSK driver instance.
// xglCheckBin is the path to the xgl_check binary (xdp-graph-lib);
// empty disables the deterministic validation gate.
func NewDriver(driverName, nodeName, cdiDir string, b backend.Backend, xglCheckBin string, client kubernetes.Interface) *Driver {
	return &Driver{
		driverName:  driverName,
		nodeName:    nodeName,
		cdiDir:      cdiDir,
		client:      client,
		backend:     b,
		state:       NewAllocationState(),
		publisher:   NewSlicePublisher(client, driverName, nodeName),
		xglCheckBin: xglCheckBin,
	}
}

// Discover publishes the node's NIC queues as DRA ResourceSlice devices.
func (d *Driver) Discover(ctx context.Context) error {
	return d.publisher.PublishSlices(ctx)
}

// Shutdown removes the ResourceSlice on driver exit.
func (d *Driver) Shutdown(ctx context.Context) {
	if err := d.publisher.DeleteSlice(ctx); err != nil {
		klog.ErrorS(err, "Deleting ResourceSlice on shutdown")
	}
}

// NodePrepareResources calls groutx.XskAdd for each allocated NIC queue.
func (d *Driver) NodePrepareResources(ctx context.Context, req *drav1.NodePrepareResourcesRequest) (*drav1.NodePrepareResourcesResponse, error) {
	resp := &drav1.NodePrepareResourcesResponse{
		Claims: make(map[string]*drav1.NodePrepareResourceResponse),
	}
	for _, claim := range req.Claims {
		resp.Claims[claim.Uid] = d.prepareClaim(ctx, claim)
	}
	return resp, nil
}

func (d *Driver) prepareClaim(ctx context.Context, claim *drav1.Claim) *drav1.NodePrepareResourceResponse {
	rc, err := d.client.ResourceV1().ResourceClaims(claim.Namespace).Get(
		ctx, claim.Name, metav1.GetOptions{})
	if err != nil {
		return errResp("fetching ResourceClaim %s/%s: %v", claim.Namespace, claim.Name, err)
	}
	if rc.Status.Allocation == nil {
		return errResp("ResourceClaim %s/%s has no allocation", claim.Namespace, claim.Name)
	}

	allQueues, err := xsk.DiscoverQueues()
	if err != nil {
		return errResp("discovering NIC queues: %v", err)
	}
	queueByID := make(map[string]*xsk.Queue, len(allQueues))
	nQueuesByIf := make(map[string]int)
	for _, q := range allQueues {
		queueByID[q.ID] = q
		if q.QueueID+1 > nQueuesByIf[q.Ifname] {
			nQueuesByIf[q.Ifname] = q.QueueID + 1
		}
	}

	// Per-claim parameters: EtherType filter set and zero-copy mode.
	requestNames := make([]string, 0, len(rc.Status.Allocation.Devices.Results))
	for _, result := range rc.Status.Allocation.Devices.Results {
		requestNames = append(requestNames, result.Request)
	}
	params, err := paramsFromClaim(rc, d.driverName, requestNames)
	if err != nil {
		return errResp("parsing parameters for claim %s: %v", claim.Uid, err)
	}
	ethertypes, zerocopy, err := params.Resolve()
	if err != nil {
		return errResp("invalid parameters for claim %s: %v", claim.Uid, err)
	}

	// Collect the candidate allocations for this claim first: the
	// deterministic validation gate must see the entire intended
	// graph (existing + candidate) before anything is created.
	var candidates []*Allocation
	for _, result := range rc.Status.Allocation.Devices.Results {
		if result.Driver != d.driverName || result.Pool != d.nodeName {
			continue
		}
		q, ok := queueByID[result.Device]
		if !ok {
			return errResp("unknown device %s in claim %s", result.Device, claim.Uid)
		}
		candidates = append(candidates, &Allocation{
			ClaimUID:   claim.Uid,
			Ifname:     q.Ifname,
			QueueID:    q.QueueID,
			NQueues:    nQueuesByIf[q.Ifname],
			NUMANode:   q.NUMANode,
			Ethertypes: ethertypes,
			Zerocopy:   zerocopy,
		})
	}
	if len(candidates) == 0 {
		return errResp("no XSK devices found in claim %s", claim.Uid)
	}

	if err := d.validateGraph(candidates); err != nil {
		return errResp("graph validation failed for claim %s: %v", claim.Uid, err)
	}

	var devices []*drav1.Device

	for _, result := range rc.Status.Allocation.Devices.Results {
		if result.Driver != d.driverName || result.Pool != d.nodeName {
			continue
		}

		q, ok := queueByID[result.Device]
		if !ok {
			return errResp("unknown device %s in claim %s", result.Device, claim.Uid)
		}

		if err := d.state.Allocate(&Allocation{
			ClaimUID:   claim.Uid,
			Ifname:     q.Ifname,
			QueueID:    q.QueueID,
			NQueues:    nQueuesByIf[q.Ifname],
			NUMANode:   q.NUMANode,
			Ethertypes: ethertypes,
			Zerocopy:   zerocopy,
		}); err != nil {
			return errResp("allocating queue %s: %v", q.ID, err)
		}

		sockPath, err := d.backend.Add(ctx, &backend.Allocation{
			Ifname:     q.Ifname,
			Ifindex:    q.Ifindex,
			QueueID:    q.QueueID,
			Ethertypes: ethertypes,
			Zerocopy:   zerocopy,
		})
		if err != nil {
			d.state.ReleaseByClaimUID(claim.Uid)
			return errResp("allocating XSK for %s queue %d via %s backend: %v",
				q.Ifname, q.QueueID, d.backend.Name(), err)
		}

		if err := WriteCDISpec(d.cdiDir, d.driverName, q.ID, q.Ifname, q.QueueID,
			sockPath, ethertypes); err != nil {
			_ = d.backend.Del(ctx, q.Ifname, q.QueueID)
			d.state.ReleaseByClaimUID(claim.Uid)
			return errResp("writing CDI spec for %s: %v", q.ID, err)
		}

		devices = append(devices, &drav1.Device{
			RequestNames: []string{result.Request},
			PoolName:     result.Pool,
			DeviceName:   result.Device,
			CdiDeviceIds: []string{CDIDeviceID(d.driverName, q.ID)},
		})

		klog.InfoS("Prepared XSK queue", "claim", claim.Uid, "backend", d.backend.Name(),
			"queue", q.ID, "socket", sockPath)
	}

	if len(devices) == 0 {
		return errResp("no XSK devices found in claim %s", claim.Uid)
	}

	return &drav1.NodePrepareResourceResponse{Devices: devices}
}

// NodeUnprepareResources frees the XSKs and removes CDI specs.
func (d *Driver) NodeUnprepareResources(ctx context.Context, req *drav1.NodeUnprepareResourcesRequest) (*drav1.NodeUnprepareResourcesResponse, error) {
	resp := &drav1.NodeUnprepareResourcesResponse{
		Claims: make(map[string]*drav1.NodeUnprepareResourceResponse),
	}
	for _, claim := range req.Claims {
		resp.Claims[claim.Uid] = d.unprepareClaim(ctx, claim)
	}
	return resp, nil
}

func (d *Driver) unprepareClaim(ctx context.Context, claim *drav1.Claim) *drav1.NodeUnprepareResourceResponse {
	released := d.state.ReleaseByClaimUID(claim.Uid)

	for _, a := range released {
		if err := d.backend.Del(ctx, a.Ifname, a.QueueID); err != nil {
			klog.ErrorS(err, "freeing XSK", "queue", queueKey(a.Ifname, a.QueueID))
		}
		RemoveCDISpec(d.cdiDir, d.driverName, queueKey(a.Ifname, a.QueueID))
	}

	klog.InfoS("Unprepared XSK claim", "claim", claim.Uid,
		"queues", len(released))
	return &drav1.NodeUnprepareResourceResponse{}
}

// validateGraph runs the deterministic xgl_check gate over the
// intended state: all existing allocations plus the candidates.
// It is a no-op when no xgl_check binary is configured.
func (d *Driver) validateGraph(candidates []*Allocation) error {
	if d.xglCheckBin == "" {
		return nil
	}

	combined := append(d.state.Snapshot(), candidates...)
	spec := buildSpec(d.nodeName, combined)

	findings, err := xglcheck.Validate(spec, d.xglCheckBin)
	if err != nil {
		// A check that cannot run fails closed: the gate is only a
		// gate if it actually runs.
		return fmt.Errorf("running xgl_check: %w", err)
	}

	for _, f := range findings {
		klog.InfoS("xgl_check finding", "severity", f.Severity,
			"code", f.Code, "message", f.Message)
	}

	if xglcheck.HasErrors(findings) {
		var errs []string
		for _, f := range findings {
			if f.IsError() {
				errs = append(errs, f.String())
			}
		}
		return fmt.Errorf("invalid graph spec: %s", strings.Join(errs, "; "))
	}
	return nil
}

func errResp(format string, args ...any) *drav1.NodePrepareResourceResponse {
	msg := fmt.Sprintf(format, args...)
	klog.Error(msg)
	return &drav1.NodePrepareResourceResponse{Error: msg}
}
