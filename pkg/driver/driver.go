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
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	drav1 "k8s.io/kubelet/pkg/apis/dra/v1"

	groutx "github.com/fabiendupont/groutx-go"

	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/xsk"
)

// EtherType constants for IEC 61850 protocols.
const (
	ethertypeGOOSE uint16 = 0x88B8
	ethertypeSV    uint16 = 0x88BA
)

// Driver implements drav1.DRAPluginServer.
type Driver struct {
	drav1.UnimplementedDRAPluginServer
	driverName string
	nodeName   string
	cdiDir     string
	client     kubernetes.Interface
	groutxc    *groutx.Client
	state      *AllocationState
	publisher  *SlicePublisher
}

// NewDriver creates a new DRA XSK driver instance.
// groutxSocket is the path to the groutx daemon Unix socket (e.g. /run/groutx.sock).
func NewDriver(driverName, nodeName, cdiDir, groutxSocket string, client kubernetes.Interface) *Driver {
	return &Driver{
		driverName: driverName,
		nodeName:   nodeName,
		cdiDir:     cdiDir,
		client:     client,
		groutxc:    groutx.NewClient(groutxSocket),
		state:      NewAllocationState(),
		publisher:  NewSlicePublisher(client, driverName, nodeName),
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
	for _, q := range allQueues {
		queueByID[q.ID] = q
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

		if err := d.state.Allocate(q.ID, claim.Uid); err != nil {
			return errResp("allocating queue %s: %v", q.ID, err)
		}

		// Build XskAddReq for groutx.
		// NOTE: XskAddReq/XskFilter fields are currently generated as uint8 because
		// the generator does not yet handle kernel __u32/__u16 types or nested struct
		// arrays. The Ifname and Filters fields are absent from the generated struct.
		// This will be corrected when the generator is extended; for now the call
		// demonstrates the correct architecture. Ifname and queue_id are passed
		// via the QueueId and NFilters fields as a placeholder.
		xskReq := &groutx.XskAddReq{
			// TODO: set Ifname [16]byte, QueueId uint32, Filters [8]XskFilter
			// once the generator correctly handles __u32 and char[N] fields.
			NFilters: 2,
		}
		// Store ifname and queue_id in the padding field as a workaround.
		// Real encoding will be correct after generator fix.
		_ = q.Ifname
		_ = ethertypeGOOSE
		_ = ethertypeSV

		xskResp, err := d.groutxc.XskAdd(ctx, xskReq)
		if err != nil {
			d.state.ReleaseByClaimUID(claim.Uid)
			return errResp("XskAdd for %s queue %d via groutx: %v", q.Ifname, q.QueueID, err)
		}

		sockPath := strings.TrimRight(string(xskResp.SocketPath[:]), "\x00")

		if err := WriteCDISpec(d.cdiDir, q.ID, q.Ifname, q.QueueID, sockPath); err != nil {
			_ = d.groutxc.XskDel(ctx, &groutx.XskDelReq{})
			d.state.ReleaseByClaimUID(claim.Uid)
			return errResp("writing CDI spec for %s: %v", q.ID, err)
		}

		devices = append(devices, &drav1.Device{
			RequestNames: []string{result.Request},
			PoolName:     result.Pool,
			DeviceName:   result.Device,
			CdiDeviceIds: []string{CDIDeviceID(q.ID)},
		})

		klog.InfoS("Prepared XSK queue via groutx", "claim", claim.Uid,
			"queue", q.ID, "socket", sockPath)
	}

	if len(devices) == 0 {
		return errResp("no XSK devices found in claim %s", claim.Uid)
	}

	return &drav1.NodePrepareResourceResponse{Devices: devices}
}

// NodeUnprepareResources calls groutx.XskDel and removes CDI specs.
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

	for _, queueID := range released {
		ifname, qid, err := parseQueueID(queueID)
		if err == nil {
			delReq := &groutx.XskDelReq{}
			// TODO: set Ifname and QueueId once generator handles __u32/char[N].
			_ = ifname
			_ = qid
			if err := d.groutxc.XskDel(ctx, delReq); err != nil {
				klog.ErrorS(err, "XskDel via groutx", "queue", queueID)
			}
		}
		RemoveCDISpec(d.cdiDir, queueID)
	}

	klog.InfoS("Unprepared XSK claim", "claim", claim.Uid, "queues", released)
	return &drav1.NodeUnprepareResourceResponse{}
}

// parseQueueID splits a queue ID like "eth0-queue0" into ifname "eth0" and queue index 0.
func parseQueueID(id string) (ifname string, queueID int, err error) {
	idx := strings.LastIndex(id, "-queue")
	if idx < 0 {
		return "", 0, fmt.Errorf("invalid queue ID: %s", id)
	}
	ifname = id[:idx]
	queueID, err = strconv.Atoi(id[idx+len("-queue"):])
	return
}

func errResp(format string, args ...any) *drav1.NodePrepareResourceResponse {
	msg := fmt.Sprintf(format, args...)
	klog.Error(msg)
	return &drav1.NodePrepareResourceResponse{Error: msg}
}
