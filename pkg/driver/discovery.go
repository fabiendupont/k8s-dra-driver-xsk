package driver

import (
	"context"
	"fmt"

	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/xsk"
)

// maxDevicesPerSlice is the API limit on ResourceSlice.spec.devices.
const maxDevicesPerSlice = 128

// SlicePublisher discovers NIC queues and publishes them as ResourceSlice devices.
type SlicePublisher struct {
	client     kubernetes.Interface
	driverName string
	nodeName   string
}

func NewSlicePublisher(client kubernetes.Interface, driverName, nodeName string) *SlicePublisher {
	return &SlicePublisher{client: client, driverName: driverName, nodeName: nodeName}
}

// PublishSlices discovers NIC queues and creates/updates the node's
// ResourceSlices. Nodes with more queues than the per-slice device
// limit (128) — e.g. a many-queue virtio NIC on a large VM — are
// paginated across multiple slices; all slices share one pool, so
// the scheduler treats them as a single device set.
func (sp *SlicePublisher) PublishSlices(ctx context.Context) error {
	queues, err := xsk.DiscoverQueues()
	if err != nil {
		return fmt.Errorf("discovering NIC queues: %w", err)
	}

	devices := make([]resourceapi.Device, 0, len(queues))
	for _, q := range queues {
		dev := resourceapi.Device{
			Name: q.ID,
			Attributes: map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{
				"ifname":   {StringValue: stringPtr(q.Ifname)},
				"queueID":  {IntValue: int64Ptr(int64(q.QueueID))},
				"driver":   {StringValue: stringPtr(q.Driver)},
				"numaNode": {IntValue: int64Ptr(int64(q.NUMANode))},
				"zerocopy": {BoolValue: boolPtr(q.Zerocopy)},
			},
		}
		devices = append(devices, dev)
	}

	ownerRef, err := sp.nodeOwnerReference(ctx)
	if err != nil {
		klog.ErrorS(err, "Could not set Node owner reference on ResourceSlice")
	}

	nSlices := (len(devices) + maxDevicesPerSlice - 1) / maxDevicesPerSlice
	if nSlices == 0 {
		nSlices = 1
	}

	// Create or update every slice; delete leftovers from a previous
	// run with more slices.
	for i := 0; i < nSlices; i++ {
		lo := i * maxDevicesPerSlice
		hi := lo + maxDevicesPerSlice
		if hi > len(devices) {
			hi = len(devices)
		}

		slice := &resourceapi.ResourceSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:            sp.sliceName(i),
				OwnerReferences: ownerRef,
			},
			Spec: resourceapi.ResourceSliceSpec{
				Driver:   sp.driverName,
				NodeName: &sp.nodeName,
				Pool: resourceapi.ResourcePool{
					Name:               sp.nodeName,
					ResourceSliceCount: int64(nSlices),
				},
				Devices: devices[lo:hi],
			},
		}

		_, err = sp.client.ResourceV1().ResourceSlices().Create(ctx, slice, metav1.CreateOptions{})
		if err == nil {
			klog.InfoS("Created ResourceSlice", "name", slice.Name,
				"devices", hi-lo, "slice", fmt.Sprintf("%d/%d", i+1, nSlices))
			continue
		}

		existing, getErr := sp.client.ResourceV1().ResourceSlices().Get(ctx, slice.Name, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("creating ResourceSlice: %w; fetching existing: %v", err, getErr)
		}

		slice.ResourceVersion = existing.ResourceVersion
		_, err = sp.client.ResourceV1().ResourceSlices().Update(ctx, slice, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("updating ResourceSlice: %w", err)
		}
		klog.InfoS("Updated ResourceSlice", "name", slice.Name,
			"devices", hi-lo, "slice", fmt.Sprintf("%d/%d", i+1, nSlices))
	}

	// Delete slices beyond the current count (queue count shrank).
	for i := nSlices; ; i++ {
		name := sp.sliceName(i)
		if err := sp.client.ResourceV1().ResourceSlices().Delete(
			ctx, name, metav1.DeleteOptions{}); err != nil {
			break // not found — no more leftovers
		}
		klog.InfoS("Deleted leftover ResourceSlice", "name", name)
	}

	return nil
}

// DeleteSlice removes the node's ResourceSlices.
func (sp *SlicePublisher) DeleteSlice(ctx context.Context) error {
	for i := 0; ; i++ {
		name := sp.sliceName(i)
		if err := sp.client.ResourceV1().ResourceSlices().Delete(
			ctx, name, metav1.DeleteOptions{}); err != nil {
			if i == 0 {
				return fmt.Errorf("deleting ResourceSlice %s: %w", name, err)
			}
			break
		}
		klog.InfoS("Deleted ResourceSlice", "name", name)
	}
	return nil
}

func (sp *SlicePublisher) sliceName(i int) string {
	if i == 0 {
		return fmt.Sprintf("%s-%s", sp.nodeName, sp.driverName)
	}
	return fmt.Sprintf("%s-%s-%d", sp.nodeName, sp.driverName, i)
}

func (sp *SlicePublisher) nodeOwnerReference(ctx context.Context) ([]metav1.OwnerReference, error) {
	node, err := sp.client.CoreV1().Nodes().Get(ctx, sp.nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting node %s: %w", sp.nodeName, err)
	}
	return []metav1.OwnerReference{{
		APIVersion: "v1",
		Kind:       "Node",
		Name:       node.Name,
		UID:        node.UID,
	}}, nil
}

func int64Ptr(v int64) *int64   { return &v }
func stringPtr(v string) *string { return &v }
func boolPtr(v bool) *bool      { return &v }
