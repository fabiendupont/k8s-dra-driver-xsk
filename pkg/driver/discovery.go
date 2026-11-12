package driver

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/hsrprp"
	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/xsk"
)

// maxDevicesPerSlice is the API limit on ResourceSlice.spec.devices.
const maxDevicesPerSlice = 128

// SlicePublisher discovers NIC queues and publishes them as ResourceSlice devices.
type SlicePublisher struct {
	client     kubernetes.Interface
	driverName string
	nodeName   string

	// instanceID identifies this process's slices. Shutdown only
	// deletes slices it stamped itself: during a rolling update the
	// old process's graceful Shutdown can race with the replacement
	// publishing identically-named slices — deleting those would
	// leave the node with no devices until the next restart.
	instanceID string
}

func NewSlicePublisher(client kubernetes.Interface, driverName, nodeName string) *SlicePublisher {
	// Random per-process ID (crypto/rand): survives no state, needs
	// no API surface. Stamped as an annotation on every slice.
	var buf [8]byte
	if _, err := crand.Read(buf[:]); err == nil {
		return &SlicePublisher{client: client, driverName: driverName,
			nodeName: nodeName, instanceID: hex.EncodeToString(buf[:])}
	}
	return &SlicePublisher{client: client, driverName: driverName,
		nodeName: nodeName, instanceID: fmt.Sprintf("pid-%d", os.Getpid())}
}

// Discover publishes the node's NIC queues as DRA ResourceSlice devices.
func (sp *SlicePublisher) PublishSlices(ctx context.Context) error {
	return sp.publish(ctx, nil)
}

// PublishHsrPrpSlices publishes the node's HSR/PRP stream devices:
// one device per redundancy group × EtherType, in a separate pool
// from the raw queue devices so selectors never mix the two.
func (sp *SlicePublisher) PublishHsrPrpSlices(ctx context.Context, cfg *hsrprp.Config) error {
	return sp.publish(ctx, cfg)
}

// publish creates/updates the node's ResourceSlices. queueCfg nil
// publishes only queue devices; a non-nil hsr-prp config additionally
// publishes stream devices in a second pool.
func (sp *SlicePublisher) publish(ctx context.Context, hsrprpCfg *hsrprp.Config) error {
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

	if err := sp.publishPool(ctx, devices, sp.sliceName, sp.nodeName); err != nil {
		return err
	}

	if hsrprpCfg == nil || len(hsrprpCfg.Groups) == 0 {
		// Still clean up any leftover stream slices from a previous
		// run with a config.
		return sp.deleteOwnSlices(ctx, sp.streamSliceName)
	}

	streamDevices := make([]resourceapi.Device, 0)
	for _, g := range hsrprpCfg.Groups {
		for _, s := range g.Streams {
			et, err := hsrprp.ParseEthertypeHex(s.Ethertype)
			if err != nil {
				return fmt.Errorf("group %q: %w", g.Name, err)
			}
			streamDevices = append(streamDevices, resourceapi.Device{
				// Device name doubles as the CDI id; see
				// prepareStreamClaim.
				Name: fmt.Sprintf("%s-%04x", g.Name, et),
				Attributes: map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{
					"type":      {StringValue: stringPtr("hsr-prp-stream")},
					"group":     {StringValue: stringPtr(g.Name)},
					"mode":      {StringValue: stringPtr(g.Mode)},
					"ports":     {StringValue: stringPtr(g.Ports[0] + "," + g.Ports[1])},
					"ethertype": {IntValue: int64Ptr(int64(et))},
					// veth-backed delivery: no zerocopy.
					"zerocopy": {BoolValue: boolPtr(false)},
				},
			})
		}
	}

	pool := streamPoolName(sp.nodeName)
	return sp.publishPool(ctx, streamDevices, sp.streamSliceName, pool)
}

// publishPool creates or updates one pool's slices. Devices are
// paginated across slices (max 128 each); all slices in a pool share
// one pool name, so the scheduler treats them as a single device set.
func (sp *SlicePublisher) publishPool(ctx context.Context, devices []resourceapi.Device,
	sliceName func(int) string, pool string) error {

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
				Name:            sliceName(i),
				OwnerReferences: ownerRef,
				Annotations: map[string]string{
					instanceAnnotation: sp.instanceID,
				},
			},
			Spec: resourceapi.ResourceSliceSpec{
				Driver:   sp.driverName,
				NodeName: &sp.nodeName,
				Pool: resourceapi.ResourcePool{
					Name:               pool,
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

	// Delete slices beyond the current count (device count shrank);
	// never touch a newer instance's slices.
	for i := nSlices; ; i++ {
		name := sliceName(i)
		existing, err := sp.client.ResourceV1().ResourceSlices().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			break // not found — no more leftovers
		}
		if existing.Annotations[instanceAnnotation] != sp.instanceID {
			break // belongs to a newer process
		}
		if err := sp.client.ResourceV1().ResourceSlices().Delete(
			ctx, name, metav1.DeleteOptions{}); err != nil {
			break
		}
		klog.InfoS("Deleted leftover ResourceSlice", "name", name)
	}

	return nil
}

// instanceAnnotation stamps the publishing process on each slice so
// a shutting-down process does not delete its replacement's slices.
const instanceAnnotation = "xsk.dra.io/instance"

// DeleteSlice removes the node's ResourceSlices (both pools), but
// only those stamped with this process's instance ID — slices from a
// newer process (rolling update) are left alone.
func (sp *SlicePublisher) DeleteSlice(ctx context.Context) error {
	if err := sp.deleteOwnSlices(ctx, sp.sliceName); err != nil {
		return err
	}
	return sp.deleteOwnSlices(ctx, sp.streamSliceName)
}

// deleteOwnSlices deletes slice 0..n of a pool, stopping at the
// first slice that belongs to another process (or is already gone).
func (sp *SlicePublisher) deleteOwnSlices(ctx context.Context, sliceName func(int) string) error {
	for i := 0; ; i++ {
		name := sliceName(i)
		existing, err := sp.client.ResourceV1().ResourceSlices().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			if i == 0 {
				// Already gone — nothing to clean up.
				return nil
			}
			break // not found — no more of ours
		}
		if existing.Annotations[instanceAnnotation] != sp.instanceID {
			// A newer process owns this slice now.
			klog.InfoS("Skipping slice owned by a newer driver instance",
				"name", name, "owner", existing.Annotations[instanceAnnotation])
			return nil
		}
		if err := sp.client.ResourceV1().ResourceSlices().Delete(
			ctx, name, metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("deleting ResourceSlice %s: %w", name, err)
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

func (sp *SlicePublisher) streamSliceName(i int) string {
	if i == 0 {
		return fmt.Sprintf("%s-%s%s", sp.nodeName, sp.driverName, StreamPoolSuffix)
	}
	return fmt.Sprintf("%s-%s%s-%d", sp.nodeName, sp.driverName, StreamPoolSuffix, i)
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
