package driver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/klog/v2"
)

// socketDir is derived from the sockPath at runtime (see WriteCDISpec).
// It is used to bind-mount the socket's parent directory into the container.

const (
	cdiVendor  = "xsk.iec61850.io"
	cdiClass   = "queue"
	cdiVersion = "0.6.0"

	// CDIDir is where the driver writes CDI spec files.
	// The container runtime (CRI-O / containerd) watches this directory.
	CDIDir = "/etc/cdi"
)

type cdiSpec struct {
	CDIVersion string      `json:"cdiVersion"`
	Kind       string      `json:"kind"`
	Devices    []cdiDevice `json:"devices"`
}

type cdiDevice struct {
	Name           string           `json:"name"`
	ContainerEdits cdiContainerEdit `json:"containerEdits"`
}

type cdiContainerEdit struct {
	Env    []string   `json:"env,omitempty"`
	Mounts []cdiMount `json:"mounts,omitempty"`
}

type cdiMount struct {
	HostPath      string   `json:"hostPath"`
	ContainerPath string   `json:"containerPath"`
	Options       []string `json:"options,omitempty"`
}

// CDIDeviceID returns the CDI device ID for a NIC queue.
// Example: "xsk.iec61850.io/queue=eth0-queue0"
func CDIDeviceID(queueID string) string {
	return cdiVendor + "/" + cdiClass + "=" + queueID
}

// WriteCDISpec writes a CDI spec for the allocated queue so the container
// runtime injects IEC61850_XSK_SOCKET and mounts the socket directory.
func WriteCDISpec(cdiDir, queueID, ifname string, queueIdx int, sockPath string) error {
	if err := os.MkdirAll(cdiDir, 0755); err != nil {
		return fmt.Errorf("creating CDI dir: %w", err)
	}

	spec := cdiSpec{
		CDIVersion: cdiVersion,
		Kind:       cdiVendor + "/" + cdiClass,
		Devices: []cdiDevice{
			{
				Name: queueID,
				ContainerEdits: cdiContainerEdit{
					Env: []string{
						fmt.Sprintf("IEC61850_XSK_SOCKET=%s", sockPath),
						fmt.Sprintf("IEC61850_XSK_IFACE=%s", ifname),
						fmt.Sprintf("IEC61850_XSK_QUEUE=%d", queueIdx),
					},
					Mounts: []cdiMount{
						{
							HostPath:      filepath.Dir(sockPath),
							ContainerPath: filepath.Dir(sockPath),
							Options:       []string{"bind", "ro"},
						},
					},
				},
			},
		},
	}

	specPath := cdiSpecPath(cdiDir, queueID)
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling CDI spec: %w", err)
	}
	if err := os.WriteFile(specPath, data, 0644); err != nil {
		return fmt.Errorf("writing CDI spec %s: %w", specPath, err)
	}

	klog.InfoS("Wrote CDI spec", "path", specPath, "queue", queueID)
	return nil
}

// RemoveCDISpec deletes the CDI spec for a queue.
func RemoveCDISpec(cdiDir, queueID string) {
	specPath := cdiSpecPath(cdiDir, queueID)
	if err := os.Remove(specPath); err != nil && !os.IsNotExist(err) {
		klog.ErrorS(err, "Removing CDI spec", "path", specPath)
	}
}

func cdiSpecPath(cdiDir, queueID string) string {
	return filepath.Join(cdiDir, cdiVendor+"-"+cdiClass+"-"+queueID+".json")
}
