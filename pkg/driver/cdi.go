package driver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/klog/v2"
)

// socketDir is derived from the sockPath at runtime (see WriteCDISpec).
// It is used to bind-mount the socket's parent directory into the container.

const (
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
// Example: "xsk.dra.io/queue=eth0-queue0"
func CDIDeviceID(driverName, queueID string) string {
	return driverName + "/" + cdiClass + "=" + queueID
}

// WriteCDISpec writes a CDI spec for the allocated queue so the container
// runtime injects XSK_SOCKET and mounts the socket directory.
func WriteCDISpec(cdiDir, driverName, queueID, ifname string, queueIdx int,
	sockPath string, ethertypes []uint16) error {
	if err := os.MkdirAll(cdiDir, 0755); err != nil {
		return fmt.Errorf("creating CDI dir: %w", err)
	}

	etList := make([]string, len(ethertypes))
	for i, et := range ethertypes {
		etList[i] = fmt.Sprintf("%#04x", et)
	}

	spec := cdiSpec{
		CDIVersion: cdiVersion,
		Kind:       driverName + "/" + cdiClass,
		Devices: []cdiDevice{
			{
				Name: queueID,
				ContainerEdits: cdiContainerEdit{
					Env: []string{
						fmt.Sprintf("XSK_SOCKET=%s", sockPath),
						fmt.Sprintf("XSK_IFACE=%s", ifname),
						fmt.Sprintf("XSK_QUEUE=%d", queueIdx),
						fmt.Sprintf("XSK_ETHTYPES=%s", strings.Join(etList, ",")),
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

	specPath := cdiSpecPath(cdiDir, driverName, queueID)
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
func RemoveCDISpec(cdiDir, driverName, queueID string) {
	specPath := cdiSpecPath(cdiDir, driverName, queueID)
	if err := os.Remove(specPath); err != nil && !os.IsNotExist(err) {
		klog.ErrorS(err, "Removing CDI spec", "path", specPath)
	}
}

func cdiSpecPath(cdiDir, driverName, queueID string) string {
	return filepath.Join(cdiDir, driverName+"-"+cdiClass+"-"+queueID+".json")
}
