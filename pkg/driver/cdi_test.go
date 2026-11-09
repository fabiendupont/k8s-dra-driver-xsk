package driver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCDISpec(t *testing.T) {
	dir := t.TempDir()

	if err := WriteCDISpec(dir, "xsk.dra.io", "eth0-queue0", "eth0", 0,
		"/run/xsk/eth0-q0.sock", []uint16{0x88B8, 0x88BA}); err != nil {
		t.Fatalf("write: %v", err)
	}

	path := filepath.Join(dir, "xsk.dra.io-queue-eth0-queue0.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("spec file: %v", err)
	}

	var spec struct {
		CDIVersion string `json:"cdiVersion"`
		Kind       string `json:"kind"`
		Devices    []struct {
			Name           string `json:"name"`
			ContainerEdits struct {
				Env    []string `json:"env"`
				Mounts []struct {
					HostPath string `json:"hostPath"`
				} `json:"mounts"`
			} `json:"containerEdits"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if spec.Kind != "xsk.dra.io/queue" {
		t.Errorf("kind = %q", spec.Kind)
	}
	if len(spec.Devices) != 1 || spec.Devices[0].Name != "eth0-queue0" {
		t.Fatalf("devices = %+v", spec.Devices)
	}
	env := strings.Join(spec.Devices[0].ContainerEdits.Env, "\n")
	for _, want := range []string{
		"XSK_SOCKET=/run/xsk/eth0-q0.sock",
		"XSK_IFACE=eth0",
		"XSK_QUEUE=0",
		"XSK_ETHTYPES=0x88b8,0x88ba",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("env missing %q:\n%s", want, env)
		}
	}
	if strings.Contains(env, "IEC61850") {
		t.Errorf("legacy IEC61850 env vars leaked:\n%s", env)
	}
	if len(spec.Devices[0].ContainerEdits.Mounts) != 1 ||
		spec.Devices[0].ContainerEdits.Mounts[0].HostPath != "/run/xsk" {
		t.Errorf("mounts = %+v", spec.Devices[0].ContainerEdits.Mounts)
	}

	if got := CDIDeviceID("xsk.dra.io", "eth0-queue0"); got != "xsk.dra.io/queue=eth0-queue0" {
		t.Errorf("CDIDeviceID = %q", got)
	}

	RemoveCDISpec(dir, "xsk.dra.io", "eth0-queue0")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("spec not removed: %v", err)
	}
}
