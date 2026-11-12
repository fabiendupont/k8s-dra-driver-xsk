package bpfman

import "testing"

func TestConstants(t *testing.T) {
	if programName != "xdp_xsk_filter" {
		t.Errorf("programName = %q, want xdp_xsk_filter", programName)
	}
	if elfPath != "/run/bpfman/xsk-dra-driver.bpf.o" {
		t.Errorf("elfPath = %q, want /run/bpfman/xsk-dra-driver.bpf.o", elfPath)
	}
	if csiMapDir != "/run/xsk/bpfman-maps" {
		t.Errorf("csiMapDir = %q, want /run/xsk/bpfman-maps", csiMapDir)
	}
	if crdNamespace != "bpfman" {
		t.Errorf("crdNamespace = %q, want bpfman", crdNamespace)
	}
}
