package bpfman

import (
	"testing"
)

// TestName verifies the backend name.
func TestName(t *testing.T) {
	// New requires a rest.Config which we don't have in unit tests;
	// just verify the constant.
	if programName != "xdp_xsk_filter" {
		t.Errorf("programName = %q, want xdp_xsk_filter", programName)
	}
	if elfDir != "/run/bpfman" {
		t.Errorf("elfDir = %q, want /run/bpfman (bpfman operator hostPath)", elfDir)
	}
	if mapRoot != "/run/bpfman/fs/maps" {
		t.Errorf("mapRoot = %q, want /run/bpfman/fs/maps", mapRoot)
	}
}
