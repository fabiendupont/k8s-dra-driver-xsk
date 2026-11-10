package driver

import (
	"strings"
	"testing"
)

func TestBuildSpec(t *testing.T) {
	allocs := []*Allocation{
		{ClaimUID: "c1", Ifname: "eth0", QueueID: 0, NQueues: 8, NUMANode: 0,
			Zerocopy: true, Ethertypes: []uint16{0x88B8, 0x88BA},
			IRQ: -1, CPU: -1, CPUNumaNode: -1},
		{ClaimUID: "c2", Ifname: "eth1", QueueID: 3, NQueues: 4, NUMANode: 1,
			Zerocopy: true, Ethertypes: []uint16{0x88B8},
			IRQ: -1, CPU: -1, CPUNumaNode: -1},
	}

	spec := buildSpec("node1", allocs)
	out, err := spec.Render()
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	for _, want := range []string{
		"graph node-node1 256 0",
		"node 0 dispatch",
		"node 1 filter_eth0_q0",
		"node 2 filter_eth1_q3",
		"edge 0 1",
		"edge 0 2",
		"xsk eth0 0 8 zerocopy numa=0",
		"xsk eth1 3 4 zerocopy numa=1",
		"filter eth0 0 0x88B8",
		"filter eth0 0 0x88BA",
		"filter eth1 3 0x88B8",
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("rendered spec missing %q:\n%s", want, out)
		}
	}
}

func TestBuildSpecDedupWithinClaim(t *testing.T) {
	// Two queues on the same interface with the same ethertype must
	// render as an ambiguous path — the gate must catch it.
	allocs := []*Allocation{
		{ClaimUID: "c1", Ifname: "eth0", QueueID: 0, NQueues: 8,
			Ethertypes: []uint16{0x88B8}},
		{ClaimUID: "c1", Ifname: "eth0", QueueID: 1, NQueues: 8,
			Ethertypes: []uint16{0x88B8}},
	}
	spec := buildSpec("node1", allocs)
	n := 0
	for _, f := range spec.Filters {
		if f.Ifname == "eth0" && f.Ethertype == 0x88B8 {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("expected 2 overlapping filters, got %d", n)
	}
}

func TestStateSnapshotCopies(t *testing.T) {
	s := NewAllocationState()
	ets := []uint16{0x88B8}
	if err := s.Allocate(&Allocation{ClaimUID: "c1", Ifname: "eth0",
		QueueID: 0, NQueues: 8, Ethertypes: ets}); err != nil {
		t.Fatalf("allocate: %v", err)
	}

	snap := s.Snapshot()
	ets[0] = 0xFFFF // mutate the original slice
	if snap[0].Ethertypes[0] != 0x88B8 {
		t.Error("snapshot shares the ethertypes slice with the caller")
	}

	if err := s.Allocate(&Allocation{ClaimUID: "c2", Ifname: "eth0",
		QueueID: 0, NQueues: 8}); err == nil {
		t.Error("expected duplicate allocation to fail")
	}
}
