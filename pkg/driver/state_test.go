package driver

import "testing"

func TestAllocateIdempotent(t *testing.T) {
	s := NewAllocationState()
	a1 := &Allocation{ClaimUID: "claim-1", Ifname: "eth0", QueueID: 0, NQueues: 4,
		Ethertypes: []uint16{0x88B8}, IRQ: -1, CPU: -1, CPUNumaNode: -1}
	a2 := &Allocation{ClaimUID: "claim-1", Ifname: "eth0", QueueID: 0, NQueues: 4,
		Ethertypes: []uint16{0x88B8}, IRQ: -1, CPU: -1, CPUNumaNode: -1}
	a3 := &Allocation{ClaimUID: "claim-2", Ifname: "eth0", QueueID: 0, NQueues: 4,
		Ethertypes: []uint16{0x88B8}, IRQ: -1, CPU: -1, CPUNumaNode: -1}

	// First allocation succeeds
	if err := s.Allocate(a1); err != nil {
		t.Fatalf("first allocate: %v", err)
	}
	// Same claim + same queue: idempotent no-op (kubelet retry)
	if err := s.Allocate(a2); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	// Different claim, same queue: conflict
	if err := s.Allocate(a3); err == nil {
		t.Fatal("expected conflict for different claim on same queue")
	}
	// Snapshot still has exactly 1 allocation
	if got := len(s.Snapshot()); got != 1 {
		t.Errorf("snapshot count = %d, want 1", got)
	}
}
