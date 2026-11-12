package driver

import (
	"fmt"
	"sync"
)

// Allocation records everything needed to rebuild the intended XDP
// graph spec for the deterministic validation gate.
type Allocation struct {
	ClaimUID    string
	Ifname      string
	QueueID     int
	NQueues     int
	NUMANode    int
	Ethertypes  []uint16
	Zerocopy    bool
	IRQ         int // discovered queue IRQ (-1 unknown)
	CPU         int // dedicated CPU (-1 none)
	CPUNumaNode int // NUMA node of CPU (-1 unknown)

	// Stream marks an HSR/PRP stream allocation: the XSK sits on a
	// dedicated per-claim veth behind the RedBox dataplane, not on
	// a discovered NIC queue. Stream allocations are excluded from
	// the xgl_check gate (they are the only consumer of their veth
	// by construction).
	Stream bool

	// CDIName is the identifier used for the CDI spec file and
	// device ID. Queue claims use the queue device ID; stream
	// claims use the stream device name (group-ethertype). Empty
	// falls back to queueKey(Ifname, QueueID).
	CDIName string
}

// cdiID returns the identifier the CDI spec was written under.
func (a *Allocation) cdiID() string {
	if a.CDIName != "" {
		return a.CDIName
	}
	return queueKey(a.Ifname, a.QueueID)
}

// AllocationState tracks which NIC queues are allocated to which ResourceClaims.
type AllocationState struct {
	mu       sync.Mutex
	// queueID → allocation
	allocated map[string]*Allocation
}

func NewAllocationState() *AllocationState {
	return &AllocationState{allocated: make(map[string]*Allocation)}
}

func (s *AllocationState) Allocate(a *Allocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := queueKey(a.Ifname, a.QueueID)
	if existing, ok := s.allocated[key]; ok {
		// Idempotent: kubelet retries NodePrepareResources on
		// gRPC timeout. If the SAME claim already holds this
		// queue, the retry is a no-op.
		if existing.ClaimUID == a.ClaimUID {
			return nil
		}
		return fmt.Errorf("queue %s already allocated to claim %s",
			key, existing.ClaimUID)
	}
	s.allocated[key] = a
	return nil
}

func (s *AllocationState) ReleaseByClaimUID(claimUID string) []*Allocation {
	s.mu.Lock()
	defer s.mu.Unlock()
	var released []*Allocation
	for key, a := range s.allocated {
		if a.ClaimUID == claimUID {
			released = append(released, a)
			delete(s.allocated, key)
		}
	}
	return released
}

func (s *AllocationState) AllocatedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.allocated)
}

// Snapshot returns a copy of all current allocations.
func (s *AllocationState) Snapshot() []*Allocation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Allocation, 0, len(s.allocated))
	for _, a := range s.allocated {
		copyA := *a
		copyA.Ethertypes = append([]uint16(nil), a.Ethertypes...)
		out = append(out, &copyA)
	}
	return out
}

func queueKey(ifname string, queueID int) string {
	return fmt.Sprintf("%s-queue%d", ifname, queueID)
}
