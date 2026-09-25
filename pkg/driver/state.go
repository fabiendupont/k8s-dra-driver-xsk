package driver

import (
	"fmt"
	"sync"
)

// AllocationState tracks which NIC queues are allocated to which ResourceClaims.
type AllocationState struct {
	mu       sync.Mutex
	// queueID → claimUID
	allocated map[string]string
}

func NewAllocationState() *AllocationState {
	return &AllocationState{allocated: make(map[string]string)}
}

func (s *AllocationState) Allocate(queueID, claimUID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.allocated[queueID]; ok {
		return fmt.Errorf("queue %s already allocated to claim %s", queueID, existing)
	}
	s.allocated[queueID] = claimUID
	return nil
}

func (s *AllocationState) ReleaseByClaimUID(claimUID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var released []string
	for queueID, uid := range s.allocated {
		if uid == claimUID {
			delete(s.allocated, queueID)
			released = append(released, queueID)
		}
	}
	return released
}

func (s *AllocationState) AllocatedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.allocated)
}
