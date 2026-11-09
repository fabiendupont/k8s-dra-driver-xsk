// Package backend defines the XSK allocation backend interface.
//
// A backend creates AF_XDP sockets for NIC RX queues, installs the
// EtherType filters that steer matching frames into them, and
// provides a Unix socket over which consumers receive the xsk fd and
// UMEM fd (SCM_RIGHTS handoff). Implementations differ in *who* does
// the privileged work: the native backend does it in-process; a
// daemon-based backend (e.g. groutx) delegates it.
package backend

import "context"

// Allocation is one XSK allocation request: a dedicated consumer for
// one RX queue with one EtherType filter set.
type Allocation struct {
	Ifname     string
	Ifindex    int
	QueueID    int
	Ethertypes []uint16
	Zerocopy   bool
}

// Backend allocates and frees AF_XDP sockets.
type Backend interface {
	// Name identifies the implementation ("native", "groutx").
	Name() string

	// Add creates the AF_XDP socket for the queue, installs the
	// filters, and returns the Unix socket path where the consumer
	// receives {xsk fd, umem fd} via SCM_RIGHTS.
	Add(ctx context.Context, a *Allocation) (string, error)

	// Del tears down the allocation for the queue.
	Del(ctx context.Context, ifname string, queueID int) error
}
