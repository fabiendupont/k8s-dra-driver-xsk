// Package xglcheck generates xgl_check graph specifications from the
// driver's allocation state and validates them with the xgl_check
// binary from xdp-graph-lib.
//
// The check is the deterministic gate: no kernel access, no
// environment reads — the same spec always yields the same verdict.
// NodePrepareResources refuses to allocate a queue whose inclusion
// would make the spec invalid (duplicate queue consumer, ambiguous
// EtherType path, shared dedicated IRQ/CPU, ...).
package xglcheck

import (
	"fmt"
	"strings"
)

// Node is one BPF node in the intended graph.
type Node struct {
	Index    int
	Name     string
	Stateful bool
}

// Edge is one declared tail-call edge.
type Edge struct {
	From int
	To   int
}

// XSK is one AF_XDP socket binding: a dedicated consumer of one RX
// queue, optionally with a dedicated IRQ and CPU (all -1 = unknown).
type XSK struct {
	Ifname      string
	QueueID     int
	NQueues     int
	Zerocopy    bool
	IRQ         int
	CPU         int
	NUMANode    int
	CPUNumaNode int
}

// NewXSK creates an XSK binding with the unknown-optional fields set
// to -1, matching the xgl_check convention. (Go zero values would
// otherwise claim IRQ 0 / CPU 0 / NUMA node 0, which are real.)
func NewXSK(ifname string, queueID, nQueues int) XSK {
	return XSK{
		Ifname:      ifname,
		QueueID:     queueID,
		NQueues:     nQueues,
		IRQ:         -1,
		CPU:         -1,
		NUMANode:    -1,
		CPUNumaNode: -1,
	}
}

// Filter redirects one EtherType on one queue to its XSK.
type Filter struct {
	Ifname    string
	QueueID   int
	Ethertype uint16
}

// Spec is the declarative description of the intended graph.
type Spec struct {
	Name       string
	MaxNodes   int
	RootIndex  int
	Nodes      []Node
	Edges      []Edge
	XSKs       []XSK
	Filters    []Filter
}

const (
	maxIfnameLen = 16
	maxNameLen   = 32
)

// Render emits the line-based spec format consumed by the xgl_check
// CLI (see xdp-graph-lib tools/xgl_check.c).
func (s *Spec) Render() (string, error) {
	var b strings.Builder

	if len(s.Name) > maxNameLen {
		return "", fmt.Errorf("spec name %q longer than %d chars", s.Name, maxNameLen)
	}
	fmt.Fprintf(&b, "graph %s %d %d\n", s.Name, s.MaxNodes, s.RootIndex)

	for _, n := range s.Nodes {
		if len(n.Name) > maxNameLen {
			return "", fmt.Errorf("node name %q longer than %d chars", n.Name, maxNameLen)
		}
		if n.Stateful {
			fmt.Fprintf(&b, "node %d %s stateful\n", n.Index, n.Name)
		} else {
			fmt.Fprintf(&b, "node %d %s\n", n.Index, n.Name)
		}
	}

	for _, e := range s.Edges {
		fmt.Fprintf(&b, "edge %d %d\n", e.From, e.To)
	}

	for _, x := range s.XSKs {
		if len(x.Ifname) > maxIfnameLen {
			return "", fmt.Errorf("ifname %q longer than %d chars", x.Ifname, maxIfnameLen)
		}
		fmt.Fprintf(&b, "xsk %s %d %d", x.Ifname, x.QueueID, x.NQueues)
		if x.Zerocopy {
			b.WriteString(" zerocopy")
		}
		if x.IRQ >= 0 {
			fmt.Fprintf(&b, " irq=%d", x.IRQ)
		}
		if x.CPU >= 0 {
			fmt.Fprintf(&b, " cpu=%d", x.CPU)
		}
		if x.NUMANode >= 0 {
			fmt.Fprintf(&b, " numa=%d", x.NUMANode)
		}
		if x.CPUNumaNode >= 0 {
			fmt.Fprintf(&b, " cpu_numa=%d", x.CPUNumaNode)
		}
		b.WriteByte('\n')
	}

	for _, f := range s.Filters {
		if len(f.Ifname) > maxIfnameLen {
			return "", fmt.Errorf("ifname %q longer than %d chars", f.Ifname, maxIfnameLen)
		}
		fmt.Fprintf(&b, "filter %s %d 0x%04X\n", f.Ifname, f.QueueID, f.Ethertype)
	}

	return b.String(), nil
}
