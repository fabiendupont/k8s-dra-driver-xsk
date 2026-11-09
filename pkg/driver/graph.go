package driver

import (
	"fmt"

	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/xglcheck"
)

// buildSpec renders the intended XDP graph for the given allocations
// as an xgl_check spec: a dispatch root with one filter node per
// allocated queue, each queue consumed by exactly one XSK, each
// EtherType redirected on exactly one queue.
//
// The spec covers the *entire* intended state — existing allocations
// plus the candidate claim — so cross-claim invariants (duplicate
// queue consumers, ambiguous EtherType paths, shared IRQs/CPUs) are
// checked, not just the claim in isolation.
func buildSpec(nodeName string, allocations []*Allocation) *xglcheck.Spec {
	spec := &xglcheck.Spec{
		Name:       fmt.Sprintf("node-%s", nodeName),
		MaxNodes:   256,
		RootIndex:  0,
	}

	spec.Nodes = append(spec.Nodes, xglcheck.Node{Index: 0, Name: "dispatch"})

	for i, a := range allocations {
		nodeIdx := i + 1
		spec.Nodes = append(spec.Nodes, xglcheck.Node{
			Index: nodeIdx,
			Name:  fmt.Sprintf("filter_%s_q%d", a.Ifname, a.QueueID),
		})
		spec.Edges = append(spec.Edges, xglcheck.Edge{From: 0, To: nodeIdx})

		x := xglcheck.NewXSK(a.Ifname, a.QueueID, a.NQueues)
		x.Zerocopy = true
		if a.NUMANode >= 0 {
			x.NUMANode = a.NUMANode
		}
		spec.XSKs = append(spec.XSKs, x)

		for _, et := range a.Ethertypes {
			spec.Filters = append(spec.Filters, xglcheck.Filter{
				Ifname:    a.Ifname,
				QueueID:   a.QueueID,
				Ethertype: et,
			})
		}
	}

	return spec
}
