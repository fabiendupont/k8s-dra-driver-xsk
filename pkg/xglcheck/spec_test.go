package xglcheck

import (
	"os"
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	s := &Spec{
		Name:      "relay-pod",
		MaxNodes:  16,
		RootIndex: 0,
		Nodes: []Node{
			{Index: 0, Name: "dispatch"},
			{Index: 1, Name: "goose_filter"},
		},
		Edges: []Edge{{From: 0, To: 1}},
		XSKs: []XSK{{
			Ifname: "eth0", QueueID: 0, NQueues: 8, Zerocopy: true,
			IRQ: 24, CPU: 2, NUMANode: 0, CPUNumaNode: 0,
		}},
		Filters: []Filter{{Ifname: "eth0", QueueID: 0, Ethertype: 0x88B8}},
	}

	out, err := s.Render()
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	want := strings.Join([]string{
		"graph relay-pod 16 0",
		"node 0 dispatch",
		"node 1 goose_filter",
		"edge 0 1",
		"xsk eth0 0 8 zerocopy irq=24 cpu=2 numa=0 cpu_numa=0",
		"filter eth0 0 0x88B8",
		"",
	}, "\n")
	if out != want {
		t.Errorf("render mismatch:\ngot:\n%s\nwant:\n%s", out, want)
	}
}

func TestRenderStateful(t *testing.T) {
	s := &Spec{
		Name: "t", MaxNodes: 4, RootIndex: 0,
		Nodes: []Node{{Index: 0, Name: "d"}, {Index: 1, Name: "hsr", Stateful: true}},
	}
	out, err := s.Render()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(out, "node 1 hsr stateful\n") {
		t.Errorf("stateful flag missing:\n%s", out)
	}
}

func TestRenderUnknownsOmitted(t *testing.T) {
	s := &Spec{
		Name: "t", MaxNodes: 4, RootIndex: 0,
		Nodes: []Node{{Index: 0, Name: "d"}},
		XSKs:  []XSK{NewXSK("eth0", 0, 4)},
	}
	out, err := s.Render()
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(out, "irq=") || strings.Contains(out, "cpu=") ||
		strings.Contains(out, "numa=") || strings.Contains(out, "zerocopy") {
		t.Errorf("unknown fields should be omitted:\n%s", out)
	}
}

func TestRenderNameTooLong(t *testing.T) {
	s := &Spec{Name: strings.Repeat("x", 40), MaxNodes: 4, RootIndex: 0}
	if _, err := s.Render(); err == nil {
		t.Error("expected error for over-long spec name")
	}
	s = &Spec{Name: "t", MaxNodes: 4, RootIndex: 0,
		Nodes: []Node{{Index: 0, Name: strings.Repeat("y", 40)}}}
	if _, err := s.Render(); err == nil {
		t.Error("expected error for over-long node name")
	}
}

// TestValidate runs the real xgl_check binary if available (point
// XGL_CHECK_BIN at it); otherwise the test is skipped. The binary is
// built from xdp-graph-lib (tools/xgl_check.c).
func TestValidate(t *testing.T) {
	bin := os.Getenv("XGL_CHECK_BIN")
	if bin == "" {
		t.Skip("XGL_CHECK_BIN not set — set it to the xgl_check binary path")
	}

	t.Run("valid spec", func(t *testing.T) {
		s := &Spec{
			Name: "valid", MaxNodes: 16, RootIndex: 0,
			Nodes: []Node{
				{Index: 0, Name: "dispatch"},
				{Index: 1, Name: "goose"},
				{Index: 2, Name: "sv"},
			},
			Edges: []Edge{{From: 0, To: 1}, {From: 0, To: 2}},
			XSKs: []XSK{
				{Ifname: "eth0", QueueID: 0, NQueues: 8, Zerocopy: true, IRQ: 24, CPU: 2, NUMANode: 0, CPUNumaNode: 0},
				{Ifname: "eth0", QueueID: 1, NQueues: 8, Zerocopy: true, IRQ: 25, CPU: 3, NUMANode: 0, CPUNumaNode: 0},
			},
			Filters: []Filter{
				{Ifname: "eth0", QueueID: 0, Ethertype: 0x88B8},
				{Ifname: "eth0", QueueID: 1, Ethertype: 0x88BA},
			},
		}
		findings, err := Validate(s, bin)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if len(findings) != 0 {
			t.Errorf("expected clean spec, got: %v", findings)
		}
	})

	t.Run("duplicate queue consumer", func(t *testing.T) {
		s := &Spec{
			Name: "dup", MaxNodes: 16, RootIndex: 0,
			Nodes: []Node{{Index: 0, Name: "dispatch"}},
			XSKs: []XSK{
				{Ifname: "eth0", QueueID: 0, NQueues: 8, IRQ: 24},
				{Ifname: "eth0", QueueID: 0, NQueues: 8, IRQ: 25},
			},
		}
		findings, err := Validate(s, bin)
		if err != nil {
			t.Fatalf("validate: %v", err)
		}
		if !HasErrors(findings) {
			t.Errorf("expected errors, got: %v", findings)
		}
		found := false
		for _, f := range findings {
			if f.Code == "E_QUEUE_DUP" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected E_QUEUE_DUP, got: %v", findings)
		}
	})
}
