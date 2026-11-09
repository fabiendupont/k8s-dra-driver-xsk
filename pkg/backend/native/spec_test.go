package native

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// TestEmbeddedSpec validates the committed bpf2go object without any
// privileges: pure ELF parsing. Catches stale or corrupted bindings
// (the compile check in CI covers source buildability).
func TestEmbeddedSpec(t *testing.T) {
	spec, err := loadFilter()
	if err != nil {
		t.Fatalf("loading embedded spec: %v", err)
	}

	prog := spec.Programs["xdp_xsk_filter"]
	if prog == nil {
		t.Fatal("program xdp_xsk_filter missing from embedded object")
	}
	if prog.Type != ebpf.XDP {
		t.Errorf("program type = %v, want XDP", prog.Type)
	}
	if len(prog.Instructions) == 0 {
		t.Error("program has no instructions")
	}

	for name, wantType := range map[string]ebpf.MapType{
		"xsk_ethertypes": ebpf.Hash,
		"xsk_map":        ebpf.XSKMap,
	} {
		m := spec.Maps[name]
		if m == nil {
			t.Errorf("map %s missing from embedded object", name)
			continue
		}
		if m.Type != wantType {
			t.Errorf("map %s type = %v, want %v", name, m.Type, wantType)
		}
	}

	if et := spec.Maps["xsk_ethertypes"]; et != nil {
		if size, err := btf.Sizeof(et.Key); err != nil || size != 2 {
			t.Errorf("ethertypes key size = %d (err %v), want 2 (__u16)", size, err)
		}
	}
}
