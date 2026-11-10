package driver

import (
	"testing"

	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func opaqueConfig(driver string, params string, requests ...string) resourceapi.DeviceAllocationConfiguration {
	e := resourceapi.DeviceAllocationConfiguration{
		Requests: requests,
	}
	e.Opaque = &resourceapi.OpaqueDeviceConfiguration{
		Driver:     driver,
		Parameters: runtime.RawExtension{Raw: []byte(params)},
	}
	return e
}

func claimWithStatusConfig(entries ...resourceapi.DeviceAllocationConfiguration) *resourceapi.ResourceClaim {
	return &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "default"},
		Status: resourceapi.ResourceClaimStatus{
			Allocation: &resourceapi.AllocationResult{
				Devices: resourceapi.DeviceAllocationResult{Config: entries},
			},
		},
	}
}

func TestParamsFromClaim(t *testing.T) {
	other := opaqueConfig("other.driver.io", `{"ethertypes":["0x1234"]}`)
	ours := opaqueConfig("xsk.dra.io", `{"ethertypes":["0x8892"],"zerocopy":false}`)

	t.Run("filters by driver", func(t *testing.T) {
		p, err := paramsFromClaim(claimWithStatusConfig(other, ours), "xsk.dra.io", nil)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		ets, zc, _, err := p.Resolve()
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if len(ets) != 1 || ets[0] != 0x8892 {
			t.Errorf("expected [0x8892], got %#x", ets)
		}
		if zc {
			t.Error("expected zerocopy=false")
		}
	})

	t.Run("later entries override", func(t *testing.T) {
		first := opaqueConfig("xsk.dra.io", `{"ethertypes":["0x8892"]}`)
		second := opaqueConfig("xsk.dra.io", `{"ethertypes":["0x88B8","0x88BA"]}`)
		p, err := paramsFromClaim(claimWithStatusConfig(first, second), "xsk.dra.io", nil)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		ets, _, _, err := p.Resolve()
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if len(ets) != 2 {
			t.Errorf("expected override with 2 ethertypes, got %#x", ets)
		}
	})

	t.Run("request scoping", func(t *testing.T) {
		scopedAway := opaqueConfig("xsk.dra.io", `{"ethertypes":["0x0800"]}`, "other-req")
		p, err := paramsFromClaim(claimWithStatusConfig(scopedAway), "xsk.dra.io", []string{"my-req"})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		ets, _, _, _ := p.Resolve()
		for _, et := range ets {
			if et == 0x0800 {
				t.Errorf("entry scoped to other-req must not apply, got %#x", ets)
			}
		}

		scopedUs := opaqueConfig("xsk.dra.io", `{"ethertypes":["0x0800"]}`, "my-req")
		p, err = paramsFromClaim(claimWithStatusConfig(scopedUs), "xsk.dra.io", []string{"my-req"})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		ets, _, _, _ = p.Resolve()
		if len(ets) != 1 || ets[0] != 0x0800 {
			t.Errorf("expected [0x0800], got %#x", ets)
		}
	})

	t.Run("no params -> legacy preset", func(t *testing.T) {
		p, err := paramsFromClaim(claimWithStatusConfig(other), "xsk.dra.io", nil)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		ets, zc, _, err := p.Resolve()
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if len(ets) != 2 || ets[0] != 0x88B8 || ets[1] != 0x88BA {
			t.Errorf("expected legacy GOOSE+SV preset, got %#x", ets)
		}
		if !zc {
			t.Error("expected default zerocopy=true")
		}
	})
}

func TestResolveValidation(t *testing.T) {
	cases := []struct {
		name  string
		params XSKParameters
		ok    bool
	}{
		{"hex with prefix", XSKParameters{Ethertypes: []string{"0x88B8"}}, true},
		{"hex without prefix", XSKParameters{Ethertypes: []string{"88B8"}}, true},
		{"mixed case", XSKParameters{Ethertypes: []string{"0x88b8"}}, true},
		{"too low (length field)", XSKParameters{Ethertypes: []string{"0x05FF"}}, false},
		{"too high", XSKParameters{Ethertypes: []string{"0x10000"}}, false},
		{"garbage", XSKParameters{Ethertypes: []string{"goose"}}, false},
		{"duplicate", XSKParameters{Ethertypes: []string{"0x88B8", "0x88B8"}}, false},
		{"nine filters", XSKParameters{Ethertypes: []string{
			"0x0600", "0x0601", "0x0602", "0x0603", "0x0604", "0x0605",
			"0x0606", "0x0607", "0x0608"}}, false},
		{"eight filters ok", XSKParameters{Ethertypes: []string{
			"0x0600", "0x0601", "0x0602", "0x0603", "0x0604", "0x0605",
			"0x0606", "0x0607"}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, _, err := c.params.Resolve()
			if (err == nil) != c.ok {
				t.Errorf("ok=%v, err=%v", c.ok, err)
			}
		})
	}
}

func TestZerocopyDefault(t *testing.T) {
	f, z, _, err := XSKParameters{}.Resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !z || len(f) != 2 {
		t.Errorf("expected defaults, got zerocopy=%v filters=%#x", z, f)
	}
	noZc := false
	_, z, _, err = XSKParameters{Zerocopy: &noZc}.Resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if z {
		t.Error("expected zerocopy=false")
	}
}

func TestCPUParameter(t *testing.T) {
	t.Run("none by default", func(t *testing.T) {
		_, _, cpu, err := XSKParameters{Ethertypes: []string{"0x88B8"}}.Resolve()
		if err != nil || cpu != -1 {
			t.Errorf("cpu=%d err=%v, want -1 nil", cpu, err)
		}
	})
	t.Run("explicit", func(t *testing.T) {
		cpu := 2
		_, _, got, err := XSKParameters{Ethertypes: []string{"0x88B8"}, CPU: &cpu}.Resolve()
		if err != nil || got != 2 {
			t.Errorf("cpu=%d err=%v, want 2 nil", got, err)
		}
	})
	t.Run("negative rejected", func(t *testing.T) {
		cpu := -1
		params := XSKParameters{Ethertypes: []string{"0x88B8"}, CPU: &cpu}
		if _, _, _, err := params.Resolve(); err == nil {
			t.Error("expected error for negative cpu")
		}
	})
}
