package driver

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/klog/v2"
)

// XSKParameters is the driver-specific configuration carried in the
// ResourceClaim (or DeviceClass) via OpaqueDeviceConfiguration.
//
//	kind: xsk-parameters
//	ethertypes: ["0x88B8", "0x88BA"]
//	zerocopy: true
//
// With no parameters at all, the driver falls back to the legacy
// IEC 61850 preset (GOOSE + SV) for backward compatibility.
type XSKParameters struct {
	// Ethertypes are hex strings ("0x88B8"). At most 8, unique, in
	// [0x0600, 0xFFFF] (IEEE 802: below 0x0600 is a length field).
	Ethertypes []string `json:"ethertypes,omitempty"`

	// Zerocopy requests XDP_ZEROCOPY for the AF_XDP sockets.
	// Defaults to true.
	Zerocopy *bool `json:"zerocopy,omitempty"`

	// CPU requests a dedicated CPU core for the consuming pod
	// (NUMA alignment with the queue is checked by the gate).
	// Optional; -1/nil = none.
	CPU *int `json:"cpu,omitempty"`
}

// maxFilters matches groutx XskAddReq.Filters array size.
const maxFilters = 8

// defaultEthertypes preserves the pre-decoupling behavior when a
// claim carries no parameters: the IEC 61850 GOOSE + SV preset.
var defaultEthertypes = []uint16{0x88B8, 0x88BA}

// parseEthertype parses "0x88B8" or "88B8" (case-insensitive; always
// hexadecimal — EtherTypes are conventionally written in hex).
func parseEthertype(s string) (uint16, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "0x") {
		s = "0x" + s
	}
	v, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid ethertype %q: %v", s, err)
	}
	if v < 0x0600 || v > 0xFFFF {
		return 0, fmt.Errorf("ethertype %#x out of range [0x0600,0xFFFF]", v)
	}
	return uint16(v), nil
}

// Resolve validates the parameters and returns the concrete filter
// set, zero-copy flag, and dedicated CPU (-1 = none), applying
// defaults.
func (p XSKParameters) Resolve() ([]uint16, bool, int, error) {
	zerocopy := true
	if p.Zerocopy != nil {
		zerocopy = *p.Zerocopy
	}

	cpu := -1
	if p.CPU != nil {
		cpu = *p.CPU
		if cpu < 0 {
			return nil, false, -1, fmt.Errorf("cpu must be >= 0, got %d", cpu)
		}
	}

	if len(p.Ethertypes) == 0 {
		klog.Warning("claim carries no ethertype parameters; " +
			"falling back to legacy IEC 61850 preset (GOOSE 0x88B8 + SV 0x88BA)")
		return append([]uint16(nil), defaultEthertypes...), zerocopy, cpu, nil
	}

	if len(p.Ethertypes) > maxFilters {
		return nil, false, -1, fmt.Errorf("too many ethertypes: %d (max %d)",
			len(p.Ethertypes), maxFilters)
	}

	seen := make(map[uint16]bool, len(p.Ethertypes))
	out := make([]uint16, 0, len(p.Ethertypes))
	for _, s := range p.Ethertypes {
		v, err := parseEthertype(s)
		if err != nil {
			return nil, false, -1, err
		}
		if seen[v] {
			return nil, false, -1, fmt.Errorf("duplicate ethertype %#04x", v)
		}
		seen[v] = true
		out = append(out, v)
	}
	return out, zerocopy, cpu, nil
}

// paramsFromClaim extracts this driver's parameters from a
// ResourceClaim. Configuration sources, in ascending precedence:
//
//  1. DeviceClass config (merged by the scheduler into
//     Status.Allocation.Devices.Config with source "fromClass")
//  2. Claim-level config (same list, source "fromClaim"; also
//     present in Spec.Devices.Config)
//
// Entries scoped with Requests apply only when they reference one of
// requestNames. Later entries override earlier ones.
func paramsFromClaim(rc *resourceapi.ResourceClaim, driverName string,
	requestNames []string) (XSKParameters, error) {

	var entries []resourceapi.DeviceAllocationConfiguration
	if rc.Status.Allocation != nil {
		entries = rc.Status.Allocation.Devices.Config
	}
	// Fallback for claims that are not allocated yet (should not
	// happen in NodePrepareResources, but keeps the parser testable).
	if len(entries) == 0 {
		for _, c := range rc.Spec.Devices.Config {
			entries = append(entries, resourceapi.DeviceAllocationConfiguration{
				Requests:            c.Requests,
				DeviceConfiguration: c.DeviceConfiguration,
			})
		}
	}

	var params XSKParameters
	found := false
	for _, e := range entries {
		if e.Opaque == nil || e.Opaque.Driver != driverName {
			continue
		}
		if len(e.Requests) > 0 && !intersects(e.Requests, requestNames) {
			continue
		}
		found = true
		if err := json.Unmarshal(e.Opaque.Parameters.Raw, &params); err != nil {
			return XSKParameters{}, fmt.Errorf("unmarshaling parameters: %w", err)
		}
	}
	if !found {
		return XSKParameters{}, nil
	}
	return params, nil
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}
