package hsrprp

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

// Config is the node-level RedBox configuration. It defines HSR/PRP
// redundancy groups: pairs of ring ports (HSR) or dual LANs (PRP)
// whose deduplicated streams are exposed to pods as DRA devices.
//
// The groups themselves are node configuration, not allocatable
// state: which ports form a ring is a property of the machine's
// wiring, not of any claim. What claims allocate is a stream within
// a group (see discovery.go: one device per group × EtherType).
type Config struct {
	Groups []Group `json:"groups"`
}

// Group is one HSR ring or PRP dual-LAN.
type Group struct {
	// Name identifies the group in device names and claims.
	Name string `json:"name"`

	// Mode is "hsr" (ring, tagged 0x892F) or "prp" (dual LAN, RCT
	// trailer). PRP is not yet implemented in the prototype.
	Mode string `json:"mode"`

	// Ports are the two ring ports (HSR) or LAN A/LAN B (PRP).
	Ports [2]string `json:"ports"`

	// Streams are the EtherTypes exposed as claimable streams
	// (e.g. 0x88B8 GOOSE, 0x88BA SV). Admin-curated: slices are
	// published at startup, so the list must be stable.
	Streams []Stream `json:"streams"`
}

// Stream is one claimable EtherType within a group.
type Stream struct {
	// Ethertype is a hex string, e.g. "0x88B8".
	Ethertype string `json:"ethertype"`
}

// ParseEthertypeHex parses "0x88B8" (always hexadecimal).
func ParseEthertypeHex(s string) (uint16, error) {
	var v uint32
	if _, err := fmt.Sscanf(s, "0x%x", &v); err != nil {
		return 0, fmt.Errorf("invalid ethertype %q: %v", s, err)
	}
	if v < 0x0600 || v > 0xFFFF {
		return 0, fmt.Errorf("ethertype %s out of range [0x0600,0xFFFF]", s)
	}
	return uint16(v), nil
}

// LoadConfig reads and validates a groups config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading hsr-prp config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing hsr-prp config: %w", err)
	}

	seenGroups := map[string]bool{}
	for i := range cfg.Groups {
		g := &cfg.Groups[i]
		if g.Name == "" {
			return nil, fmt.Errorf("group %d: empty name", i)
		}
		if seenGroups[g.Name] {
			return nil, fmt.Errorf("duplicate group %q", g.Name)
		}
		seenGroups[g.Name] = true

		switch g.Mode {
		case "hsr":
			// supported
		default:
			return nil, fmt.Errorf("group %q: mode %q not supported (prototype: hsr only)", g.Name, g.Mode)
		}
		if g.Ports[0] == "" || g.Ports[1] == "" || g.Ports[0] == g.Ports[1] {
			return nil, fmt.Errorf("group %q: needs two distinct ports", g.Name)
		}
		if len(g.Streams) == 0 {
			return nil, fmt.Errorf("group %q: no streams", g.Name)
		}
		seenET := map[uint16]bool{}
		for _, s := range g.Streams {
			et, err := ParseEthertypeHex(s.Ethertype)
			if err != nil {
				return nil, fmt.Errorf("group %q: %v", g.Name, err)
			}
			if seenET[et] {
				return nil, fmt.Errorf("group %q: duplicate stream %#04x", g.Name, et)
			}
			seenET[et] = true
		}
	}
	return &cfg, nil
}
