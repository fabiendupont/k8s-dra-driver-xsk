package xsk

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// IRQKey identifies one NIC RX queue for IRQ lookup.
type IRQKey struct {
	Ifname  string
	QueueID int
}

// ParseInterrupts extracts per-queue IRQ numbers from /proc/interrupts
// content for the given interfaces. It is a pure function of its
// inputs (deterministic, testable); DiscoverIRQs applies it to the
// live file.
//
// Kernel IRQ labels are driver-specific but follow a common shape
// for the drivers that matter for AF_XDP:
//
//	ice:   ice-enp3s0-TxRx-0
//	i40e:  i40e-enp3s0-TxRx-0
//	ixgbe: ixgbe-enp3s0-TxRx-0
//	igc:   igc-TxRx-0 (interface name not always present)
//	mlx5:  mlx5_comp70@pci:... (NO interface or queue in the label)
//
// For labels that contain "<something>-<ifname>-...-<queue>" the
// queue's IRQ is recovered. Drivers whose labels cannot be mapped
// (mlx5) simply yield no entry — the dedication check treats
// unknown IRQs as not dedicated rather than guessing.
func ParseInterrupts(content string, ifnames []string) map[IRQKey]int {
	out := make(map[IRQKey]int)
	wanted := make(map[string]bool, len(ifnames))
	for _, ifname := range ifnames {
		wanted[ifname] = true
	}

	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		irqStr := strings.TrimSuffix(fields[0], ":")
		irq, err := strconv.Atoi(irqStr)
		if err != nil {
			continue // header line ("CPU0 CPU1 ...") or non-numeric
		}

		// Walk the label tokens after the per-CPU counters.
		for i := 1; i < len(fields); i++ {
			tok := fields[i]
			if !strings.Contains(tok, "-") {
				continue
			}
			parts := strings.Split(tok, "-")
			// Find the interface name among the dash-separated parts.
			for j, p := range parts {
				if !wanted[p] {
					continue
				}
				// The queue index is the last numeric part after the
				// interface name (e.g. ice-eth0-TxRx-3 -> 3).
				queue, ok := trailingQueue(parts[j+1:])
				if ok {
					out[IRQKey{Ifname: p, QueueID: queue}] = irq
				}
				break
			}
		}
	}
	return out
}

// trailingQueue returns the last part if it is a small non-negative
// integer (a queue index).
func trailingQueue(parts []string) (int, bool) {
	if len(parts) == 0 {
		return 0, false
	}
	last := parts[len(parts)-1]
	if len(last) > 3 { // not a queue index
		return 0, false
	}
	q, err := strconv.Atoi(last)
	if err != nil || q < 0 {
		return 0, false
	}
	return q, true
}

// DiscoverIRQs reads /proc/interrupts and returns the per-queue IRQ
// map for the given interfaces. Missing entries mean the driver's
// IRQ labels are not mappable (see ParseInterrupts).
func DiscoverIRQs(ifnames []string) (map[IRQKey]int, error) {
	data, err := os.ReadFile("/proc/interrupts")
	if err != nil {
		return nil, err
	}
	return ParseInterrupts(string(data), ifnames), nil
}

// CPUNumaNode returns the NUMA node of the given CPU, or -1 if
// unknown.
func CPUNumaNode(cpu int) int {
	base := filepath.Join("/sys/devices/system/cpu", "cpu"+strconv.Itoa(cpu), "node%d")
	// A CPU belongs to exactly one node; find node* directory.
	for node := 0; node < 16; node++ {
		if _, err := os.Stat(fmt.Sprintf(base, node)); err == nil {
			return node
		}
	}
	return -1
}
