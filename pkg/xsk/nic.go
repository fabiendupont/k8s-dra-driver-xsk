// Package xsk models NIC queues available for AF_XDP socket allocation.
package xsk

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Queue represents one NIC RX queue that can be allocated for AF_XDP.
type Queue struct {
	// ID is the device name used in ResourceSlice/CDI (e.g., "eth0-queue0").
	ID string

	// Ifname is the network interface name.
	Ifname string

	// Ifindex is the interface index (for XDP attach and AF_XDP bind).
	Ifindex int

	// QueueID is the NIC RX queue index.
	QueueID int

	// Driver is the kernel driver name (e.g., "ice", "i40e").
	Driver string

	// NUMANode is the NUMA node the NIC is attached to (-1 if unknown).
	NUMANode int

	// Zerocopy indicates whether the driver supports XDP_ZEROCOPY.
	Zerocopy bool
}

// zerocopyDrivers is the set of kernel drivers known to support XDP_ZEROCOPY.
var zerocopyDrivers = map[string]bool{
	"ice":       true,
	"i40e":      true,
	"ixgbe":     true,
	"igc":       true,
	"mlx5_core": true,
	"bnxt_en":   true,
}

// includeVirtual is set by UseVirtualInterfaces (development and
// testing only — e.g. kind clusters whose nodes expose only veths).
var includeVirtual bool

// UseVirtualInterfaces includes virtual interfaces (veth) in
// discovery.  Development/testing only.
func UseVirtualInterfaces() { includeVirtual = true }

// DiscoverQueues enumerates all eligible NIC queues on the node.
// It skips loopback and virtual interfaces (unless
// UseVirtualInterfaces was called).
func DiscoverQueues() ([]*Queue, error) {
	return discoverQueues(includeVirtual)
}

func discoverQueues(includeVirtual bool) ([]*Queue, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, fmt.Errorf("reading /sys/class/net: %w", err)
	}

	var queues []*Queue
	for _, e := range entries {
		ifname := e.Name()
		if ifname == "lo" {
			continue
		}

		driverLink := filepath.Join("/sys/class/net", ifname, "device/driver")
		driverTarget, err := os.Readlink(driverLink)
		if err != nil {
			// Virtual or software interface.
			if !includeVirtual {
				continue
			}
		}
		driver := filepath.Base(driverTarget)
		if driver == "" || driver == "." {
			driver = "virtual"
		}

		numaNode := numaNodeFor(ifname)
		nQueues := rxQueueCount(ifname)
		if nQueues <= 0 {
			nQueues = 1
		}

		for q := 0; q < nQueues; q++ {
			queues = append(queues, &Queue{
				ID:       fmt.Sprintf("%s-queue%d", ifname, q),
				Ifname:   ifname,
				Ifindex:  ifindexFor(ifname),
				QueueID:  q,
				Driver:   driver,
				NUMANode: numaNode,
				Zerocopy: zerocopyDrivers[driver],
			})
		}
	}

	return queues, nil
}

func ifindexFor(ifname string) int {
	data, err := os.ReadFile(
		filepath.Join("/sys/class/net", ifname, "ifindex"))
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return -1
	}
	return n
}

func numaNodeFor(ifname string) int {
	data, err := os.ReadFile(
		filepath.Join("/sys/class/net", ifname, "device/numa_node"))
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return -1
	}
	return n
}

// rxQueueCount reads the number of RX queues from sysfs.
// Falls back to 1 if the file is absent.
func rxQueueCount(ifname string) int {
	data, err := os.ReadFile(
		filepath.Join("/sys/class/net", ifname, "queues"))
	if err != nil {
		// Count rx-N directories under /sys/class/net/<if>/queues/
		entries, err2 := os.ReadDir(
			filepath.Join("/sys/class/net", ifname, "queues"))
		if err2 != nil {
			return 1
		}
		count := 0
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "rx-") {
				count++
			}
		}
		if count == 0 {
			return 1
		}
		return count
	}
	_ = data
	return 1
}
