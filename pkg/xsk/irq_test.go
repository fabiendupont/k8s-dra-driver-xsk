package xsk

import "testing"

const iceInterrupts = `            CPU0       CPU1       CPU2       CPU3
   0:         11          0          0          0  IO-APIC   2-edge      timer
 122:          0          0          0     145212  PCI-MSI 1572864-edge      ice-enp3s0-TxRx-0
 123:          0          0       1234          0  PCI-MSI 1572865-edge      ice-enp3s0-TxRx-1
 124:         42          0          0          0  PCI-MSI 1572866-edge      ice-enp3s0-TxRx-2
 125:          0          0          0          7  PCI-MSI 1572867-edge      ice-enp3s0-TxRx-3
 126:          0        981          0          0  PCI-MSI 1572868-edge      mlx5_comp70@pci:0000:3b:00.0
NMI:          0          0          0          0   Non-maskable interrupts
ERR:          0          0
`

const i40eInterrupts = `           CPU0
  51:    12345   PCI-MSI 32768-edge      i40e-eth1-rx-0
  52:      999   PCI-MSI 32769-edge      i40e-eth1-rx-1
  53:       77   PCI-MSI 32770-edge      i40e-eth1-TxRx-2
`

func TestParseInterrupts(t *testing.T) {
	got := ParseInterrupts(iceInterrupts, []string{"enp3s0"})
	if len(got) != 4 {
		t.Fatalf("expected 4 ice queues, got %d: %v", len(got), got)
	}
	want := map[IRQKey]int{
		{"enp3s0", 0}: 122,
		{"enp3s0", 1}: 123,
		{"enp3s0", 2}: 124,
		{"enp3s0", 3}: 125,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%v: got irq %d, want %d", k, got[k], v)
		}
	}

	// mlx5 labels carry no ifname/queue: must yield nothing.
	if v, ok := got[IRQKey{"mlx5", 0}]; ok {
		t.Errorf("mlx5 unexpectedly mapped: irq %d", v)
	}
}

func TestParseInterruptsI40E(t *testing.T) {
	got := ParseInterrupts(i40eInterrupts, []string{"eth1"})
	want := map[IRQKey]int{
		{"eth1", 0}: 51,
		{"eth1", 1}: 52,
		{"eth1", 2}: 53,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%v: got irq %d, want %d", k, got[k], v)
		}
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d: %v", len(got), got)
	}
}

func TestParseInterruptsOtherIfaces(t *testing.T) {
	// Asking for an interface absent from the labels yields nothing.
	got := ParseInterrupts(iceInterrupts, []string{"eth9"})
	if len(got) != 0 {
		t.Errorf("expected no entries, got %v", got)
	}
}
