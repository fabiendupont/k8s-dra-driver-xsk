package native

import (
	"bytes"
	"encoding/binary"
	"net"
	"os/exec"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend"
)

// hasCaps reports whether the test process can load BPF programs.
func hasCaps(t *testing.T) bool {
	t.Helper()
	if _, err := loadFilter(); err != nil {
		return false
	}
	return true
}

// TestHandoffProtocol exercises the SCM_RIGHTS handoff with memfd
// dummies — no privileges required.
func TestHandoffProtocol(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/eth0-q0.sock"

	fd1, err := unix.MemfdCreate("dummy1", 0)
	if err != nil {
		t.Fatalf("memfd: %v", err)
	}
	defer unix.Close(fd1)
	fd2, err := unix.MemfdCreate("dummy2", 0)
	if err != nil {
		t.Fatalf("memfd: %v", err)
	}
	defer unix.Close(fd2)

	info := HandoffInfo{
		Ifname: "eth0", Ifindex: 2, QueueID: 0,
		FrameSize: 4096, NumFrames: 4096, Zerocopy: true,
		Ethertypes: []uint16{0x88B8, 0x88BA},
	}
	s, err := startHandoffServer(path, info, fd1, fd2)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Close()

	gotInfo, xfd, ufd, err := ReceiveHandoff(path)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	defer unix.Close(xfd)
	defer unix.Close(ufd)

	if gotInfo.Ifname != "eth0" || gotInfo.QueueID != 0 ||
		gotInfo.FrameSize != 4096 || gotInfo.NumFrames != 4096 ||
		!gotInfo.Zerocopy || len(gotInfo.Ethertypes) != 2 {
		t.Errorf("info mismatch: %+v", gotInfo)
	}

	// Verify the fds are real: write into one memfd, read from the
	// received fd (same file description).
	if _, err := unix.Write(fd1, []byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := unix.Pread(xfd, buf, 0); err != nil {
		t.Fatalf("pread on received fd: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("received fd is not the same file: %q", buf)
	}
}

// TestBackendEndToEnd is the real data path, privileges required:
// veth pair, XDP attach, XSK creation, handoff, and a frame with a
// matching EtherType steered into the UMEM. Skipped without
// CAP_BPF/CAP_NET_ADMIN (i.e. in CI).
func TestBackendEndToEnd(t *testing.T) {
	if !hasCaps(t) {
		t.Skip("no CAP_BPF/CAP_NET_ADMIN — skipping privileged data-path test")
	}

	const (
		vethA = "xsktest0"
		vethB = "xsktest1"
		et    = uint16(0x88B8)
	)

	// veth pair for the test.
	if err := exec.Command("ip", "link", "add", vethA, "numrxqueues", "1",
		"numtxqueues", "1", "type", "veth", "peer", "name", vethB).Run(); err != nil {
		t.Skipf("cannot create veth pair: %v", err)
	}
	defer exec.Command("ip", "link", "del", vethA).Run()
	mustRun(t, "ip", "link", "set", vethA, "up")
	mustRun(t, "ip", "link", "set", vethB, "up")
	// numrxqueues=1: injected frames must land on queue 0 where
	// the XSK is bound (real NICs steer via RSS/ntuple instead).

	iface, err := net.InterfaceByName(vethA)
	if err != nil {
		t.Fatalf("ifname: %v", err)
	}

	b := New(t.TempDir())
	ctx := t.Context()

	sockPath, err := b.Add(ctx, &backend.Allocation{
		Ifname:     vethA,
		Ifindex:    iface.Index,
		QueueID:    0,
		Ethertypes: []uint16{et},
		Zerocopy:   false, // veth is always copy mode
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	defer b.Del(ctx, vethA, 0)

	// Consumer side: inherit the XSK from the handoff.
	info, xfd, ufd, err := ReceiveHandoff(sockPath)
	if err != nil {
		t.Fatalf("handoff: %v", err)
	}
	if info.QueueID != 0 || info.Ifname != vethA || !containsET(info.Ethertypes, et) {
		t.Fatalf("info mismatch: %+v", info)
	}
	xsk, err := Inherit(xfd, ufd, info.FrameSize, info.NumFrames)
	if err != nil {
		t.Fatalf("inherit: %v", err)
	}
	defer xsk.Close()

	// Inject a frame with the matching EtherType from the peer.
	payload := []byte("GOOSE-test-payload")
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], []byte{0x02, 0, 0, 0, 0, 0x01}) // dst
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 0x02}) // src
	binary.BigEndian.PutUint16(frame[12:14], et)
	copy(frame[14:], payload)
	injectFrame(t, vethB, frame)

	// Expect it in the RX ring.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		descs := xsk.Recv(16)
		for _, d := range descs {
			if int(d.len) != len(frame) {
				continue
			}
			got := xsk.Umem()[d.addr : d.addr+uint64(d.len)]
			if bytes.Equal(got, frame) {
				return // data path works end to end
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("frame with matching ethertype never arrived in the XSK")
}

// TestBackendNonMatchingPasses: frames with other ethertypes must
// NOT land in the XSK.
func TestBackendNonMatchingPasses(t *testing.T) {
	if !hasCaps(t) {
		t.Skip("no CAP_BPF/CAP_NET_ADMIN — skipping privileged test")
	}
	const vethA, vethB = "xskntest0", "xskntest1"
	if err := exec.Command("ip", "link", "add", vethA, "numrxqueues", "1",
		"numtxqueues", "1", "type", "veth", "peer", "name", vethB).Run(); err != nil {
		t.Skipf("cannot create veth pair: %v", err)
	}
	defer exec.Command("ip", "link", "del", vethA).Run()
	mustRun(t, "ip", "link", "set", vethA, "up")
	mustRun(t, "ip", "link", "set", vethB, "up")
	// numrxqueues=1: injected frames must land on queue 0 where
	// the XSK is bound (real NICs steer via RSS/ntuple instead).

	iface, err := net.InterfaceByName(vethA)
	if err != nil {
		t.Fatalf("ifname: %v", err)
	}
	b := New(t.TempDir())
	ctx := t.Context()
	sockPath, err := b.Add(ctx, &backend.Allocation{
		Ifname: vethA, Ifindex: iface.Index, QueueID: 0,
		Ethertypes: []uint16{0x88B8}, Zerocopy: false,
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	defer b.Del(ctx, vethA, 0)

	info, xfd, ufd, err := ReceiveHandoff(sockPath)
	if err != nil {
		t.Fatalf("handoff: %v", err)
	}
	xsk, err := Inherit(xfd, ufd, info.FrameSize, info.NumFrames)
	if err != nil {
		t.Fatalf("inherit: %v", err)
	}
	defer xsk.Close()

	frame := make([]byte, 20)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800) // IP
	injectFrame(t, vethB, frame)

	time.Sleep(300 * time.Millisecond)
	if got := xsk.Recv(16); len(got) != 0 {
		t.Fatalf("non-matching ethertype leaked into XSK: %+v", got)
	}
}

func containsET(ets []uint16, et uint16) bool {
	for _, e := range ets {
		if e == et {
			return true
		}
	}
	return false
}

func mustRun(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%v: %v (%s)", args, err, out)
	}
}

// injectFrame sends a raw Ethernet frame on an interface.
func injectFrame(t *testing.T, ifname string, frame []byte) {
	t.Helper()
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		t.Fatalf("ifname: %v", err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(unix.ETH_P_ALL))
	if err != nil {
		t.Fatalf("af_packet socket: %v", err)
	}
	defer unix.Close(fd)

	sa := &unix.SockaddrLinklayer{
		Protocol: unix.ETH_P_ALL,
		Ifindex:  iface.Index,
	}
	if err := unix.Bind(fd, sa); err != nil {
		t.Fatalf("bind af_packet: %v", err)
	}
	if _, err := unix.Write(fd, frame); err != nil {
		t.Fatalf("inject: %v", err)
	}
}

var _ = unsafe.Sizeof(0) // keep unsafe import if unused after edits
