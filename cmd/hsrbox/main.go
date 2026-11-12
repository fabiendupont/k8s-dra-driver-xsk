// SPDX-License-Identifier: Apache-2.0
//
// hsrbox — HSR/PRP stream e2e traffic tool.
//
// Subcommands:
//
//	rx        inherit an XSK from a handoff socket and count received
//	          frames (dedup verification: unique payload sequence
//	          numbers vs. total frames)
//	tx        send untagged frames through an inherited XSK (the
//	          node RedBox tags and clones them onto both ring ports)
//	send-dup  craft HSR-tagged frames and send duplicates on two
//	          interfaces (the far end of the ring); --only-a simulates
//	          a ring break
//	sniff     count HSR-tagged frames on an interface and report
//	          their path field (TX clone verification)
//
// rx/tx run inside the consuming pod; send-dup/sniff run on the node
// (or in a network namespace holding the far ends of the ring ports).
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend/native"
)

const (
	hsrEthertype = 0x892F
	pathA        = 0x0000
	pathB        = 0x1000
)

// payload layout after the (stripped) Ethernet header:
// 4-byte magic + 4-byte sequence number + filler.
var payloadMagic = [4]byte{'H', 'S', 'R', 'X'}

func makeFrame(seq uint32) []byte {
	p := make([]byte, 64)
	copy(p, payloadMagic[:])
	binary.BigEndian.PutUint32(p[4:8], seq)
	return p
}

func parsePayload(frame []byte) (seq uint32, ok bool) {
	if len(frame) < 8 {
		return 0, false
	}
	if frame[0] != payloadMagic[0] || frame[1] != payloadMagic[1] ||
		frame[2] != payloadMagic[2] || frame[3] != payloadMagic[3] {
		return 0, false
	}
	return binary.BigEndian.Uint32(frame[4:8]), true
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hsrbox {rx|tx|send-dup|sniff} [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "rx":
		err = cmdRX(os.Args[2:])
	case "tx":
		err = cmdTX(os.Args[2:])
	case "send-dup":
		err = cmdSendDup(os.Args[2:])
	case "sniff":
		err = cmdSniff(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hsrbox:", err)
		os.Exit(1)
	}
}

// inherit connects to the driver's SCM_RIGHTS handoff socket and
// reconstructs the XSK.
func inherit(sockPath string) (*native.XSK, error) {
	info, xfd, ufd, err := native.ReceiveHandoff(sockPath)
	if err != nil {
		return nil, fmt.Errorf("handoff: %w", err)
	}
	x, err := native.Inherit(xfd, ufd, info.FrameSize, info.NumFrames)
	if err != nil {
		return nil, fmt.Errorf("inherit: %w", err)
	}
	fmt.Fprintf(os.Stderr, "hsrbox: inherited XSK %s q%d (%d frames of %d bytes, zerocopy=%v)\n",
		info.Ifname, info.QueueID, info.NumFrames, info.FrameSize, info.Zerocopy)
	return x, nil
}

func cmdRX(args []string) error {
	fs := flag.NewFlagSet("rx", flag.ExitOnError)
	sock := fs.String("socket", "", "handoff socket path (required)")
	count := fs.Int("count", 10, "expected unique frames")
	timeout := fs.Duration("timeout", 10*time.Second, "give up after")
	fs.Parse(args)
	if *sock == "" {
		return fmt.Errorf("--socket required")
	}

	x, err := inherit(*sock)
	if err != nil {
		return err
	}
	defer x.Close()

	deadline := time.Now().Add(*timeout)
	seen := map[uint32]int{}
	total := 0
	for time.Now().Before(deadline) && len(seen) < *count {
		frames, addrs := x.RecvFrames(64)
		for i, frame := range frames {
			total++
			// XSK frames include the Ethernet header; the RedBox
			// tag-strip restores the inner frame's header.
			if len(frame) >= 14+8 {
				if seq, ok := parsePayload(frame[14:]); ok {
					seen[seq]++
				}
			}
			x.Refill(addrs[i])
		}
		if len(frames) == 0 {
			time.Sleep(20 * time.Millisecond)
		}
	}

	// Report and assert: every sequence number exactly once.
	dups := 0
	for _, n := range seen {
		if n > 1 {
			dups += n - 1
		}
	}
	out, _ := json.Marshal(map[string]any{
		"total_frames": total,
		"unique":       len(seen),
		"expected":     *count,
		"duplicates":   dups,
	})
	fmt.Println(string(out))
	if len(seen) < *count {
		return fmt.Errorf("received %d unique frames, want %d", len(seen), *count)
	}
	if dups > 0 {
		return fmt.Errorf("duplicate delivery: %d frames delivered more than once", dups)
	}
	return nil
}

func cmdTX(args []string) error {
	fs := flag.NewFlagSet("tx", flag.ExitOnError)
	sock := fs.String("socket", "", "handoff socket path (required)")
	count := fs.Int("count", 5, "frames to send")
	ethertype := fs.String("ethertype", "0x88B8", "frame EtherType (hex)")
	gap := fs.Duration("gap", 10*time.Millisecond, "inter-frame gap")
	fs.Parse(args)
	if *sock == "" {
		return fmt.Errorf("--socket required")
	}
	var et uint16
	if _, err := fmt.Sscanf(*ethertype, "0x%x", &et); err != nil {
		return fmt.Errorf("invalid ethertype %q", *ethertype)
	}

	x, err := inherit(*sock)
	if err != nil {
		return err
	}
	defer x.Close()

	for i := 0; i < *count; i++ {
		payload := makeFrame(uint32(i))
		frame := make([]byte, 14+len(payload))
		copy(frame[0:6], net.HardwareAddr{0x02, 0, 0, 0, 0, 0x10})  // dst
		copy(frame[6:12], net.HardwareAddr{0x02, 0, 0, 0, 0, 0x11}) // src
		binary.BigEndian.PutUint16(frame[12:14], et)
		copy(frame[14:], payload)
		if err := x.Send(frame); err != nil {
			return fmt.Errorf("frame %d: %w", i, err)
		}
		time.Sleep(*gap)
	}
	fmt.Printf("sent %d frames\n", *count)
	if st, err := x.Stats(); err == nil {
		fmt.Printf("xsk stats: %+v\n", st)
	}
	return nil
}

// hsrFrame builds an HSR-tagged frame: eth header with EtherType
// 0x892F, 6-byte HSR tag (path|lsdu, seq, encap proto), payload.
func hsrFrame(path uint16, seq uint16, ethertype uint16, payload []byte) []byte {
	lsdu := 6 + len(payload) // tag + payload
	frame := make([]byte, 14+6+len(payload))
	copy(frame[0:6], net.HardwareAddr{0x02, 0, 0, 0, 0, 0x21})  // dst
	copy(frame[6:12], net.HardwareAddr{0x02, 0, 0, 0, 0, 0x22}) // src (dedup key)
	binary.BigEndian.PutUint16(frame[12:14], hsrEthertype)
	binary.BigEndian.PutUint16(frame[14:16], path|uint16(lsdu))
	binary.BigEndian.PutUint16(frame[16:18], seq)
	binary.BigEndian.PutUint16(frame[18:20], ethertype)
	copy(frame[20:], payload)
	return frame
}

func cmdSendDup(args []string) error {
	fs := flag.NewFlagSet("send-dup", flag.ExitOnError)
	ifA := fs.String("a", "", "ring port A far end (required)")
	ifB := fs.String("b", "", "ring port B far end (required)")
	count := fs.Int("count", 10, "duplicate frame pairs to send")
	seqStart := fs.Int("seq-start", 0, "first HSR sequence number")
	ethertype := fs.String("ethertype", "0x88B8", "inner EtherType (hex)")
	onlyA := fs.Bool("only-a", false, "send on port A only (ring break)")
	gap := fs.Duration("gap", 10*time.Millisecond, "inter-frame gap")
	fs.Parse(args)
	if *ifA == "" || *ifB == "" {
		return fmt.Errorf("--a and --b required")
	}
	var et uint16
	if _, err := fmt.Sscanf(*ethertype, "0x%x", &et); err != nil {
		return fmt.Errorf("invalid ethertype %q", *ethertype)
	}

	sockA, err := rawSocket(*ifA)
	if err != nil {
		return err
	}
	defer unix.Close(sockA)
	sockB, err := rawSocket(*ifB)
	if err != nil {
		return err
	}
	defer unix.Close(sockB)

	for i := 0; i < *count; i++ {
		seq := uint16(*seqStart + i)
		payload := makeFrame(uint32(seq))
		fa := hsrFrame(pathA, seq, et, payload)
		fb := hsrFrame(pathB, seq, et, payload)
		if err := rawSend(sockA, fa); err != nil {
			return fmt.Errorf("port A frame %d: %w", i, err)
		}
		if !*onlyA {
			if err := rawSend(sockB, fb); err != nil {
				return fmt.Errorf("port B frame %d: %w", i, err)
			}
		}
		time.Sleep(*gap)
	}
	fmt.Printf("sent %d frames (dup=%v)\n", *count, !*onlyA)
	return nil
}

func cmdSniff(args []string) error {
	fs := flag.NewFlagSet("sniff", flag.ExitOnError)
	iface := fs.String("iface", "", "interface to sniff (required)")
	count := fs.Int("count", 5, "expected HSR frames")
	timeout := fs.Duration("timeout", 10*time.Second, "give up after")
	fs.Parse(args)
	if *iface == "" {
		return fmt.Errorf("--iface required")
	}

	fd, err := rawSocket(*iface)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	buf := make([]byte, 2048)
	deadline := time.Now().Add(*timeout)
	hsrCount, pathACount, pathBCount, other := 0, 0, 0, 0
	for time.Now().Before(deadline) && hsrCount < *count {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				// EINTR: Go's async preemption (SIGURG) interrupts
				// blocking syscalls; just retry.
				time.Sleep(20 * time.Millisecond)
				continue
			}
			return err
		}
		if n < 14 {
			continue
		}
		if binary.BigEndian.Uint16(buf[12:14]) != hsrEthertype {
			other++
			continue
		}
		hsrCount++
		if n >= 16 {
			switch binary.BigEndian.Uint16(buf[14:16]) & 0xF000 {
			case pathA:
				pathACount++
			case pathB:
				pathBCount++
			}
		}
	}
	out, _ := json.Marshal(map[string]any{
		"hsr_frames": hsrCount,
		"path_a":     pathACount,
		"path_b":     pathBCount,
		"other":      other,
	})
	fmt.Println(string(out))
	if hsrCount < *count {
		return fmt.Errorf("sniffed %d HSR frames, want %d", hsrCount, *count)
	}
	return nil
}

// ethPAllBE is htons(ETH_P_ALL): sockaddr_ll.sll_protocol and the
// socket() protocol argument are big-endian on the wire. x/sys
// lacks Htons, so swap the constant by hand.
const ethPAllBE = 0x0300

// rawSocket opens a bound AF_PACKET socket with a 1s recv timeout.
func rawSocket(ifname string) (int, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return -1, fmt.Errorf("interface %s: %w", ifname, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, ethPAllBE)
	if err != nil {
		return -1, fmt.Errorf("af_packet: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: ethPAllBE, Ifindex: iface.Index,
	}); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("bind %s: %w", ifname, err)
	}
	tv := unix.NsecToTimeval(int64(time.Second))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func rawSend(fd int, frame []byte) error {
	// The socket is already bound to the interface.
	_, err := unix.Write(fd, frame)
	return err
}
