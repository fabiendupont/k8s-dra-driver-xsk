package native

import (
	"fmt"
	"os"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// XSK is an AF_XDP socket bound to one NIC RX queue, with its UMEM
// backed by a memfd so the {xsk fd, umem fd} pair can be handed to
// an unprivileged consumer via SCM_RIGHTS. The consumer re-mmaps the
// UMEM and rings from the fds (see Inherit) — no CAP_BPF or
// CAP_NET_ADMIN needed on the consumer side.
//
// Modeled on the xgl_xsk_inherit pattern from xdp-graph-lib.
type XSK struct {
	Ifindex   int
	QueueID   int
	Zerocopy  bool
	FrameSize uint32
	NumFrames uint32

	xskFd  int
	umemFd int
	umem   []byte

	fillRing    *ring
	rxRing      *ring
	ringOffsets xdpMmapOffsetsT
}

// mmap offsets for the AF_XDP rings (missing from x/sys/unix).
// linux/if_xdp.h: RX ring at 0, TX ring at 0x80000000, fill ring at
// 0x100000000, completion ring at 0x180000000.
const (
	xdpPgoffRxRing   = 0x0
	xdpUgoffFillRing = 0x100000000
)

// XDP_MMAP_OFFSETS getsockopt option (missing from x/sys/unix).
const xdpMmapOffsets = 1

const defaultFillRingSize = 4096

// xdp_umem_reg (uapi/linux/if_xdp.h).
type xdpUmemReg struct {
	addr     uint64
	len      uint64
	size     uint32
	headroom uint32
	flags    uint32
	txMeta   uint32
}

// xdp_ring_offset (uapi/linux/if_xdp.h) — 64-bit fields.
type xdpRingOffset struct {
	producer uint64
	consumer uint64
	desc     uint64
	flags    uint64
}

// xdp_mmap_offsets (uapi/linux/if_xdp.h): all four ring offsets in
// one getsockopt(XDP_MMAP_OFFSETS).
type xdpMmapOffsetsT struct {
	rx   xdpRingOffset
	tx   xdpRingOffset
	fill xdpRingOffset
	comp xdpRingOffset
}

// xdp_desc for rx/tx rings.
type xdpDesc struct {
	addr    uint64
	len     uint32
	options uint32
}

// OpenXSK creates an AF_XDP socket bound to (ifindex, queueID) with
// a memfd-backed UMEM and the fill ring primed with every frame.
// Zero-copy is attempted first; falls back to copy mode when the
// driver does not support it.
func OpenXSK(ifindex, queueID int, frameSize, numFrames uint32, zerocopy bool) (*XSK, error) {
	if frameSize == 0 || frameSize%2048 != 0 {
		return nil, fmt.Errorf("frame size %d must be a multiple of 2048", frameSize)
	}
	if numFrames == 0 || numFrames&(numFrames-1) != 0 {
		return nil, fmt.Errorf("num frames %d must be a power of two", numFrames)
	}

	umemFd, err := unix.MemfdCreate("xsk-umem", 0)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	umemSize := int(frameSize) * int(numFrames)
	if err := unix.Ftruncate(umemFd, int64(umemSize)); err != nil {
		unix.Close(umemFd)
		return nil, fmt.Errorf("ftruncate umem: %w", err)
	}
	umem, err := unix.Mmap(umemFd, 0, umemSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(umemFd)
		return nil, fmt.Errorf("mmap umem: %w", err)
	}

	xskFd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		unix.Munmap(umem)
		unix.Close(umemFd)
		return nil, fmt.Errorf("socket(AF_XDP): %w", err)
	}

	x := &XSK{
		Ifindex:   ifindex,
		QueueID:   queueID,
		FrameSize: frameSize,
		NumFrames: numFrames,
		xskFd:     xskFd,
		umemFd:    umemFd,
		umem:      umem,
	}
	// From here on, Close() owns everything.
	if err := x.setup(zerocopy); err != nil {
		x.Close()
		return nil, err
	}
	return x, nil
}

func (x *XSK) setup(zerocopy bool) error {
	ringSize := x.NumFrames
	if ringSize > defaultFillRingSize {
		ringSize = defaultFillRingSize
	}

	reg := xdpUmemReg{
		addr: uint64(uintptr(unsafe.Pointer(&x.umem[0]))),
		len:  uint64(len(x.umem)),
		size: x.FrameSize,
	}
	if err := setsockopt(x.xskFd, unix.XDP_UMEM_REG, unsafe.Pointer(&reg), unsafe.Sizeof(reg)); err != nil {
		return fmt.Errorf("XDP_UMEM_REG: %w", err)
	}

	// Ring sizes must be set before bind. The RX ring is sized here
	// even though the driver never reads it: consumers mmap it from
	// the inherited fd after the SCM_RIGHTS handoff.
	if err := setsockoptU32(x.xskFd, unix.XDP_RX_RING, ringSize); err != nil {
		return fmt.Errorf("XDP_RX_RING: %w", err)
	}
	if err := setsockoptU32(x.xskFd, unix.XDP_UMEM_FILL_RING, ringSize); err != nil {
		return fmt.Errorf("XDP_UMEM_FILL_RING: %w", err)
	}
	if err := setsockoptU32(x.xskFd, unix.XDP_UMEM_COMPLETION_RING, ringSize); err != nil {
		return fmt.Errorf("XDP_UMEM_COMPLETION_RING: %w", err)
	}

	flags := uint16(unix.XDP_USE_NEED_WAKEUP | unix.XDP_ZEROCOPY)
	sa := &unix.SockaddrXDP{Flags: flags, Ifindex: uint32(x.Ifindex), QueueID: uint32(x.QueueID)}
	if err := unix.Bind(x.xskFd, sa); err != nil {
		if !zerocopy || err != unix.EOPNOTSUPP {
			// Try copy mode before giving up.
			sa.Flags = uint16(unix.XDP_USE_NEED_WAKEUP | unix.XDP_COPY)
			if err2 := unix.Bind(x.xskFd, sa); err2 != nil {
				return fmt.Errorf("bind AF_XDP queue %d: %w (zerocopy fallback also failed: %v)",
					x.QueueID, err, err2)
			}
		}
		x.Zerocopy = false
	} else {
		x.Zerocopy = true
	}

	// Fetch RX ring offsets for consumers (they mmap from the fd).
	// Fetch ring offsets for consumers (they mmap from the fd).
	offs, err := getMmapOffsets(x.xskFd)
	if err != nil {
		return fmt.Errorf("ring offsets: %w", err)
	}
	x.ringOffsets = offs

	// Map and prime the fill ring.
	fill, err := mapRing(x.xskFd, offs.fill, 8 /* u64 addr descs */, ringSize, xdpUgoffFillRing)
	if err != nil {
		return fmt.Errorf("mmap fill ring: %w", err)
	}
	x.fillRing = fill

	// Prime: make every frame available to the kernel.
	n := fill.capacity()
	for i := uint32(0); i < n; i++ {
		addr := uint64(uint32(i)) * uint64(x.FrameSize)
		if !fill.push(&xdpDesc{addr: addr}) {
			break
		}
	}
	fill.flush(x.xskFd)
	return nil
}

// ringOffset fetches all four ring offsets via getsockopt.
func getMmapOffsets(fd int) (xdpMmapOffsetsT, error) {
	var offs xdpMmapOffsetsT
	size := unsafe.Sizeof(offs)
	if err := getsockoptRaw(fd, xdpMmapOffsets, unsafe.Pointer(&offs), &size); err != nil {
		return offs, err
	}
	return offs, nil
}

// ring is a mmap'd producer/consumer ring over the xsk fd.
type ring struct {
	data        []byte
	descSize    int
	producer    *uint32
	consumer    *uint32
	cachedProd  uint32
	cachedCons  uint32
	mask        uint32
	descs       []byte
	descsStride int
}

func mapRing(fd int, off xdpRingOffset, descSize int, count uint32, mmapOffset int64) (*ring, error) {
	// Map enough pages to cover desc array end.
	end := int(off.desc) + descSize*int(count)
	mapLen := (end + os.Getpagesize() - 1) &^ (os.Getpagesize() - 1)
	data, err := unix.Mmap(fd, mmapOffset, mapLen, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	if int(off.desc)%descSize != 0 {
		unix.Munmap(data)
		return nil, fmt.Errorf("desc offset %d not aligned to desc size %d", off.desc, descSize)
	}
	return &ring{
		data:        data,
		descSize:    descSize,
		producer:    (*uint32)(unsafe.Pointer(&data[off.producer])),
		consumer:    (*uint32)(unsafe.Pointer(&data[off.consumer])),
		mask:        count - 1,
		descs:       data[off.desc : int(off.desc)+descSize*int(count)],
		descsStride: descSize,
	}, nil
}

// capacity returns the usable descriptor count (power of two).
func (r *ring) capacity() uint32 { return r.mask + 1 }

// push appends one descriptor if the ring has room.
func (r *ring) push(d *xdpDesc) bool {
	if r.cachedProd-r.cachedCons >= r.capacity() {
		r.cachedCons = atomic.LoadUint32(r.consumer)
		if r.cachedProd-r.cachedCons >= r.capacity() {
			return false
		}
	}
	idx := r.cachedProd & r.mask
	if r.descSize == 8 {
		// fill/completion ring: u64 addr only
		*(*uint64)(unsafe.Pointer(&r.descs[int(idx)*8])) = d.addr
	} else {
		*(*xdpDesc)(unsafe.Pointer(&r.descs[int(idx)*16])) = *d
	}
	r.cachedProd++
	return true
}

// flush publishes the produced descriptors and wakes the kernel.
func (r *ring) flush(fd int) {
	atomic.StoreUint32(r.producer, r.cachedProd)
	// Wake the kernel if it is polling (XDP_USE_NEED_WAKEUP):
	// sendto on the xsk socket with no destination does exactly that.
	_ = unix.Sendto(fd, nil, unix.MSG_DONTWAIT, nil)
}

// Fds returns the {xsk fd, umem fd} pair for SCM_RIGHTS handoff.
func (x *XSK) Fds() (xskFd, umemFd int) { return x.xskFd, x.umemFd }

// UMemFd returns the memfd backing the UMEM (for SCM_RIGHTS
// handoff by other backends).
func (x *XSK) UMemFd() int { return x.umemFd }

// Inherit reconstructs an XSK from the {xsk fd, umem fd} pair
// received via SCM_RIGHTS (see ReceiveHandoff). This is the
// consumer side — no CAP_BPF or CAP_NET_ADMIN required. The ring
// sizes were fixed by the creator before bind; they are re-fetched
// here and re-mapped.
func Inherit(xskFd, umemFd int, frameSize, numFrames uint32) (*XSK, error) {
	umemSize := int(frameSize) * int(numFrames)
	umem, err := unix.Mmap(umemFd, 0, umemSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap umem: %w", err)
	}

	x := &XSK{
		FrameSize: frameSize,
		NumFrames: numFrames,
		xskFd:     xskFd,
		umemFd:    umemFd,
		umem:      umem,
	}

	// Ring sizes: recover from the ring offsets (desc count is a
	// power of two; the creator used min(numFrames, 4096)).
	ringSize := numFrames
	if ringSize > defaultFillRingSize {
		ringSize = defaultFillRingSize
	}

	offs, err := getMmapOffsets(xskFd)
	if err != nil {
		unix.Munmap(umem)
		return nil, fmt.Errorf("ring offsets: %w", err)
	}
	x.ringOffsets = offs

	rx, err := mapRing(xskFd, offs.rx, 16 /* xdp_desc */, ringSize, xdpPgoffRxRing)
	if err != nil {
		unix.Munmap(umem)
		return nil, fmt.Errorf("mmap rx ring: %w", err)
	}
	x.rxRing = rx

	fill, err := mapRing(xskFd, offs.fill, 8, ringSize, xdpUgoffFillRing)
	if err != nil {
		unix.Munmap(umem)
		return nil, fmt.Errorf("mmap fill ring: %w", err)
	}
	x.fillRing = fill
	return x, nil
}

// Umem exposes the shared packet memory region.
func (x *XSK) Umem() []byte { return x.umem }

// Recv returns up to max received descriptors (addr/len into Umem).
// The consumer should eventually return processed frames to the fill
// ring (Refill).
func (x *XSK) Recv(max int) []xdpDesc {
	r := x.rxRing
	prod := atomic.LoadUint32(r.producer)
	n := prod - r.cachedCons
	if n > r.capacity() {
		n = r.capacity()
	}
	if int(n) > max {
		n = uint32(max)
	}
	out := make([]xdpDesc, 0, n)
	for i := uint32(0); i < n; i++ {
		idx := (r.cachedCons + i) & r.mask
		d := *(*xdpDesc)(unsafe.Pointer(&r.descs[int(idx)*16]))
		out = append(out, d)
	}
	r.cachedCons += n
	atomic.StoreUint32(r.consumer, r.cachedCons)
	return out
}

// Refill returns a processed frame address to the fill ring.
func (x *XSK) Refill(addr uint64) {
	if x.fillRing.push(&xdpDesc{addr: addr}) {
		x.fillRing.flush(x.xskFd)
	}
}

// Close tears down the socket and UMEM.
func (x *XSK) Close() {
	if x.fillRing != nil {
		unix.Munmap(x.fillRing.data)
		x.fillRing = nil
	}
	if x.umem != nil {
		unix.Munmap(x.umem)
		x.umem = nil
	}
	if x.xskFd >= 0 {
		unix.Close(x.xskFd)
		x.xskFd = -1
	}
	if x.umemFd >= 0 {
		unix.Close(x.umemFd)
		x.umemFd = -1
	}
}

// --- raw setsockopt/getsockopt on SOL_XDP ---

func setsockopt(fd, opt int, ptr unsafe.Pointer, size uintptr) error {
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd),
		uintptr(unix.SOL_XDP), uintptr(opt), uintptr(ptr), size, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func setsockoptU32(fd, opt int, v uint32) error {
	return unix.SetsockoptInt(fd, unix.SOL_XDP, opt, int(v))
}

func getsockoptRaw(fd, opt int, ptr unsafe.Pointer, size *uintptr) error {
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd),
		uintptr(unix.SOL_XDP), uintptr(opt), uintptr(unsafe.Pointer(ptr)),
		uintptr(unsafe.Pointer(size)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// RecvStrings is a convenience wrapper around Recv returning the
// packet contents (for diagnostics and simple consumers).
func (x *XSK) RecvStrings(max int) []string {
	descs := x.Recv(max)
	out := make([]string, 0, len(descs))
	for _, d := range descs {
		out = append(out, string(x.umem[d.addr:d.addr+uint64(d.len)]))
	}
	return out
}

// xdp_statistics (uapi/linux/if_xdp.h).
type xdpStatistics struct {
	rxDropped       uint64
	rxInvalidDescs  uint64
	txDropped       uint64
	txInvalidDescs  uint64
}

// Stats reads the kernel-side XSK statistics.
func (x *XSK) Stats() (xdpStatistics, error) {
	var st xdpStatistics
	size := unsafe.Sizeof(st)
	if err := getsockoptRaw(x.xskFd, unix.XDP_STATISTICS, unsafe.Pointer(&st), &size); err != nil {
		return st, err
	}
	return st, nil
}
