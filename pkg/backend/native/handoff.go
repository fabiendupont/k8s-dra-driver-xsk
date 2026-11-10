package native

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

// HandoffInfo describes an allocated XSK to the consumer. It is sent
// as a JSON header line before the SCM_RIGHTS message carrying the
// {xsk fd, umem fd} pair.
type HandoffInfo struct {
	Ifname    string `json:"ifname"`
	Ifindex   int    `json:"ifindex"`
	QueueID   int    `json:"queue_id"`
	FrameSize uint32 `json:"frame_size"`
	NumFrames uint32 `json:"num_frames"`
	Zerocopy  bool   `json:"zerocopy"`
	Ethertypes []uint16 `json:"ethertypes"`
}

// HandoffServer serves (see StartHandoffServer). one XSK's fds on a Unix socket. Consumers may
// connect at any time (including reconnecting after a restart) and
// always receive the current fd pair — reconnects after Del close
// the listener.
// HandoffServer serves one XSK's fds on a Unix socket via
// SCM_RIGHTS. Exported for reuse by other backends (bpfman).
type handoffServer struct {
	mu     sync.Mutex
	ln     net.Listener
	path   string
	info   HandoffInfo
	xskFd  int
	umemFd int
	closed bool
}

// StartHandoffServer starts the SCM_RIGHTS fd-handoff server for
// one XSK at path. Exported for reuse by other backends.
func StartHandoffServer(path string, info HandoffInfo, xskFd, umemFd int) (*HandoffServer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("creating handoff dir: %w", err)
	}
	// Remove a stale socket from a previous run.
	if err := os.RemoveAll(path); err != nil {
		return nil, fmt.Errorf("removing stale socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", path, err)
	}
	s := &HandoffServer{ln: ln, path: path, info: info, xskFd: xskFd, umemFd: umemFd}
	go s.acceptLoop()
	return s, nil
}

func (s *HandoffServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		s.serve(conn)
	}
}

func (s *HandoffServer) serve(conn net.Conn) {
	defer conn.Close()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	info := s.info
	xskFd, umemFd := s.xskFd, s.umemFd
	s.mu.Unlock()

	header, err := json.Marshal(info)
	if err != nil {
		return
	}
	if _, err := conn.Write(append(header, '\n')); err != nil {
		return
	}

	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}
	rights := unix.UnixRights(xskFd, umemFd)
	if _, _, err := uc.WriteMsgUnix(nil, rights, nil); err != nil {
		return
	}
}

func (s *HandoffServer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.ln.Close()
	os.RemoveAll(s.path)
}

// ErrHandoffClosed is returned when the handoff socket no longer
// exists (the allocation was removed).
var ErrHandoffClosed = errors.New("handoff socket closed")

// ReceiveHandoff connects to a handoff socket and returns the info
// plus the {xsk fd, umem fd} pair. The fds are owned by the caller.
// This is the consumer side; it needs no privileges.
func ReceiveHandoff(path string) (HandoffInfo, int, int, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return HandoffInfo{}, -1, -1, fmt.Errorf("%w: %v", ErrHandoffClosed, err)
	}
	defer conn.Close()

	// Read the JSON header line.
	var header []byte
	buf := make([]byte, 1)
	for {
		n, err := conn.Read(buf)
		if n == 0 || err != nil {
			return HandoffInfo{}, -1, -1, fmt.Errorf("reading header: %w", err)
		}
		if buf[0] == '\n' {
			break
		}
		header = append(header, buf[0])
		if len(header) > 1<<16 {
			return HandoffInfo{}, -1, -1, errors.New("header too large")
		}
	}

	var info HandoffInfo
	if err := json.Unmarshal(header, &info); err != nil {
		return HandoffInfo{}, -1, -1, fmt.Errorf("parsing header: %w", err)
	}

	uconn, ok := conn.(*net.UnixConn)
	if !ok {
		return HandoffInfo{}, -1, -1, errors.New("not a unix connection")
	}
	oob := make([]byte, unix.CmsgSpace(2*4))
	_, oobn, _, _, err := uconn.ReadMsgUnix(nil, oob)
	if err != nil {
		return HandoffInfo{}, -1, -1, fmt.Errorf("receiving fds: %w", err)
	}

	fds, err := parseFds(oob[:oobn])
	if err != nil {
		return HandoffInfo{}, -1, -1, err
	}
	if len(fds) != 2 {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return HandoffInfo{}, -1, -1, fmt.Errorf("expected 2 fds, got %d", len(fds))
	}
	return info, fds[0], fds[1], nil
}

func parseFds(oob []byte) ([]int, error) {
	var fds []int
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}
	for _, m := range msgs {
		got, err := unix.ParseUnixRights(&m)
		if err != nil {
			return nil, err
		}
		fds = append(fds, got...)
	}
	return fds, nil
}
