// Package native implements backend.Backend in-process: it loads the
// XDP filter program itself, creates AF_XDP sockets directly, and
// hands the {xsk fd, umem fd} pair to consumers over a Unix socket
// via SCM_RIGHTS. No daemon, no subprocess — the driver is the
// privileged process.
package native

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip /usr/bin/strip filter bpf/xdp_filter.bpf.c -- -O2 -g -target bpf -D__TARGET_ARCH_x86
