// Package hsrprp implements the node-local RedBox dataplane that
// composes xdp-hsr-prp graph nodes with the driver's XSK filter,
// exposing deduplicated HSR/PRP streams to pods.
package hsrprp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -strip /usr/bin/strip redbox bpf/redbox.bpf.c -- -O2 -g -target bpf -D__TARGET_ARCH_x86
