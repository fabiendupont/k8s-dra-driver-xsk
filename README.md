# k8s-dra-driver-xsk

Kubernetes DRA (Dynamic Resource Allocation) driver that allocates
**NIC RX queues as AF_XDP sockets** — each claim gets a dedicated
queue with an EtherType filter set, zero-copy packet delivery into a
memfd-backed UMEM, and a rootless fd handoff into the pod.

Protocol-neutral: the filter set comes from claim parameters, so
IEC 61850 (GOOSE/SV), industrial Ethernet, or any L2 protocol work
equally well.

## How it works

```
            ┌───────────────── node ─────────────────┐
 NIC RX ───▶│ XDP filter (EtherType map → XSKMAP)     │
 queue N    │        │                                │
            │   AF_XDP socket (zero-copy preferred)   │
            │        │  {xsk fd, umem fd}             │
            │        ▼  SCM_RIGHTS over /run/xsk/…    │
            │   pod (XSK_SOCKET env via CDI)          │
            └─────────────────────────────────────────┘
```

1. **Discovery**: enumerates physical NIC RX queues from sysfs
   (queue id, driver, NUMA node, zero-copy capability) and publishes
   them as DRA ResourceSlice devices.
2. **Claim**: a pod requests queues via a DeviceClass; the scheduler
   allocates.
3. **Validation** (optional, recommended): the intended allocation
   is rendered as an [xgl_check] spec — queue dedication, EtherType
   disjointness, resource uniqueness — and validated before anything
   is created. Fail-closed.
4. **Allocation** (`NodePrepareResources`): the driver loads the XDP
   filter program (in-process, [cilium/ebpf]), creates the AF_XDP
   socket with a memfd-backed UMEM, inserts it into the XSKMAP, and
   starts a per-queue Unix socket serving the fd pair via
   SCM_RIGHTS.
5. **Injection**: a CDI spec gives the pod `XSK_SOCKET`,
   `XSK_IFACE`, `XSK_QUEUE`, and `XSK_ETHTYPES` environment
   variables plus a read-only mount of the handoff directory. The
   pod connects and receives the fds — **no capabilities required
   in the pod**.

## Quickstart

```sh
# Build and load the image
docker build -t quay.io/fabiendupont/dra-xsk-driver:latest .

# Device classes (generic + IEC 61850 preset)
kubectl apply -f deployments/device-class.yaml

# Driver (labels XDP-capable nodes: xsk.dra.io/capable=true)
kubectl apply -f deployments/daemonset.yaml

# Request a queue with explicit filters
kubectl apply -f deployments/examples/claim-generic.yaml
kubectl apply -f deployments/examples/pod.yaml

# In the pod:
#   XSK_SOCKET=/run/xsk/eth0-q0.sock  — connect, recv fds (SCM_RIGHTS)
#   XSK_IFACE=eth0 XSK_QUEUE=0 XSK_ETHTYPES=0x8892,0x88a4
```

Consuming the socket from Go:

```go
import "github.com/fabiendupont/k8s-dra-driver-xsk/pkg/backend/native"

info, xskFd, umemFd, err := native.ReceiveHandoff(os.Getenv("XSK_SOCKET"))
xsk, err := native.Inherit(xskFd, umemFd, info.FrameSize, info.NumFrames)
for {
    for _, d := range xsk.Recv(64) {
        pkt := xsk.Umem()[d.addr : d.addr+uint64(d.len)]
        // ...
    }
}
```

## Claim parameters

Parameters are carried via `OpaqueDeviceConfiguration`
(`driver: xsk.dra.io`) on the claim or the DeviceClass; claims
override classes:

```yaml
config:
  - deviceConfiguration:
      opaque:
        driver: xsk.dra.io
        parameters:
          apiVersion: xsk.dra.io/v1alpha1
          kind: XSKParameters
          ethertypes: ["0x88B8", "0x88BA"]   # hex, 0x0600–0xFFFF, max 8
          zerocopy: true                      # default true
          cpu: 2                              # optional: dedicated CPU
```

With no parameters, the legacy IEC 61850 preset (GOOSE + SV)
applies. The `xsk-iec61850` DeviceClass ships the preset as class
config.

## Backends: native and bpfman

The XDP loading layer is pluggable (`--backend`):

- **native** (default): in-process loading via cilium/ebpf — no
  daemon, the driver owns the XDP attach point.
- **bpfman**: delegates program load/attach/unload to a
  [bpfman](https://github.com/bpfman/bpfman) daemon (`--bpfman-socket`,
  default `/run/bpfman/bpfman.sock`). bpfman's dispatcher owns the
  interface, composing our filter program with other XDP programs;
  the driver keeps identical DRA semantics, XSK creation, and
  SCM_RIGHTS handoff (the same embedded ELF, pinned-map updates).

Complementary rather than competing with bpfman's ecosystem: this
driver is the DRA-native successor to the device-plugin-based
AF_XDP pattern, and composes with bpfman where it is already the
program manager.

## Determinism

The as-deterministic-as-possible recipe is machine-checked: one
queue + one IRQ + one CPU, NUMA-aligned. The driver discovers queue
IRQs (from `/proc/interrupts`) and CPU NUMA topology, accepts a
dedicated `cpu` parameter, and — with the `xgl_check` gate enabled —
rejects any allocation that shares a dedicated resource or makes a
frame's path ambiguous.

## Security

- Driver pod: root with `CAP_BPF` + `CAP_NET_ADMIN` only (see
  DaemonSet); consuming pods: **zero** capabilities — fd inheritance
  needs none. The UMEM is a memfd; consumers mmap it from the
  received fd.

### Why each privilege, and what can be dropped

| Privilege | Needed for | Droppable? |
|---|---|---|
| `CAP_BPF` | XDP program + map load | Native: no (kernel requires it even with a 6.8+ BPF token, which only delegates the `CAP_SYS_ADMIN`/`CAP_NET_ADMIN` *aspects* of BPF commands). **bpfman backend: yes** — bpfman does the loading |
| `CAP_NET_ADMIN` | XDP attach (per netns) | Native: no (BPF tokens do not cover link attach). bpfman backend: yes for loading, attach is bpfman's |
| `CAP_SYS_RESOURCE` | MEMLOCK for BPF maps, kernels < 5.11 | **Dropped** — all supported kernels (>= 5.11) memcg-account BPF memory |
| root (uid 0) | Kubelet plugin registration socket and CDI dir are root-owned; a non-root driver cannot write to kubelet's `plugins_registry` | Only by chowning kubelet's directories from an init container — more invasive than root with two capabilities. If your cluster runs bpfman, the driver still needs the socket, so root stays |

The practical privilege floor for the native backend is
`CAP_BPF` + `CAP_NET_ADMIN` + root-for-directories. For a
locked-down cluster, the **bpfman backend** is the answer: bpfman
holds the BPF and network privileges ("the daemon has the elevated
privileges so the applications don't need to be" — the eBPF Manager
design), leaving the driver with only the socket/CDI directory
needs. On kernel 6.8+, cilium/ebpf also transparently uses BPF
tokens from delegated bpffs mounts where available.

## Verification

- The XDP filter program is PREVAIL-verified at the bytecode level
  (kernel-independent) and structurally checked in CI
- The graph validation gate is pure and deterministic
- The data path has an end-to-end test: matching EtherType frames
  arrive in the UMEM byte-for-byte; non-matching frames do not leak

## Development

```sh
go build ./... && go test ./...

# Privileged data-path tests (need CAP_BPF/CAP_NET_ADMIN + veth):
sudo -E go test ./pkg/backend/native/ -run TestBackendEndToEnd -v

# BPF regeneration (developer machine, needs clang + libbpf headers):
go generate ./pkg/backend/native/
```

[xgl_check]: https://github.com/fabiendupont/xdp-graph-lib
[cilium/ebpf]: https://github.com/cilium/ebpf
