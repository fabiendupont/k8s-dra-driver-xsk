# k8s-dra-driver-xsk

Helm chart for the XSK DRA driver: AF_XDP sockets (and HSR/PRP
redundant streams, IEC 62439-3) for pods via Kubernetes Dynamic
Resource Allocation.

## Install

```sh
helm upgrade --install dra-xsk-driver ./chart/k8s-dra-driver-xsk -n kube-system
```

Label XDP-capable nodes first (`nodeSelector` default):

```sh
kubectl label node <node> xsk.dra.io/capable=true
```

Claims use the `xsk` (generic EtherType filters), `xsk-iec61850`
(GOOSE+SV preset) or `hsr-prp-stream` (deduplicated redundant
streams) device classes — see `deployments/examples/`.

## Values

See `values.yaml` for the full list and comments. The notable ones:

| Value | Default | Purpose |
|---|---|---|
| `backend` | `native` | `native` (in-process XDP, needs CAP_BPF/CAP_NET_ADMIN) or `bpfman` (delegates to the bpfman operator via CRDs + CSI) |
| `hsrprp.enabled` | `false` | RedBox stream pool; groups configured under `hsrprp.groups` |
| `includeVirtual` | `false` | Dev only: veth queue discovery (kind) |
| `securityContext.privileged` | `false` | Dev only: kind's containerd ignores capabilities.add |

## Notes

- Resource and device-class names are fixed (not release-prefixed):
  claims, docs and tooling reference them directly.
- The `driverName` (`xsk.dra.io`) is baked into claim CEL selectors
  and the kubelet plugin socket path; changing it means updating
  claims too.
- `appVersion` tracks the driver release and is the default image
  tag; CI builds override it with `--set image.tag`.
