#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# test/e2e/run.sh — end-to-end test on a kind cluster.
#
# Validates the full DRA chain: device discovery (veths via
# --include-virtual), ResourceSlice publication, claim scheduling,
# NodePrepareResources (XDP attach + XSK creation + handoff socket),
# and CDI injection into the consuming pod (XSK_* env vars and the
# handoff directory mount).
#
# Prerequisites: docker, kind, kubectl. Kubernetes >= 1.34 (DRA v1).
#
# Usage: test/e2e/run.sh [cluster-name]     (default: xsk-e2e)

set -euo pipefail

CLUSTER="${1:-xsk-e2e}"
IMAGE="quay.io/fabiendupont/dra-xsk-driver:e2e"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "=== building driver image"
docker build -q -t "$IMAGE" "$REPO_ROOT" >/dev/null

echo "=== creating kind cluster $CLUSTER"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --image kindest/node:v1.34.0 \
    --config "$REPO_ROOT/test/e2e/kind-config.yaml"
kind load docker-image "$IMAGE" --name "$CLUSTER"

K="kubectl --context kind-$CLUSTER"

echo "=== waiting for node ready"
$K wait --for=condition=ready node --all --timeout=120s

# Label the (single) worker so the DaemonSet schedules; add the
# dev-only --include-virtual flag (kind nodes expose only veths).
$K label --overwrite node "$CLUSTER-worker" xsk.dra.io/capable=true

echo "=== deploying driver (Helm chart)"
# kind values: include-virtual (kind nodes expose only veths) and
# privileged (this sandbox's containerd ignores capabilities.add, so
# the minimal-capability securityContext cannot take effect there;
# on normal clusters the CAP_BPF/CAP_NET_ADMIN list is correct).
# No HSR/PRP groups here — run.sh has no ring ports wired.
helm upgrade --install dra-xsk-driver "$REPO_ROOT/chart/k8s-dra-driver-xsk" \
    -n kube-system --kube-context "kind-$CLUSTER" \
    -f "$REPO_ROOT/test/e2e/values-kind.yaml" \
    --set hsrprp.enabled=false \
    --set image.tag=e2e --wait --timeout 120s

echo "=== checking ResourceSlice publication"
$K wait --for=jsonpath='{.status.deviceCount}'=0 resource_slice --all \
    --timeout=1s 2>/dev/null || true # just checking existence below
if ! $K get resourceslices -o name | grep -q .; then
    fail "no ResourceSlices published"
fi
DEVICES=$($K get resourceslices -o jsonpath='{range .items[*]}{.spec.devices[*].name}{" "}{end}')
echo "    devices: $DEVICES"
[ -n "$DEVICES" ] || fail "no devices in ResourceSlice"

echo "=== creating claim and pod"
$K apply -f - <<EOF
apiVersion: resource.k8s.io/v1
kind: ResourceClaim
metadata:
  name: xsk-e2e
spec:
  devices:
    requests:
      - name: queue
        exactly:
          deviceClassName: xsk
          selectors:
            - cel:
                expression: "device.driver == \"xsk.dra.io\""
    config:
      - requests: ["queue"]
        opaque:
          driver: xsk.dra.io
          parameters:
            apiVersion: xsk.dra.io/v1alpha1
            kind: XSKParameters
            ethertypes: ["0x88B8"]
---
apiVersion: v1
kind: Pod
metadata:
  name: xsk-e2e-consumer
spec:
  restartPolicy: Never
  containers:
    - name: consumer
      image: busybox:1.36
      command: ["sh", "-c", "env | grep ^XSK_ | sort; ls -la /run/xsk/; sleep 300"]
      resources:
        claims:
          - name: xsk
  resourceClaims:
    - name: xsk
      resourceClaimName: xsk-e2e
EOF

echo "=== waiting for pod"
$K wait --for=condition=ready pod/xsk-e2e-consumer --timeout=180s \
    || { $K describe pod xsk-e2e-consumer; fail "pod not ready"; }

echo "=== verifying CDI injection"
ENV_OUT=$($K exec xsk-e2e-consumer -- env)
echo "$ENV_OUT" | grep -q "XSK_SOCKET=/run/xsk/" || fail "XSK_SOCKET not injected"
echo "$ENV_OUT" | grep -q "XSK_IFACE=" || fail "XSK_IFACE not injected"
echo "$ENV_OUT" | grep -q "XSK_QUEUE=" || fail "XSK_QUEUE not injected"
echo "$ENV_OUT" | grep -q "XSK_ETHTYPES=0x88b8" || fail "XSK_ETHTYPES not injected"

MOUNTS=$($K exec xsk-e2e-consumer -- cat /proc/mounts)
echo "$MOUNTS" | grep -q "/run/xsk" || fail "handoff dir not mounted"

SOCK=$($K exec xsk-e2e-consumer -- sh -c 'ls /run/xsk/ | head -1')
[ -n "$SOCK" ] || fail "no handoff socket in /run/xsk"
echo "    handoff socket: $SOCK"

echo ""
echo "PASS: full DRA chain works — discovery, slice, claim, prepare, CDI injection"
echo "     (cluster $CLUSTER left running for inspection; delete with:"
echo "      kind delete cluster --name $CLUSTER)"
