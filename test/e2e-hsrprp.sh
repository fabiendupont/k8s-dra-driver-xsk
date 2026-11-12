#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# test/e2e-hsrprp.sh — HSR/PRP RedBox stream e2e test on kind.
#
# Creates its own cluster unless one with the same name already
# exists (then reuses it — idempotent re-runs are fast).
#
# Topology (all on the worker node):
#
#   netns "ringpeer"                     node netns (driver, hostNetwork)
#   ┌──────────────────┐                 ┌──────────────────────────────┐
#   │  ring0pa ─────────┼── veth pair ───┼─ ring0a (XDP redbox_root)    │
#   │  ring0pb ─────────┼── veth pair ───┼─ ring0b (XDP redbox_root)    │
#   └──────────────────┘                 │        │ dedup + tag strip   │
#        hsrbox send-dup / sniff         │        ▼                     │
#                                        │  xskh-XXXXXn (pod XSK)      │
#                                        └──────────────────────────────┘
#
# Verifies:
#   1. Stream devices published (pool <node>-hsrprp)
#   2. Claim -> NodePrepareResources -> CDI injection
#   3. RX: duplicate HSR frames on both ring ports -> exactly one
#      untagged copy per sequence number in the pod's XSK
#   4. Ring break: frames on port A only -> still delivered
#   5. TX: pod XSK frames -> HSR-tagged clones on both ring port
#      far ends with distinct path fields
#
# The BPF objects under test come from the xdp-hsr-prp revision
# baked into the image (Dockerfile HSRPRP_REF build arg — override
# with HSRPRP_REF=... to test a specific commit).
#
# Requirements: docker, kind, kubectl, a Docker daemon (CI needs a
# privileged runner).
#
# Usage: test/e2e-hsrprp.sh [cluster-name]     (default: xsk-e2e)

set -euo pipefail

CLUSTER="${1:-xsk-e2e}"
IMAGE="quay.io/fabiendupont/dra-xsk-driver:e2e"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NODE="${CLUSTER}-worker"

cd "$REPO_ROOT"
K="kubectl --context kind-$CLUSTER"
D="docker exec -i $NODE"

fail() { echo "FAIL: $*" >&2; exit 1; }

echo "=== building driver image (with xdp-hsr-prp objects + hsrbox)"
docker build ${HSRPRP_REF:+--build-arg HSRPRP_REF=$HSRPRP_REF} \
    ${HSRPRP_REPO:+--build-arg HSRPRP_REPO=$HSRPRP_REPO} \
    -q -t "$IMAGE" "$REPO_ROOT" >/dev/null

if ! kind get clusters 2>/dev/null | grep -q "^$CLUSTER$"; then
    echo "=== creating kind cluster $CLUSTER"
    kind create cluster --name "$CLUSTER" --image kindest/node:v1.34.0 \
        --config "$REPO_ROOT/test/e2e/kind-config.yaml"
    kind load docker-image "$IMAGE" --name "$CLUSTER"
    $K wait --for=condition=ready node --all --timeout=120s
    # Label the worker so the DaemonSet schedules; add the dev-only
    # --include-virtual flag (kind nodes expose only veths).
    $K label --overwrite node "$NODE" xsk.dra.io/capable=true
    $K apply -f "$REPO_ROOT/deployments/rbac.yaml"
    $K apply -f "$REPO_ROOT/deployments/device-class.yaml"
    $K apply -f "$REPO_ROOT/deployments/daemonset.yaml"
    $K -n kube-system set image daemonset/dra-xsk-driver driver="$IMAGE"
    # Same kind-sandbox caveats as test/e2e/run.sh: capabilities.add
    # is ignored by this containerd, and :latest defaults to Always.
    $K -n kube-system patch daemonset dra-xsk-driver --type=json -p='[
      {"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"IfNotPresent"},
      {"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--include-virtual"},
      {"op":"add","path":"/spec/template/spec/containers/0/securityContext/privileged","value":true},
      {"op":"replace","path":"/spec/template/spec/containers/0/securityContext/allowPrivilegeEscalation","value":true}
    ]'
else
    echo "=== reusing kind cluster $CLUSTER"
    kind load docker-image "$IMAGE" --name "$CLUSTER"
fi

echo "=== wiring ring ports on $NODE"
$D sh -c '
  ip netns del ringpeer 2>/dev/null || true
  ip link del ring0a 2>/dev/null || true
  ip netns add ringpeer
  ip link add ring0a type veth peer name ring0pa
  ip link add ring0b type veth peer name ring0pb
  ip link set ring0pa netns ringpeer
  ip link set ring0pb netns ringpeer
  ip link set ring0a up
  ip link set ring0b up
  ip netns exec ringpeer ip link set ring0pa up
  ip netns exec ringpeer ip link set ring0pb up
  ip netns exec ringpeer ip link set lo up
'
# hsrbox for send-dup/sniff (runs on the node, inside ringpeer).
# Static build; the kind node is glibc but the binary is static.
CGO_ENABLED=0 go build -trimpath -o /tmp/opencode/hsrbox ./cmd/hsrbox
docker cp /tmp/opencode/hsrbox "$NODE":/usr/bin/hsrbox

echo "=== deploying HSR/PRP config, device class, driver update"
$K apply -f "$REPO_ROOT/deployments/hsrprp-configmap.yaml"
$K apply -f "$REPO_ROOT/deployments/device-class-hsrprp.yaml"
# Mount the config + enable the flag on the DaemonSet (idempotent).
if ! $K -n kube-system get daemonset dra-xsk-driver \
    -o jsonpath='{.spec.template.spec.volumes[*].name}' | grep -q hsrprp-config; then
  $K -n kube-system patch daemonset dra-xsk-driver --type=json -p='[
    {"op":"add","path":"/spec/template/spec/volumes/-","value":{
       "name":"hsrprp-config","configMap":{"name":"dra-xsk-hsrprp"}}},
    {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{
       "name":"hsrprp-config","mountPath":"/etc/xsk-dra"}}
  ]'
fi
if ! $K -n kube-system get daemonset dra-xsk-driver \
    -o jsonpath='{.spec.template.spec.containers[0].args}' | grep -q hsrprp-config; then
  $K -n kube-system patch daemonset dra-xsk-driver --type=json \
    -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--hsrprp-config=/etc/xsk-dra/hsrprp.yaml"}]'
fi
$K -n kube-system set image daemonset/dra-xsk-driver driver="$IMAGE"
# The image tag never changes between runs; force the rollout so a
# rebuilt image actually deploys.
$K -n kube-system rollout restart daemonset/dra-xsk-driver
$K -n kube-system rollout status daemonset/dra-xsk-driver --timeout=180s

# Workaround: the kubelet's plugin watcher sometimes fails to pick up
# the re-created registration socket after a driver pod restart. If
# the driver is not registered within 60s, restart the kubelet once
# (its startup re-scan always registers; the driver re-publishes its
# ResourceSlices on registration, so that path is safe).
if ! timeout 60 bash -c "until $K -n kube-system logs ds/dra-xsk-driver 2>/dev/null | grep -q 'registered with kubelet successfully'; do sleep 5; done"; then
    echo "    driver not registered after 60s; restarting kubelet (known kind flake)"
    $D systemctl restart kubelet
    timeout 90 bash -c "until $K -n kube-system logs ds/dra-xsk-driver 2>/dev/null | grep -q 'registered with kubelet successfully'; do sleep 5; done" \
        || fail "driver never registered with the kubelet"
fi

echo "=== checking stream devices"
STREAMS=$($K get resourceslices -o json \
  | python3 -c '
import json,sys
for sl in json.load(sys.stdin)["items"]:
    if sl["spec"]["pool"]["name"].endswith("-hsrprp"):
        for d in sl["spec"]["devices"]:
            print(d["name"], end=" ")
')
echo "    stream devices: $STREAMS"
echo "$STREAMS" | grep -q "ring1-88b8" || fail "ring1-88b8 stream device not published"

echo "=== creating stream claim"
$K apply -f "$REPO_ROOT/deployments/examples/claim-hsrprp-stream.yaml"

# Handoff socket path is deterministic: the stream veth is
# "xskh-" + first 5 hex chars of the claim UID (dashes stripped)
# + "n" (pkg/hsrprp trimUID), and the backend names sockets
# "<ifname>-q<queue>.sock".
CLAIM_UID=$($K get resourceclaim hsr-goose-stream -o jsonpath='{.metadata.uid}')
VETH="xskh-$(echo "$CLAIM_UID" | tr -d '-' | cut -c1-5)n"
SOCK="$VETH-q0.sock"
echo "    claim $CLAIM_UID -> veth $VETH, socket /run/xsk/$SOCK"

# Consumer pods run hsrbox directly (the driver image is distroless —
# no shell). One pod per test; each exits when its traffic phase
# completes, so "Succeeded" is the pass signal.
consumer_pod() { # name json-args
  local name=$1 args=$2
  $K delete pod "$name" --ignore-not-found >/dev/null 2>&1
  $K apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $name
spec:
  restartPolicy: Never
  containers:
    - name: consumer
      image: $IMAGE
      command: ["/usr/bin/hsrbox"]
      args: $args
      securityContext:
        runAsUser: 0
        capabilities:
          add: ["NET_RAW"]
      resources:
        claims:
          - name: stream
  resourceClaims:
    - name: stream
      resourceClaimName: hsr-goose-stream
EOF
  # Fast-exiting commands (tx) may reach Succeeded before Ready is
  # ever observed — accept that.
  $K wait --for=condition=ready "pod/$name" --timeout=120s || {
    phase=$($K get pod "$name" -o jsonpath='{.status.phase}')
    if [ "$phase" != "Succeeded" ]; then
      $K describe pod "$name"; fail "consumer pod $name not ready (phase: $phase)"
    fi
  }
}

wait_pod_done() { # name timeout
  $K wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$1" --timeout="$2" \
    || { $K logs "$1" 2>/dev/null || true; $K describe pod "$1" | tail -8; fail "pod $1 did not succeed"; }
  $K logs "$1"
}

echo "=== RX: 10 duplicate pairs -> 10 unique frames in the pod XSK"
consumer_pod hsr-rx1 "[\"rx\",\"--socket\",\"/run/xsk/$SOCK\",\"--count\",\"10\",\"--timeout\",\"30s\"]"
sleep 3
$D ip netns exec ringpeer /usr/bin/hsrbox send-dup \
  --a ring0pa --b ring0pb --count 10 --ethertype 0x88B8
wait_pod_done hsr-rx1 90s

echo "=== RX: ring break (port A only) -> still delivered"
consumer_pod hsr-rx2 "[\"rx\",\"--socket\",\"/run/xsk/$SOCK\",\"--count\",\"5\",\"--timeout\",\"30s\"]"
sleep 3
$D ip netns exec ringpeer /usr/bin/hsrbox send-dup \
  --a ring0pa --b ring0pb --count 5 --seq-start 100 --only-a
wait_pod_done hsr-rx2 90s

echo "=== TX: 5 pod frames -> tagged clones on both ring far ends"
($D ip netns exec ringpeer /usr/bin/hsrbox sniff \
   --iface ring0pa --count 5 --timeout 30s > /tmp/opencode/txa.json) &
PA=$!
($D ip netns exec ringpeer /usr/bin/hsrbox sniff \
   --iface ring0pb --count 5 --timeout 30s > /tmp/opencode/txb.json) &
PB=$!
sleep 3
consumer_pod hsr-tx "[\"tx\",\"--socket\",\"/run/xsk/$SOCK\",\"--count\",\"5\",\"--ethertype\",\"0x88B8\",\"--gap\",\"150ms\"]"
wait_pod_done hsr-tx 90s
wait $PA || fail "no tagged TX frames on ring0pa (see /tmp/opencode/txa.json)"
wait $PB || fail "no tagged TX frames on ring0pb (see /tmp/opencode/txb.json)"
echo "    A: $(cat /tmp/opencode/txa.json)"
echo "    B: $(cat /tmp/opencode/txb.json)"

# Path fields must differ (original on A, clone patched on B)
PA_N=$(python3 -c "import json;print(json.load(open('/tmp/opencode/txa.json'))['path_a'])")
PB_N=$(python3 -c "import json;print(json.load(open('/tmp/opencode/txb.json'))['path_b'])")
[ "$PA_N" -ge 1 ] || fail "port A saw no path-A frames"
[ "$PB_N" -ge 1 ] || fail "port B saw no path-B frames"

# Path fields must differ (original on A, clone patched on B)
PA_N=$(python3 -c "import json;print(json.load(open('/tmp/opencode/txa.json'))['path_a'])")
PB_N=$(python3 -c "import json;print(json.load(open('/tmp/opencode/txb.json'))['path_b'])")
[ "$PA_N" -ge 1 ] || fail "port A saw no path-A frames"
[ "$PB_N" -ge 1 ] || fail "port B saw no path-B frames"

echo ""
echo "PASS: HSR/PRP RedBox stream works end to end —"
echo "     deduplicated delivery (including ring break) and TX clone/tag."
