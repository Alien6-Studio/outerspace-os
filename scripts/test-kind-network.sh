#!/bin/bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
lab_kubeconfig=${1:?Pass the isolated outerspace-lab kubeconfig explicitly}
kube=(kubectl --kubeconfig "$lab_kubeconfig" -n outerspace-verification)
kubectl --kubeconfig "$lab_kubeconfig" apply -f "$repo/tests/integration/network.yaml"
"${kube[@]}" label pod client access=allowed --overwrite
"${kube[@]}" wait --for=condition=Ready pod/echo pod/client --timeout=180s
url=http://echo.outerspace-verification.svc.cluster.local:8080
ready=false
for attempt in {1..60}; do
    if "${kube[@]}" exec client -- wget -T 2 -qO- "$url" 2>/dev/null | grep -qx outerspace-network-ok; then
        ready=true
        break
    fi
    sleep 1
done
[[ "$ready" == true ]] || { echo 'Initial cross-node service route failed' >&2; exit 1; }
"${kube[@]}" label pod client access=denied --overwrite
# Wait for the selector update to be realized, polling traffic rather than sleeping.
denied=false
for attempt in {1..60}; do
    if ! "${kube[@]}" exec client -- wget -T 2 -qO- "$url" >/dev/null 2>&1; then
        denied=true
        break
    fi
    sleep 1
done
[[ "$denied" == true ]] || { echo 'Network policy failed to deny traffic' >&2; exit 1; }
"${kube[@]}" label pod client access=allowed --overwrite
allowed=false
for attempt in {1..60}; do
    if "${kube[@]}" exec client -- wget -T 2 -qO- "$url" 2>/dev/null | grep -qx outerspace-network-ok; then
        allowed=true
        break
    fi
    sleep 1
done
[[ "$allowed" == true ]] || { echo 'Network policy failed to restore traffic' >&2; exit 1; }
echo 'OUTERSPACE_CILIUM_NETWORK_OK: cross-node DNS/service routing, deny, restore'
