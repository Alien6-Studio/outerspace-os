#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Run inside the untrusted workload; no host mount, token or elevated capability.
set -eu
fail() { echo "OUTERSPACE_AGENT_FAIL: $*" >&2; exit 1; }
test "$(id -u)" = 65534 || fail 'wrong uid'
test "$(id -g)" = 65534 || fail 'wrong gid'
test "$(cat /proc/self/attr/current)" = 'outerspace-agent-v1 (enforce)' || fail 'AppArmor not enforcing'
grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status || fail 'privilege escalation permitted'
grep -Eq '^Seccomp:[[:space:]]+2$' /proc/self/status || fail 'seccomp filter absent'
awk '$2 == "/" && ("," $4 ",") ~ /,ro,/ {found=1} END {exit !found}' /proc/mounts || fail 'root mount not read-only'
for field in CapInh CapPrm CapEff CapBnd CapAmb; do
    grep -Eq "^$field:[[:space:]]+0+$" /proc/self/status || fail "capability present: $field"
done
test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token || fail 'service account token exposed'
for path in /host /var/lib/kubelet/pki /run/containerd/containerd.sock /var/run/docker.sock /dev/kvm /dev/nvidia0; do
    test ! -e "$path" || fail "host authority exposed: $path"
done
printf 'agent-workspace-ok\n' > /workspace/result
printf 'agent-scratch-ok\n' > /scratch/result
grep -qx agent-workspace-ok /workspace/result || fail 'workspace not usable'
if touch /etc/outerspace-agent-write-test 2>/scratch/root-error; then fail 'root filesystem writable'; fi
test -f /dev/termination-log || fail 'termination log mount absent'
if sh -c ': > /dev/termination-log' 2>/scratch/termination-error; then fail 'host termination log writable'; fi
grep -q 'Permission denied' /scratch/termination-error || fail 'termination log denial was not a permission failure'
if cat /proc/sys/kernel/random/boot_id >/scratch/host-id 2>/scratch/lsm-error; then
    fail 'host identity readable through proc'
fi
grep -q 'Permission denied' /scratch/lsm-error || fail 'LSM denial was not a permission failure'
if sh -c 'printf unconfined > /proc/self/attr/exec' 2>/scratch/policy-error; then
    fail 'workload can change its confinement'
fi
if unshare -Ur id -u >/scratch/unshare-output 2>/scratch/unshare-error; then
    fail 'user namespace escalation succeeded'
fi
grep -Eq 'Operation not permitted|Permission denied' /scratch/unshare-error || fail 'unshare refusal was not a permission failure'
if setuidgid 0 id -u >/scratch/setuid-output 2>/scratch/setuid-error; then
    fail 'uid escalation succeeded'
fi
grep -Eq 'Operation not permitted|Permission denied' /scratch/setuid-error || fail 'uid refusal was not a permission failure'
mkdir -p /scratch/mount-refusal
if mount -t tmpfs tmpfs /scratch/mount-refusal 2>/scratch/mount-error; then fail 'mount succeeded'; fi
grep -Eq '[Pp]ermission denied|Operation not permitted|must be root|must be superuser' /scratch/mount-error || fail 'mount refusal was not a permission failure'
if mknod /workspace/forbidden-device c 1 3 2>/scratch/device-error; then fail 'device creation succeeded'; fi
grep -Eq '[Pp]ermission denied|Operation not permitted' /scratch/device-error || fail 'device refusal was not a permission failure'
# The child must inherit the same LSM boundary.
sh -c 'test "$(cat /proc/self/attr/current)" = "outerspace-agent-v1 (enforce)"' || fail 'child escaped AppArmor'
echo '{"status":"passed","uid":65534,"gid":65534,"apparmor":"outerspace-agent-v1 (enforce)","seccomp":2,"no_new_privileges":true,"read_only_root":true,"capabilities":"none","workspace":"passed","host_access":"denied","privilege_escalation":"denied","mounts":"denied","device_creation":"denied","policy_change":"denied","termination_log_write":"denied","child_confinement":"passed"}'
