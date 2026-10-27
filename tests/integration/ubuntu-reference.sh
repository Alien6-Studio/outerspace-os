#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Test fixture only. Invoked by NoCloud inside a disposable official Ubuntu VM.
set -euo pipefail
umask 077
seed=/mnt/reference
. /usr/lib/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]]
[[ $(uname -r) == 6.8.0-147-generic ]]
export DEBIAN_FRONTEND=noninteractive
# No upgrade or substitute runtime: a version mismatch must fail the comparison.
apt-get update
apt-get install -y --no-install-recommends runc=1.3.4-0ubuntu1~24.04.1 \
    linux-modules-extra-6.8.0-147-generic=6.8.0-147.147 conntrack ethtool
architecture=$(dpkg --print-architecture)
[[ "$architecture" != amd64 ]] || architecture=x86-64
python3 "$seed/install-components.py" / "$architecture" "$seed/components.lock.json" "$seed/cache"
install -d /var/lib/outerspace /var/lib/kubelet /etc/containerd /usr/lib/outerspace \
    /usr/share/outerspace/apparmor
cp "$seed/containerd.toml" /etc/containerd/config.toml
cp "$seed/agent-v1" /usr/share/outerspace/apparmor/agent-v1
install -m 0755 "$seed/agent-io" /usr/lib/outerspace/agent-io
# Same I/O class, on the reference's unstacked root disk (which contains /var).
# Retain Ubuntu's writable root and stock OS identity; record the layout difference.
state=$(readlink -f "$(findmnt -nro SOURCE --target /var)")
e2label "$state" OOS_STATE
# Relabeling an already discovered partition does not update udev's label links.
# The identical Agent I/O initializer requires the actual OOS_STATE device.
udevadm trigger --action=change "/sys/class/block/${state##*/}"
udevadm settle --timeout=30
[[ $(readlink -f /dev/disk/by-label/OOS_STATE) == "$state" ]]
# Dependency lists cannot be reset in systemd drop-ins. Materialize fixture
# units without the product's provisioning/P2P dependencies; keep ExecStart,
# delegation, limits and runtime configuration identical.
for service in containerd kubelet; do
    sed 's/ outerspace-provision.service//g; s/ dfdaemon.service//g' \
        "$seed/$service.service" > "/etc/systemd/system/$service.service"
done
sed -i '/^\[Service\]/a Environment=OUTERSPACE_PROFILE=agent' /etc/systemd/system/containerd.service
cp "$seed/outerspace-agent-profile.service" /etc/systemd/system/
cp "$seed/90-outerspace.conf" /etc/sysctl.d/
cp "$seed/modules.conf" /etc/modules-load.d/reference.conf
while read -r module; do [[ -z "$module" || "$module" == \#* ]] || modprobe "$module"; done < "$seed/modules.conf"
sysctl --system
cat > /etc/crictl.yaml <<'EOF'
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 10
EOF
mkdir -p /mnt/node-config
mount -o ro,nosuid,nodev,noexec /dev/disk/by-label/OOS_CONFIG /mnt/node-config
install -m 0600 /mnt/node-config/cluster-ca.crt /mnt/node-config/kubelet.yaml /var/lib/outerspace/
install -m 0600 /mnt/node-config/bootstrap-kubeconfig /var/lib/kubelet/
umount /mnt/node-config
# The configured worker uses the identical CNI paths and Agent policy.
mkdir -p /var/lib/cni /var/lib/outerspace/cni/net.d
mkdir -p /opt /etc/cni
ln -s /var/lib/cni /opt/cni
ln -s /var/lib/outerspace/cni/net.d /etc/cni/net.d
swapoff -a
# Bound automatic apt activity during measurement; do not remove stock services.
systemctl stop apt-daily.timer apt-daily-upgrade.timer
systemctl disable apt-daily.timer apt-daily-upgrade.timer
dpkg-query -W -f='${Package}\t${Version}\n' > /var/lib/outerspace/reference-packages.tsv
systemctl daemon-reload
systemctl enable --now outerspace-agent-profile containerd kubelet
echo OUTERSPACE_UBUNTU_REFERENCE_CONFIGURED
