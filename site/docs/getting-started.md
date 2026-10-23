---
title: Build and test
description: Build an OuterSpace OS development image from source using Python, Make, Docker and mkosi, then verify it with QEMU.
---
# Build a development image

Requirements: Python 3.11+, Make and Docker running Linux containers. The build
uses the Docker VM's native architecture: arm64 on Apple Silicon, amd64 on CI.
Allow several gigabytes for package caches and build output.

```sh
git clone https://github.com/Alien6-Studio/outerspace-os.git
cd outerspace-os
make check
make builder
make build
make smoke
```

The disposable builder uses privileged Linux mount namespaces. It has no host
devices or Docker socket mounted. QEMU verification needs no additional privileges.

The `build/` directory contains a raw GPT disk, UKI, split kernel/initrd, package
manifest and boot log. Development images are unsigned. Do not overwrite a physical
disk to try this first version; use the snapshot-based QEMU smoke test.

The smoke test checks read-only root, verity mapping, writable state, cgroup v2,
BPF/BTF availability, AppArmor, selected hardening settings, locked operator account
and CRI availability. It boots the split kernel/initrd, not the EFI boot path.

## Configure a worker

The repository includes a config-drive generator. It accepts a real cluster CA,
a short-lived bootstrap token read from a protected file, and an HTTPS API address.
It validates input and produces private files. No password is baked into the image.

```sh
python3 scripts/node-config.py \
  --api-server https://api.example.net:6443 \
  --ca /secure/cluster-ca.crt \
  --token-file /secure/bootstrap-token \
  --cluster-dns 10.96.0.10
./scripts/config-drive.sh
```

The generated drive contains credentials. Attach it only to the intended node,
detach after enrollment and revoke the token. Cluster enrollment on this image
is still a release gate. See the [repository guide](https://github.com/Alien6-Studio/outerspace-os#configure-a-worker).

## Operator identity

The image includes an `outerspace` account (UID 1000), locked by default. Root is
also locked; no SSH server, shared password, sudo or autologin is installed. An
explicit, audited administrative-access design is required before hardware rollout.
The ASCII boot banner identifies the distribution and development version.
