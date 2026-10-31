---
title: Get started
description: Choose an OuterSpace OS profile, prepare a CPU VM and connect it to your Kubernetes cluster.
---
# Try OuterSpace OS

Start with a disposable CPU virtual machine in a self-managed Kubernetes cluster.
Choose **Agent** for small, bounded task containers or **Inference** for CPU model
serving. Read the [profile comparison](features.md) and [alpha limits](releases.md)
before preparing a worker.

## What you need

- A UEFI VM matching your image architecture, with **4 vCPUs and 4 GiB RAM** and
  **Secure Boot disabled**. This is the reference setup, not a model-sizing guide.
- A separate **Kubernetes 1.36** control plane reachable from the worker, with
  TLS bootstrap and certificate rotation enabled.
- **Cilium 1.20.3**, deployed using the supplied
  [cluster configuration](https://github.com/Alien6-Studio/outerspace-os/tree/v0.1.0-alpha.1/src/cluster/cilium).
  Use a dedicated evaluation cluster; do not replace an existing cluster's CNI
  using these instructions.
- The control plane CA, a dedicated short-lived bootstrap token and your
  cluster DNS address.

The worker image does not create the control plane. Application containers,
serving engines and model weights are deployed separately.

## Prepare an image

**0.1.0-alpha.1 is currently a draft release.** Public downloads will appear on
[GitHub Releases](https://github.com/Alien6-Studio/outerspace-os/releases) when
published. You can build the tagged source now.

Install Python 3.11+, Make and Docker running Linux containers. The build uses
Docker's native architecture: ARM64 on Apple Silicon, AMD64 on x86 hosts. Allow
disk space for the image, source archives and reusable download caches.

```sh
git clone https://github.com/Alien6-Studio/outerspace-os.git
cd outerspace-os
git checkout v0.1.0-alpha.1
make PROFILE=agent HARDWARE=cpu builder build smoke package
# Use PROFILE=inference for a model-serving worker.
```

Images and bundles are written under `out/<profile>-cpu-<architecture>/`.
The command also boots the image to check that it starts successfully. See the
[build guide](https://github.com/Alien6-Studio/outerspace-os/blob/v0.1.0-alpha.1/build/README.md)
for output files and options.

### Verify a release bundle

When downloads are available, choose the archive matching your profile and
architecture. Download its `.sha256` and `.tar.attestation.jsonl` companions,
plus `verify-attestation.py` and its checksum. Check the archive and helper
checksums, then extract the archive into a new directory.

With Python 3.11+ and the GitHub CLI installed, authenticate the bundle's inner
`SHA256SUMS` inventory using the supplied helper. Replace the two paths below;
the expected source, tag and build run are fixed for this alpha:

```sh
python3 verify-attestation.py \
  --checksums /path/to/extracted/SHA256SUMS \
  --bundle /path/to/archive.tar.attestation.jsonl \
  --commit a1df243a099e8ab74ba2c1706a0fa719d681c689 \
  --tag v0.1.0-alpha.1 \
  --run 41219970340
```

Inside the extracted bundle, run `sha256sum -c SHA256SUMS` before decompressing
or using the raw disk. On macOS, use `shasum -a 256 -c SHA256SUMS`. The attestation
authenticates the inventory; it does not enable Secure Boot.

## Connect the worker to your cluster

From the matching source checkout, generate a config drive with your cluster's
values. Store the bootstrap token in a protected file:

```sh
python3 build/tools/node-config.py \
  --api-server https://api.example.net:6443 \
  --ca /secure/cluster-ca.crt \
  --token-file /secure/bootstrap-token \
  --cluster-dns 10.96.0.10
make config-drive
```

Use the raw OS image as the VM's boot disk and attach `out/node-config.raw` as a
second disk. Boot through UEFI with Secure Boot disabled. Check the worker from
your evaluation cluster's Kubernetes context:

```sh
kubectl get nodes -o wide
```

The control plane must have an explicit approval policy for serving-certificate
requests. Once the node has enrolled, detach the config drive and revoke the
bootstrap token. The drive contains credentials: keep it private. The worker
retains its rotated identity in persistent state and can boot without the drive.

Manage workloads through Kubernetes. The image has locked local accounts and
no SSH server or shared password.

## Deploy your workload

For **Agent**, apply the supplied execution profile, label the intended worker
and adapt the example task container using the
[Agent setup instructions](https://github.com/Alien6-Studio/outerspace-os/blob/v0.1.0-alpha.1/src/cluster/README.md#native-oci-agent-v1-profile).
Network access is denied by default; allow only the flows your task needs.

For **Inference**, deploy your CPU serving container and model weights through
Kubernetes, selecting the OuterSpace worker and setting suitable resource
requests and limits. Keep important model and application data externally.

See the [worker configuration reference](https://github.com/Alien6-Studio/outerspace-os/blob/v0.1.0-alpha.1/src/cluster/README.md)
for cluster integration details. If enrollment or a workload fails, report the
version, profile, architecture and reproduction steps in an
[issue](https://github.com/Alien6-Studio/outerspace-os/issues), without credentials.
