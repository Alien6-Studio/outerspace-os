---
title: Introduction
description: The qualified Agent and Inference CPU profiles of OuterSpace OS and the scope of the first alpha.
---
# One OS, two worker profiles

OuterSpace OS is an Ubuntu-based Linux distribution for Kubernetes workers.
The shared Core supplies the kernel, systemd, containerd, kubelet and immutable
node identity. Agent frameworks, inference engines, models and their language
libraries run in separately deployed containers.

**Version 0.1.0-alpha.1 is qualified for CPU evaluation and prepared as a draft.**
The first milestone, [Execution foundation](https://github.com/Alien6-Studio/outerspace-os/milestone/1),
is complete. Public downloads await publication of the draft; there is no stable
or supported production release.

## Qualified today

- **Agent:** native OCI admission and isolation, enforced resource limits, pressure
  scenarios and recovery after worker restart.
- **Inference:** real CPU model serving, workload replacement and drain/recovery.
- **Both:** separate AMD64 and ARM64 images, UEFI boot, Kubernetes/Cilium enrollment,
  certificate rotation and cold-boot recovery on the actual OuterSpace kernel.

The host combines Ubuntu 24.04 LTS packages with source-built Linux 6.18.60 and
pinned runtimes. A read-only dm-verity root is paired with persistent `/var`.
Dragonfly is an optional OCI delivery component; its fleet/P2P qualification is
still separate work.

## Evaluation scope

Use disposable UEFI VMs and a separate, self-managed Kubernetes control plane.
The native qualification used four vCPUs and 4 GiB RAM per worker. Bare-metal,
GPU, authenticated updates and production support have not been qualified.
Host VPNs and custom network configurations are outside the alpha's reviewed scope.

Start with [build and test](getting-started.md), [architecture](architecture.md)
and the [alpha release information](releases.md).
