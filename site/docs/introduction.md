---
title: Introduction
description: What OuterSpace OS builds, who it is for, and what the development image supports today.
---
# A Linux host with one mission

OuterSpace OS is an Ubuntu-based operating system for Kubernetes inference workers,
installed on bare metal or tested in virtual machines. A small host supplies Linux,
systemd, containerd and kubelet. Inference engines, model frameworks and user-space
accelerator libraries belong in containers.

!!! warning "Development — 0.1.0-dev.0"
    There is no stable release, supported production image or CIS certification.
    The source and tests are available; hardware qualification, secure updates and
    security audit evidence are still required.

The first foundation uses Ubuntu 24.04 LTS, a generic server kernel, a read-only
root protected by dm-verity, and a writable `/var` for runtime state. Native
Dragonfly integration provides optional P2P image delivery. Cilium supplies the
cluster networking and policy profile.

## Where it fits

- Physical inference workers in self-managed Kubernetes / kubeadm clusters.
- Virtual machines for image qualification and self-managed cloud clusters.
- Local Docker/kind tests for cluster integration, separately from OS image tests.

Managed AKS node pools require provider-supported OS images. OuterSpace cannot
replace their base OS. On Azure, test this OS on VMs running a self-managed cluster;
AKS can separately test portable workloads and supported cluster components.

Start with the [build guide](getting-started.md), [architecture](architecture.md),
and [release policy](releases.md).
