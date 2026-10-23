---
title: Architecture
description: Read-only Ubuntu host, persistent runtime state, containerd, Kubernetes, eBPF and peer-assisted image delivery.
---
# Architecture

```text
Inference pods: models · serving engines · user-space libraries
──────────────────────────────────────────────────────────────
Kubernetes: kubelet · CRI · Cilium networking and policy
──────────────────────────────────────────────────────────────
OuterSpace OS: Ubuntu kernel · systemd · containerd · Dragonfly
──────────────────────────────────────────────────────────────
Bare metal / virtual machine
```

## Image layout

| Partition | Purpose | Status |
| --- | --- | --- |
| EFI system partition | systemd-boot and unified kernel image | Unsigned development boot assets |
| OOS_ROOT | Read-only ext4 host filesystem | dm-verity data |
| OOS_VERITY | Root hash tree | Expected hash embedded in UKI |
| OOS_STATE | Persistent `/var` | Runtime images, kubelet identity, bounded logs |

A trusted root hash is necessary for authenticity. Development UKIs are unsigned;
Secure Boot signing is a release gate. The current image has one root slot.
Authenticated A/B updates, boot health checks and rollback are planned together.
There are no in-place `apt` upgrades on the running host.

## Runtime and networking

containerd uses overlayfs, systemd cgroups and the CRI API. Kubelet is configured
with anonymous authentication disabled, webhook authorization, TLS bootstrap,
certificate rotation and default seccomp. CNI binaries and configuration live in
persistent state through fixed paths in the read-only filesystem.

Cilium is the first eBPF integration. Its trusted agents need privileges; host
policy disables unprivileged BPF. Kernel BPF/BTF features are checked at build time.
A local three-node kind lab validates cross-node DNS/service connectivity and
network-policy deny/restore. That lab uses Docker's kernel and does not qualify
the OuterSpace OS kernel as a joined cluster node.

## Image and model delivery

Dragonfly is enabled by node configuration with explicit registry routing.
Containerd retains HTTPS origin resolution and digest verification. Each node
still stores the image content needed by its containers. P2P reduces repeated
traffic from origin; it does not make local storage unnecessary.

Kubelet owns unused image garbage collection (24h maximum age, 80%/65% pressure
thresholds). Its age tracking resets on kubelet restart. Dragonfly's peer cache
has a separate six-hour TTL. No external prune loop competes with kubelet.

Model weights are a separate lifecycle: an image being ready does not mean weights
are loaded into RAM or VRAM. Measure image delivery, model loading and inference
readiness independently. End-to-end P2P, private registry authorization and GPU
profiles remain qualification work.

The [source design](https://github.com/Alien6-Studio/outerspace-os/blob/main/design/architecture.md)
records detailed decisions and references.
