---
title: Architecture
description: Shared immutable Core, independently qualified Agent and Inference profiles, and separately deployed cluster workloads.
---
# Architecture

```text
Agent pods / inference pods: tools · models · serving engines
──────────────────────────────────────────────────────────────
Kubernetes: kubelet · CRI · Cilium networking and policy
──────────────────────────────────────────────────────────────
OuterSpace Core: Linux · systemd · containerd · optional Dragonfly
──────────────────────────────────────────────────────────────
Qualified CPU UEFI virtual machines: AMD64 / ARM64
```

The Agent and Inference profiles share one build and maintenance stream. Each
shipped image has its own manifest, source/image identity, SBOM and qualification
records. A passing result for one profile never promotes another image.
The Kubernetes control plane, Cilium and application workloads are deployed
separately from the host image.

## Image layout

| Partition | Purpose | Alpha status |
| --- | --- | --- |
| EFI system partition | systemd-boot and unified kernel image | UEFI boot qualified; Secure Boot disabled |
| OOS_ROOT | Read-only ext4 host filesystem | dm-verity data |
| OOS_VERITY | Root hash tree | Expected hash embedded in UKI |
| OOS_STATE | Persistent `/var` | Runtime images, rotated kubelet identity and bounded logs; unencrypted |

The current image has one root slot. dm-verity detects root-filesystem corruption;
it does not provide authenticated boot by itself. Signed boot, authenticated A/B
updates and rollback remain future qualification work. The running host does not
use in-place `apt` upgrades.

## Native execution and networking

containerd uses overlayfs, systemd cgroups and CRI. Kubelet has anonymous
authentication disabled, webhook authorization, TLS bootstrap and certificate
rotation. The actual CPU candidates have passed enrollment, Cilium/Envoy readiness,
DNS/service traffic, default-deny/allow checks and cold-boot recovery.

The Agent v1 profile combines native admission, AppArmor, seccomp and cgroup v2
limits. It qualifies a shared-kernel OCI workload within one trusted administrative
domain. Revocable workload authority, external approval brokers, fleet quarantine
and VM-backed tenant isolation remain distinct roadmap items.

Inference qualifies a separately pinned CPU serving workload. Model containers
and weights have their own provenance and licenses; they are not part of the OS
image's redistribution approval.

## OCI delivery and persistent state

Dragonfly is enabled through explicit node configuration. Containerd retains
HTTPS origin resolution and content-digest verification. Kubelet owns runtime
image garbage collection, with a 24-hour maximum unused age and 80%/65% pressure
thresholds. Dragonfly's peer cache has a separate six-hour TTL.

End-to-end P2P, private-registry authorization, peer security and fleet cache
lifecycle remain unqualified. Model-weight caching is a separate lifecycle.
No throughput or storage-reduction guarantee is implied by the architecture.

See the [architecture decisions](https://github.com/Alien6-Studio/outerspace-os/tree/main/docs/adr)
and [worker configuration](https://github.com/Alien6-Studio/outerspace-os/blob/main/src/cluster/README.md).
