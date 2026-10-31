---
title: How it works
description: How the immutable host, persistent node state and your Kubernetes workloads fit together.
---
# How OuterSpace fits your cluster

OuterSpace runs as a worker in your self-managed Kubernetes cluster. The OS
provides the host and container runtime; your cluster supplies networking,
workload scheduling and the applications.

```text
Your workloads       Agent tasks or model-serving containers
                     Kubernetes deployments, services and storage
──────────────────────────────────────────────────────────────
Your cluster         Separate control plane and Cilium add-ons
──────────────────────────────────────────────────────────────
OuterSpace worker    kubelet · containerd · Linux · systemd
                     Read-only system + persistent node state
──────────────────────────────────────────────────────────────
CPU alpha            AMD64 or ARM64 UEFI virtual machine
```

## A host that stays separate from your applications

The system root is read-only and protected by dm-verity. Install application
libraries, tools and serving engines in your workload containers. The running
host does not use in-place `apt` upgrades.

Both worker profiles use the same Core. Agent adds the host policy and I/O
budgets needed by its restricted execution profile. Inference provides a worker
for your model-serving deployments, with a larger default state partition.
See the [profile comparison](features.md) to choose an image.

## What persists

| Storage | Holds | Behavior |
| --- | --- | --- |
| System root | OS and host services | Read-only |
| Node state (`/var`) | Container storage, worker identity and logs | Survives reboot; unencrypted in the alpha |
| Agent workspace and scratch | Files created by a task | Temporary; discarded with the pod |
| Application data and model weights | Your workload's data | Storage and backups are managed by your deployment |

An enrolled worker retains its hostname and rotated Kubernetes identity after
restart. Its original config drive is no longer needed. Persistent node state
is not an application backup; keep important data externally.

## Joining and networking

A config drive supplies the cluster API address, CA and a short-lived bootstrap
token. Kubelet enrolls the node and rotates its certificates. The cluster operator
controls serving-certificate approval and workload policy.

The supplied Cilium configuration provides cluster networking, services and
network policy. The Agent profile starts with default-deny ingress and egress;
the operator must allow the flows a task needs.

## Container storage

Containerd stores the images used by workloads in node state. Kubelet reclaims
unused images periodically using age and disk-pressure settings. Budget disk
space for both image layers and your workloads.

Optional Dragonfly peer delivery is experimental in this alpha. It does not
replace local image storage or manage model weights. End-to-end peer delivery,
private-registry access control and fleet cache behavior are outside the
evaluated scope.

## Replacing a node

The alpha uses a single system slot and has no authenticated updater or rollback
mechanism. Plan to drain and recreate disposable evaluation nodes when changing
the OS image. UEFI boot requires Secure Boot to be disabled.

Follow [Get started](getting-started.md) to prepare a worker. For design rationale,
see the [architecture decisions](https://github.com/Alien6-Studio/outerspace-os/tree/main/docs/adr).
