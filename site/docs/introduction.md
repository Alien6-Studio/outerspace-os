---
title: Overview
description: A dedicated Kubernetes worker OS for containerized agent tasks and CPU model serving.
---
# A dedicated host for AI workers

OuterSpace OS is an immutable, Ubuntu-based Linux distribution for Kubernetes
workers running agent tasks and inference. It brings the host system, container
runtime and node services together in one image. Your tools, serving engines and
models stay in containers, where you can deploy and replace them independently.

## Where it fits

Use OuterSpace when you operate a self-managed Kubernetes cluster and want
dedicated workers for AI workloads. The OS supplies Linux, systemd, containerd
and kubelet. You supply the control plane, Cilium networking and the applications
you want to run.

The system root is read-only. Container storage, logs and the worker's identity
live in separate persistent state, so an enrolled node can restart and rejoin
the cluster without its original bootstrap credentials.

## Pick a profile

**Agent** provides bounded execution for small containerized tasks and tools.
The operator controls admission and network access; each task runs with restricted
permissions and fixed resource budgets.

**Inference** hosts CPU model-serving containers. Deploy your serving engine and
weights through Kubernetes, replace the workload as it changes, and drain the
worker when you need to take it out of service.

Both profiles are available as source builds for AMD64 and ARM64. The
[profile guide](features.md) explains the differences and the Agent alpha's limits.

## Start with a disposable VM

The current version, **0.1.0-alpha.1**, is a CPU preview. Its release is still a
draft, so public downloads are pending. Build the tagged source to evaluate it
today, using a UEFI VM with 4 vCPUs, 4 GiB RAM and Secure Boot disabled.

GPU workers, bare-metal support and production operation are outside this alpha.
Read the [release information](releases.md), then follow [Get started](getting-started.md).
