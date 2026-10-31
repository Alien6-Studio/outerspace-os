---
title: FAQ
description: Choosing a worker profile, bringing your applications and understanding where the CPU alpha can run.
---
# Questions about OuterSpace OS

## Is this an OS or a container image?

OuterSpace is an operating-system disk image for Kubernetes workers. Your agent
tasks and inference applications run in containers on that host. The OS has a
read-only system root and separate persistent node state.

## Does it create a Kubernetes cluster for me?

You provide a self-managed control plane and configure the worker to join it.
The alpha uses Kubernetes 1.36 with the supplied Cilium configuration. It is not
a supported replacement for a managed cloud provider's node image.

## Which profile should I choose?

Choose **Agent** for small containerized tasks that fit the supplied execution
policy and resource budgets. Choose **Inference** to host CPU model-serving
containers. Both are available for AMD64 and ARM64; see the
[profile comparison](features.md).

## Does OuterSpace include an agent framework or a model?

You deploy those separately. The Agent profile supplies the execution boundary
for task containers; it does not manage agent reasoning, credentials or approvals.
The Inference alpha has been exercised with llama.cpp, but the serving engine
and model weights are not bundled into the OS.

## What survives a restart?

The worker's identity, container storage and logs live in persistent state.
Agent task workspaces are temporary and disappear when their pods are removed.
Keep important application data externally. The alpha does not encrypt the state
partition or provide an authenticated update/rollback path.

## Can I use a GPU or install it on a server?

Evaluate this release in disposable UEFI VMs with Secure Boot disabled. GPU
support and a qualified bare-metal hardware matrix are not available yet.

## Is it ready for production?

It is an experimental CPU alpha, without a production support commitment or
performance guarantee. Review the [release limits](releases.md) and
[security scope](security.md), including the time-limited kernel risk acceptance.

## Where do I download it?

The alpha release is still a draft. Public downloads will appear on
[GitHub Releases](https://github.com/Alien6-Studio/outerspace-os/releases) after
publication. Follow [Get started](getting-started.md) to build the tagged source
in the meantime.
