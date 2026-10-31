---
title: Releases
description: What you can do with OuterSpace OS 0.1.0-alpha.1, how to try it and the limits of this CPU preview.
---
# 0.1.0-alpha.1 — AI workers on CPU

The first OuterSpace OS alpha lets you evaluate a dedicated Kubernetes worker OS
for agent tasks and model serving. It is intended for teams exploring these
workloads in a self-managed cluster, using disposable CPU virtual machines.

**The release is currently a draft.** Public downloads will appear on
[GitHub Releases](https://github.com/Alien6-Studio/outerspace-os/releases) when
published. You can [build the tagged source](getting-started.md) today.

## What you can do

- **Run bounded agent tasks.** The Agent profile combines restricted container
  execution, default-deny networking and enforced resource budgets for small
  tasks and tools controlled by your operator.
- **Serve models on CPU.** The Inference profile hosts your containerized serving
  engine and weights. Deploy a model, replace the workload, drain the node and
  recover after a worker restart. The alpha has been exercised with llama.cpp.
- **Keep the host separate from your applications.** Both profiles use a
  read-only system root and persistent node state. An enrolled worker retains
  its identity across restarts.

Agent and Inference each have **AMD64 and ARM64** images. Your Kubernetes control
plane, cluster add-ons, application containers and model weights are deployed
separately. See [Choose your worker](features.md) for profile details.

## Try it

Use a **UEFI VM with 4 vCPUs and 4 GiB RAM**, with Secure Boot disabled, and a
separate Kubernetes 1.36 control plane with the supplied Cilium configuration.
Choose a profile, prepare the image and configure the worker to join your cluster.

The [getting-started guide](getting-started.md) covers building an image,
verifying a downloaded bundle and enrolling the worker. Release bundles include
checksums, attestations, a software inventory, sources and license notices.

## Know the limits

This is an evaluation preview, with no production support commitment or
performance guarantee. GPU workers, a qualified bare-metal hardware matrix,
Secure Boot and authenticated update/rollback are not available. Persistent
state is unencrypted; keep important data externally.

Agent tasks share the host kernel. The alpha does not provide a credential
broker, approval service or isolation for mutually untrusted tenants.

The accepted **CVE-2019-14899** risk applies only to the stock CPU configuration
without host VPNs or custom networking and expires on **14 November 2026 at
06:24:43 UTC**. See the [security scope](security.md) for the exact boundary.

## Share your experience

[Report a problem](https://github.com/Alien6-Studio/outerspace-os/issues) with your
version, profile, architecture and the steps that reproduce it. Evaluation
support is best-effort. Report vulnerabilities through the
[private security channel](https://github.com/Alien6-Studio/outerspace-os/security/advisories/new).
