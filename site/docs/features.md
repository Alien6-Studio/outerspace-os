---
title: Agent and Inference
description: Choose bounded execution for agent tasks or a dedicated worker for CPU model serving.
---
# Choose your worker

OuterSpace OS has two profiles built on the same immutable Ubuntu-based Core.
Choose a profile for each worker according to the workloads it will host.
Both CPU profiles target AMD64 and ARM64.

| | Agent | Inference |
| --- | --- | --- |
| Intended use | Small, containerized agent tasks and tools | CPU model-serving containers |
| Workload policy | Restricted execution with fixed budgets and default-deny networking | Your Kubernetes deployment and resource policy |
| Application stack | Bring your task containers and external orchestration | Bring your serving engine and model weights |
| Default persistent state | 2 GiB | 8 GiB |

## Agent: give each task a boundary

Use the Agent profile to execute tasks under policies owned by the cluster
operator. The supplied profile requires an unprivileged container, a read-only
container root, AppArmor and seccomp. It rejects privileged execution, host mounts,
runtime sockets and injected credentials. Network access is denied until the
operator explicitly permits a flow.

The first alpha supports **one container per task**, with ceilings of **1 CPU and
256 MiB RAM**. Each task has a temporary 64 MiB workspace and 16 MiB scratch area.
Process and disk-I/O limits bound resource use; log rotation limits retained logs.
Workspaces are discarded with the task. The supplied namespace allows four active
tasks, including queued launches.

This profile suits small tools and bounded jobs. A larger agent framework or
model server needs a different deployment arrangement. The alpha does not provide
an agent framework, credential broker or approval service. Tasks share the host
kernel within one trusted administrative domain; this is not VM isolation for
mutually untrusted tenants.

See the [Agent configuration and example workload](https://github.com/Alien6-Studio/outerspace-os/blob/v0.1.0-alpha.1/src/cluster/README.md#native-oci-agent-v1-profile)
to apply the profile and adapt a task container.

## Inference: keep model serving in your workloads

Use the Inference profile for a Kubernetes worker dedicated to CPU model serving.
Your serving engine and weights live outside the host image, so changing a model
or application does not require baking it into the OS.

The alpha supports CPU serving, workload replacement, node draining and recovery
after a worker restart. It has been exercised with llama.cpp. Choose models that
fit the memory and compute resources of your evaluation VM; the alpha makes no
throughput or latency guarantee.

GPU acceleration is not available in this release. Model storage, application
availability and the licenses of your model and serving engine remain part of
your workload deployment.

## Shared host behavior

Both profiles provide a read-only system root, persistent container and node state,
Kubernetes certificate rotation, and networking through the supplied Cilium
configuration. Persistent state is unencrypted. Neither profile includes the
Kubernetes control plane.

[Get started](getting-started.md) with a disposable CPU VM and review the
[alpha limits](releases.md) before deploying a workload.
