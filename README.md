# OuterSpace OS

<img src="src/branding/outerspace-mark.svg" alt="OuterSpace OS" width="96">

**An immutable Linux OS for Kubernetes workers running AI agents and inference.**

OuterSpace OS gives your cluster a dedicated host for containerized agent tasks
and model serving. Built on Ubuntu, it keeps the system read-only and node state
persistent. Your agent tools, serving engines and models run in containers, so you
can change workloads independently of the host image.

[Website](https://os.outerspace.sh/) · [Get started](https://os.outerspace.sh/getting-started/)
· [Releases](https://github.com/Alien6-Studio/outerspace-os/releases)

## Why OuterSpace OS?

- **A host focused on your workers.** Linux, the container runtime and Kubernetes
  node services are assembled into one OS image. Application dependencies stay
  with your workloads.
- **A consistent system across restarts.** The read-only root separates the host
  from writable container storage, logs and node identity. An enrolled worker
  keeps its identity when it reboots.
- **Two profiles for different jobs.** Choose bounded execution for agent tasks
  or a worker for CPU model serving, on either AMD64 or ARM64.

OuterSpace is for teams evaluating dedicated AI workers in a **self-managed
Kubernetes cluster**. You provide the control plane and deploy Cilium, your
applications and their models separately.

## Choose your worker

| Profile | Use it for | What it provides |
| --- | --- | --- |
| **Agent** | Running small, containerized agent tasks and tools under operator-controlled policies | Restricted container execution, default-deny networking, and enforced CPU, memory, process, I/O and workspace limits |
| **Inference** | Serving models on CPU through your chosen containerized engine | A persistent Kubernetes worker for model serving, workload replacement, node draining and recovery after restart |

Both profiles share an Ubuntu-based Core with containerd, kubelet and a read-only
root protected by dm-verity. The Inference profile has been exercised with
llama.cpp. Serving engines and model weights are separate from the OS.

The Agent alpha is deliberately bounded: one container per task, up to 1 CPU and
256 MiB RAM, with temporary workspace and no network access by default. It uses
a shared kernel within one trusted administrative domain. See the
[profile guide](https://os.outerspace.sh/features/) before choosing it for your
agent architecture.

## Try the CPU alpha

**0.1.0-alpha.1 is an experimental preview for disposable UEFI VMs.** Agent and
Inference images cover AMD64 and ARM64. The release is currently a draft; public
downloads will appear on [GitHub Releases](https://github.com/Alien6-Studio/outerspace-os/releases)
when published. You can build the tagged source today.

Use a VM with **4 vCPUs and 4 GiB RAM**, with Secure Boot disabled, and a separate
Kubernetes 1.36 control plane using the supplied Cilium configuration.

1. Choose the profile and architecture for your workload.
2. Build the image, or verify a release bundle when downloads are available.
3. Configure the worker to join your cluster, then deploy your workload.

The [getting-started guide](https://os.outerspace.sh/getting-started/) covers image
verification, VM setup and cluster enrollment.

To build locally, install Make, Python 3.11+ and Docker running Linux containers:

```sh
git clone https://github.com/Alien6-Studio/outerspace-os.git
cd outerspace-os
git checkout v0.1.0-alpha.1
make PROFILE=agent HARDWARE=cpu builder build smoke package
# Use PROFILE=inference to build a model-serving worker.
```

The build uses Docker's native architecture: ARM64 on Apple Silicon, AMD64 on
x86 hosts. Outputs are written under `out/<profile>-cpu-<architecture>/`.
See the [build guide](build/README.md) for options.

## Alpha limits

This preview is for evaluation. GPU support, a qualified bare-metal hardware
matrix, Secure Boot and an authenticated update/rollback path are not available.
Persistent state is unencrypted; keep important data externally. There is no
production support commitment or performance guarantee.

The accepted **CVE-2019-14899** risk is limited to the stock CPU configuration
without host VPNs or custom networking and expires on **14 November 2026 at
06:24:43 UTC**. Read the [security scope](https://os.outerspace.sh/security/)
before using the alpha.

## Explore and contribute

- [Worker configuration](src/cluster/README.md) and [architecture decisions](docs/adr/).
- [Roadmap](https://github.com/Alien6-Studio/outerspace-os/issues/7) and [contributing](CONTRIBUTING.md).
- [Report a bug](https://github.com/Alien6-Studio/outerspace-os/issues) or [report a vulnerability privately](SECURITY.md).

OuterSpace source is licensed under [Apache-2.0](LICENSE). Bundled components
retain their [upstream licenses and notices](src/third_party/README.md); see
[NOTICE](NOTICE).

By [Alien6](https://alien6.com) · Part of [OuterSpace](https://outerspace.sh/).
