# OuterSpace OS

<img src="branding/outerspace-mark.svg" alt="OuterSpace OS" width="96">

A minimal, Ubuntu-based Linux distribution for **Kubernetes inference workers**.
Install it on bare metal, keep the host small, and run inference engines and their
dependencies in containers.

The [agent execution direction](design/agent-execution.md) extends this minimal
host to isolated agents, with optional integrations such as OpenShell. That
profile is planned; it is not an existing compatibility claim.

[![Distribution checks](https://github.com/Alien6-Studio/outerspace-os/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Alien6-Studio/outerspace-os/actions/workflows/ci.yml?query=branch%3Amain)
[![Website](https://github.com/Alien6-Studio/outerspace-os/actions/workflows/website.yml/badge.svg?branch=gh-pages)](https://os.outerspace.sh/)
[![Stage: development](https://img.shields.io/badge/stage-development-purple)](release/README.md)
[![Base: Ubuntu 24.04 LTS](https://img.shields.io/badge/base-Ubuntu_24.04_LTS-E95420)](design/architecture.md)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

[Website](https://os.outerspace.sh/) · [Architecture](design/architecture.md) ·
[Roadmap](design/roadmap.md) · [Contributing](CONTRIBUTING.md)

**Current version: `0.1.0-dev.0` — development only.** There is no public alpha or
supported production image yet. Secure Boot signing, A/B updates, GPU support and
CIS audit results are release gates. See the [validation report](tests/reports/2026-10-23-development.md)
for measured results and their limits.

## What the host provides

| Capability | Current implementation |
| --- | --- |
| Minimal, immutable foundation | Ubuntu 24.04 packages, read-only root with dm-verity, separate writable `/var`, UEFI image and UKI builds for amd64 and arm64 |
| Kubernetes runtime | Hash-locked containerd, kubelet and crictl; cgroup v2, AppArmor and default seccomp; config-drive worker bootstrap |
| Image delivery and retention | Optional native Dragonfly P2P peer, digest-pinned prefetch, kubelet unused-image GC and a separate peer-cache TTL; end-to-end qualification pending |
| eBPF and hardening | Kernel BPF/BTF checks, Cilium integration profile, locked accounts and a documented CIS security target; OS-node integration and audit pending |

The distribution is assembled from Ubuntu packages. Model weights, inference
engines, Python and CUDA user-space libraries belong to workloads. Faster image
delivery and a smaller footprint are objectives to benchmark, not published claims.

## Build and boot a development image

You need **Python 3.11+, Make and Docker running Linux containers**. Builds use the
Docker VM's native architecture: arm64 on Apple Silicon, amd64 on x86 machines.

```sh
git clone https://github.com/Alien6-Studio/outerspace-os.git
cd outerspace-os
make check
make builder build smoke
```

The disposable builder requires privileged mount namespaces. The smoke test boots
the complete disk through UEFI twice, checking root integrity, CRI, writable state
and stable identity on a disposable overlay. It does not qualify Secure Boot,
Kubernetes enrollment or physical hardware. Outputs and
logs are written to `build/`; use disposable VMs while the image is in development.

Follow the [build guide](design/building.md) for firmware profiles, artifacts and
rebuild limits, then the [worker configuration guide](cluster/README.md#configure-a-worker).

## Deployment targets

The first target is a **bare-metal worker in a self-managed Kubernetes cluster**,
such as one created with kubeadm. QEMU and cloud VMs provide test environments.
The image contains no Kubernetes control plane.

AKS and similar managed services control their supported node images. OuterSpace
is not a supported replacement for an AKS node OS. Azure VMs running self-managed
Kubernetes are a separate qualification target. See [cluster integration](cluster/README.md).

## Follow or contribute

- [Release and maintenance policy](release/README.md): development → alpha → beta → RC → stable, with evidence required at each stage.
- [Security policy](SECURITY.md) and [CIS hardening target](security/README.md).
- [Contribution guide](CONTRIBUTING.md), [issues](https://github.com/Alien6-Studio/outerspace-os/issues) and [discussions](https://github.com/Alien6-Studio/outerspace-os/discussions).

Distribution sources live on `main`. Website sources and generated HTML live on
[`gh-pages`](https://github.com/Alien6-Studio/outerspace-os/tree/gh-pages).

## License

Original OuterSpace source uses **Apache License 2.0**; see [LICENSE](LICENSE) and
[NOTICE](NOTICE). Bundled components retain their own licenses and
[third-party notices](third_party). Redistribution and corresponding-source review
are required before any public alpha binary.

An [Alien6](https://alien6.com) open-source project, part of [OuterSpace](https://outerspace.sh/).
