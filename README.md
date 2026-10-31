# OuterSpace OS

<img src="src/branding/outerspace-mark.svg" alt="OuterSpace OS" width="96">

A minimal Ubuntu-based Linux distribution for Kubernetes workers running inference
and agent workloads. The host provides the kernel, container runtime, node
identity and immutable root filesystem. Application engines, models and their
language dependencies run in containers.

[![Distribution checks](https://github.com/Alien6-Studio/outerspace-os/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Alien6-Studio/outerspace-os/actions/workflows/ci.yml?query=branch%3Amain)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Current version: `0.1.0-dev.0`.** Development images are intended for disposable
VMs and qualification labs. A production release requires the evidence defined
in the [release policy](build/release/README.md).

## Repository

| Directory | Responsibility |
| --- | --- |
| [src/](src/README.md) | OS image configuration, systemd services, cluster integration, runtime locks and upstream notices |
| [build/](build/README.md) | Builder, image assembly, packaging and release preparation |
| [tests/](tests/README.md) | Unit tests, QEMU/Kubernetes harness, workloads and benchmark protocols |
| [docs/adr/](docs/adr/) | Architectural decisions, alternatives and consequences |

`out/` contains generated images, bundles, logs and reports. `.cache/` contains
reusable downloads. Both are excluded from version control.

## Build and qualify

Install Make, Python 3.11+ and Docker with Linux containers. The builder uses
Docker's native architecture: arm64 on Apple Silicon, amd64 on x86 machines.

```sh
make check
# Build from committed source, with an explicit profile.
make PROFILE=agent builder build smoke package
make PROFILE=inference build smoke package
```

Run `make help` for available commands. The [build guide](build/README.md) covers
artifacts, firmware variants and image identity. The [test guide](tests/README.md)
covers Kubernetes enrollment and real CPU model serving.

The base image uses a read-only dm-verity root, persistent `/var`, containerd,
kubelet, AppArmor and default seccomp. Agent state starts at 2 GiB; Inference
state starts at 8 GiB. CPU images target amd64 and arm64. Secure Boot, A/B updates,
GPU profiles, physical hardware and production service behavior have separate
qualification gates.

## Documentation

- [Architecture decisions](docs/adr/) and [milestones](https://github.com/Alien6-Studio/outerspace-os/milestones).
- [Worker configuration and cluster integration](src/cluster/README.md).
- [Security policy](SECURITY.md).
- [Contributing](CONTRIBUTING.md) and [release process](build/release/README.md).

The [website](https://os.outerspace.sh/) is maintained on the separate
[`gh-pages`](https://github.com/Alien6-Studio/outerspace-os/tree/gh-pages) branch.

## License

OuterSpace source is licensed under [Apache-2.0](LICENSE). Bundled components
retain their [upstream licenses and notices](src/third_party/README.md); see
[NOTICE](NOTICE). An [Alien6](https://alien6.com) project, part of
[OuterSpace](https://outerspace.sh/).
