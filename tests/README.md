# Qualification framework

The root Makefile exposes all checks. `tests/targets.mk` owns the test commands.

| Path | Responsibility |
| --- | --- |
| `unit/` | Contract, integrity and failure-path tests for build and test tooling |
| `harness/` | QEMU boot, Kubernetes enrollment, network and model-serving orchestration |
| `integration/` | Manifests and small programs executed by test workloads |
| `benchmarks/` | Model/runtime lock and reproducible benchmark protocols |
| `reports/` | Historical qualification reports bound to their tested commits |
| `Dockerfile` | Additional networking tools for the disposable VM runner |

## Fast checks

Make and Python 3.11+ are sufficient:

```sh
make check
```

This runs the unit suite and shell syntax checks without Docker.

## Image and Kubernetes qualification

Build the image first with the [build commands](../build/README.md). QEMU is
provided by the builder image. Kubernetes labs also need kind, kubectl and Helm
on the development host.

```sh
make PROFILE=agent smoke
make PROFILE=agent enrollment
make PROFILE=inference enrollment
make PROFILE=inference cpu-serving
```

`smoke` loads the on-disk UKI through UEFI and checks root integrity, CRI and
persistent state across two cold starts. `enrollment` tests the actual OuterSpace
kernel against a disposable control plane: bootstrap, Node Ready, Cilium,
certificate rotation and recovery without a config drive. A separate kind-only
network lab exercises Cilium configuration; it cannot qualify the OS kernel.

`cpu-serving` adds real generation with a pinned llama.cpp image and GGUF model,
network isolation, pod replacement, drain recovery and node reboot. See the
[CPU serving protocol](benchmarks/cpu-serving.md) for inputs and evidence scope.

The Kubernetes labs use one exclusive lab name and network; run them sequentially.
They verify committed source and exact packaged image bytes. Reports and logs
are written under `out/PROFILE-HARDWARE-ARCH/`. A complete report is emitted only
after the scenario and cleanup pass. Measurements from emulated VMs are
functional observations, not hardware performance claims.

`smoke-split` remains available for boot diagnostics. It passes an external kernel
and initrd, so its output is not accepted as UEFI qualification evidence.
