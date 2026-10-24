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
make agent-admission
make PROFILE=agent agent-isolation
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

Every Docker-backed test removes obsolete, untagged OuterSpace tooling images,
including on failure. Current tagged builder/runner images remain reusable.
Kubernetes teardown removes the runner's anonymous volumes and the dedicated
kind nodes' `/var` volumes; volume cleanup failure fails qualification. Other
projects' images and volumes are outside this cleanup. `make clean-test-cache`
also removes obsolete tooling images independently.

`smoke-split` remains available for boot diagnostics. It passes an external kernel
and initrd, so its output is not accepted as UEFI qualification evidence.

`agent-admission` preflights the native Agent policy against a disposable API
without Cilium or an OS worker. `agent-isolation` runs that policy on the real
Agent image, checks process/filesystem/LSM controls and missing-profile refusal,
then repeats execution and ingress/egress checks after cold-node recovery.
The [Agent profile](../src/cluster/README.md#native-oci-agent-v1-profile) describes
the administrative trust boundary, allowed workspace and static limits.
