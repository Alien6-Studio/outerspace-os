# OuterSpace OS

A purpose-built, minimal Ubuntu-based Linux distribution installed on bare-metal
Kubernetes inference workers, with VM builds for testing. The host supplies a
kernel, a container runtime and a kubelet; inference
engines, Python, CUDA user-space libraries and model weights belong to workloads.

This repository builds the distribution from Ubuntu packages. It does not modify
an Ubuntu cloud image and does not fork the Linux kernel. The website sources and
published HTML live exclusively on the `gh-pages` branch (`site/` and `docs/`).

## Development image

- Ubuntu 24.04 LTS / Noble, minimal package selection, no recommendations or docs.
- UEFI disk image and unified kernel image, read-only ext4 root with dm-verity.
- Generic server kernel 6.8.0-147 with extra hardware modules and build-time checks
  for eBPF/BTF capabilities; an explicit optional full-firmware profile.
- Separate writable `/var` for container images, kubelet identity and bounded logs.
- containerd 2.3.7, kubelet 1.36.5, crictl 1.36.0; upstream binaries SHA256-locked
  for amd64 and arm64. cgroup v2 with the systemd driver, overlayfs, AppArmor and
  default seccomp for Kubernetes containers.
- No SSH server or unlocked interactive root account; no in-place apt updates.
- Optional local config drive for authenticated Kubernetes worker bootstrap.
- Native Dragonfly 1.4.9 peer, enabled by configuration, for P2P OCI blob delivery.
- Kubelet-owned unused image GC (24h retention, 80%/65% pressure thresholds), a
  separate Dragonfly cache TTL (6h), digest-pinned CRI prefetch and compressed-layer
  GC. All performance claims still require measurements.
- Cilium eBPF cluster profile and a documented CIS Level 1 Server security target.

**Development status:** the initial image pipeline and bootstrap contract are
implemented. This is not a production release or a security certification.
Secure Boot signing, authenticated A/B updates, GPU drivers, cluster join testing,
Cilium on an enrolled OS node, Dragonfly end-to-end tests, CIS audit results and inference benchmarks are
release gates, not existing claims.

## Build and verify

Requirements: Python 3.11+, Make and Docker running Linux containers. The build is
native to the Docker VM architecture (arm64 on Apple Silicon, amd64 on CI).
The disposable builder needs privileged mount namespaces; no host devices or
Docker socket are exposed to it. The QEMU smoke test runs without extra privileges.

```sh
make check
make builder
make build
make smoke
```

For hardware discovery with the complete Ubuntu firmware set (larger image):
`./scripts/build.sh --profile=full-firmware`. The default uses the same generic
kernel on physical servers and in VMs; firmware still needs qualification for
each server model. The kernel ABI is pinned and must be deliberately updated with
security releases.

Artifacts are placed under `build/`: raw GPT disk, UKI, split kernel/initrd,
package manifest and boot log. Do not write an image to a physical disk during
development. See [architecture](design/architecture.md) and [release gates](design/roadmap.md).
The [release and maintenance policy](release/README.md) defines conventional
versions, prelaunch stages, candidate inventories and evidence-gated draft releases.
See the [local validation report](tests/reports/2026-10-23-development.md) for actual
results and their limits.
See [cluster integration](cluster/README.md) for Dragonfly, Cilium and managed
provider support boundaries, and the [CIS security target](security/README.md).

The smoke test boots the split kernel/initrd with the UKI's embedded verity root
hash. It checks read-only root, writable state, cgroup v2, AppArmor, selected
sysctls and the CRI API. It does not prove EFI disk boot, Secure Boot, Kubernetes
Node Ready, GPU execution or model latency.

## Configure a worker

Use a dedicated, short-lived Kubernetes bootstrap token and the control plane CA.
The target cluster must allow TLS bootstrap and certificate rotation. The kubelet
minor version must be compatible with that control plane. The CNI is installed by
the cluster; its binaries live in writable `/opt/cni/bin` (see architecture).

```sh
python3 scripts/node-config.py \
  --api-server https://api.example.net:6443 \
  --ca /secure/cluster-ca.crt \
  --token-file /secure/bootstrap-token \
  --cluster-dns 10.96.0.10
./scripts/config-drive.sh
```

Attach `build/node-config.raw` as a second virtual disk. It contains credentials;
do not publish it. Detach it after successful enrollment and revoke the bootstrap
token. The node keeps its rotated identity in `/var/lib/kubelet`, and its stable
hostname in `/var/lib/outerspace/hostname`. Serving certificate CSRs still require
an approval policy on the control plane; there is no blanket auto-approval here.

To warm the CRI cache, add a `prefetch-images` file to `node-config/` before making
the drive, with one `registry/repository@sha256:<64 hex characters>` per line.
This initial prefetch supports public registries; private prefetch credential
delivery remains a release gate. Workload imagePullSecrets are handled by CRI.

Ubuntu packages currently track the signed Noble update/security repositories;
only upstream runtime binaries and builder inputs are hash-locked. Exact
bit-for-bit rebuilds require a pinned Ubuntu package snapshot and pinned build
time metadata. Review the generated manifest for every build.
