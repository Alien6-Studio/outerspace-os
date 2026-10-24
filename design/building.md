# Build and verify a development image

Requirements: Python 3.11+, Make and Docker running Linux containers. The build
uses the Docker VM's native architecture. CI builds amd64 and arm64 independently.

```sh
git clone https://github.com/Alien6-Studio/outerspace-os.git
cd outerspace-os
make check
make builder
make PROFILE=agent build smoke package
make PROFILE=inference build smoke package
```

The disposable builder needs privileged mount namespaces; no host devices or
Docker socket are exposed to it. Run only trusted source in this builder. The
QEMU smoke test runs without extra privileges. Do not write a development image
to a physical disk containing data.

Builds require committed source and consume that exact Git archive. `PROFILE` is
mandatory; output directories are `build/PROFILE-HARDWARE-ARCH/`, with `cpu` as the
default hardware profile. Builds and proof files from one profile cannot qualify
another. Existing unprofiled output is not accepted by this contract.

Writable state has a 2 GiB minimum on Agent and an 8 GiB minimum on Inference.
The larger Inference partition accommodates Cilium, OCI image extraction and the
small CPU serving model; it adds no packages to the immutable root. These are
development image capacities, not storage budgets for arbitrary models. Provision
space for the selected workloads and caches. Existing images are not resized by
this change; rebuild and qualify a fresh Inference image for the CPU serving lab.

## Firmware and kernel

For hardware discovery with the complete Ubuntu firmware set (larger image):

```sh
make PROFILE=inference HARDWARE=cpu-full-firmware build smoke package
```

The default uses the same generic kernel on physical servers and in VMs; firmware
still needs qualification for each server model. The kernel ABI is pinned and
must be deliberately updated with security releases. Runtime versions, source
URLs and hashes are recorded in [components.lock.json](../components.lock.json).
The discovery variant is development-only and is outside the default release
matrix until its own hardware qualification is added to release policy.

## Artifacts and smoke-test scope

Outputs under each profile directory include the raw GPT disk, UKI, split kernel/initrd,
package manifest and boot log. `make package` adds the compressed image, source
archive, component inventory, build metadata and SHA256 checksums to a versioned
bundle. Development CI publishes logs and inventories only; binary redistribution
is gated by license and source review.
`build-identity.json` binds profile, hardware, architecture, commit, component lock,
disk/UKI/manifest/source digests and verity root hash. The immutable guest identity
must appear in each boot log; schema 2 smoke reports bind this identity and all logs.

The default smoke test starts QEMU with UEFI firmware and the complete GPT disk.
It loads systemd-boot and the on-disk UKI without passing an external kernel or
initrd. Two cold starts share a disposable qcow2 overlay and firmware variables.
The original raw image must remain unchanged.

Both boots check read-only root, cgroup v2, AppArmor, selected sysctls and the CRI
API. A nonce and hostname written to `/var` must survive shutdown. The second
boot must have a new boot ID and the same machine ID; the VM's fixed UUID supplies
the latter. This does not qualify machine-ID persistence on physical hardware or
the persistence of a rotated Kubernetes worker identity.

Outputs include `boot-uefi-prepare.log`, `boot-uefi-verify.log`, the combined
`boot-smoke.log` and `uefi-smoke.json`. The report binds success to the raw disk's
SHA256. Packaging rejects absent, failed, partial or stale boot evidence.

For diagnostics, `make PROFILE=agent smoke-split` still boots the extracted kernel/initrd.
It cannot qualify a package; rerun `make PROFILE=agent smoke` before packaging. Neither mode
qualifies Secure Boot, Kubernetes Node Ready, GPU execution or model latency.
The earlier [development report](../tests/reports/2026-10-23-development.md)
records the original split-kernel test and its limits.

The current disk profile uses 512-byte logical sectors consistently for GPT and
EFI FAT32. Native 4K-sector disks require a separately qualified image profile.
ARM64 Ubuntu gzip kernels are decompressed into EFI-loadable payloads before UKI
assembly; package-input and prepared hashes are recorded inside the image at
`/usr/share/outerspace/kernel-preparation.json`. The ESP contains EFI boot assets,
not duplicate loose kernels or kernel debug metadata.

Ubuntu packages currently track the signed Noble update/security repositories;
upstream runtime binaries and builder inputs are hash-locked. Exact bit-for-bit
rebuilds still require a pinned Ubuntu package snapshot and pinned build-time
metadata. Review the generated manifest for every build.

Continue with [worker configuration](../cluster/README.md#configure-a-worker),
[architecture](architecture.md), [release gates](roadmap.md) and the
[release and maintenance policy](../release/README.md).
