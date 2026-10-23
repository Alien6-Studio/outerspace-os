# Build and verify a development image

Requirements: Python 3.11+, Make and Docker running Linux containers. The build
uses the Docker VM's native architecture. CI builds amd64 and arm64 independently.

```sh
git clone https://github.com/Alien6-Studio/outerspace-os.git
cd outerspace-os
make check
make builder
make build
make smoke
make package
```

The disposable builder needs privileged mount namespaces; no host devices or
Docker socket are exposed to it. Run only trusted source in this builder. The
QEMU smoke test runs without extra privileges. Do not write a development image
to a physical disk containing data.

## Firmware and kernel

For hardware discovery with the complete Ubuntu firmware set (larger image):

```sh
./scripts/build.sh --profile=full-firmware
```

The default uses the same generic kernel on physical servers and in VMs; firmware
still needs qualification for each server model. The kernel ABI is pinned and
must be deliberately updated with security releases. Runtime versions, source
URLs and hashes are recorded in [components.lock.json](../components.lock.json).

## Artifacts and smoke-test scope

Outputs under `build/` include the raw GPT disk, UKI, split kernel/initrd,
package manifest and boot log. `make package` adds the compressed image, source
archive, component inventory, build metadata and SHA256 checksums to a versioned
bundle. Development CI publishes logs and inventories only; binary redistribution
is gated by license and source review.

The smoke test boots the split kernel/initrd with the UKI's embedded verity root
hash. It checks read-only root, writable state, cgroup v2, AppArmor, selected
sysctls and the CRI API. It does not prove EFI disk boot, Secure Boot, Kubernetes
Node Ready, GPU execution or model latency. See the [validation report](../tests/reports/2026-10-23-development.md).

Ubuntu packages currently track the signed Noble update/security repositories;
upstream runtime binaries and builder inputs are hash-locked. Exact bit-for-bit
rebuilds still require a pinned Ubuntu package snapshot and pinned build-time
metadata. Review the generated manifest for every build.

Continue with [worker configuration](../cluster/README.md#configure-a-worker),
[architecture](architecture.md), [release gates](roadmap.md) and the
[release and maintenance policy](../release/README.md).
