# Build and release tooling

The root Makefile exposes the build commands. `build/targets.mk` defines assembly
and packaging; qualification commands live in [tests/](../tests/README.md).

| Path | Responsibility |
| --- | --- |
| `Dockerfile` | Pinned Ubuntu builder with mkosi and image utilities |
| `build.sh` | Archive committed source and launch the isolated builder |
| `assemble.sh` | Assemble the selected mkosi profile inside the builder |
| `tools/` | Component integrity, kernel preparation, image identity and release validation |
| `release/` | Release policy, evidence schema and version-specific notes |

## Build an image

Requirements: Make, Python 3.11+ and Docker running Linux containers. Builds use
Docker's native architecture. CI builds amd64 and arm64 independently.

```sh
make check
make PROFILE=agent builder build smoke package
make PROFILE=inference build smoke package
```

`PROFILE` is mandatory. Builds consume an immutable Git archive and reject
uncommitted source. The disposable builder needs privileged mount namespaces;
no host devices or Docker socket are mounted into it.

Outputs go to `out/PROFILE-HARDWARE-ARCH/`, with `cpu` as the default hardware
profile. Images and evidence from one profile cannot qualify another.

Agent has a 2 GiB minimum state partition; Inference has an 8 GiB minimum for
Cilium, OCI extraction and model staging. Existing disks are not automatically
resized. Rebuild an old Inference image before running the CPU serving lab.

To include Ubuntu's complete firmware set for hardware discovery:

```sh
make PROFILE=inference HARDWARE=cpu-full-firmware build
```

That variant needs its own hardware qualification and idle-host budget before
`smoke` and `package` can pass. The kernel ABI and upstream
runtimes are pinned in the [image configuration](../src/image/mkosi.conf) and
[component lock](../src/components.lock.json).

## Artifacts and identity

Assembly produces a raw GPT disk, UKI, split kernel/initrd, package manifest and
source archive. `build-identity.json` records the profile, architecture, source
commit, component lock, disk/UKI/manifest/source digests and verity root hash.

`make smoke` boots the complete disk through UEFI twice on a disposable overlay.
The raw image stays unchanged. Packaging requires both successful boots and
matching identity/log hashes. `make smoke-split` is a diagnostic shortcut and
cannot qualify a package; see the [test guide](../tests/README.md).
Both boots must meet the measured CPU/RAM regression ceilings for their exact
profile and architecture. Packaging independently reapplies the policy and
includes its checksum and result; see the [baseline policy](../tests/benchmarks/agent-baseline.md).

`make package` creates a versioned bundle with the compressed disk, UKI, exact
source archive, inventories, boot evidence and SHA256 checksums. Development CI
uploads reports and inventories. Candidate promotion follows the
[release process](release/README.md).

Ubuntu packages use signed Noble update/security repositories. Exact binary
reproduction additionally requires a pinned package snapshot and build metadata.

## Worker configuration

[Worker configuration](../src/cluster/README.md#configure-a-worker) is rendered
with `build/tools/node-config.py`. `make config-drive` packages `out/node-config/`
into `out/node-config.raw`; an existing config-drive image is never overwritten.
Configuration contains bootstrap credentials and stays outside version control.
