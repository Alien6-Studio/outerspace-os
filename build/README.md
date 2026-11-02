# Build and release tooling

The root Makefile exposes the build commands. `build/targets.mk` defines assembly
and packaging; qualification commands live in [tests/](../tests/README.md).

| Path | Responsibility |
| --- | --- |
| `Dockerfile` | Pinned Ubuntu builder with mkosi and image utilities |
| `build.sh` | Archive committed source and launch the isolated builder |
| `assemble.sh` | Assemble the selected mkosi profile inside the builder |
| `tools/` | Component integrity, kernel preparation, image identity and release validation |
| `sbom/` | Pinned offline scanner policy and per-image inventory coverage |
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
The final disk is then scanned read-only to produce an independently bound
[CycloneDX SBOM](sbom/README.md), raw scanner evidence and explicit coverage gaps.
The scanner remains in the builder; no scanner enters the OS image.

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
Both packaging and promotion require the exact SBOM and recheck its hashes,
image subject, installed runtime entries and reconstruction from raw inputs.
Older images must be rebuilt through this pipeline before candidate packaging.

## Go runtime dependency updates

The files under `build/runtime/{crictl,containerd,kubelet}/` are frozen build
inputs, not standalone applications. Kubernetes staging modules are part of the
complete kubelet workspace. A dependency proposal that edits only one staging
`go.mod` or `go.sum` cannot be merged independently.

Resolve updates against the pinned upstream source and Go toolchain, synchronize
the whole workspace, verify downloaded modules and regenerate its vendor
inventory. Preserve every resulting manifest, the selected module archives and
historical graph metadata with their Go checksums and SHA256/size records in the
component's `*-dependencies.lock.json`. Update that lock's digest in both the
runtime recipe and `sbom/sources.lock.json`; `make check` rejects mismatched
manifests or source locks. The build independently reconstructs the vendor tree
offline and verifies the compiled binary's dependencies.

Compile and test the affected runtime, then qualify both OS profiles on each
native architecture. New source inputs invalidate prior security and source/notice
reviews. Keep development changes on a unique `-dev.N` version until the new
candidate's review and qualification are complete. Existing alpha tags and their
artifacts remain immutable.

Ubuntu packages use the signed Noble snapshot locked in `inputs.lock.json`.
The locked `apt-snapshot.tar.gz` contains the exact signed releases and the
update/security indexes for both architectures. APT verifies the signatures and
index checksums, fetches the unchanged Noble base indexes by signed hash, and
downloads matching package bytes from official Ubuntu archive/ports mirrors.
The snapshot service remains a package fallback. Corresponding-source downloads
also try official pool mirrors and always verify the previously locked SHA256.

When refreshing the snapshot, fetch its three original `InRelease` files and the
main/universe source, amd64 and arm64 `.xz` indexes for both update and security
pockets into their original `dists/` paths. Run
`python3 build/tools/freeze-apt-snapshot.py --snapshot TIMESTAMP --index-root DIR --output FILE`
on a Linux host with the Ubuntu archive keyring, review the printed digests, and
update the lock, archive and snapshot fallback URL together. The tool verifies
Ubuntu's signatures and every index checksum before creating the archive.
Builder identity, full corresponding-source archives, native package source
metadata and security/redistribution decisions accompany every bundle. Independent
build comparisons record remaining nondeterminism; bit-identical output is not
assumed. Candidate promotion requires the signed checksum inventory and passing
source-bound review gates; see the [patch workflow](security/README.md).

## Worker configuration

[Worker configuration](../src/cluster/README.md#configure-a-worker) is rendered
with `build/tools/node-config.py`. `make config-drive` packages `out/node-config/`
into `out/node-config.raw`; an existing config-drive image is never overwritten.
Configuration contains bootstrap credentials and stays outside version control.
