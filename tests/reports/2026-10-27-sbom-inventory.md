# Per-image SBOM pipeline — 2026-10-27

Local qualification of the inventory increment for issue #9. Agent and Inference
were built independently from local snapshot
`83d9662e2da1d8e279b4cec438c981e53b2d1f7a`, based on main
`6b006a4828787b4aab792b36e219aee2a9ce0763`. All eight changed build/release inputs
match the implementation; additional refusal tests and documentation were added
after the snapshot. This is development evidence, not a release attestation or
acceptance of the whole supply-chain issue.

## Validation

- `make check`: 94 tests and shell syntax checks pass. Tests exercise absent,
  altered, cross-image, symlink and forged-coverage evidence; approved runtime
  bytes; unsafe disk layouts; scanner archive integrity; and promotion refusals.
- Both native arm64 `build smoke package` pipelines pass, with two complete
  four-vCPU/4-GiB QEMU UEFI boots per image and persistent state/identity.
- Both actual bundles pass the promotion verifier, which checks checksum-bound
  inventories and reconstructs their final CycloneDX documents. Bound boot logs,
  image identities and the two successful power cycles were independently checked.
- Scanner intake verifies the pinned archive; scans run without network access
  on read-only root, state and EFI partitions. Each installed external executable
  matches its approved upstream archive and its scan hash. Disk/input hashes are
  checked before and after scanning. Syft is absent from both shipping images.
- Preliminary scans of the existing pristine Agent and Inference disks produced
  documents accepted by the official CycloneDX 1.6 schema with jsonschema 4.23.0.
- No build/qualification containers remain. No release, promotion, GitHub write
  or push was performed for this increment.

The qualification used `outerspace-builder:sbom-dev` with Syft 1.55.0. Commands
ran in the clean local checkout `/private/tmp/outerspace-sbom-validation`:

```sh
make PROFILE=agent OUTERSPACE_BUILDER=outerspace-builder:sbom-dev build smoke package
make PROFILE=inference OUTERSPACE_BUILDER=outerspace-builder:sbom-dev build smoke package
```

## Subjects and coverage

| Subject | Raw disk SHA256 | CycloneDX SHA256 |
| --- | --- | --- |
| Agent CPU arm64 | `22bf3abb36e5dea3da45ba2f394bc3f3faccfa6be7199a288bc0b3f093afc73e` | `897aa6d1dfe33958c8fe22b61f568224eb45715aa3c1df588db3d0cf61da91a0` |
| Inference CPU arm64 | `05761ee7cf335a8eb7b5bf4dd2346e17b588e26525087dfc1bc3593769c433cf` | `570d92ffdf518f949084dd9d9335277e955d27cb70dcbd003c555d882181b587` |

Each new image has 124 installed APT manifest entries, six verified external
executables and 15,316 scanned filesystem entries. Syft reports 533 Go module
records, 7,723 kernel modules, four binary identifications and three ELF-note
Debian package inferences. These are scanner records, not a deduplicated count
of dependencies. APT manifest entries remain distinct from ELF-note inferences.

Dragonfly's executable has no supported embedded dependency metadata. Its
version, approved archive and installed file digest are verified, but its
transitive dependencies remain unknown. Both inventories keep
`complete_dependency_graph: false` and license, corresponding-source and
vulnerability reviews `pending`.

The full bundles and raw evidence remain under the ignored
`out/sbom-qualification/{agent,inference}-cpu-arm64/` directories. Independent
checks are recorded in `out/milestone1-sbom-verification.json`; exact changed
build/release input hashes are in `out/milestone1-sbom-inputs.json`. Build and
test logs use the `out/milestone1-sbom-*` prefix.

This change has no new native amd64, full-firmware, Kubernetes enrollment,
serving or physical-hardware qualification. It does not complete source/license
review, vulnerability triage, dependency coverage, snapshot locking, reproducible
builds or signed provenance. See the [inventory protocol and remaining gates](../../build/sbom/README.md).
