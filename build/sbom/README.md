# Per-image software inventory

Every build scans the completed GPT disk with pinned Syft 1.55.0, outside the
shipping OS. Root, state and EFI partitions are mounted read-only, without
executing image code or replaying ext4 journals. A network namespace disables
remote enrichment. SHA256 checks before and after the scan bind the result to
the exact disk, UKI, source archive, manifest, profile and architecture.

The builder verifies the scanner's archive against
[`syft.lock.json`](syft.lock.json); it records the installed scanner hash too.
Scanner updates must change the lock through review and rebuild the builder.
No floating download, additional host runtime or scanner service is installed.

## Outputs and enforcement

`make PROFILE=agent builder build smoke package` and the corresponding Inference
command generate and carry these files in each independently qualified bundle:

- `sbom.cdx.json`: CycloneDX 1.6 inventory with the raw image SHA256 as its root
  component, source/profile identity, observed packages/files, exact installed
  APT manifest and externally installed runtime binaries.
- `sbom.syft.json`: unmodified native scanner evidence, including file hashes,
  inferred packages, kernel modules, embedded Go/Rust metadata when available,
  declared licenses and unknowns. Standard formats can omit scanner details.
- `sbom.scan.cdx.json`: the scanner's original CycloneDX output, retained so
  packaging and promotion can reconstruct and verify the final document.
- `sbom-evidence.json`: exact image identity, scanner/archive/configuration
  digests, partition layout, verified runtime inputs, coverage and file hashes.
- `syft.lock.json` and `syft.yaml`: the scanner policy used by this source.

mkosi removes the DPKG database during image cleanup. The complete installed APT
list therefore comes from its hash-bound package manifest. These components are
marked `outerspace:inventory-source=mkosi-installed-manifest`; ELF-note package
inferences remain distinguishable in the raw scan and are not substituted for
the installed package names. Every non-APT executable in `components.lock.json`
is checked against its digest-verified upstream archive and against the scan's
file hashes. The scan also records EFI binaries, firmware files when present,
and kernel modules; a file hash alone does not establish its origin or license.

Packaging refuses missing, stale, cross-image, altered or incomplete required
inventory. Promotion rechecks the same files against the qualified bundle's
SHA256SUMS without rebuilding or rescanning the candidate. This is checksum-bound
build evidence, not a cryptographically signed attestation. Workflow and source
review remain part of the trust boundary.

## Coverage and remaining gates

This implements an inventory increment of issue #9, not its closure. Syft
extracts many embedded Go dependencies from the approved runtimes. The pinned
Dragonfly executable exposes no supported embedded dependency metadata; its own
version, origin and binary digest are recorded, while its transitive dependency
coverage is explicitly unknown. No full dependency graph is claimed. CycloneDX
composition remains `incomplete`; coverage always leaves license, vulnerability
and corresponding-source review pending.

Declared or inferred licenses are evidence for review, not a redistribution
decision. The APT manifest does not provide license expressions or package
dependency edges; installed notices remain in the image and its file inventory.
Complete corresponding sources/notices, unknown dependency resolution, expiring
vulnerability exceptions, signed provenance, Ubuntu snapshot locking and
reproducibility checks remain required work. Generating these files does not
satisfy the independent `license_review`, `sbom` or `vulnerability_review`
release gates automatically. Model weights and workload images are separate
subjects, never silently included in the host inventory.
Scanner timestamps, generated identifiers and temporary mount paths can also
differ between scans; byte-for-byte reproducibility of the SBOM is not claimed.

References: [Syft formats](https://oss.anchore.com/docs/guides/sbom/formats/),
[configuration](https://oss.anchore.com/docs/reference/syft/configuration/),
[Go binary discovery](https://oss.anchore.com/docs/capabilities/go/), and
[CycloneDX 1.6 schema](https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json).
