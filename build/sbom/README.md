# Per-image software and source inventory

The builder uses the Ubuntu snapshot, signed APT indexes, base-image digest and
mkosi archive in `build/inputs.lock.json`. `build/apt.sources` configures both the
builder and mkosi, including the security pocket. The CA bootstrap package is
fetched over HTTPS and checksum-verified before APT runs. The exact builder image
ID and installed builder package versions accompany each image.

Pinned Syft scans the completed GPT disk outside the shipping OS. Root, state and
EFI partitions are mounted read-only, without replaying ext4 journals or executing
image code. The scan has no network. Hashes before and after bind it to the exact
disk, UKI, source revision, profile and architecture. Every external runtime is
compared with its approved archive and the observed file hash. The scan includes
kernel modules, firmware files when present and Go function symbols.

`make PROFILE=agent builder build smoke package` and the equivalent Inference
command preserve:

- `sbom.syft.json`, `sbom.scan.cdx.json`, `sbom.cdx.json`, `sbom-evidence.json`:
  original disk scan, its conversion and the installed-manifest inventory.
- `apt-inputs.json`, `apt.sbom.syft.json`, `apt-notices.tar`: exact installed
  binary/source identities, original DPKG metadata, package copyright notices and
  common license texts, captured before mkosi removes its package database.
- `source-index.json`, `corresponding-source.tar.zst`: hash-verified Ubuntu source
  descriptors, original archives and distro patches; runtime source repositories
  including vendored Go dependencies; Go standard-library source; Cargo registry
  and explicitly pinned Git dependencies. The archive embeds the exact index.
  Supplemental source archives recover omitted crate notices. Where present,
  `.cargo_vcs_info.json` must identify the exact publication commit; mismatches
  are rejected. For four crates without that metadata, the lock explicitly
  selects source directories, original notice paths and hashes of Cargo's
  packaging metadata. Every other published file, including import-library
  binaries, must match the pinned repository bytes. `Cargo.toml.orig` must match
  its source manifest. Only individually pinned `Cargo.toml` and `Cargo.lock`
  files may differ; code, binary and wildcard exemptions are refused. These
  records say `publication_commit_proven: false`: matching published contents
  does not establish the upstream publication commit or approve redistribution.
- `distribution.sbom.syft.json`, `distribution.sbom.cdx.json`: combined native
  inventory used by Grype and the distribution's CycloneDX 1.6 inventory. APT
  source names replace ELF guesses. Runtime dependencies are checked against
  archived vendor versions and embedded source revisions when available.
- `build-provenance.json`, `builder-packages.tsv`, `supply-chain.json`: image,
  input, tool and source bindings. Promotion verifies the source archive's objects
  and Cargo closure, not only a self-reported checksum. It independently repeats
  supplemental notice checks from the bundled objects and rejects altered notice
  inventories or content-match records, even when their archive is rehashed.
- `vulnerabilities.grype.json`, `vulnerability-database.json`,
  `security-review.json`, `redistribution-review.json`: unabridged findings,
  exact database hash/date, expiring decisions and notice-review status.

The upstream Dragonfly binary is stripped. Its Cargo.lock closure is archived and
inventoried conservatively, including build/test/other-target crates. This does
not prove which crates are linked, nor that its upstream build used `--locked`.
CycloneDX composition therefore remains incomplete. Source-declared dependencies
are marked as such; they are not represented as scanner-observed file contents.

Package creation permits a development bundle with blocked review findings so
that evidence can be examined. `make PROFILE=agent security-gate`, candidate
signing and release promotion require passing security and redistribution
decisions. Inventory generation alone never approves redistribution.

The candidate workflow must run at its exact version tag, with workflow and
checkout at the same commit. GitHub keyless provenance signs `SHA256SUMS`, which
binds the image, SBOMs, sources, tests and reviews. Promotion verifies the Sigstore
certificate, transparency proof, digest, repository, workflow, source/signer
revision, tag and qualified run; self-hosted signers are refused. The public
attestation is shipped separately. This does not provide Secure Boot or signed
on-host updates; those remain issue #19.

Reproducibility is measured by independent builds of the same source and builder:

```sh
make PROFILE=agent build
make PROFILE=agent OUT_DIR="$PWD/out/repeated" build
python3 build/tools/reproducibility.py out/agent-cpu-arm64 \
  out/repeated/agent-cpu-arm64 --output out/agent-cpu-arm64/reproducibility.json
```

The comparison rejects changed inputs, records package selection, file-content
and metadata differences, artifact digests and differing 64-KiB disk/UKI regions.
It reports remaining nondeterminism instead of promising bit-identical images.
CI runs it independently for both profiles on native amd64 and arm64 runners.

No scanner, source downloader or compiler is installed in the OS. Model weights,
serving containers and Agent workloads remain separate supply-chain subjects.
See [security patch and review workflow](../security/README.md).

Primary references: [Ubuntu snapshots](https://snapshot.ubuntu.com/),
[Syft configuration](https://oss.anchore.com/docs/reference/syft/configuration/),
[Grype database](https://oss.anchore.com/docs/guides/vulnerability/database/),
[GitHub attestation verification](https://cli.github.com/manual/gh_attestation_verify).
