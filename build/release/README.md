# Release and maintenance policy

Current channel: **development**, `0.1.0-dev.0`. No supported production release,
public alpha, CIS certification or published performance guarantee exists.

## Version identity

Assembly passes the root `VERSION` to mkosi with `--image-version`.
Use `MAJOR.MINOR.PATCH[-dev.N|-alpha.N|-beta.N|-rc.N]` and
Git tags `v` followed by that exact value. Prerelease counters start at 1; dev
snapshots may start at 0. There are no moving `latest` release tags.

Example: `0.1.0-dev.0 → 0.1.0-alpha.1 → 0.1.0-beta.1 → 0.1.0-rc.1 → 0.1.0`.
A candidate's software change creates a new candidate number and invalidates its
previous qualification. Never overwrite a tag or replace a published artifact.

- **MAJOR:** incompatible configuration, persistent-state or support-contract change.
- **MINOR:** a new tested capability or compatible hardware/runtime support profile.
- **PATCH:** compatible fixes and security rebuilds, including package-only changes.
- Before 1.0, breaking experiments still need explicit migration notes. Stable
  *channel* and 1.0 maturity are separate decisions; neither follows automatically.

Ubuntu release, kernel ABI, containerd, kubelet, Cilium and Dragonfly have their own
versions. Record them in inventories and compatibility matrices, not in the distro
version string. An upstream Linux LTS label is not an Ubuntu kernel support policy.

## Phase gates

The machine-readable minimum gates are in [policy.json](policy.json). All gates
are cumulative. Missing, pending or failed evidence blocks release preparation.

Schema 2 also requires independent evidence for every profile/hardware/architecture
in the policy matrix. Agent images require isolation and resource-limit gates;
Inference images require real CPU serving. Selected optional capabilities add
their own gates. GPU capability is refused on CPU artifacts. Copy each candidate's
complete `build-identity.json` into its artifact `identity` and every gate's
`subject`; no gate or checksum from another artifact can qualify it. The example
contains pending placeholders, not qualification results.

| Stage | Audience / expectation | Additional gates |
| --- | --- | --- |
| dev | Internal engineering, disposable labs | Tests and build feedback; cannot be released |
| alpha | Experimental preview, data loss possible | Boot, CRI, config contract, checksums, notes, license/source review |
| beta | Cluster integration testers | OS node ready, Cilium, real P2P, GC, state/reboot |
| rc | Frozen production candidate | Bare metal, CIS audit, signed boot, upgrade/rollback, SBOM, vulnerability review |
| stable | Supported within an explicit matrix | Soak qualification and published support policy |

A kind lab uses Docker's kernel. It cannot satisfy the `cluster_ready`, `cilium`
or `dragonfly_p2p` gates for an OuterSpace image. `make smoke` now exercises full
UEFI disk boot and state/hostname persistence across two cold starts. Its report
is bound to the raw image hash and required by packaging. The diagnostic
split-kernel test cannot satisfy this requirement. Neither test qualifies Secure
Boot, a physical server or persistence of a rotated kubelet identity. Each evidence record
must say which architecture, hardware, image checksum and scenario it covers.
An alpha explicitly documents its unsigned boot and absent updater. RC/stable
cannot waive those minimum gates by changing their descriptions.

## Build once, qualify, promote the same bytes

1. Prepare a reviewed change on `main` (or later a supported `release/X.Y` branch).
   Update VERSION, locked runtimes/hashes, kernel ABI and version-specific notes.
   Define the exact configuration and hardware matrix for this release.
2. Create an immutable candidate tag after contracts pass. Run **Candidate images**
   with that existing tag. The Agent/Inference × native amd64/arm64 matrix builds, QEMU-smokes, packages
   and upload candidate bundles. No release is published by a tag push.
3. Download those bundles and run the phase-specific tests against these exact
   images. Preserve logs/reports outside the source commit, so evidence can refer
   to that commit without a self-referential Git hash. Record candidate run ID,
   full source SHA and the SHA256 of each bundle's `SHA256SUMS` file.
4. Complete [evidence.example.json](evidence.example.json). Attach version-specific
   release notes in `build/release/notes/VERSION.md` before tagging. A human reviewer
   checks evidence quality; a nonempty URL alone is not proof of compliance.
5. Run **Prepare draft release** with tag, successful candidate run ID and evidence
   JSON. It validates all gates, downloads that run's candidates, checks identity,
   bound inventories and every file hash, and prepares a GitHub **draft** release.
   It never rebuilds during promotion and never marks a release public itself.
6. Inspect the draft, provenance/signature reports, limitations, upgrade directions
   and support matrix. Publish only after the release owner accepts the evidence.
   Alpha/beta/RC remain GitHub prereleases; stable publication also needs support.
7. Update the website's displayed version/status and support/download links in a
   separate `gh-pages` change. Keep directory submissions consistent with reality.

Candidates expire after 30 days in Actions storage. If artifacts have expired,
build a new candidate and repeat qualification. Do not silently rebuild and reuse
the old evidence. SHA256 inventories are integrity checks, not cryptographic proof
of the publisher's identity. Signed provenance and trusted boot require separate
implementation and review before RC.

The validator enforces gate status and identity, not the truth of an audit report.
Repository access and workflow review remain part of release trust. No stable
release should be created while signing/updater/audit gates are unimplemented.

## Release contents

Per profile, hardware and architecture: a tar bundle containing compressed raw disk, UKI, exact package
manifest, runtime lock, build metadata, QEMU log and SHA256SUMS. The tar also gets
an external checksum; qualification evidence accompanies the draft. The manifest
is an inventory, not a complete SPDX/CycloneDX SBOM. RC requires a proper SBOM,
license review and vulnerability report, including non-apt upstream binaries.
The initial apt inputs are signed Noble repositories, not snapshot-locked;
bit-for-bit reproducibility must not be claimed yet.

## Maintenance cadence and ownership

- **Weekly automated checks:** rebuild both architectures from current signed
  Ubuntu repositories; preserve logs/inventories; run contract and boot tests.
  Dependabot proposes Docker base-image and GitHub Actions updates in PRs.
- **Weekly maintainer review:** Ubuntu security notices, kernel ABI, containerd LTS,
  Kubernetes skew/support, Cilium and Dragonfly releases. The custom component lock
  is updated by reviewed PR with upstream digest verification, not Dependabot.
- **Security fixes:** triage applicability and exploitation, prepare a patch image,
  run relevant regression/update tests and document affected versions. An urgent
  fix can shorten soak only through a documented risk decision; signing, integrity
  and successful boot cannot be skipped. Prelaunch has no response-time SLA.
- **Monthly integration review:** cluster join, denied/allowed network paths, P2P
  origin/peer outages, cache pressure/restarts and inference readiness benchmarks.
- **Before every release:** update the dependency/kernel matrix, known CVEs and
  accepted exceptions with owner, rationale, expiry and compensating controls.

Whole-image updates replace in-place apt maintenance. A supported lifecycle must
pair node drain, authenticated download, A/B root+UKI transaction, boot attempt
counting, health commit and rollback. Until implemented, rebuilds are lab images,
not a fleet rollout mechanism. GPU modules must match the pinned kernel ABI and
be rebuilt, signed and tested in the same release transaction.

## Stable support contract (required before launch)

Publish an owner and contact channel, start/end dates, supported architectures and
server/GPU models, Ubuntu/kernel/runtime/Kubernetes matrix, upgrade paths, state
schema compatibility, rollback/downgrade limits and vulnerability response process.
Choose support duration only after capacity and upstream lifecycles are reviewed.
No implicit support extension comes from Ubuntu LTS or a component LTS label.

## Prelaunch communication and directories

The website must show the actual channel on home, release pages and download links.
Use “development”, “preview” and “release candidate” consistently. No fake stable
button, certification badge, unmeasured speed claim or unsupported managed-AKS claim.

Before applying to distribution directories: finalize source licensing and
redistribution notices, publish independently installable qualified artifacts,
checksums/signatures, release notes, support/security contacts and hardware/install
instructions. Verify each directory's current admission rules at submission time.
Listing is a later launch task, not evidence of technical qualification.

## Project licensing

Original OuterSpace source uses Apache License 2.0. Upstream components retain
their licenses. License notices, transitive dependencies, firmware redistribution
and exact corresponding-source availability must pass review before any public
alpha binary. Development CI publishes logs and inventories only; candidate images
remain qualification artifacts until that review is complete.
