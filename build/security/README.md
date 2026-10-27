# Whole-image security patches and release review

`policy.json` owns the vulnerability threshold. Critical, High and Unknown
findings block promotion, including findings without a fix. Lower severities
remain in the report. Grype and its policy are pinned; its built-in header-only
ignore rules are recorded explicitly, and any actually ignored match fails the
review. No global package, CVE or unfixed-finding suppression is used.

The build refreshes Grype's database, then scans the combined native SBOM offline.
The report records the actual database SHA256, provider metadata and build date.
Packaging and promotion independently recompute decisions. Databases and scans
older than 120 hours, future timestamps, changed subjects and expired exceptions
are rejected. Scanners stay in disposable build/qualification tooling.

Runtime labs can qualify `-dev.N` images with unresolved findings, after checking
the complete integrity, source and review evidence. This explicit development
path rejects alpha/beta/RC/stable versions. Candidate promotion always requires
passing vulnerability and redistribution reviews; it never enables that path.

For each finding, inspect the original `vulnerabilities.grype.json`, installed
source package, architecture, binary symbols and upstream advisory. Ubuntu tracks
source names: for example, `runc-app` supplies the `runc` executable while `runc`
can refer to a different source library. Grype can report both names; retaining
the source name alone does not prove a finding inapplicable. A missing symbol is
not by itself proof of safety when indirect calls or another artifact can expose
the vulnerable behavior.

An exception in `policy.json` requires the exact `finding_key` from the report,
scope (profile, hardware profile, architecture, components-lock, Ubuntu/builder
input-lock and source-lock digests), owner,
authorized `approved_by`, review timestamp, expiry within 30 days, a detailed
rationale and HTTPS evidence. Decisions are `not-affected` or `accepted-risk`.
Unused scoped exceptions fail, and a changed dependency version/path cannot reuse
one. The initially empty exception list deliberately grants no risk acceptance.

For a patch:

1. Update the Ubuntu snapshot and CA bootstrap digest, or the exact runtime
   binary/source/tool locks. Keep both architectures and both profiles aligned
   where they share inputs. Review upstream signatures/digests before intake.
2. Build a new whole image from committed source. Do not run APT, replace runtime
   executables or inject scanners on deployed hosts.
3. Run `make check`, independent-build comparison, UEFI persistence/smoke,
   profile-specific enrollment/Agent isolation/resource tests and any affected
   capability tests on each native architecture. Retain original failures.
4. Review every blocking finding. Gather missing notices from the exact upstream
   source and record the redistribution decision in `build/licenses/reviews.json`.
   That approval must bind the report's exact source/notice subject; it cannot
   transfer to a different profile, architecture or dependency selection.
5. Produce a version-tagged candidate, pass `security-gate`, sign its checksum
   inventory, and qualify those exact bytes. Promotion verifies the signed
   inventory, archived sources, reviews and evidence without rebuilding.
6. If evidence expires before promotion, rescan the same immutable image/SBOM
   in isolated tooling and produce a newly qualified, signed candidate evidence
   bundle. Its image digest must remain unchanged; rerun affected checks after
   any actual image change. Never edit a signed bundle in place.

`redistribution-review.json` lists source archives lacking notice files and all
required distribution obligations. A license expression or an archived repository
is evidence, not a completed legal review. Reviews must resolve all missing
notice entries and record their rationale/evidence. No approval is synthesized.
Publish corresponding sources, distro patches, project source and original
notices alongside binaries; Apache-2.0 applies only to original project code.

To verify a downloaded candidate, first verify its `SHA256SUMS` with the provided
attestation using `build/tools/attestations.py`'s repository/workflow/tag/commit/run
constraints, then verify every listed file. The draft-release workflow performs
both steps automatically. Workload image approval remains in the supported
Kubernetes admission policy and its native negative tests; OS provenance is not
workload authorization.
