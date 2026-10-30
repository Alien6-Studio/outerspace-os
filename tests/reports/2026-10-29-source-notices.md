# Supplemental source notices, 2026-10-29

Local qualification recovers original notices for four additional crates in the
archived Dragonfly Cargo closure. This verifies corresponding source contents;
it does not qualify a rebuilt OS image or approve public redistribution.

## Evidence basis

The four crates have no `.cargo_vcs_info.json`. Their original manifests and
every published file other than explicitly pinned Cargo packaging metadata match
the following immutable upstream repositories:

| Crate | Upstream revision | Matched files | Packaging metadata retained separately |
| --- | --- | ---: | --- |
| `valuable 0.1.0` | [tokio-rs/valuable e89de880](https://github.com/tokio-rs/valuable/tree/e89de8805f524aefafdbcc1fcd1b20ecfd0d22b6) | 19 | `Cargo.toml`, `Cargo.lock` |
| `symbolic-common 12.8.0` | [getsentry/symbolic 032b134a](https://github.com/getsentry/symbolic/tree/032b134a3f45316bf37accd29712d832557e55af) | 9 | `Cargo.toml` |
| `winapi-i686-pc-windows-gnu 0.4.0` | [retep998/winapi-rs 9497609e](https://github.com/retep998/winapi-rs/tree/9497609ef44cc9bcd16cd2411c0ee6ccaf5483aa) | 1,390 | `Cargo.toml` |
| `winapi-x86_64-pc-windows-gnu 0.4.0` | same revision | 1,419 | `Cargo.toml` |

All 2,837 matched files are compared by SHA256 and size, including the Windows
import libraries. `Cargo.toml.orig` maps to the source `Cargo.toml`. The complete
upstream archives preserve the original root `LICENSE` or `LICENSE-APACHE` and
`LICENSE-MIT` files. The lock identifies their exact paths and preserves each
packaging file's hash. No generated binary is exempted from matching.

The source index records `basis: published-files-match` and
`publication_commit_proven: false` for these four crates. The 30 earlier recovered
crates retain their separate `cargo-vcs-publication-commit` basis. Existing VCS
metadata cannot be overridden by the content-matching mechanism.

## Local verification

`make check` passes all 146 tests. Nine new tests cover complete matches, changed
or additional code, unmatched generated binaries, forbidden exemptions, altered
packaging/license identity, conflicting VCS metadata, absent implicit fallbacks,
unsafe or duplicate archive paths, and rehashed bundles with forged notice
inventories or provenance records.

The real source archive was regenerated and independently read back with the
preserved Agent arm64 APT source inventory. All 937 objects passed checksum and
source-closure verification. Promotion recomputes both proof methods and notice
inventories from the archive; it does not trust the index's asserted matches.

| Artifact | SHA256 |
| --- | --- |
| `build/sbom/sources.lock.json` | `e36c0f1d2de38c357fd72690a8b53411386a5cf339df4cf3f79deb6c12e58b9e` |
| `source-index.json` | `d7e76f5bc41c72f6f15392da62b4cb67f3c789843025c50891d61b4c11b62c40` |
| `corresponding-source.tar.zst` | `f70326ab252476a024ce3654f78b9b3195b38beccc0dda887b3e7e8a9469c8d6` |

The local audit is retained under `out/notice-audit-20261029/`. To repeat source
qualification with a preserved profile-specific APT inventory:

```sh
python3 build/tools/source-bundle.py --cache .cache/source-inputs \
  --output out/notice-audit --apt-inputs path/to/apt-inputs.json
```

## Remaining acceptance

The recovered total is 34 crates. `crc32c 0.6.8`, `crunchy 0.2.2`,
`http-serde 2.1.1` and `rustls-platform-verifier-android 0.1.1` remain unresolved.
The Android crate includes generated Maven files and an AAR absent from the
examined repository; matching its Rust source and manifest is insufficient to
accept the complete crate under this rule.

The source-bound redistribution result remains `review-required`; no approval
or vulnerability exception was added. Exact dependencies linked into the
stripped upstream Dragonfly binary, vulnerability triage and positive signed
candidate qualification remain separate open requirements of issue #9. This
local audit does not change the already qualified #24/#29 source/image pairs.
