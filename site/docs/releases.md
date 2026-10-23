---
title: Releases and maintenance
description: OuterSpace OS release phases, versioning, evidence gates and maintenance policy from development through stable.
---
# Releases and maintenance

**Current status: `0.1.0-dev.0`. No stable or public alpha release exists.**

OuterSpace uses its own `MAJOR.MINOR.PATCH` version, independent of the Ubuntu,
Linux kernel and Kubernetes versions. It follows familiar prerelease conventions:

```text
0.1.0-dev.0 → 0.1.0-alpha.1 → 0.1.0-beta.1 → 0.1.0-rc.1 → 0.1.0
```

A tagged build is not automatically a supported release. Each stage requires
version- and commit-specific evidence. The validator refuses missing gates and
refuses publishing a `-dev.N` version as a release.

## Qualification phases

| Phase | Intended use | Required evidence |
| --- | --- | --- |
| Development | Internal engineering and disposable labs | Unit/contract checks and image build logs |
| Alpha | Explicit experimental preview | Boot, CRI, config contract, checksums, release notes and license/source review |
| Beta | Integration testing | Alpha gates plus Node Ready, Cilium, P2P, GC and state persistence |
| Release candidate | Frozen candidate for qualification | Beta gates plus bare metal, CIS audit, signed boot, upgrade/rollback, SBOM and vulnerability review |
| Stable | Supported operation within a published matrix | RC gates plus soak tests and an explicit support policy |

Release CI prepares **draft** releases after verification. Maintainer review and
complete evidence are required before publication. Stable status is never inferred
from a green build or a tag. No automatic promotion between stages occurs.

## Maintenance model

- Rebuild images from reviewed Ubuntu security/update packages; deploy whole images.
- Pin runtime binaries and verify SHA256. Review kernel ABI and dependent modules together.
- Run regular integration builds to detect package and upstream drift.
- Review dependency updates in pull requests, including release notes and migration risks.
- Record exact package manifests, runtime versions, architecture and source commit.
- Qualify upgrade, downgrade and persistent-state compatibility before promotion.

Prelaunch work has no production support commitment. A stable branch must state
its support dates, architectures, kernel/runtime/Kubernetes matrix and security
response ownership before it can pass the support gate. Upstream Ubuntu LTS
coverage does not automatically confer support on this distribution.

## Launch sequence

1. Publish source and clearly marked development documentation.
2. Qualify and publish alpha artifacts with known limitations.
3. Validate on a dedicated bare-metal worker, then a self-managed cloud VM cluster.
4. Complete beta integration and RC security/update gates.
5. Publish support policy and stable artifacts with checksums, SBOM and provenance.
6. Only then apply to distribution directories with accurate status and licensing.

The authoritative [release policy and evidence contract](https://github.com/Alien6-Studio/outerspace-os/tree/main/release)
live with the build source. There is no downloadable stable image at this stage.
