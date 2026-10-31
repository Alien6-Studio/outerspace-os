---
title: Releases and maintenance
description: Status, qualified scope and limitations of OuterSpace OS 0.1.0-alpha.1, with the remaining release gates.
---
# Releases and maintenance

**Current version: `0.1.0-alpha.1` — qualified CPU alpha, release in draft.**
[Execution foundation](https://github.com/Alien6-Studio/outerspace-os/milestone/1)
is closed with all seven delivery issues completed. The draft contains the four
qualified images and their verification material. Public downloads will appear on
[GitHub Releases](https://github.com/Alien6-Studio/outerspace-os/releases) after
publication; no stable or production release is claimed.

## What the first alpha qualifies

| Profile | Architectures | Native scenarios |
| --- | --- | --- |
| Agent | AMD64, ARM64 | OCI admission/isolation, resource-pressure cases and worker recovery |
| Inference | AMD64, ARM64 | Real CPU serving, workload replacement/drain and worker recovery |

All four images passed two UEFI boots, persistence and host budgets,
Kubernetes/Cilium enrollment, certificate rotation, cold-boot recovery and their
own security/redistribution gates. Integration records also retain the static
Agent resource and operation-phase baselines with their exact image identities.

The distributions include checksums, GitHub attestations, SBOMs, **2,554
corresponding-source objects and 120 original APT notices** per reviewed inventory.
The release also preserves the native and integration records and provides a
verification companion. Attestations authenticate the inner `SHA256SUMS`; they
are not Secure Boot signatures.

- [Qualified version source](https://github.com/Alien6-Studio/outerspace-os/tree/v0.1.0-alpha.1)
- [Four-candidate qualification](https://github.com/Alien6-Studio/outerspace-os/actions/runs/41219970340)
- [Verified draft preparation](https://github.com/Alien6-Studio/outerspace-os/actions/runs/41230956048)
- [Remaining roadmap](https://github.com/Alien6-Studio/outerspace-os/issues/7)

## Evaluation limits

Use disposable CPU UEFI VMs; the native reference setup has four vCPUs and 4 GiB
RAM with Secure Boot disabled. A separate Kubernetes control plane is required.
Bare-metal/GPU qualification, authenticated A/B updates, production support and
performance guarantees are not included. Persistent state is unencrypted.

The accepted **CVE-2019-14899** risk expires on **14 November 2026 at 06:24:43 UTC**
and applies only to the stock CPU configuration without host VPNs or custom
networking. No universal kernel fix is claimed. Model weights and application
containers have separate provenance and licensing requirements.

## Qualification phases

OuterSpace uses its own `MAJOR.MINOR.PATCH` version, independent of Ubuntu, Linux
and Kubernetes. A version tag alone does not establish support.

| Phase | Intended use | Required evidence |
| --- | --- | --- |
| Alpha | Explicit experimental preview | Boot, CRI, configuration, checksums, notes, licenses/sources, SBOM, vulnerability review and profile-specific workload gates |
| Beta | Integration testing | Alpha gates plus cluster readiness, Cilium, P2P, image GC and state persistence |
| Release candidate | Hardware/security qualification | Beta gates plus bare metal, CIS audit, signed boot and upgrade/rollback |
| Stable | Supported operation within a published matrix | RC gates plus soak evidence and an explicit support policy |

The [policy](https://github.com/Alien6-Studio/outerspace-os/blob/main/build/release/policy.json)
and [release process](https://github.com/Alien6-Studio/outerspace-os/blob/main/build/release/README.md)
are authoritative. Release CI prepares a draft from existing qualified artifacts;
promotion does not rebuild them. Publication and later stages remain explicit decisions.

## Maintenance

Update reviewed, pinned inputs and deploy whole images. Preserve the source,
profile, architecture and image identity with every result. Reassess expiring
vulnerability decisions and retain original upstream notices. No supported
in-place update path or production support window is offered by this alpha.
