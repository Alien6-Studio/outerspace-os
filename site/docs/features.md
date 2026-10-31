---
title: Capabilities and status
description: Qualified CPU alpha capabilities and the remaining Agent security and Fleet qualification work.
---
# Capabilities and status

**Execution foundation is complete: seven delivery issues closed.**
The four CPU candidates for `0.1.0-alpha.1` passed independently. The release
is currently a draft.

| Area | Qualified or implemented in this alpha | Remaining scope |
| --- | --- | --- |
| Worker profiles | Independent Agent/Inference images on AMD64 and ARM64 | Bare-metal and GPU hardware matrices |
| Boot and state | Two UEFI boots, read-only dm-verity root, persistent state | Authenticated Secure Boot and A/B rollback |
| Kubernetes | Real OuterSpace nodes, CRI, certificate rotation and cold-boot recovery | Fleet-scale lifecycle and upgrades |
| Networking | Cilium/Envoy, DNS/services and default-deny/allow on each image | Custom networking and host VPNs |
| Agent execution | Native OCI admission, AppArmor/seccomp enforcement and resource-pressure cases | Scoped credentials, approvals, egress mediation and quarantine |
| Inference | Real CPU model serving, replacement, drain and recovery | GPU/CDI, shared tenancy and serving QoS |
| Resource evidence | Static baselines and trusted operation-phase measurements | Hardware capacity claims and adaptive-budget research |
| OCI delivery | Optional native Dragonfly component and explicit routing | P2P, private auth, peer security and cache lifecycle qualification |
| Supply chain | SBOMs, sources/notices, reviewed vulnerabilities and attested checksums | Ongoing updates and renewal of expiring decisions |
| Release | Four qualified CPU candidates and verified draft preparation | Public publication, then later beta/RC/stable gates |

The [roadmap](https://github.com/Alien6-Studio/outerspace-os/issues/7) tracks the
remaining **Agent security** and **Fleet qualification** milestones. No general
latency, energy, image-size reduction or CIS compliance claim follows from these
reference results. See [security](security.md) and [release information](releases.md).
