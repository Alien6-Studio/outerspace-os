---
title: Capabilities and status
description: Implemented foundations and outstanding qualification gates for the OuterSpace OS development image.
---
# Capabilities and status

| Area | Implemented foundation | Still to qualify |
| --- | --- | --- |
| Minimal host | Ubuntu package assembly, no desktop or model framework | Hardware-specific footprint and firmware |
| Immutable root | Read-only ext4 with dm-verity | Signed boot, tamper tests, A/B rollback |
| Kubernetes runtime | containerd, kubelet, CRI tools | OS node enrollment and real inference pod |
| eBPF | Kernel checks, Cilium profile, local kind policy test | Cilium on an enrolled OuterSpace node |
| Image delivery | Native Dragonfly peer, explicit registry routing | P2P metrics, outage cases, private auth, peer security |
| Cache cleanup | Kubelet max age/pressure and separate peer TTL | Long-running GC, restart and disk-pressure tests |
| Hardening | Accounts locked, AppArmor, seccomp defaults, audit and sysctls | CIS audit, tailoring, enforcement and vulnerability evidence |
| Accelerators | CPU foundation | GPU kernel/driver/CDI profile and hardware tests |
| Releases | Version and evidence gate validator | Qualified preview artifacts, signing and supported stable branch |

No latency, image-size reduction percentage or CIS compliance score is published
without a reproducible measurement. See [security](security.md) and
[release qualification](releases.md).
