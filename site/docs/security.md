---
title: Security
description: Understand the host and workload protections, and the boundaries of the CPU alpha before evaluating it.
---
# Security for the CPU alpha

OuterSpace separates the read-only host system from writable node state. The
Agent profile adds restricted execution and resource budgets for task containers.
Use the alpha in a disposable evaluation environment under one trusted
administrative domain.

## Host and workload protections

- **Read-only root.** dm-verity detects corruption of the system filesystem.
  It does not authenticate the boot chain; Secure Boot must be disabled for
  this alpha.
- **Restricted Agent tasks.** The supplied profile requires AppArmor, seccomp
  and unprivileged execution. It refuses host access and privilege escalation,
  and enforces resource budgets. Network access is denied unless the operator
  explicitly permits it.
- **Worker identity.** Kubernetes enrollment uses a short-lived bootstrap token
  and certificate rotation. The enrolled worker keeps its identity after reboot.
- **Verifiable downloads.** Release bundles include checksums, GitHub
  attestations, a software inventory, corresponding sources and original license
  notices. Follow the [verification steps](getting-started.md#verify-a-release-bundle)
  before using a downloaded image.

## Boundaries to understand

Agent tasks share the host kernel. This alpha is not intended to isolate mutually
untrusted tenants and supplies no credential broker or approval service.

Persistent node state is **unencrypted**. There is no authenticated A/B updater
or rollback mechanism. Keep important data externally and plan to recreate
evaluation nodes. The release has no CIS certification, production support
commitment or qualified GPU/bare-metal hardware matrix.

Optional Dragonfly peer delivery remains experimental. Private-image access
control, peer security and fleet cache behavior are outside the evaluated alpha
scope; do not use it to share private images across tenants.

## Time-limited kernel risk

**CVE-2019-14899 is accepted only for the stock CPU alpha until 14 November 2026,
06:24:43 UTC.** That scope excludes host VPN clients, configured VPN tunnels and
custom network configurations. IPsec/XFRM remains compiled for Cilium; no
universal kernel fix is claimed.

The acceptance is conditional on the reviewed image and configuration. It does
not extend to a modified image or beyond its expiry date. The release bundles
retain the vulnerability reports and recorded review decisions.

## Report a vulnerability

Use the [private security advisory channel](https://github.com/Alien6-Studio/outerspace-os/security/advisories/new).
Include the version, profile, architecture and steps needed to reproduce the
problem. See the [security policy](https://github.com/Alien6-Studio/outerspace-os/blob/main/SECURITY.md)
for reporting details.
