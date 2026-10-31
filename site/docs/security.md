---
title: Security scope
description: Enforced CPU alpha boundaries, reviewed supply-chain decisions and the limits of the current OuterSpace OS qualification.
---
# Security scope

The CPU alpha has passed actual-image boot, native workload and supply-chain
checks. The Agent profile has demonstrated admission refusals, AppArmor/seccomp
enforcement, bounded resource pressure and recovery. These results qualify the
stated shared-kernel profile, not arbitrary untrusted tenancy or production use.

Each distribution includes an SBOM, corresponding sources, original notices,
unfiltered vulnerability reports and accountable review decisions. The four
checksum inventories have GitHub attestations tied to their exact source, tag
and candidate workflow. Promotion verifies every payload before preparing a draft.

## Time-limited accepted risk

**CVE-2019-14899 is accepted only for the stock CPU alpha until 14 November 2026,
06:24:43 UTC.** No host VPN client or configured VPN tunnel is included in this
qualification. IPsec/XFRM remains compiled for Cilium; no universal kernel fix is
claimed. Host VPN setup and custom network configurations are outside this scope.

The recorded kernel non-applicability decisions and source/notice reviews are
conditional on the verified inputs and configuration. Unknown findings remain
blocking, and expired decisions must be reviewed again.

## Remaining limits

- UKIs are unsigned; dm-verity alone does not authenticate boot. Disable Secure Boot for this alpha.
- Persistent state is unencrypted, and no authenticated A/B updater or rollback is supplied.
- Bare-metal and GPU configurations have not been qualified.
- Agent authority brokers, fleet quarantine, private P2P authorization and peer security remain roadmap work.
- A full CIS audit and production support commitment are not present.

CIS Ubuntu Level 1 Server remains an audit target with explicit Kubernetes/eBPF
tailoring, not a certification. Hardware, signed updates and fleet adversarial
qualification belong to the later milestones.

See the [security policy](https://github.com/Alien6-Studio/outerspace-os/blob/main/SECURITY.md)
and [recorded release decisions](https://github.com/Alien6-Studio/outerspace-os/tree/main/build/security).
Report vulnerabilities through the repository's
[private advisory channel](https://github.com/Alien6-Studio/outerspace-os/security/advisories/new).
