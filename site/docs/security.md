---
title: Security target
description: OuterSpace OS targets CIS Ubuntu Level 1 Server with Kubernetes and eBPF tailoring, documented release gates and no premature compliance claims.
---
# Security target

The target is **CIS Ubuntu Linux 24.04 LTS v2.0.0, Level 1 Server**, with explicit
Kubernetes/eBPF tailoring. CIS is the Center for Internet Security. Its benchmarks
provide configuration recommendations; choosing them is not a certification.

The image includes a read-only verity root, locked local accounts, no SSH server,
AppArmor availability, Kubernetes seccomp defaults, kernel-introspection restrictions,
audit rules and bounded logs. Runtime enforcement still requires testing.

## Material development limitations

- UKIs are unsigned; dm-verity alone does not establish boot authenticity.
- The state partition is unencrypted.
- There is no authenticated A/B updater or rollback implementation yet.
- Full CIS host and Kubernetes audit evidence is absent.
- Private P2P registry authorization and peer security remain unqualified.

## Evidence before claims

Run Canonical USG with a suitable Ubuntu Pro subscription and a reviewed tailoring
file on a disposable image instance. Preserve audit output. Select a Kubernetes
benchmark that matches the actual Kubernetes version and retain worker results.
Translate accepted remediations into the image build; do not blindly mutate an
enrolled worker with an audit tool's fix command.

Document every exception with applicability, rationale, owner, review date and
supporting tests. IP forwarding, trusted BPF agents and executable container state
need workload-aware policies. Never omit a rule solely to improve a score.

For the full target, see [security documentation](https://github.com/Alien6-Studio/outerspace-os/tree/main/security).
For sensitive reports, use GitHub's private reporting feature if enabled; otherwise
request a private reporting channel without posting exploit details publicly.
