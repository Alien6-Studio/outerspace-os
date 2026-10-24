# Hardening and CIS evidence

The security target is the **CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.0,
Level 1 Server**, plus applicable Kubernetes worker controls from the CIS
Kubernetes Benchmark. Pin the exact Kubernetes benchmark revision when the
cluster minor version and audit tooling have been qualified.

This is a target profile, **not an audit result, conformance score or CIS
certification**. A read-only image, AppArmor and a few sysctls are not enough to
assert full benchmark compliance. Use the licensed benchmark text and record
control-by-control evidence rather than inventing rule identifiers here.

## Already represented in the image

- Locked root and no SSH daemon; kubelet TLS bootstrap and webhook authorization.
- Read-only verity-protected root; executable state separated under `/var`.
- AppArmor, seccomp-by-default for Kubernetes containers, auditd and kernel-module
  audit rules. Core dumps disabled; bounded journald storage.
- Restricted kernel pointers, kernel logs, unprivileged BPF and perf access.
- Selected unused filesystems/protocols blocked through modprobe policy.
- Host temporary storage mounted nodev/nosuid/noexec; no swap is provisioned.

These configurations still require runtime enforcement and failure-path tests.
Development UKIs are unsigned, and the initial state partition is unencrypted.
They are material outstanding boot-authenticity and data-at-rest decisions.

## Required tailoring decisions

| Requirement area | Worker-specific decision | Evidence required |
| --- | --- | --- |
| IP forwarding | Enabled for Kubernetes traffic | CNI connectivity and isolation tests |
| eBPF | Privileged trusted agents allowed; unprivileged BPF disabled | BTF/BPF feature checks, Cilium policy tests |
| Kernel modules | Network/storage/GPU modules needed; no blanket modules_disabled | Hardware profile and module-load audit |
| `/var` execution | Container roots execute from runtime state; no blanket noexec | Container execution and privilege tests |
| Local accounts / SSH | Remote interactive administration absent | Account lock and listener inventory |
| Root filesystem verification | dm-verity present; Secure Boot pending | Signed boot and tamper rejection |
| Firewall | Must match CNI and Dragonfly peer topology | Allowed-flow and denied-flow test matrix |
| Audit rules | Image rules present; full benchmark coverage pending | Persistent audit report and retention policy |
| Model and image caches | Writable application data | Tenant access, GC and recovery tests |

No deviation is automatically approved for production. Every deviation needs an
owner, rationale, test evidence and a review date before a release is called
hardened. Exclude a rule only with documented applicability, not to improve a score.

## Audit workflow to qualify

Canonical's USG can audit `cis_level1_server` with a suitable Ubuntu Pro
subscription. Run audit tooling against a disposable image instance with an
explicit tailoring file and preserve XML/HTML output. Keep the OS identity
Ubuntu-compatible for tooling. Do not run `usg fix` blindly on an enrolled worker;
translate accepted remediations into the image build, rebuild and rerun the audit.

Kubernetes worker checks need a live disposable cluster. Add node configuration
and file-permission evidence there, with a pinned kube-bench/CIS profile matching
the Kubernetes version. A VM boot smoke test does not substitute for these audits.

Sources: [CIS Ubuntu benchmark versions](https://www.cisecurity.org/benchmark/ubuntu_linux),
[Ubuntu Security Guide](https://documentation.ubuntu.com/security/compliance/usg/),
[USG support for Noble](https://ubuntu.com/blog/hardening-automation-for-cis-benchmarks-now-available-for-ubuntu-24-04-lts).
