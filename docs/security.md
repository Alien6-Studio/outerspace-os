# Host security controls

The image configuration lives in [`src/image/`](../src/image/). The following
controls describe that configuration, not a CIS certification or completed audit.

- Locked root and no SSH daemon; kubelet TLS bootstrap and webhook authorization.
- Read-only verity-protected root; executable state separated under `/var`.
- AppArmor, seccomp defaults for Kubernetes containers, auditd and module audit
  rules. Core dumps disabled; bounded journald storage.
- Restricted kernel pointers, kernel logs, unprivileged BPF and perf access.
- Selected unused filesystems/protocols blocked through modprobe policy.
- Host temporary storage mounted nodev/nosuid/noexec; no swap is provisioned.

The [native Agent profile](../src/cluster/README.md#native-oci-agent-v1-profile)
adds workload admission, AppArmor, resource limits and network policy.
Image-bound runtime reports establish what was actually exercised.

Development UKIs are unsigned and the state partition is unencrypted. Verity
detects root corruption only while the expected hash is trusted. Containers
share the host kernel; their resource limits do not authorize tool actions or
protect credentials on behalf of an application.

## Worker-specific constraints

| Area | Configuration and required evidence |
| --- | --- |
| IP forwarding | Enabled for Kubernetes; CNI connectivity and isolation checks |
| eBPF | Privileged trusted agents allowed, unprivileged BPF disabled; BTF/BPF and Cilium checks |
| Kernel modules | Network/storage modules retained; hardware and module-load audit |
| `/var` execution | Container roots execute from runtime state; privilege and execution checks |
| Accounts and SSH | Remote interactive administration absent; account and listener inventory |
| Root verification | dm-verity present, Secure Boot pending; authenticated boot and tamper rejection |
| Firewall | Must match CNI and peer topology; allowed and denied flow checks |
| Audit rules | Image rules present; full control coverage and retention audit pending |
| Caches | Writable application data; tenant access, cleanup and recovery checks |

The CIS audit and control-by-control tailoring belong to
[#20](https://github.com/Alien6-Studio/outerspace-os/issues/20). Authenticated boot
and updates belong to [#19](https://github.com/Alien6-Studio/outerspace-os/issues/19).
Dependency vulnerabilities and redistribution review belong to
[#9](https://github.com/Alien6-Studio/outerspace-os/issues/9). Configuration and
scanner output alone do not close those requirements.

See the [security policy](../SECURITY.md) for private reporting and the
[release policy](../build/release/README.md) for publication gates.
