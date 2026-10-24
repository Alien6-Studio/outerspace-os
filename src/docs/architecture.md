# Distribution architecture

## Product boundary

OuterSpace targets a minimal execution host for inference and isolated agents.
The first implemented profile is a Kubernetes inference worker. Kubernetes control
planes, agent frameworks, training toolchains and a desktop are outside the host image.
Compatibility with ordinary OCI images and Kubernetes CRI is the baseline.

The [agent execution direction](agent-execution.md) defines a lightweight OS
boundary independent of optional services such as OpenShell. Agent isolation
profiles and OpenShell compatibility remain unqualified future work.

Ubuntu Noble provides the kernel, glibc, systemd, AppArmor, network stack and
security package updates. mkosi assembles a new image from the selected packages;
systemd-repart creates its GPT layout. The pinned generic server kernel includes
extra hardware modules and required eBPF/BTF capabilities. Firmware is selected
per hardware fleet; `full-firmware` is an optional larger discovery profile.
Bare-metal NIC/storage coverage must be qualified on actual server models.

## Storage and boot

| Partition | Purpose | Mutability |
| --- | --- | --- |
| EFI system partition | systemd-boot and UKI | Writable boot assets; unsigned in development |
| `OOS_ROOT` | Host software and static configuration | Read-only ext4, dm-verity data |
| `OOS_VERITY` | Root hash tree | dm-verity hash partition |
| `OOS_STATE` | `/var`: CRI storage, kubelet identity, logs | Writable ext4 |

The root hash is embedded in the UKI command line. This detects corruption only
when that expected hash is trusted. Development images are unsigned: an attacker
able to replace boot assets could replace both the kernel and expected hash.
Signed UKIs with an owned Secure Boot trust chain are required before asserting
boot authenticity. dm-verity does not authenticate mutable workload state.

`/etc` is static. `/run` and `/tmp` are volatile. `/opt` must point into persistent
state for CNI installers; the image creates `/opt/cni -> /var/lib/cni`. Root is
never made writable just to accommodate a Kubernetes DaemonSet. Kernel modules
are fixed by the image; no compiler or DKMS installation at node startup.

The initial partition scheme has one root slot. It deliberately contains no
unverified updater. A/B root and matching UKI, signed release metadata, boot
attempt counting, node health confirmation, rollback and Kubernetes drain are
required as one update transaction. Root and UKI cannot be switched independently.

## Container execution

containerd 2.3 is the selected upstream LTS line. Its config schema is v3. Kubelet
and runc use systemd cgroups. Network forwarding and bridge netfilter are enabled;
an arbitrary host firewall is not installed before a CNI policy is chosen.
Containerd and kubelet retain the privileges and mount propagation they require.
Applying `ProtectSystem=strict` or `PrivateMounts` to these daemons would break
privileged CSI/CNI operations and is not a substitute for workload isolation.

Host protections include AppArmor availability, kubelet anonymous auth disabled,
webhook authorization, TLS bootstrap, serving-certificate requests, certificate
rotation, seccomp-by-default for pods, restricted kernel introspection, no swap,
locked root and no remote login daemon. AppArmor *availability* is not a claim
that a particular application profile has been enforced. GPU driver loading,
unprivileged user namespaces and CNI eBPF requirements need compatibility tests.
No CIS compliance or CVE-free status is claimed.

## Image delivery

The default is native overlayfs. `discard_unpacked_layers` permits garbage
collection of compressed blobs after extraction, reducing duplicated storage.
This trades away locally exporting/reusing those blobs without fetching them
again. CRI image prefetch uses digest-pinned references; it does not clear a
running node's cache or claim that cached content will never be garbage-collected.

Containerd reads registry hosts from `/var/lib/outerspace/certs.d`. The config drive
can route selected registries through the native Dragonfly peer's loopback proxy,
while retaining HTTPS origin resolution and fallback. The peer is a sandboxed
dynamic system user with writable state confined to its own directories. See
[cluster integration](../cluster/README.md) for its separate cache lifecycle.
No external HTTP registry or `skip_verify` setting is generated. Private registry
P2P authorization, peer mTLS and custom mirror certificates still need qualification.

Dragonfly is the selected P2P delivery mechanism and is activated per node through
configuration. Remote snapshotting (stargz or Nydus) remains optional future work.
Both must beat the baseline on time-to-ready and bytes transferred and pass
registry authentication, token scope, integrity, failure/restart, garbage
collection and disconnected-node tests. Stargz 0.19 changed its CRI image-service
endpoint requirement for a security fix: adopting an older example configuration
without that review is unacceptable.

Model weights have a separate lifecycle. A container starting quickly does not
prove that inference is ready: weights may still need downloading, mapping into
RAM/VRAM and engine initialization. Content-addressed shared model caches and
prefetch policy should be measured separately from OCI layer transport.

## Hardware profiles

The core image supplies CPU inference workers. A future NVIDIA profile must lock
the kernel/module ABI, driver version, firmware and container toolkit, expose
devices through CDI and pass a real inference workload. User-space CUDA remains
in containers. AMD and other accelerators require their own tested profiles.
No GPU support is claimed by merely installing a device plugin.

## Security target

The host targets CIS Ubuntu Linux 24.04 LTS v2.0.0 Level 1 Server with documented
Kubernetes/eBPF tailoring. Audits and their evidence are required before claiming
conformance; see the [security profile](security.md). Cilium is the first
eBPF integration; its BPF programs and toolchain run in trusted cluster agents.

## Sources used for the initial design

- [Ubuntu 24.04 support and release notes](https://documentation.ubuntu.com/release-notes/24.04/)
- [mkosi v25.3 reference](https://github.com/systemd/mkosi/blob/v25.3/mkosi/resources/man/mkosi.1.md)
- [Kubernetes container runtimes and systemd cgroups](https://kubernetes.io/docs/setup/production-environment/container-runtimes/)
- [containerd release lifecycle and Kubernetes compatibility](https://github.com/containerd/containerd/blob/main/RELEASES.md)
- [stargz releases and security changes](https://github.com/containerd/stargz-snapshotter/releases/tag/v0.19.0)
