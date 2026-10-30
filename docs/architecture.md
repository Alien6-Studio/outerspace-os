# Distribution architecture

OuterSpace provides Agent and Inference CPU profiles for Kubernetes workers.
Ubuntu Noble supplies the kernel, glibc, systemd, AppArmor and network stack;
mkosi assembles the image and systemd-repart creates its GPT layout. Kubernetes
control planes, agent frameworks, language runtimes, model engines and weights
live outside the host image.

## Storage and boot

| Partition | Purpose | Mutability |
| --- | --- | --- |
| EFI system partition | systemd-boot and UKI | Writable boot assets; unsigned in development |
| `OOS_ROOT` | Host software and static configuration | Read-only ext4, dm-verity data |
| `OOS_VERITY` | Root hash tree | dm-verity hash partition |
| `OOS_STATE` | `/var`: CRI storage, kubelet identity, logs | Writable ext4 |

The expected root hash is embedded in the UKI command line. Development images
are unsigned, so verity detects corruption while that hash is trusted; it does
not authenticate replaceable boot assets or mutable workload state.

`/etc` is static; `/run` and `/tmp` are volatile. `/opt/cni` points to
`/var/lib/cni` for CNI installers. Kernel modules are fixed in the image; no
compiler or DKMS installation runs at node startup. The layout has one root slot
and no updater. Authenticated updates and rollback are tracked in
[#19](https://github.com/Alien6-Studio/outerspace-os/issues/19).

## Container execution

Runtime versions and checksums are pinned in
[`components.lock.json`](../src/components.lock.json). Containerd uses config
schema v3; kubelet and runc use systemd cgroups. Forwarding and bridge netfilter
are enabled for Kubernetes traffic. Runtime privileges and mount propagation
must allow CSI/CNI operations.

The [native OCI Agent profile](../src/cluster/README.md#native-oci-agent-v1-profile)
uses Kubernetes admission, cgroup v2 limits, AppArmor, seccomp and Cilium policy.
Containers share the host kernel. This profile does not supply VM isolation,
workload credentials or approval of agent actions. Agent dependencies remain in
workload containers. See [host controls](security.md) for configuration limits.

## Image delivery

The default snapshotter is native overlayfs. `discard_unpacked_layers` permits
collection of compressed blobs after extraction; reusing them can require a new
fetch. CRI prefetch uses digest-pinned references and does not clear a running
node's cache.

Containerd reads registry hosts from `/var/lib/outerspace/certs.d`. The config
drive can route selected registries through the native Dragonfly peer's loopback
proxy, retaining HTTPS origin resolution and fallback. The peer runs as a
sandboxed dynamic system user with its own writable state. No external HTTP
registry or `skip_verify` setting is generated. See
[cluster integration](../src/cluster/README.md) for configuration and cache
retention. Private-registry P2P authorization, peer mTLS and custom mirror
certificates still need qualification.

Agent workspaces and secrets do not belong in the OCI cache. Model weights are
workload data with a separate download, loading and readiness lifecycle.

## Qualification and scope

CPU profiles target amd64 and arm64. Native VM reports bind boot, enrollment and
workload checks to exact image bytes; they do not qualify physical hardware.
The [test guide](../tests/README.md) describes the harnesses, including CPU serving
and [trusted operation/resource correlation](agent-phase-correlation.md).

The [GitHub milestones](https://github.com/Alien6-Studio/outerspace-os/milestones)
track implementation and remaining work, including GPU support, fleet behavior
and agent governance. The [release policy](../build/release/README.md) defines
publication gates. This architecture document is not a qualification report.
