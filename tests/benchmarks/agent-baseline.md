# Agent reference and regression policy

The static Agent v1 workload has a 500m CPU / 128 MiB reservation and limit,
256 PIDs, 64 MiB private workspace and 16 MiB private scratch, both tmpfs.
Its container and descendants share 8 MiB/s reads, 4 MiB/s writes and
256 read/write IOPS on the unstacked state disk. Namespace quota permits four
Agents, including queued launches. Existing native resource qualification checks
the actual cgroups, six pressure cases, neighbor/API responsiveness and teardown.

## Idle host gates

[idle-host.lock.json](idle-host.lock.json) records the maximum of both cold
boots from the four successful archives of
[run 40185732988](https://github.com/Alien6-Studio/outerspace-os/actions/runs/40185732988),
including each archive digest and UEFI report digest. The source tree is
`a8fb058c30055d09a85cef91979013b3c9f610fd` (merged in PR #39).
The failed first Agent amd64 attempt is excluded.

| CPU image | Maximum RAM unavailable | Maximum guest busy CPU |
| --- | ---: | ---: |
| Agent amd64 | 451 MiB | 2% |
| Agent arm64 | 287 MiB | 13% |
| Inference amd64 | 448 MiB | 2% |
| Inference arm64 | 292 MiB | 12% |

RAM is `MemTotal - MemAvailable`; CPU is guest work across four vCPUs.
The ceilings use the observed maximum, with reviewed headroom: RAM × 1.25
rounded up to a MiB, CPU × 2 rounded up to a percentage point. These margins
are regression policy choices, not confidence intervals. Four memory samples
and three CPU intervals per boot do not establish statistical capacity or
physical performance. The observer remains included.

`make smoke` fails if either cold boot exceeds either ceiling. Packaging
independently recomputes the observations from the source-bound logs, reapplies
the current policy, and rejects absent or altered gate results. The bundle
includes the policy, its checksum and the measured result. Missing reference
profiles fail closed; `cpu-full-firmware` has no qualified budget yet.
Changing the baseline or headroom requires a reviewed policy change with new
raw evidence. Wall-clock launch times under TCG are observations, not gates.

## Standard Ubuntu comparison

Use an already packaged, immutable Agent candidate and a clean committed
checkout containing the comparison harness:

```sh
make worker-comparison IMAGE_OUTPUT=/absolute/path/to/out/agent-cpu-arm64
```

The target uses the existing builder and enrollment runner; `gpg`, Docker,
kind, kubectl and Helm must already be available. Generated results belong in
`out/worker-comparison`; verified downloads go in `.cache/ubuntu-reference`.
This is an opt-in qualification tool, not a shipping third OS profile.

The fixture boots the versioned official Ubuntu 24.04 cloud image pinned in
[ubuntu-reference.lock.json](ubuntu-reference.lock.json). Its checksum must
occur exactly once in Canonical's signed inventory, validated with the pinned
full signing-key fingerprint. The existing hash-locked installer supplies the
same containerd, shim, kubelet and crictl. A fixed Ubuntu runc package and kernel
modules are installed without a general upgrade. No Python or benchmark daemon
is added to OuterSpace OS; Ubuntu keeps its stock packages and OS identity.
See Canonical's [verification instructions](https://ubuntu.com/docs/public-images/public-images-how-to/verify-image-checksum/)
and [local NoCloud configuration](https://ubuntu.com/docs/public-images/public-images-how-to/use-local-cloud-init-ds/).

Workers run serially, on the same four-vCPU/4-GiB UEFI QEMU TCG configuration,
with the same pinned control plane, Cilium values, kubelet reservations,
containerd configuration, AppArmor policy, qualification pods and Agent image.
The comparison rejects different kernel version/build notes, runtime binary
hashes or configuration hashes. The report distinguishes the candidate's
source commit from the comparison harness commit and retains both identities.

Ubuntu's first-boot package installation and initramfs generation have a separate
60-minute preparation deadline under TCG, before any observation or launch timing.
The reference bootstrap token lasts two hours so that the separate preparation
window cannot expire the normal thirty-minute enrollment token. Every comparison
runs both workers from fresh overlays with the same committed harness; partial
results from an earlier run are retained only as diagnostics.

After readiness, the existing read-only probe collects four raw samples,
separated by at least ten guest seconds, after a 60-second settling period.
Stages contain zero, one, two and four Agents. Raw platform and per-pod
cgroup counters, actual limits, filesystem use, guest ticks and RAM remain in
the report. First launch includes image delivery; subsequent launches reuse
the running image. The observer and qualification workloads are included on
both sides. No model or agent framework is loaded.

Storage layouts differ: Ubuntu keeps a writable root, expanded to 12 GiB,
where `/var` resides; OuterSpace uses a verity root and separate state. The
Ubuntu root partition is relabeled for the identical I/O policy in this
disposable, single-boot fixture. Automatic apt timers are stopped during the
measurement. The optional P2P service is inactive in OuterSpace and absent in
Ubuntu. These differences remain explicit; no storage throughput claim is made.

Each laboratory owns its network, nodes, runner, overlays and anonymous volumes.
They are removed after success or failure; only obsolete labeled tooling images
are pruned. Logs and raw observations survive outside disposable state.
Density at 10/100 Agents remains untested: the reference admission quota is
four, and the 4-vCPU worker cannot reserve CPU for ten 500m Agents. No physical
machine, higher-density capacity or cross-architecture speed claim follows
from these short VM observations.
