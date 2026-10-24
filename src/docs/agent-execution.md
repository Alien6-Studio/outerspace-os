# Lightweight agent execution: OS boundary

Status: the native OCI Agent v1 profile is implemented for development qualification.
Its image-bound `agent-isolation.json` defines the tested runtime scope; density,
action governance and optional integrations remain separate work. The current
image is still `0.1.0-dev.0`.

## Decision

OuterSpace supplies a small, immutable execution host for inference and agents.
Its responsibility is the kernel, runtime, resource boundaries, image delivery,
host identity and update lifecycle. Agent frameworks and their application
dependencies run in workloads. They are not part of the base OS.

OpenShell is an optional integration above this host. A native OuterSpace profile
should provide a useful OCI execution boundary without requiring OpenShell's
gateway, supervisor or policy APIs. Integrating those higher-level services can
add credential mediation and agent governance. It does not redefine the host's
security or update contract. No OpenShell compatibility is claimed yet.

## Responsibilities

| Layer | Responsibility | Placement |
| --- | --- | --- |
| OS | Kernel/firmware, verity root, systemd, runtime, trusted host configuration and eventually authenticated updates | Minimal host image |
| Execution | OCI workload lifecycle, namespaces, cgroup v2 quotas, capability reduction, seccomp and tested LSM profiles | containerd/runc plus explicit runtime configuration |
| Network and visibility | Default-deny connectivity, permitted flows and security events | Trusted platform components; Cilium/eBPF profile on Kubernetes |
| Agent services | Agent logic, tools, Python/Node dependencies, task state and model clients | Workload containers |
| Governance integration | Workload identity, credentials, API/tool authorization and approvals | Optional services such as OpenShell, outside the untrusted agent |

Linux kernel mechanisms enforce concrete process, file and network restrictions.
They do not understand whether a tool call is appropriate for a business task.
eBPF telemetry is not authorization, and a packet allowlist is not an L7
credential broker. Those higher-level contracts remain explicit integrations.

## Keep the base small

- Keep Python, Node, compilers, agent SDKs and user-space CUDA in workload images.
  Add host binaries only when the host boundary actually needs them.
- Reuse OCI and CRI contracts before introducing a new agent-specific daemon.
  Any additional native component needs a measured footprint and a lifecycle owner.
- Share one maintained OS foundation. Select inference/GPU and agent isolation
  profiles by node or workload instead of loading every integration by default.
- Keep OpenShell, external identity systems and policy control planes optional.
- Use ordinary OCI isolation as the initial profile. Evaluate stronger isolation
  such as a VM-backed Kubernetes RuntimeClass for hostile or mutually untrusted
  workloads; select it explicitly and measure its memory and startup cost.

Kubernetes workers remain the first deployment target. A standalone agent mode
without kubelet would be a separately qualified profile, not an existing feature.

## Agent execution contract to qualify

The [native v1 profile](../cluster/README.md#native-oci-agent-v1-profile) implements
the initial ephemeral OCI boundary with Kubernetes admission and AppArmor. The
remaining contract below also covers later identity, governance and stronger
isolation profiles; it is not a claim that all of those capabilities exist.

Each agent gets a distinct workload identity and execution environment. The
`outerspace` host operator account is not an agent identity. Workloads should
have a read-only root, bounded ephemeral scratch space, explicitly authorized
workspace mounts, CPU/memory/PID/storage quotas, no host runtime socket and no
host namespaces or privileged mode.

Apply and test seccomp, capability and LSM restrictions before starting the agent.
Detect the running kernel's supported ABI, including Landlock when selected.
A profile requiring an unavailable control must refuse execution rather than
silently weaken its guarantees. AppArmor/Landlock policy composition and user
namespace behavior require tests on the actual Ubuntu kernel.

Start with denied network access and a minimal explicit allowlist. Secret and
provider access should use short-lived, workload-scoped authority. Endpoint-bound
credential injection requires a broker/proxy outside the agent; kernel controls
alone do not implement it. Keep policy changes and privileged platform operations
outside the agent's writable workspace.

Container namespaces share the host kernel. A hardened OCI profile is not a
claim of VM-equivalent tenant isolation. Stronger profiles need their own threat
model, escape tests and hardware requirements before support is advertised.

Dragonfly can accelerate immutable OCI blobs subject to registry authorization
and cache qualification. Agent workspaces, mutable task state and secret material
must never enter the P2P cache. Model-cache authorization and retention remain
separate from OCI caching.

## Qualification sequence

1. Finish full-disk UEFI boot, state/identity persistence, OS-node enrollment and
   a CPU inference workload. Both execution use cases depend on this foundation.
2. Introduce a small OCI agent execution profile. Test allowed execution and
   denial of host-file access, privilege escalation, resource exhaustion and
   unauthorized egress. Bind reports to the image and runtime versions.
3. Measure that profile against the plain OCI baseline. Record root filesystem
   size, compressed image size, idle host memory/CPU, per-sandbox memory, cold/warm
   startup, density and cleanup behavior on a fixed hardware matrix. Separate
   host, platform agents, workload dependencies and model memory in every report.
4. Qualify one OpenShell integration with a pinned release: sandbox boundary,
   workload identity, credential mediation, network policy, restart and revocation.
   Describe which component owns each control and test overlapping policies.
5. Evaluate a stronger isolation profile and publish its resource tradeoffs.

No speed, density or memory target becomes a product claim before measurement.
The base must stay independently usable when optional agent services are absent.

## Monitoring boundary informed by METR

These are design requirements, not implemented guarantees.

[Rein and Kaufman, 2026-10-22](https://metr.org/blog/2026-10-22-red-teaming-openai-agent-monitoring/)
describe gaps and bypasses in a historical internal monitoring system assessed
in July. The post does not establish the current system's coverage. For OuterSpace,
we derive these requirements:

- Keep monitor configuration, credentials and audit storage outside agent write access.
- Account for child agents, provider-executed tools, restarts and long-running
  tasks; monitoring must not depend on the agent ending its turn.
- Reconcile expected and observed events; expose loss, errors and coverage gaps.

[Haskins et al., 2026-09-27](https://metr.org/notes/2026-09-27-implementing-a-basic-blocking-action-monitor/)
describe a per-action monitor and incomplete evidence for its effectiveness.
Our proposed profile must:

- Block a governed action until its required check succeeds; timeouts and errors
  must not grant permission.
- Keep review authority and the approval interface inaccessible to the agent.
- Test hidden child actions, spoofed context, retries, reviewer impersonation and
  attempts to disable controls.

The kernel enforces deterministic resource/access boundaries. Tool-call context
and approval semantics need a trusted runtime integration; eBPF alone cannot
prove complete semantic monitoring. Keep optional model-based review outside the
base image. Bound local buffers and measure collection/enforcement overhead;
critical event loss must trigger the profile's explicit blocking/quarantine policy.
Protect sensitive data and export only the audit fields required by that policy.

## Design references

- [OpenShell architecture](https://docs.nvidia.com/openshell/v0.1.5/about/architecture)
- [Linux Landlock interface and ABI negotiation](https://docs.kernel.org/userspace-api/landlock.html)
- [Kubernetes RuntimeClass](https://kubernetes.io/docs/concepts/containers/runtime-class/)

References checked on 2026-10-23. They inform the boundary; they do not establish
compatibility with the current OuterSpace image.
