# ADR 0001: Share a minimal Kubernetes/OCI host between execution profiles

Status: implemented decision, recorded retrospectively on 2026-10-30.

## Context

Agent and inference workloads need the same kernel, container runtime, node
identity and image delivery. Their application dependencies and resource needs
differ. Installing frameworks and model engines in the host would couple OS
updates to application releases and increase the base image's maintenance scope.

## Decision

Maintain one Ubuntu Noble foundation assembled with mkosi, with separate Agent
and Inference profiles. Use kubelet, containerd and OCI workloads as the execution
interface. Keep the Kubernetes control plane, agent frameworks, language runtimes,
model engines and weights outside the host image.

The native Agent profile adds admission, resource limits, AppArmor, seccomp and
network policy to the shared runtime. Optional governance services remain outside
the base OS; they are not required to run an ordinary OCI workload.

## Alternatives and tradeoffs

- A general-purpose mutable server image would simplify host-side installation,
  but enlarge the supported host state and dependency surface.
- Separate Agent and Inference distributions would allow independent choices,
  but duplicate runtime, bootstrap and security maintenance.
- A dedicated agent runtime or bundled framework would expose richer application
  APIs, but couple the OS to that framework and require another lifecycle.

## Consequences

Applications can evolve without rebuilding the host. Host packages must serve an
OS responsibility; profile-specific additions need an explicit reason. Kubernetes
is the supported integration boundary, so standalone execution needs a separate
decision. OCI containers share the kernel; this choice does not establish
isolation between mutually untrusted tenants or authorize application actions.

Implementation: [base image](../../src/image/mkosi.conf),
[profiles](../../src/image/mkosi.profiles/),
[Agent contract](../../src/cluster/agent/profile-v1.json) and
[worker integration](../../src/cluster/README.md).
