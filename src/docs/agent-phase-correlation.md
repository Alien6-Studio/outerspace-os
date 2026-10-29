# Trusted operation and resource correlation v1

The foundation reference implementation is an authenticated benchmark gateway,
not an agent SDK, host daemon, semantic monitor or authorization service. It
runs outside the untrusted Agent OCI workloads. The kernel supplies cgroup v2
measurements; the gateway supplies operation semantics. Neither the OS nor the
collector parses prompts or infers tool boundaries from process names.

## Contract and authority

[`phase-correlation.py`](../../tests/harness/phase-correlation.py) implements
`outerspace.phase.v1`. A gateway session has a random run UUID, issuer UUID,
256-bit per-run HMAC key and SHA256 of the applied Agent policy. Kubernetes API
authentication authorizes the gateway to resolve the node, Pod UID, container ID,
OCI image digest, boot ID and restart count. It registers each container once.
Repeated operations can reuse that scope; a restarted container gets a new one.
An agent cannot register a scope, obtain this key or access another tenant's
observation channel. The reference channel uses the administrator's existing TLS
Kubernetes exec connection to the trusted, read-only observer.

Every signed start/end event contains the schema, issuer/run/policy identity,
strictly increasing sequence, operation UUID, agent UUID, optional parent-agent
UUID, opaque tool UUID, scope UUID or explicit external-provider scope, Unix and
monotonic timestamps, outcome, and OpenTelemetry trace/span/optional parent-span
IDs. Unknown fields are refused. Prompts, command arguments, environment,
credentials and tenant filesystem paths are absent from the contract. Boundary
MACs are checked before accepting events; altered, replayed, cross-run or
unmatched boundaries are refused. The key never enters the untrusted workload
or exported dataset. Exported MACs document the accepted live channel; they are
not a public signature or a replacement for release/audit attestations.

Only the trusted gateway starts and ends an operation. An agent returning from
a tool does not establish that all descendants have stopped. The collector
retains PID/start-time identities within the authenticated cgroup and reports
observed descendants that outlive a boundary or move out of the scope. Processes
that escape and die between snapshots cannot be enumerated; that coverage is
explicitly unknown. Cgroup counters still include work charged to descendants
while they were members. The Agent profile refuses cgroup writes and host
namespace/mount access, and its service account cannot modify observer/exporter
configuration or exec into other tenants.

## Accounting semantics

[`phase-probe.py`](../../tests/integration/phase-probe.py) reads the exact container
cgroup and descendants through the observer's read-only host mount. It records
CPU usage/user/system/throttling, current and lifetime-peak memory, anon/file/shmem
charges, OOM events, CPU/memory/I/O PSI, per-device I/O, process identities and
collector CPU/RSS/read duration. No Python interpreter or language runtime is
installed into the host. Observation envelopes retain gateway request timing
brackets and guest monotonic times; their clock domains are never equated.

The dataset stores each scope and counter interval once. OpenTelemetry-compatible
span identities refer to those scopes and deliberately contain no allocated
per-tool CPU, memory or I/O value. Even a dedicated scope includes its wrapper
and descendants. Shared or overlapping tools, reused workers and background
children are **scope-only** measurements, not exact tool attribution. Memory
peaks are lifetime gauges, never subtracted or summed. Shared memory and file
cache are cgroup charges, not private RSS, and first-touch cache charging does
not identify a unique tool's physical-memory ownership. External provider work
has no local scope; its CPU/memory/tokens remain unknown.

Missing cgroups, changed boot/cgroup instances, counter regressions, collector
races and unfinished operations produce explicit partial reasons. A restart
never joins a new counter epoch to an old one. Cancellation preserves the last
observed counters and the missing-scope endpoint; it does not invent final
counters after teardown. A scope may be measured accurately while its semantic
per-tool attribution remains unknown.

## Bounded collection and failure behavior

One session accepts at most 32 unique scopes, 1,024 boundary events, 256 samples
per scope and 8 MiB of serialized measurements. Boundary messages are limited to
4 KiB and process observations to 128 identities, with a 4,096-entry host procfs
enumeration ceiling. Host procfs supplies process IDs because `cgroup.procs`
masks foreign-container PIDs in the observer's PID namespace. Invalid authentication is
refused without granting execution authority. Exhausted buffers or loss of the
required observer stop pending benchmark work, delete the disposable execution
scope and retain the failed/partial trace. No successful measurement is emitted
for a missing interval. These performance failures are not security approvals
or policy decisions; full governance and audit remain the separate #15 scope.

## Native benchmark

Run `make agent-phases IMAGE_OUTPUT=/absolute/path/to/agent-cpu-ARCH` from clean,
committed source after packaging a native Agent CPU image. The isolated lab runs
two serial fresh UEFI VMs of that exact image, first without phase collection,
then with it. Both have four vCPUs, 4 GiB RAM, identical OCI bytes, Agent controls,
Cilium and the same endpoint resource observer. The enabled arm adds the trusted
boundaries and periodic read-only collection. Gateway wall durations include
the API/exec, collector and correlation costs; they are not engine-only timings.

Each arm repeats ten fresh sandboxes and four finite BusyBox tools: CPU hashing,
a retained heap allocation, direct block reads and a two-second HTTP provider
wait. The delayed private HTTP fixture models remote LLM waiting without making
an external provider call; it executes no model. Its remote compute is unknown.
The first sandbox includes image delivery. The other nine are fresh processes
using an already pulled image. Raw observations and p50/p95 are retained for
phase latency, cached-image fresh-sandbox startup, CPU and memory. First image
delivery has a single observation per arm, not a latency-distribution claim.

The enabled arm also exercises concurrent tools in one cgroup, a background
descendant crossing boundaries, reused tmpfs data, shared cached image reads in
distinct OCI scopes under the same logical agent ID, a real OOM container
restart, cancellation and a deliberately
removed collector. It checks live refusal of counter resets, cgroup migration,
exporter changes, observer exec, other-tenant Pod access and an agent-emitted
forged boundary. The final deliberate collector failure remains visible as a
failed trace; the scenario passes only when work stops and evidence is retained.

`out/agent-phases/phase-benchmark.json` binds the image, runtime, policy, OCI
workload, exact harness source and all raw observations. Per-arm observations,
partial traces and boot/QEMU logs are retained even after failure. These are
synthetic native-QEMU measurements, not physical efficiency, energy, production
endurance or real provider-performance claims. Acceptance requires a completed
native report; unit tests and the existence of this harness do not qualify #29.
The Agent CI matrix runs the complete paired scenario on amd64 and arm64 after
ordinary image, boot, isolation and resource qualification. It retains the raw
phase datasets and failure traces with each architecture's development artifact.

The [2026-10-27 local qualification](../../tests/reports/2026-10-27-agent-phases.md)
links the complete immutable dataset, independently verified failure cases and
measured collection overhead.
