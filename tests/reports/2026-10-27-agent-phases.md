# Trusted Agent phase validation — 2026-10-27

Local development qualification for #29, using two fresh serial arm64 UEFI
QEMU TCG VMs with four vCPUs and 4096 MiB RAM. The same immutable Agent image
and OCI workload ran first without phase collection, then with authenticated
boundaries and periodic read-only observations. Both arms completed ten fresh
sandboxes, each running CPU, heap, direct-I/O and synthetic provider-wait phases.

## Identity and retained evidence

- Harness and Agent image source: `b575d80cef331eff89f52f717724efa268c0acba`.
- Raw disk SHA256: `65e46cc243e96a70bedc07b555dc2fa64fee0e51ed73350f3c38226c64392bbd`.
- Combined report SHA256: `c6c8ba767505559263a41645a11cf9bdfeb94c2cbfebc3a585eb0c546810b590`.
- [Immutable dataset](https://github.com/Alien6-Studio/outerspace-os/tree/a42d7d870e39876896ae9d9d60097035a1d2fafe/evidence/agent-phases-20261027):
  15 files, including both raw boot logs, observations, partial traces,
  QEMU commands, independent verifier and cleanup/secret-scan reviews.

The independent verification checks all 31 source inputs and eight bound files,
recomputes quantiles and counter intervals, and validates 14 execution scopes
and 53 trusted operations. It checks positive CPU work, the retained memory
spike, at least 8 MiB of actual direct reads in every I/O repetition, and the
synthetic provider's two-second minimum wait. All archive checksums match the
committed bytes. The owned containers, network, temporary state and inventoried
kind volumes were cleaned successfully. Per-run HMAC keys are absent from the
archive; offline verification does not claim to authenticate exported MACs.

## Observed cost

Gateway wall duration includes Kubernetes exec, correlation and collection.
Nearest-rank p50/p95 below use ten samples per phase and arm, in seconds.

| Phase | Baseline p50 | Baseline p95 | Profiled p50 | Profiled p95 |
| --- | ---: | ---: | ---: | ---: |
| cpu-burst | 5.0787 | 5.6727 | 35.2954 | 37.5848 |
| memory-spike | 6.1523 | 6.5163 | 34.9597 | 38.9047 |
| io | 3.2836 | 3.5108 | 34.4767 | 36.8702 |
| remote-llm-wait | 3.3978 | 3.4407 | 33.7666 | 38.5375 |

The profiled path increases these p50 durations by 28.8–31.2 seconds in this
emulated laboratory. This is substantial measurement overhead; no production
latency target or low-overhead claim is established. The common endpoint
observer runs in both arms, outside the gateway-duration interval. Raw host
CPU, Pod CPU and memory observations remain in the dataset.

First-image create-to-ready took 47.0209
seconds without profiling and 41.3497
seconds with profiling, one observation each. The nine cached-image fresh
sandboxes have startup p50/p95 of
8.5157/8.9622
seconds without profiling and
8.3305/10.4109
seconds with profiling. Collector peak-RSS p50/p95 is
18.2656/18.4805
MiB across 149 observations, including later failure scenarios.
Pod current-memory p50 is 0.5742
MiB in both arms; lifetime peaks and shared/page-cache charges are not private
RSS or per-tool memory. Serial baseline-first ordering, emulation and host
noise limit performance conclusions. There is no physical-efficiency or energy claim.

## Native failure and attribution coverage

The enabled arm passes live refusal of exporter changes, other-tenant reads,
observer exec, cgroup writes/counter resets and an agent-forged boundary. It
retains background descendants across boundaries, overlaps two tools in one
scope, reuses shared memory, and reads cached image data from distinct OCI
scopes under the same logical agent ID.
A real OOMKilled restart creates a new container scope; cancellation observes
the running tool before teardown. Removing the collector stops subsequent work
and preserves a deliberately failed/partial trace. The benchmark passes because
these failure behaviors are proven, not because missing measurements are accepted.

Each scope interval occurs once. OTel spans reference those scopes with unknown
per-tool allocation. External provider compute and unobserved escaped processes
remain unknown. The private delayed HTTP fixture executes no model; it represents
remote waiting. No SDK or language runtime is installed in the host.

`make check` passed 137 unit/contract tests and syntax checks for the qualified
source. The [decision and implementation references](../../docs/adr/0003-correlate-trusted-operations-with-cgroup-scopes.md)
explain why measurements remain at scope level. Current-source Agent/Inference
amd64/arm64 build, boot and native qualification are tracked separately in
[PR #43](https://github.com/Alien6-Studio/outerspace-os/pull/43). This local dataset
is development evidence and grants no release or redistribution approval.
