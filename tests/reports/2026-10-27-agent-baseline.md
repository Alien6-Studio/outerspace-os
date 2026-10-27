# Agent baseline validation — 2026-10-27

Local development qualification of idle-host regression budgets and the matched
Agent/Ubuntu density harness. Both workers completed fresh, serial UEFI QEMU TCG
runs with four vCPUs and 4096 MiB RAM. This is a sandbox/platform baseline with
idle BusyBox workloads; no agent framework or model is loaded.

## Source and image identity

- Harness snapshot: [`7b72987556665d863d323376268b55647689227b`](https://github.com/Alien6-Studio/outerspace-os/tree/7b72987556665d863d323376268b55647689227b),
  committed before the run. All 27 bound inputs match the implementation.
- Agent image source: `3282cdacf551a9401e983cf6114c6ad8b0365b5a`;
  raw disk SHA256: `98cbffd8070c7aa4c2592b38b47bdcaafce33c2068d49102276724f244ce4fb8`.
- Ubuntu reference: official Noble arm64 cloud image build `20261017`, SHA256
  `50e24e1fb79e89116e939d90aa7738f7af48c442fa1bc2510131e0b39c50348e`, verified
  against Canonical's signed inventory and the pinned full signing fingerprint.
- Combined report SHA256:
  `6b1fc656b97f5bdcbd585fd19fb06e27b5f715416198e622bacdc1ad720c9430`.

Both workers retain their own OS identity. Kernel version/build notes, all four
runtime binary hashes, containerd/kubelet/AppArmor configuration hashes, clock
frequency and vCPU count match. The workers use kernel `6.8.0-147-generic`,
containerd `2.3.7`, kubelet `1.36.5`, Cilium chart `1.20.3` and the same Agent
image, admission policy, resource limits and qualification workloads.

## Observations

Each stage has four memory samples and three CPU intervals after at least
60 guest seconds settling; intervals span at least ten guest seconds.
RAM is `MemTotal - MemAvailable`. CPU is guest work across all four vCPUs.
The read-only observer, Cilium and qualification workloads remain included.

| Agents | OuterSpace RAM median, MiB | Ubuntu RAM median, MiB | OuterSpace CPU median, % | Ubuntu CPU median, % |
| --- | ---: | ---: | ---: | ---: |
| 0 | 616.16 | 672.58 | 18.95 | 18.37 |
| 1 | 610.24 | 672.08 | 26.16 | 21.81 |
| 2 | 595.76 | 676.46 | 28.49 | 24.29 |
| 4 | 637.54 | 700.41 | 34.76 | 30.22 |

Individual idle Agent Pod cgroup charges range from 0.82–1.15 MiB on OuterSpace
and 0.82–1.07 MiB on Ubuntu across the active stages. These charges include the
sandbox and its descendants; they are not private RSS or useful-agent memory.
Host memory falls between some stages, and the observer does more work as the
population grows. Differences between stage totals do not isolate per-Agent
memory or CPU costs. These observations establish no CPU-efficiency advantage.

| Create-to-Ready wall time, seconds | OuterSpace | Ubuntu |
| --- | ---: | ---: |
| First Agent, including image delivery | 14.32 | 13.07 |
| Second Agent, image already running | 9.75 | 8.88 |
| Third Agent, image already running | 10.53 | 9.25 |
| Fourth Agent, image already running | 11.27 | 8.89 |

These are individual emulated-VM observations, not latency distributions or
physical-hardware performance. Ubuntu keeps a writable 12-GiB root; OuterSpace
uses a verity root and separate state. Ubuntu preparation completed before any
measurement. No storage throughput or useful-agent throughput was measured.

## Checks and retained evidence

- `make check`: 85 tests and syntax checks pass.
- All four archived Agent/Inference amd64/arm64 idle baselines were recomputed
  from their eight cold-boot logs. Archive, report and log hashes and observed
  maxima match the [regression policy](../benchmarks/idle-host.lock.json).
  Boot and packaging enforce the documented CPU/RAM ceilings independently.
- The paired report was checked against all 27 harness hashes and eight bound
  evidence files. All 32 raw samples, 24 CPU intervals and 32 health observations
  were rechecked, including actual CPU/memory/PID/I/O limits and stable Agents.
- Both workers pass every stage's health checks; all retained Agent and
  platform container restart counts are zero. Teardown removes every Agent's
  processes, cgroups, mounts and workspace. Both laboratories, their anonymous
  volumes and private temporary state are removed after the run.

The [immutable evidence snapshot](https://github.com/Alien6-Studio/outerspace-os/tree/aa6353f57977879167c3b1799b8399a22dd0a47c/evidence/agent-baseline-20261027)
publishes the combined report and all eight bound observations, boot/DHCP logs
and QEMU commands, with `SHA256SUMS`. Its parent is the exact harness snapshot
used by the run. Evidence is archived separately from the distribution source.
Local copies remain in the ignored `out/worker-comparison-20261027/` directory.
Independent verification and cleanup results are
`out/milestone1-comparison-verification.json` and
`out/milestone1-comparison-cleanup.json`. This checked-in summary is local
development evidence, not a release attestation. Current-source build, smoke,
packaging and native worker qualification across the four Agent/Inference
amd64/arm64 candidates are tracked separately in [PR #40](https://github.com/Alien6-Studio/outerspace-os/pull/40)
and its Actions runs; this local comparison does not replace those checks.

The [protocol](../benchmarks/agent-baseline.md) documents reproduction and limits.
Density at 10/100 Agents, amd64 Ubuntu comparison and physical hardware remain
untested. The separate resource-pressure lab qualifies an offender beside a
responsive neighbor at two concurrent Agents. This run does not qualify
four-Agent pressure containment, Inference serving or the whole Execution
foundation milestone; source/redistribution review, remaining Inference work and
trusted operation-phase profiling retain their own acceptance requirements.
