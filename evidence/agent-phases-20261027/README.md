# Trusted Agent phase comparison

Development evidence for issue #29. The same immutable Agent image and OCI
workload ran in two serial arm64 QEMU TCG VMs, first without phase collection,
then with trusted boundaries and periodic collection. Each arm completed ten
fresh sandboxes and four finite phases: CPU hashing, retained heap allocation,
direct I/O and a synthetic two-second private HTTP provider wait.

## Reproducibility

- Harness source: `b575d80cef331eff89f52f717724efa268c0acba`.
- Image source: `b575d80cef331eff89f52f717724efa268c0acba`.
- Raw disk SHA256: `65e46cc243e96a70bedc07b555dc2fa64fee0e51ed73350f3c38226c64392bbd`.
- Report SHA256: `c6c8ba767505559263a41645a11cf9bdfeb94c2cbfebc3a585eb0c546810b590`.
- Independently verified: 31 source inputs,
  8 checksum-bound files,
  14 profiled execution scopes and
  53 trusted operations.

Both arms have four virtual CPUs, 4096 MiB RAM, matching kernel notes, runtime
binaries, configurations and OCI image bytes. The first startup in each arm
includes image delivery. Nine later startups use cached OCI bytes but create
fresh processes. Both arms use the same endpoint resource observer; only the
profiled arm adds phase boundaries and periodic measurements.

## Observations

The following gateway wall durations are seconds, including Kubernetes exec,
correlation and collection costs. Quantiles use nearest ranks over ten samples.

| Phase | Baseline p50 | Baseline p95 | Profiled p50 | Profiled p95 |
| --- | ---: | ---: | ---: | ---: |
| cpu-burst | 5.0787 | 5.6727 | 35.2954 | 37.5848 |
| memory-spike | 6.1523 | 6.5163 | 34.9597 | 38.9047 |
| io | 3.2836 | 3.5108 | 34.4767 | 36.8702 |
| remote-llm-wait | 3.3978 | 3.4407 | 33.7666 | 38.5375 |

First-image create-to-ready took
47.0209 seconds without
profiling and 41.3497 seconds
with profiling. These are individual observations, not distributions.
Cached-image fresh-sandbox startup p50/p95 was
8.5157/
8.9622 seconds without
profiling and 8.3305/
10.4109 seconds with profiling.

The report retains endpoint Pod CPU, host busy CPU, host unavailable RAM,
Pod current memory and lifetime peaks, plus collector CPU/RSS/read duration.
The following endpoint distributions pool the 40 repeated phase observations
per arm. CPU values are deltas over each phase; memory values are endpoint
gauges. Raw per-phase values remain available in the report.

| Measurement | Baseline p50 | Baseline p95 | Profiled p50 | Profiled p95 |
| --- | ---: | ---: | ---: | ---: |
| Pod CPU, seconds | 1.5443 | 2.4105 | 1.6744 | 2.5431 |
| Host busy CPU, seconds | 18.5600 | 23.5900 | 53.2200 | 63.6100 |
| Host unavailable RAM, MiB | 613.3242 | 650.2422 | 616.0547 | 626.9609 |
| Pod current charge, MiB | 0.5742 | 0.6172 | 0.5742 | 0.6211 |
| Pod lifetime peak, MiB | 19.2656 | 19.3984 | 19.3047 | 19.4531 |

The profiled observer, including the later failure scenarios, consumed
801.0842 process CPU seconds.
Its process peak-RSS p50/p95 was
18.2656/
18.4805 MiB, and its cgroup-read
wall-time p50/p95 was 0.8619/
1.0051 seconds. Those figures
exclude control-plane and gateway process costs; gateway wall duration includes
their latency. The endpoint benchmark observer is common to both arms.

Memory values are cgroup charges and lifetime peaks, not private RSS or exact
per-tool allocations. Repeated phase traces include OOM counters, all three
PSI classes, per-device I/O and bounded PID/start-time identities.

## Failure and scope coverage

The profiled arm additionally proves overlapping operations in one scope,
reused shared-memory state, shared image-cache reads across distinct agents,
background descendants crossing operation boundaries, an actual OOMKilled
container restart, cancellation after observing the running tool, and loss
of the required collector. Live tests refuse exporter changes, observer exec,
other-tenant reads, cgroup writes/counter resets and a forged agent boundary.

The deliberately removed collector makes the final retained trace **failed**.
The benchmark passes because pending work stops and partial evidence survives;
it does not treat missing measurements as successful observations. Old and new
container epochs remain separate. Each scope interval occurs once; OTel spans
reference scopes without allocating shared counters or peaks to individual tools.
External provider compute and unobserved escaped processes remain unknown.

## Archive and limits

`phase-benchmark.json` binds the raw per-arm observations and original logs.
`independent-verification.json` records checksums, recomputed distributions,
counter intervals and operation links. `verify-phases.py` reruns those checks
against the exact source checkout. HMAC keys are deliberately absent, so this
offline verifier does not claim to verify exported MACs cryptographically.
`cleanup-verification.json` records removal of the owned laboratory.
`SHA256SUMS` covers all archived files except itself.

The archive excludes disks, config drives, kubeconfigs, credentials and model
prompts. Full raw logs are reviewed and scanned before publication. This is
synthetic emulated-VM evidence, with serial baseline-first ordering; it does not
establish physical-machine efficiency, energy savings, production endurance or
actual remote-model performance. No SDK or language runtime is installed in the
host. Performance correlation is not a governance or security-audit decision.
Cross-architecture CI and integration are tracked separately in PR #43.
