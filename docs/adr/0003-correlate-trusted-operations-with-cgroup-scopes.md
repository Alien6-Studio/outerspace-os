# ADR 0003: Correlate trusted operations with cgroup scopes

Status: implemented reference design, recorded retrospectively on 2026-10-30.
Runtime qualification is tracked in
[#29](https://github.com/Alien6-Studio/outerspace-os/issues/29).

## Context

An agent tool boundary does not necessarily match a process or cgroup lifetime.
Tools can overlap, reuse workers, leave descendants running or wait for remote
providers. Kernel counters cannot recover these semantics, and an untrusted
agent cannot be authoritative about its own observation coverage.

## Decision

Keep operation boundaries in a trusted gateway outside the workload. Authenticate
and sequence its events, bind observations to concrete container and cgroup
identities, and export trace/span references to measured resource scopes.

Keep counters at scope level. Do not allocate shared CPU, memory or I/O to tools
as if that allocation were measured. Remote provider resources remain unknown;
missing samples, restarts and unfinished operations remain explicitly partial.
Memory peaks are lifetime gauges, not additive interval counters.

Use one authenticated Kubernetes exec stream to the read-only collector per
session. Measure startup separately, validate collector identity around each
observation and fail the benchmark session on channel loss or replacement.
Do not silently reconnect and join different observation epochs.

## Alternatives and tradeoffs

- Agent-emitted boundaries are easy to integrate but cannot establish trustworthy
  coverage or prevent forged timing and identity claims.
- Process-name inference or proportional resource allocation could produce
  per-tool numbers, but those numbers would be estimates with ambiguous ownership.
- Starting a collector for every sample isolates requests, but adds repeated
  interpreter and exec startup to latency and observer CPU cost.

## Consequences

The dataset distinguishes measured resources from semantic attribution and
exposes coverage gaps. Consumers must handle scope-only and partial results.
The persistent stream needs bounded messages, deadlines and identity checks;
observer startup and collection overhead remain part of benchmark accounting.

This is a benchmark reference design, not an authorization service or a production
agent SDK. It installs no language runtime in the host. Qualification reports
belong to the implementing PR and its image artifacts, not this decision record.

Implementation: [event and accounting contract](../../tests/harness/phase-correlation.py),
[collector](../../tests/integration/phase-probe.py),
[authenticated stream](../../tests/harness/phase-stream.py) and
[paired benchmark](../../tests/harness/agent-phase-benchmark.py).
