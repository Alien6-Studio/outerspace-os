# Inference worker benchmark protocol

No hardware performance comparison has been established yet. Capture raw results before
choosing a snapshotter or advertising a reduction.

The opt-in [real CPU model serving lab](cpu-serving.md) adds fixed-model HTTP
generation, streaming timings and restart/reboot checks to the enrollment test.
Its emulated VM observations do not replace this hardware benchmark protocol.

`make PROFILE=agent smoke` (or `PROFILE=inference`) also records an unconfigured
host baseline in `uefi-smoke.json`, under `idle_host`. Both UEFI cold boots use
the same four-vCPU/4-GiB reference as the enrollment lab. The existing opt-in boot
selftest waits 60 seconds, then collects four samples across three intervals of
at least ten seconds. CRI must respond with no sandboxes or containers; kubelet
and the optional P2P peer must remain inactive. No CNI, probe pod, Agent or model
is loaded. The native Bash observer is part of the reported footprint and its
cgroup counters are retained separately, without subtracting shared memory.
Service memory records distinguish anonymous, file-cache and kernel charges;
their total is cgroup accounting, not private resident memory. The counters are
sampled separately and are not forced to sum to a synchronized total.

Raw observations retain `/proc/meminfo`, `/proc/stat`, guest uptime, `CLK_TCK`,
root/state filesystem usage and selected service cgroups. CPU work uses the
user/nice/system/irq/softirq tick deltas divided by the actual clock frequency
and observed guest interval; idle, iowait and steal are separate from this work.
Guest time is already included in user time. See the kernel's
[/proc/stat manual](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.17.pdf)
and [cgroup v2 accounting](https://www.kernel.org/doc/html/v6.8/admin-guide/cgroup-v2.html).
Memory summaries use `MemTotal - MemAvailable`, rather than process RSS.
Min/median/max and all samples remain bound to source identity and boot logs;
packaging recomputes the summaries and rejects altered evidence. These short
virtual-machine observations establish no hardware performance threshold.
The [Agent baseline protocol](agent-baseline.md) defines measured idle regression
ceilings enforced by boot and packaging, and the opt-in matched Ubuntu worker
comparison. Enrolled-platform measurements remain in
`agent-resources.json` and include their explicitly listed qualification pods.

For each run record the OS build and manifest, kernel, runtime, image digest, model
hash, hardware, node count, link bandwidth/latency and registry location. Use the
same CNI and workload. Measure cold and warm states separately and report the
number of samples, median, p95 and variance.

| Measurement | Start | End |
| --- | --- | --- |
| Boot | VM power-on | CRI serving |
| Node enrollment | VM power-on | Kubernetes Node Ready |
| OCI delivery | CRI pull request | CRI pull complete |
| Container startup | Pod scheduled | Container started |
| Model readiness | Container started | Real inference request succeeds |
| User latency | Inference request | First token and full response |

Record physical image bytes (allocated and apparent), idle memory, total memory,
`/var` allocated bytes, transferred registry/peer/model bytes and CPU overhead.
Observe after GC as well as immediately after pull; the duplicate compressed
layer saving is asynchronous. Include a normal Ubuntu worker with the same kernel
and runtime versions as a reference.

Run only on disposable nodes. Do not delete containerd storage to manufacture a
cold-cache test on an enrolled node. Provision a fresh disk for each cold run.
The existing idle-host budgets use the qualified cold-boot observations and
explicit reviewed headroom. Additional hardware performance gates require
their own measurements.
