# Inference worker benchmark protocol

No performance numbers have been established yet. Capture raw results before
choosing a snapshotter or advertising a reduction.

The opt-in [real CPU model serving lab](cpu-serving.md) adds fixed-model HTTP
generation, streaming timings and restart/reboot checks to the enrollment test.
Its emulated VM observations do not replace this hardware benchmark protocol.

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
Performance gates and acceptable footprint budgets will be selected from these
measurements, rather than guessed before the first working image.
