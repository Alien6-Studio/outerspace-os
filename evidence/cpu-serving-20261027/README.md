# CPU serving comparison — 2026-10-27

Development evidence for issue #24. Both serial arm64 QEMU TCG workers completed
the same real llama.cpp/SmolLM2 workload: initial serving, sustained load, pod
replacement, same-worker drain/uncordon and cold-node recovery. Each worker
served 46 measured requests and 368 generated tokens. The sustained
phase contains at least 30 requests over at least 60 seconds. Nine admission
refusals and two actual incompatible/untrusted model refusals pass on each worker.

## Identity and reproducibility

- Harness: `f5efaabaa07d4a6fc93c050867a4d403ea31d82a`, the parent of this evidence commit.
- Inference image source: `56a96282b63b27caf66d8e81a8273d05226bb036`.
- Raw disk SHA256: `d77cd1a1316f73a75566e1d80cabfc36df0b1534b7add96b3fd2fb45e4c6a3e1`.
- Combined report SHA256: `fcd907a53c6b28f5d9e1a4b93682157d8275bc80589a7f800515e91bd6c556c5`.
- Official Ubuntu arm64 cloud image SHA256: `50e24e1fb79e89116e939d90aa7738f7af48c442fa1bc2510131e0b39c50348e`;
  its inventory and detached signature were verified with the pinned Canonical fingerprint.
- All 28 harness inputs and 32 bound files were
  independently checked. Every latency/TTFT quantile and token total was recomputed.

Both workers have four vCPUs and 4096 MiB RAM, matching kernel version/build
notes, runtime binary hashes, containerd/kubelet/AppArmor configuration, Cilium,
model and runtime pins. Ubuntu retains its own OS identity. The CPU server is
limited to two CPUs and 512 MiB, one request at a time, with a five-token prompt
and an eight-token output limit, seed 42 and temperature zero. The model and
tokenizer bytes are the SHA256-locked Q4_K_M GGUF. NUMA topology is recorded;
physical power is unavailable in this TCG laboratory.

## Observations

| Measurement | OuterSpace | Ubuntu |
| --- | ---: | ---: |
| Cold create-to-inference-Ready, seconds | 351.0739 | 350.9435 |
| Replacement pod with cached OCI image, seconds | 93.9013 | 94.3115 |
| Sustained latency p50, seconds | 2.4965 | 2.4028 |
| Sustained latency p95, seconds | 2.9026 | 2.8239 |
| Sustained first-token p50, seconds | 0.8624 | 0.8362 |
| Sustained first-token p95, seconds | 1.1843 | 0.8879 |
| Generated tokens / summed request seconds | 3.1485 | 3.3173 |

Cold and replacement times include Kubernetes scheduling/readiness polling and
model/OCI delivery as applicable. A replacement pod gets a new private model
volume; the OCI image is already cached. These are individual startup observations,
not startup distributions. Raw engine timestamps separately record model loading.
Latency/TTFT quantiles use nearest ranks over the sustained samples. The token
rate divides generated tokens by summed request durations, not isolated kernel
execution time. These serial emulated-VM observations establish no hardware,
energy or cost advantage.

Every load interval preserves the same Pod/container/image/restart identity;
all memory OOM counters remain zero. The replacement and drain change Pod IDs.
Cold recovery changes the boot ID and container while preserving the registered
node and serving Pod, with exactly one expected container restart. Actual CPU
and memory cgroup limits, current charges and lifetime peaks are retained. Peaks
are not per-request memory or private RSS. Allowed requests and denied ingress
and egress are checked in all five phases.

## Evidence and limits

`serving-comparison.json` binds the observations and original logs byte-for-byte.
`independent-verification.json` records the secondary checks; `verify-serving.py`
can rerun them against a checkout of the exact harness source. `SHA256SUMS`
covers every archived file except itself. The original dataset remains unchanged.
`cleanup-verification.json` records successful removal of the owned laboratory.
The archive excludes VM disks, model weights, config drives, kubeconfigs and
bootstrap credentials. Exact secret-scanner false positives, if listed in the
branch's `.gitleaksignore`, are public kernel certificate identifiers or Kubernetes
Pod/volume identifiers; they are not private keys or access tokens.

Only one small generative model and arm64 TCG are compared with Ubuntu here.
There is no physical-machine, GPU, energy, multi-node migration or production
endurance claim. Ubuntu uses a writable root; OuterSpace uses a verity root and
separate state. Current-source Agent/Inference amd64/arm64 qualification is
tracked separately in PR #43; this older image/harness pair does not substitute
for those checks or grant release/redistribution approval. The later serving
startup-budget fix changes the permitted wait only, not this run's model,
runtime, resource controls or measured protocol.
