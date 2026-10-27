# CPU serving validation — 2026-10-27

Local development qualification for #24. OuterSpace Inference and standard
Ubuntu completed the same pinned llama.cpp/SmolLM2 CPU workload in fresh,
serial arm64 QEMU TCG VMs with four vCPUs and 4096 MiB RAM. Kernel notes,
runtime binaries, configuration, model and OCI identities match. Ubuntu
retains its OS identity; OuterSpace uses verity and separate persistent state.

## Identity and retained evidence

- Harness source: `f5efaabaa07d4a6fc93c050867a4d403ea31d82a`.
- Inference image source: `56a96282b63b27caf66d8e81a8273d05226bb036`.
- Raw disk SHA256: `d77cd1a1316f73a75566e1d80cabfc36df0b1534b7add96b3fd2fb45e4c6a3e1`.
- Combined report SHA256: `fcd907a53c6b28f5d9e1a4b93682157d8275bc80589a7f800515e91bd6c556c5`.
- Ubuntu Noble arm64 cloud image build `20261017`, SHA256
  `50e24e1fb79e89116e939d90aa7738f7af48c442fa1bc2510131e0b39c50348e`,
  verified against Canonical's signed inventory and pinned signing fingerprint.
- [Immutable dataset](https://github.com/Alien6-Studio/outerspace-os/tree/5d23cd066a07cac0b099cfc3e2c495705a11fcf9/evidence/cpu-serving-20261027):
  complete raw observations and all 20 boot, engine and API diagnostic logs,
  checksums, independent verifier, cleanup and full-log secret-scan review.

Independent checks verify all 28 source inputs and 32 bound files, recompute
quantiles/token totals and confirm matching worker/runtime/model identities.
Both laboratories and their owned volumes and temporary state were removed.
The archive contains no VM disk, model weights, kubeconfig or bootstrap credentials.

## Serving and lifecycle results

Each worker served 46 measured requests and 368 generated tokens across initial
serving, sustained load, pod replacement, same-worker drain/uncordon and cold-node
recovery. Sustained load contains 30 requests over 76.23 seconds on OuterSpace
and 72.35 seconds on Ubuntu. Readiness requires successful token generation.

| Measurement | OuterSpace | Ubuntu |
| --- | ---: | ---: |
| Cold create-to-inference-ready, seconds | 351.0739 | 350.9435 |
| Replacement with cached OCI image, seconds | 93.9013 | 94.3115 |
| Sustained latency p50, seconds | 2.4965 | 2.4028 |
| Sustained latency p95, seconds | 2.9026 | 2.8239 |
| Sustained TTFT p50, seconds | 0.8624 | 0.8362 |
| Sustained TTFT p95, seconds | 1.1843 | 0.8879 |
| Tokens / summed request seconds | 3.1485 | 3.3173 |

The server uses two CPUs, 512 MiB and concurrency one, with a five-token prompt,
eight-token output limit, seed 42 and temperature zero. Model/tokenizer bytes and
Q4_K_M quantization are pinned in the [benchmark lock](../benchmarks/cpu-serving.lock.json).
NUMA topology is recorded; physical power is unavailable. Startup observations
include scheduling/readiness and model/OCI delivery, and are not distributions.
Replacement pods use cached OCI bytes but get a new private model volume. Raw
engine timestamps separately record model loading. Token rate divides generated
tokens by summed request duration. Memory charges/peaks include cache ownership
and establish no private-RSS saving. No hardware, energy or cost advantage is claimed.

Every load interval preserves Pod/container/image identity with no restart or OOM.
Replacement and drain change Pod IDs. Cold-node recovery changes boot/container
identity while retaining the node and serving Pod, with one expected container
restart. Actual CPU and memory cgroup controls are checked in all five phases.
Allowed-client access and denied ingress/egress also pass in every phase.

Each worker passes nine admission refusals for missing/incompatible controls or
budgets and two real incompatible/untrusted-model artifact refusals. No public
network or accelerator fallback is accepted. The endpoint is isolated to the lab;
this does not qualify a public production serving service.

The final native arm64 run also passed with harness
`b575d80cef331eff89f52f717724efa268c0acba` and the same immutable Inference image:
46 requests, 368 generated tokens, all five lifecycle phases and all refusals.
Two native boots prove real certificate rotation, persistence and recovery without
the bootstrap config drive. Independent verification checks 19 harness inputs,
all 40 packaged files, the raw disk, and 7 bound boot/QEMU evidence files.
The enrollment report SHA256 is
`47a25c5fb20edb60b9f62479234ce51e8cf6936ba285af93238c882b223e0b34`. Image construction files under `build/`, `src/image/`
and `src/components.lock.json` are unchanged between the recorded image and
harness revisions. The later 20-minute startup allowance changes the laboratory
wait budget; model/runtime bytes, resource limits and serving protocol remain
unchanged. Local verification is retained in
`out/milestone1-final-native-serving-verification.json`.

The [reproduction protocol](../benchmarks/cpu-serving.md) describes the lifecycle,
measurements and limits. Current-source Agent/Inference amd64/arm64 qualification
is tracked separately in [PR #43](https://github.com/Alien6-Studio/outerspace-os/pull/43).
This dataset covers one small generative model and emulated arm64 workers.
Physical machines, GPUs, multi-node migration and production endurance remain
untested. Development evidence grants no release or redistribution approval.
