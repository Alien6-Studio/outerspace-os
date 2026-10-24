# CPU model serving development lab

This opt-in test runs a real small language model on the Inference worker's own
kernel. It extends the disposable enrollment lab; it does not add an inference
engine, Python, model weights or model credentials to the OS image.

```sh
make check
# Commit changes before building or qualifying an image.
make PROFILE=inference builder build smoke package
make PROFILE=inference cpu-serving
```

Docker, kind, kubectl, Helm and Python 3.11+ are required. The same exclusive lab
name and network as `make enrollment` are used, so run them sequentially. The
model is approximately 101 MiB; the CPU server image is downloaded separately.
No cloud resource or public HTTP listener is created. There is one emulated
OuterSpace worker, with four vCPUs and 4 GiB RAM.
Rebuild the Inference image with its 8 GiB state partition. Earlier 2 GiB images
can pass enrollment but exhaust writable storage while unpacking the server image.
Serving qualification rejects an undersized disk or less than 2 GiB of available
state space before staging the model. The Agent profile retains its 2 GiB minimum.

## Fixed workload

[cpu-serving.lock.json](cpu-serving.lock.json) locks llama.cpp's official CPU
server image by OCI index digest, source commit and build version. It selects
SmolLM2 135M Instruct, quantized as Q4_K_M, by the quantization publisher's exact
repository revision, file size and SHA256. The tokenizer is embedded in these
locked GGUF bytes. The upstream base model revision is recorded as a reference;
it is not proof that this third-party quantization can be reproduced from that
revision. Regenerating or substituting a GGUF requires new qualification.

License review for these selected inputs: the pinned llama.cpp source declares
[MIT](https://github.com/ggml-org/llama.cpp/blob/c7fc5094179bf8a9c73c18593db714f8da41a402/LICENSE).
The [base model card](https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct/blob/12fd25f77366fa6b3b4b768ec3050bf629380bac/README.md)
and [quantization model card](https://huggingface.co/bartowski/SmolLM2-135M-Instruct-GGUF/blob/09816acd5d99df7be770d85ea30822623dab342c/README.md)
declare Apache-2.0. This recipe downloads weights for a local test; weights are
not included in the repository or OS bundles. A public combined model/runtime
artifact still needs its own transitive dependency and redistribution review.

## Execution and checks

The host fetches only the immutable model URL and rejects wrong size, SHA256,
format or a symlink in the cache. It stages the verified file on the lab-owned
reference kind worker. A read-only model-source pod serves it inside the private
cluster; the OuterSpace pod's init container verifies it again before startup.
The model has its own 128 MiB `emptyDir`, separate from OCI image retention and
host boot state. A pod replacement deliberately reloads this model cache.
When an init container runs again after a node reboot, it re-verifies and reuses
the retained file without DNS or network access. A present but invalid or symlinked
cache entry fails; it is never silently replaced by another download.

The server runs as UID 65534, with a read-only root and model mount, all
capabilities dropped, no privilege escalation, default seccomp and no service
account token or host mounts/namespaces. Limits are two CPUs and 512 MiB, with
256 context tokens and one server slot. CPU-only and offline flags are explicit.
Missing or changed required controls cause qualification to fail.

NetworkPolicy permits model staging from its private source and DNS initially.
After readiness, all server egress is denied. Only the lab client can connect to
the serving port. Negative checks use IP addresses, so a DNS failure cannot stand
in for an egress or ingress denial. The server must still answer the allowed
client. This is a lab-isolated endpoint, not an authenticated production API.

Readiness performs actual one-token generation. Each sample group then sends
four streaming requests, with a fixed prompt, seed, temperature zero, eight output
tokens and prompt caching disabled. Evidence retains prompt evaluation, generated
text, token counts, engine timings, wall latency and observed time to first token.
The test repeats after a pod restart, a serving-only node drain/uncordon, and the
enrollment lab's cold reboot without bootstrap credentials. Drain uses a pod
selector, so the enrollment probe and deterministic CPU smoke pods are preserved.

`build/inference-cpu-ARCH/cpu-serving.json` is written only after the entire
enrollment, serving and cleanup sequence passes. It binds the image identity,
harness hashes, model/runtime lock, raw samples, running pod controls, running
model SHA256 and exact engine version. Per-phase logs retain model loading and
runtime diagnostics. A failed run removes its previous serving report.

## Scope and remaining qualification

Cold start wall time includes model staging, image pull and startup; consult the
per-phase engine logs for model loading details. Initial, restarted and recovered
raw samples are separate. Four samples characterize a functional test; their
median/p95 are observations with a very small sample size, not a service-level
objective or a hardware benchmark.

This lab does not establish model quality, production traffic endurance, a matched
Ubuntu comparison, physical-machine support, NUMA placement, power consumption,
GPU support or multi-node drain migration. Those remain separate work in #24 and
the hardware qualification track. Do not publish performance savings from TCG
measurements or promote them to a production serving claim.
