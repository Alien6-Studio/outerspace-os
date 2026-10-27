# CPU serving qualification and Ubuntu comparison

The native lab serves the pinned SmolLM2 135M Instruct Q4_K_M model with the
official CPU llama.cpp OCI image on an actual OuterSpace Inference worker.
The engine, Python and model weights remain workloads, outside the host image.

```sh
make check
make serving-admission                     # disposable API preflight only
make PROFILE=inference builder build smoke package
make PROFILE=inference cpu-serving         # native lifecycle and refusals
make serving-comparison                    # same immutable image versus Ubuntu
```

`SERVING_IMAGE_OUTPUT=/absolute/path/to/inference-cpu-ARCH` selects an already
packaged image for comparison. `OUT_DIR` selects reports and `REFERENCE_CACHE`
the signed Ubuntu download cache. Commit the harness before qualification. Docker,
kind, kubectl, Helm, GnuPG and Python 3.11+ are test prerequisites. The exclusively
owned local cluster, network and VMs are removed even after failure. Run these
labs sequentially; existing labs are never silently reused or deleted.

## Locked inputs and execution boundary

[cpu-serving.lock.json](cpu-serving.lock.json) records the engine OCI digest and
source revision, the quantizer's immutable repository revision, model bytes and
SHA256, base-model reference, quantization and limits. The tokenizer is embedded
in the locked GGUF bytes. The quantizer's artifact is not proof that the GGUF can
be reproduced from the declared base-model revision.

The selected llama.cpp source declares [MIT](https://github.com/ggml-org/llama.cpp/blob/c7fc5094179bf8a9c73c18593db714f8da41a402/LICENSE).
The [base-model card](https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct/blob/12fd25f77366fa6b3b4b768ec3050bf629380bac/README.md)
and [quantization card](https://huggingface.co/bartowski/SmolLM2-135M-Instruct-GGUF/blob/09816acd5d99df7be770d85ea30822623dab342c/README.md)
declare Apache-2.0. Downloads are local test inputs, not repository or OS bundle
contents. Public redistribution of combined model/runtime artifacts requires its
own dependency and license review.

The worker needs the Inference profile's 8 GiB state partition and at least 2 GiB
available before staging. The roughly 101 MiB model is hash-checked on the test
runner and copied to a read-only private source on the lab's reference kind node.
A verified init container stages it in a 128 MiB per-Pod `emptyDir`; this cache is
separate from OCI retention and OS boot state. Pod replacement reloads it. After
node reboot, a retained valid model is verified locally without network access.
A present invalid cache is refused, never repaired by downloading a replacement.

The server runs on the selected worker as UID 65534, without service-account
tokens, host mounts/namespaces, extra capabilities or privilege escalation. Its
root and model mount are read-only, seccomp is RuntimeDefault, and actual cgroup
limits must be two CPUs and 512 MiB. The engine has a 256-token context, one slot,
two threads and explicit offline/zero-GPU flags. Readiness generates a token.

A fail-closed ValidatingAdmissionPolicy protects every Pod in the dedicated
`outerspace-inference-v1` lab namespace, including resize and ephemeral-container
updates. It binds the exact engine/init images, model verification command, CPU
arguments, resources, volumes and security controls. The model source and trusted
observer stay in the separate enrollment namespace. This is a single supported
benchmark entry point; shared tenant authorization is the separate #28 scope.

NetworkPolicy admits only the lab client to the serving endpoint. Model-source
and DNS egress are allowed only during staging, then all server egress is denied.
Each measured phase proves allowed inference and refused ingress/egress using
IP-address checks. No public listener, accelerator or external-model fallback is
created.

## Functional and failure-path qualification

The live API refuses nine altered configurations: untrusted engine or model pin,
over-budget or insufficient model memory, missing seccomp, writable root/model,
removed offline mode, and GPU fallback. These must fail before a Pod exists.
The low-memory refusal is an admission result, not a model OOM benchmark.

On the actual worker, two correctly admitted Pods receive corrupted model-source
bytes. Invalid GGUF magic and a changed payload must fail the init verifier for
the expected reason, before the server container starts. Original source bytes
are restored and verified after each test. These native refusals supplement the
unit checks; API-only preflight does not qualify OS execution.

The successful scenario records initial cold serving, sustained serving, a warm
Pod replacement, same-worker drain/uncordon, and clean cold-node recovery without
bootstrap credentials. The registered Node UID must persist and its boot ID must
change. Four streaming requests exercise each lifecycle phase. Sustained serving
requires at least 30 sequential requests over at least 60 seconds, with a bounded
maximum of 1,024 samples and a 30-minute client observation budget. A failed or
incomplete interval never produces a passing report.

Every request uses the fixed prompt `The capital of France is`, seed 42,
temperature zero, eight output tokens, concurrency one and prompt caching disabled.
Raw samples preserve prompt token counts, output text/tokens, engine timings,
wall latency and observed first-token time. Reports recompute p50/p95 and aggregate
tokens per request wall second. They also record engine model-load timestamps,
first server startup versus replacement startup, actual CPU/memory cgroups,
current/lifetime-peak memory, CPU/throttling/OOM counters and virtual NUMA topology.
The server Pod, container and image identity must remain stable during each group.
Model-load duration from container startup includes engine setup; raw logs retain
finer diagnostics. Cgroup memory peaks cover the container lifetime, not only the
request interval. Physical power is unavailable in this QEMU TCG reference.

## Matched reference and retained evidence

`serving-comparison` runs OuterSpace and the signed, hash-locked official Ubuntu
24.04 cloud image serially on the same native runner: four virtual CPUs, 4 GiB RAM
and QEMU TCG. It requires identical kernel notes/version, runtime executable bytes,
containerd/kubelet configuration, OCI model engine, model artifact and workload
settings. Both receive the same Cilium configuration, observer, resource limits,
refusal tests and lifecycle/load scenario. Ubuntu retains its stock OS identity
and writable 12 GiB root; OuterSpace retains verity root and a separate state disk.
This storage-layout difference is explicit, not hidden behind a savings claim.

The standalone native report is `out/inference-cpu-ARCH/cpu-serving.json`, bound to
the image and enrollment evidence. The paired report is
`out/serving-comparison/serving-comparison.json`, with per-subject raw observations,
boot/engine logs and hashes. It binds the exact packaged image/source and the
independently committed harness, plus Canonical's signed reference inventory.
Changed model/runtime bytes, missing samples or mismatched worker inputs reject
the comparison. Failed labs remove their previous passing report and preserve
failure logs. CI runs the native scenario for each Inference CPU architecture;
the larger paired Ubuntu comparison is opt-in.

These are measured development baselines for one small model, one slot and a
bounded load interval. They establish no production endurance, model quality,
physical-machine support, power savings, GPU support or multi-node migration.
Architecture-specific acceptance comes from completed reports, never from the
existence of a harness or the results of the other architecture.
