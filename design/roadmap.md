# Milestones and release gates

## 0.1 — Bootable inference worker foundation

- Image assembled from a small Ubuntu package set; website isolated on gh-pages.
- Hash-locked upstream runtime binaries, package manifest, root verity, persistent
  state, runtime hardening configuration and local declarative bootstrap.
- Native arm64 development build and native amd64/arm64 CI pipeline.
- Bare-metal generic kernel/modules, eBPF/BTF build checks, Cilium cluster profile,
  native Dragonfly peer integration and independent runtime/peer cache retention.
- Passed locally on arm64: QEMU boot with CRI available and read-only root.
- Passed separately in kind: three-node Cilium DNS/service routing, deny and restore.
- This lab does not qualify an OuterSpace node in Kubernetes.
- Still required: UEFI disk boot, state persistence across reboot, config-drive
  enrollment into a disposable cluster, Node Ready and a CPU inference pod.
- Still required: AppArmor/seccomp enforcement tests, privilege boundaries,
  dependency/vulnerability inventory and an agreed source license.

## 0.2 — Faster and smaller delivery, measured

- Reference inference image and model, pinned by digest and content hash.
- Benchmark standard pull, TLS registry mirror, prefetch, remote snapshotter and
  then P2P at 1/10/100 nodes. Include cache misses, restart and registry outages.
- Gate: published measurements and a documented decision per component.
- Separate OCI layer delivery, model loading, time to first token and steady-state
  throughput. Do not trade correctness or private registry authorization for speed.

## 0.3 — GPU worker profile

- Image-baked kernel/driver combination, signed modules, NVIDIA toolkit/CDI.
- Device discovery, resource allocation, warm/cold real-model inference tests.
- Gate: validated hardware matrix and footprint/latency report.

## 0.4 — Managed immutable lifecycle

- A/B root and UKI pairs, signed release metadata and owned Secure Boot keys.
- Drain, staged write, boot-attempt limit, node-health commit and automatic rollback.
- Gate: power-loss/fault injection, corrupted image rejection, expired signature,
  failed boot rollback, state migration and downgrade compatibility.
- Snapshot-locked Ubuntu inputs, reproducibility comparison, SBOM, provenance and
  release vulnerability policy. No unsigned development image promoted to stable.

The [release policy](../release/README.md) defines alpha/beta/RC/stable gates,
maintenance cadence and the distinction between a roadmap milestone and a release.
