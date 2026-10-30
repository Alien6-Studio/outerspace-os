# Distribution sources

This directory defines the content and configuration of an OuterSpace OS image.

| Path | Content |
| --- | --- |
| `image/` | mkosi profiles, partition definitions, host configuration and systemd services |
| `cluster/` | Worker configuration contract and Cilium integration settings |
| `components.lock.json` | Exact upstream runtime versions, URLs and checksums |
| `third_party/` | Upstream licenses and provenance |
| `branding/` | Distribution identity assets |

[Build tooling](../build/README.md) assembles these inputs into an image.
[Test tooling](../tests/README.md) runs outside the image. Host services are
systemd units and shell programs under `image/mkosi.extra/`; Python, compilers,
model weights and inference engines are not installed in the base OS.

See [architecture](../docs/architecture.md) for the host/workload boundary and
[cluster integration](cluster/README.md) for provisioning a worker.
