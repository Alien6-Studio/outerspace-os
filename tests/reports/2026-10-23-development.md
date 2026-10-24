# Local development validation — 2026-10-23

Paths and commands below describe the layout used for this run. Current entry
points are documented in the [test guide](../README.md).

Status: `0.1.0-dev.0`, local working-tree validation. This is not a release gate
attestation or production qualification. CI must bind future results to its exact
source commit and candidate inventory.

## Passed

- `make check`: 24 tests for worker bootstrap input/permissions, protected archive
  extraction and digest verification, version/release gates and candidate tamper
  rejection. Shell syntax checks and Python compilation also pass.
- `make build`: native arm64 image assembly with mkosi 25.3, Noble generic kernel
  6.8.0-147, containerd 2.3.7 and kubelet 1.36.5. Kernel BPF/BTF feature checks pass.
- `make smoke`: QEMU TCG, 2 virtual CPUs, 1 GiB RAM, snapshot disk, split kernel and
  initrd with the UKI's embedded root hash. `OUTERSPACE_SELFTEST_OK`, then orderly
  VM poweroff; process exit 0. Checks cover read-only ext4 root and root mapping,
  writable state, cgroup v2, bpffs/BTF, AppArmor availability, selected sysctls,
  locked `outerspace` UID/home and the containerd CRI API.
- Separate kind lab: Kubernetes 1.36.1, one control plane plus two workers,
  kube-proxy disabled, Cilium chart 1.20.3; three nodes Ready and Cilium status OK.
  `scripts/test-kind-network.sh /private/tmp/outerspace-lab.kubeconfig` returns
  `OUTERSPACE_CILIUM_NETWORK_OK`: cross-node DNS/service request, policy deny,
  then restored access. Test pods use restricted security contexts.

## Observations, not product performance claims

In this single empty-worker QEMU test, `free -m` reported 170 MiB used of 956 MiB
available guest memory; root ext4 showed 577 MiB used in an 863 MiB filesystem.
The raw disk has a 3.2 GiB apparent size including its 2 GiB state partition;
allocated disk space was about 1.1 GiB. Firmware, GPU drivers, workloads and caches
change these numbers. TCG boot time on a development workstation is not a hardware
boot benchmark. No inference speed or P2P bandwidth benefit was measured.

## Not demonstrated

UEFI disk boot, Secure Boot, bare-metal NIC/storage/firmware compatibility,
config-drive enrollment, OS node Ready, real inference workloads, GPU operation,
Dragonfly peer transfer/fallback/private authorization, image/cache age and disk
pressure cleanup, persistence across reboot, CIS host/Kubernetes audits, SBOM/CVE
review, artifact signing, A/B updates, fault-injection rollback and soak tests.

The kind cluster runs Docker's Linux kernel, not this OS image's kernel. Its
network policy test is useful integration evidence but cannot qualify Cilium on
OuterSpace. The QEMU test calls CRI info; it does not run an inference container.

## Reproduce

Use `make check builder build smoke` for the image. For the isolated kind network
lab, see [cluster integration](../../src/cluster/README.md). Local build output and
logs are in ignored `build/`; bootstrap credentials and cloud resources are not
committed. No Scaleway or Azure resource was provisioned.
