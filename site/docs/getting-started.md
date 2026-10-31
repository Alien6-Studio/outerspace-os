---
title: Build and test
description: Build the qualified CPU source snapshot and configure an OuterSpace OS Kubernetes worker in a disposable UEFI VM.
---
# Build and evaluate the CPU alpha

The `0.1.0-alpha.1` images are qualified and prepared as a draft. Published downloads
will appear on [GitHub Releases](https://github.com/Alien6-Studio/outerspace-os/releases).
Read the [alpha limitations](releases.md) before evaluating a worker.

## Build from source

Install Python 3.11+, Make and Docker running Linux containers. The build uses
Docker's native architecture: ARM64 on Apple Silicon, AMD64 on x86 hosts.
Allow space for image output, source archives and reusable download caches.

```sh
git clone https://github.com/Alien6-Studio/outerspace-os.git
cd outerspace-os
git checkout v0.1.0-alpha.1
make check
make PROFILE=agent HARDWARE=cpu builder build smoke package
# Build the other profile independently:
make PROFILE=inference HARDWARE=cpu build smoke package
```

Images, bundles and reports are written under `out/<profile>-cpu-<architecture>/`;
`.cache/` holds reusable downloads. The builder uses privileged Linux mount
namespaces without a host Docker socket or host devices mounted inside it.

The smoke test boots the packaged image through **UEFI twice** and checks
persistence, read-only root, verity, cgroup v2/PSI, kernel BPF/BTF, AppArmor,
CRI availability and host resource budgets. Native enrollment and workload
qualification are separate targets; `make help` lists them.

## Verify and boot a downloaded candidate

Check the archive checksum, then extract the distribution bundle into a new
directory. The accompanying `.tar.attestation.jsonl` authenticates its inner
`SHA256SUMS`, not the outer tar file. Use the release's `verify-attestation.py`
companion with the expected commit, tag and candidate run from the release notes.
Then run `sha256sum -c SHA256SUMS` inside the bundle before using the disk image.

Use a disposable UEFI VM with four vCPUs and 4 GiB RAM, with Secure Boot disabled.
The qualified configuration uses a separate Kubernetes 1.36 control plane and
Cilium 1.20.3 with the supplied `src/cluster/cilium` configuration. This worker
image does not create the control plane.

## Configure a worker

From the corresponding source checkout, supply the real cluster CA, a protected
short-lived bootstrap-token file and the HTTPS API address:

```sh
python3 build/tools/node-config.py \
  --api-server https://api.example.net:6443 \
  --ca /secure/cluster-ca.crt \
  --token-file /secure/bootstrap-token \
  --cluster-dns 10.96.0.10
make config-drive
```

Attach `out/node-config.raw` only to the intended worker. It contains credentials;
keep it private, detach it after enrollment and revoke the bootstrap token.
The worker retains its rotated identity in persistent state. Use an explicit
control-plane policy for serving-certificate CSR approval.

See the [worker guide](https://github.com/Alien6-Studio/outerspace-os/blob/main/src/cluster/README.md)
for the Agent profile, CPU serving and native qualification commands. The `outerspace`
and root accounts are locked; the image provides no SSH server or shared password.
