# Cluster integration

The first target is **bare-metal Kubernetes created with kubeadm** (or a
compatible self-managed control plane), with OuterSpace as its worker OS.
The same raw image can be qualified in QEMU before testing physical NICs,
storage controllers and GPUs on a dedicated server.

The OS image includes neither a control plane nor an embedded cluster creation
tool. kubeadm can create the control plane elsewhere; the worker joins by the
standard kubelet TLS-bootstrap contract. A control-plane image profile is a
separate scope because it also needs API server, etcd and their lifecycle.

## Configure a worker

Use a dedicated, short-lived Kubernetes bootstrap token and the control plane CA.
The target cluster must allow TLS bootstrap and certificate rotation. The kubelet
minor version must be compatible with that control plane. The CNI is installed by
the cluster; its binaries live in writable `/opt/cni/bin` (see architecture).

```sh
python3 build/tools/node-config.py \
  --api-server https://api.example.net:6443 \
  --ca /secure/cluster-ca.crt \
  --token-file /secure/bootstrap-token \
  --cluster-dns 10.96.0.10
make config-drive
```

Attach `out/node-config.raw` as a second virtual disk. It contains credentials;
do not publish it. Detach it after successful enrollment and revoke the bootstrap
token. The node keeps its rotated identity in `/var/lib/kubelet`, and its stable
hostname in `/var/lib/outerspace/hostname`. Serving certificate CSRs still require
an approval policy on the control plane; there is no blanket auto-approval here.

To warm the CRI cache, add a `prefetch-images` file to `out/node-config/` before making
the drive, with one `registry/repository@sha256:<64 hex characters>` per line.
This initial prefetch supports public registries; private prefetch credential
delivery remains a release gate. Workload imagePullSecrets are handled by CRI.

A fresh node without a complete config drive reports
`OUTERSPACE_ENROLLMENT_CONFIG_INVALID` and fails the provisioning unit. Kubelet
requires successful provisioning. An enrolled node can boot without the drive;
the provisioning unit removes its obsolete local bootstrap kubeconfig.

## VM worker qualification

After building, smoke-testing and packaging a committed source tree, run
`make PROFILE=agent enrollment` and `make PROFILE=inference enrollment` separately.
Requirements: Docker, kind, kubectl, Helm and Python 3.11+ on the development host.
The harness creates and cleans only `outerspace-enrollment`, its own private
kubeconfig and a labelled Docker network (`172.30.80.0/24`). It refuses an existing
lab or overlapping network. The default kubecontext is never used.
The harness must remain committed and unchanged during the test. Lab pods tolerate
up to thirty minutes of node unavailability to allow slow emulated cold boots;
the bounded recovery checks still have to pass.
The emulated worker uses four vCPUs and 4 GiB of RAM to allow image unpacking and
Cilium startup to progress concurrently. The harness waits for both Cilium and Envoy Ready
before launching application pods and after reboot. Network checks establish a
healthy service response, require default-deny to block it, then require recovery
after an explicit allow policy.
Both boots then require the named probe, CPU server and client pods to become
Ready within twenty minutes. This TCG lab budget includes endpoint compilation
and image extraction; it is not a hardware startup target. The supervising
process allows kubectl to report its own bounded timeout. Agent readiness alone does not prove endpoint
creation or application recovery. Failed runs retain workload pod status alongside
node status, events and Cilium logs to distinguish CNI startup from probe failures.

The packaged disk boots through UEFI in a QEMU VM connected by TAP to a dedicated
kubeadm-compatible kind control plane. Only that control plane and a reference
client use Docker's kernel. The OuterSpace worker must expose its own pinned
kernel and immutable profile/source identity. The test runner needs TUN and
network capabilities; no Docker socket or host network namespace enters it.

The test checks Node Ready, a deterministic CPU classifier, cross-node Cilium
DNS/service traffic, default-deny and explicit allow. A read-only host probe
checks locked accounts and public certificate fingerprints. Serving CSRs are
approved only after checking requester, subject, usages and the exact node SANs.
The lab alone uses ten-minute initial client certificates to observe real rotation,
then one-hour renewals so the credential stays valid during an emulated cold boot.
It then revokes the bootstrap token (or proves its server-side absence if the TTL
has already expired), powers off the VM, detaches the config drive
and checks the same Node UID, hostname, machine ID and rotated certificate on the
next boot, followed by workload/network recovery. A fresh disk overlay and stable
VM UUID are used; the packaged raw disk must remain unchanged.

`enrollment.json` binds the result to the full image identity, public configuration,
probe snapshots and selected workload digest. Private config drives and tokens
remain in a temporary directory removed during cleanup. This is VM enrollment
evidence, not physical-server, production model-serving, CIS or Secure Boot
qualification. Existing UEFI smoke and enrollment reports remain distinct gates.

## Native OCI Agent v1 profile

Agent images load `outerspace-agent-v1` AppArmor policy at boot without writing
to the immutable root. The boot check requires an enforcing profile and AppArmor
policy ABI v7. A workload requests that exact Localhost profile and RuntimeDefault
seccomp. An absent profile prevents execution; Landlock is not selected by v1.

The versioned [cluster profile](agent/profile-v1.json) creates an exclusive
`outerspace-agents-v1` namespace, an unprivileged service account, a RuntimeClass,
default-deny ingress/egress, a four-pod quota and native validating admission.
It targets Kubernetes 1.36 with Node authorization and NodeRestriction enabled.
The operator owns the policies and the protected node label; workloads receive
no API token or RBAC grant and cannot change their own enforcement.

After qualifying the Agent node and its loaded policy:

```sh
kubectl apply -f src/cluster/agent/profile-v1.json
kubectl label node AGENT_NODE outerspace.sh.node-restriction.kubernetes.io/agent-profile=v1
kubectl apply -f src/cluster/agent/workload-v1.json
```

The [example workload](agent/workload-v1.json) runs a digest-pinned BusyBox image
as UID/GID 65534. Replace its immutable image and command with the intended agent
workload. V1 permits one container, no init/debug containers, all capabilities
dropped, no privilege escalation, a read-only root and two per-pod memory-backed
volumes: 64 MiB workspace and 16 MiB scratch. CPU, memory and ephemeral-storage
requests/limits are mandatory; ceilings are 1 CPU, 256 MiB and 64 MiB respectively.
Host mounts/namespaces/ports, runtime sockets, injected credentials, additional
devices, accelerator resources and mutable image tags are refused at admission.
Container overrides and the ephemeral-container update subresource are checked.

This is a shared-kernel execution profile within one trusted administrative
domain. It grants no network access by default. Additional permitted flows and
launcher identities must be controlled by the trusted operator. It provides no
provider credentials, approval broker, persistent tenant workspace, VM-equivalent
isolation or measured density/OOM-containment guarantee.

`make agent-admission` tests API acceptance/refusal in a disposable kind cluster;
it does not qualify OS enforcement. `make PROFILE=agent agent-isolation` extends
the real OS enrollment lab with running UID/capability/seccomp/AppArmor checks,
workspace execution, denied host access/escalation/policy changes, an unloaded-LSM
refusal and allowed/denied network paths before and after cold node recovery.
It emits `agent-isolation.json` only after runtime checks and cleanup succeed.

The admission mechanism and explicit AppArmor selection follow the Kubernetes
[admission policy](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/)
and [AppArmor](https://v1-36.docs.kubernetes.io/docs/tutorials/security/apparmor/)
interfaces. Qualification is bound to the actual image/runtime and test report.

## eBPF network profile

The initial Cilium Helm profile is pinned to chart **1.20.3**. The image checks
required kernel features during the build, mounts bpffs at boot and exposes BTF.
Unprivileged BPF stays disabled; only trusted system agents can load programs.
Compilers and BPF toolchains stay inside the agent containers.

On a disposable kubeadm cluster created with pod CIDRs and without kube-proxy:

```sh
helm install cilium oci://quay.io/cilium/charts/cilium \
  --version 1.20.3 --namespace kube-system \
  -f src/cluster/cilium/values.yaml \
  --set k8sServiceHost=api.example.net \
  --set k8sServicePort=6443
```

This is an integration profile, not a successful cluster certification. Gate it
with Cilium connectivity/policy tests, node reboot, agent restart and the target
Kubernetes minor version. Do not replace an existing cluster CNI in place using
this example. Hubble visibility is enabled; exposing Hubble endpoints is not.
Tetragon runtime detection/enforcement is the next eBPF integration, after defining
and testing policies for containerd, GPU access and module loading.

## Dragonfly

The native dfdaemon 1.4.9 client is in the host image so its startup does not depend
on first pulling a DaemonSet image. Enable it with a reachable HTTPS Dragonfly
Manager and an explicit registry allowlist when generating the config drive:

```sh
python3 build/tools/node-config.py \
  --api-server https://api.example.net:6443 \
  --ca /secure/cluster-ca.crt --token-file /secure/bootstrap-token \
  --cluster-dns 10.96.0.10 \
  --dragonfly-manager https://dragonfly-manager.example.net:65003 \
  --p2p-registry docker.io --p2p-registry ghcr.io \
  --image-max-age 24h --p2p-cache-ttl 6h
```

The Manager, schedulers and optional dedicated seed peers are external cluster
services and are not deployed by this command. The first integration targets
public images on a trusted cluster network. Private-image P2P needs authorization
isolation and peer/manager/scheduler mTLS before use across tenants.

Containerd pulls blobs through the loopback proxy on 4001 and keeps HTTPS origin
resolution/fallback. The proxy and diagnostic endpoints bind to loopback. Peers
need TCP 4000 between permitted nodes; do not expose peer service on an untrusted
network. Dedicated seed nodes should outlive worker cache TTLs, so simultaneous
worker eviction does not force a new origin download for every rollout.

The two caches have separate owners:

| Cache | Owner | Initial retention | Pressure thresholds |
| --- | --- | --- | --- |
| Unused OCI images/snapshots | kubelet via CRI/containerd | 24h without use | 80% high / 65% low |
| Dragonfly task pieces | dfdaemon | 6h without task access | 70% high / 50% low |

Kubelet GC protects images referenced by containers; there is no external cron
pruning containerd storage. Collection is periodic, not an exact expiry alarm.
Kubelet resets its age accounting when restarted, so a restart can extend the
retention window. Dragonfly may retain a piece because it is serving other peers,
even after the local OCI image was removed. The inverse is also normal: removing
peer pieces does not remove an unpacked runtime image. Both stores share `/var`;
account for their combined disk budget and validate concurrent GC under pressure.

## Managed providers

AKS and similar managed services control which node OS images are supported.
OuterSpace is not a supported replacement for a stock AKS node image. AKS on
Windows Server/Arc also restricts replacing the managed node base image.
Qualifying a custom image for a particular managed provider requires its supported
image integration path, separate from Kubernetes CRI/CNI compatibility. Azure VMs
running a self-managed cluster and bare-metal servers can be independent targets.

Sources: [Cilium host requirements](https://docs.cilium.io/en/stable/operations/system_requirements/),
[Dragonfly/containerd integration](https://d7y.io/docs/next/operations/integrations/container-runtime/containerd/),
[Kubelet image GC](https://kubernetes.io/docs/concepts/architecture/garbage-collection/),
[AKS node support policies](https://learn.microsoft.com/en-us/azure/aks/support-policies),
[AKS on Windows Server support](https://learn.microsoft.com/en-us/azure/aks/aksarc/support-policies).

## Isolated local network lab

This runs on Docker's kernel, separately from the OS image test. It creates only
an explicitly named disposable cluster and uses a separate kubeconfig:

```sh
kind create cluster --name outerspace-lab --config tests/integration/kind.yaml \
  --kubeconfig /private/tmp/outerspace-lab.kubeconfig
api_host=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' outerspace-lab-control-plane)
helm --kubeconfig /private/tmp/outerspace-lab.kubeconfig install cilium \
  oci://quay.io/cilium/charts/cilium --version 1.20.3 -n kube-system \
  -f src/cluster/cilium/values.yaml --set k8sServiceHost="$api_host" \
  --set k8sServicePort=6443 --set bpf.autoMount.enabled=true \
  --set cgroup.autoMount.enabled=true --wait --timeout=10m
./tests/harness/kind-network.sh /private/tmp/outerspace-lab.kubeconfig
```

Use an OS-appropriate private temporary directory instead of `/private/tmp` on
Linux. The two auto-mount overrides are specific to kind; the OS mounts these
filesystems itself. Cleanup only this lab with
`kind delete cluster --name outerspace-lab` when done.
