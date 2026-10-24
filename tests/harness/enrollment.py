#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Qualify one packaged worker in an exclusively owned, disposable local VM lab."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
BUILD_TOOLS = ROOT / 'build/tools'
sys.path.insert(0, str(BUILD_TOOLS))
LAB = 'outerspace-enrollment'
RUNNER = LAB + '-vm'
LABEL = 'io.outerspace.enrollment-lab'
KIND_IMAGE = 'kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5'
PYTHON_IMAGE = 'python:3.12-alpine@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d'
VM_IP = '172.30.80.10'
HARNESS_INPUTS = ['tests/harness/enrollment.py', 'tests/harness/enrollment-vm.py',
                  'tests/integration/node-probe.py', 'tests/integration/cpu-smoke.py',
                  'tests/harness/cpu-serving.py', 'tests/integration/serving-client.py',
                  'tests/integration/model-stage.py', 'tests/benchmarks/cpu-serving.lock.json',
                  'tests/integration/agent-isolation.sh', 'src/cluster/agent/profile-v1.json',
                  'tests/integration/agent-resources.sh',
                  'src/image/mkosi.extra/etc/outerspace/kubelet.yaml',
                  'src/cluster/agent/workload-v1.json',
                  'src/image/mkosi.extra/usr/share/outerspace/apparmor/agent-v1',
                  'src/image/mkosi.extra/usr/lib/systemd/system/outerspace-agent-profile.service']
AGENT_NAMESPACE = 'outerspace-agents-v1'
AGENT_NODE_LABEL = 'outerspace.sh.node-restriction.kubernetes.io/agent-profile'


def run(*args, data=None, check=True, env=None, timeout=900):
    result = subprocess.run(list(map(str, args)), input=data, capture_output=True, text=True,
                            check=False, env=env, timeout=timeout)
    if check and result.returncode:
        # No command input is included: it may contain the bootstrap token.
        raise RuntimeError(f'{args[0]} failed: {result.stderr[-3000:]}')
    return result


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load_script(name, directory=Path(__file__).resolve().parent):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), directory / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wait_for(description, function, timeout=600):
    print(description, flush=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = function()
        if value:
            return value
        time.sleep(3)
    raise RuntimeError(f'Timed out: {description}')


def verify_agent_probe(observation):
    required = {'status': 'passed', 'uid': 65534, 'gid': 65534,
                'apparmor': 'outerspace-agent-v1 (enforce)', 'seccomp': 2,
                'no_new_privileges': True, 'read_only_root': True, 'capabilities': 'none',
                'workspace': 'passed', 'host_access': 'denied', 'privilege_escalation': 'denied',
                'mounts': 'denied', 'device_creation': 'denied',
                'policy_change': 'denied', 'child_confinement': 'passed'}
    if any(type(observation.get(key)) is not type(value) or observation.get(key) != value
           for key, value in required.items()):
        raise ValueError('Agent did not prove every required runtime boundary')


def verify_agent_resource_limits(pod):
    expected = {'cpu.max': '50000 100000', 'memory.max': '134217728', 'pids.max': '256'}
    if not pod.get('path') or any(pod.get('files', {}).get(key) != value for key, value in expected.items()):
        raise ValueError('Actual Agent cgroup CPU, memory or PID limit differs from the budget')


def agent_pressure_observed(mode, before, after):
    verify_agent_resource_limits(before)
    verify_agent_resource_limits(after)
    def counter(pod, file, key):
        values = dict(line.split() for line in pod['files'][file].splitlines())
        return int(values[key])
    def increase(file, key):
        return counter(after, file, key) - counter(before, file, key)
    if mode == 'cpu':
        # CFS throttle counts are not hierarchical. A container's own quota
        # can fire before its identical parent Pod quota is exhausted.
        def throttles(pod):
            return counter(pod, 'cpu.stat', 'nr_throttled') + sum(int(dict(line.split() for line in
                group['cpu.stat'].splitlines())['nr_throttled']) for group in pod.get('descendants', {}).values())
        return throttles(after) > throttles(before) and increase('cpu.stat', 'usage_usec') > 100000
    if mode == 'fork':
        return increase('pids.events', 'max') > 0 and int(after['files']['pids.current']) >= 250
    if mode == 'oom':
        return increase('memory.events', 'oom_kill') > 0 and after['result'] == 'oom-container-restarted'
    if mode == 'scratch':
        fs = after.get('scratch', {})
        return (after['result'] == 'scratch-full' and fs.get('capacity_bytes') == 16 * 1024**2
                and fs.get('used_bytes', 0) >= 15 * 1024**2)
    if mode == 'logs':
        files = after['log_files']
        return (after['result'] == 'logs-written' and any('.log.' in name for name in files)
                and len(files) <= 2 and sum(files.values()) <= 24 * 1024**2)
    raise ValueError('Unknown Agent pressure mode: ' + mode)


def verify_recovery(before, rotated, after, before_node, after_node, bootstrap_certificate_sha256=None):
    for key in ['identity', 'hostname', 'machine_id']:
        if not before.get(key) or before[key] != rotated.get(key) or before[key] != after.get(key):
            raise ValueError(f'Node identity did not persist: {key}')
    initial = bootstrap_certificate_sha256 or before['client_certificate_sha256']
    if initial == rotated['client_certificate_sha256']:
        raise ValueError('No real client certificate rotation observed')
    if rotated['client_certificate_sha256'] != after['client_certificate_sha256']:
        raise ValueError('The rotated client certificate did not survive the cold boot')
    if before['boot_id'] == after['boot_id'] or after['bootstrap_present']:
        raise ValueError('Expected a new kernel boot without bootstrap credentials')
    if before_node['metadata']['uid'] != after_node['metadata']['uid']:
        raise ValueError('The Kubernetes Node object was replaced')
    if not all(probe.get('accounts_locked') for probe in [before, rotated, after]):
        raise ValueError('Default accounts must remain locked')


def validate_serving_csr(request, name):
    if (request.get('username') != 'system:node:' + name
            or request.get('signerName') != 'kubernetes.io/kubelet-serving'
            or set(request.get('usages', [])) not in ({'digital signature', 'server auth'},
                                                    {'digital signature', 'key encipherment', 'server auth'})):
        raise ValueError('Unexpected serving certificate requester, signer or usage')
    pem = base64.b64decode(request['request'], validate=True).decode()
    text = run('openssl', 'req', '-noout', '-verify', '-text', data=pem).stdout
    subject = run('openssl', 'req', '-noout', '-subject', '-nameopt', 'RFC2253', data=pem).stdout.strip()
    san = re.search(r'X509v3 Subject Alternative Name:\s*\n\s*([^\n]+)', text)
    if (subject != f'subject=CN=system:node:{name},O=system:nodes' or not san
            or set(san.group(1).split(', ')) != {'DNS:' + name, 'IP Address:' + VM_IP}):
        raise ValueError('Serving CSR subject/SAN does not match the observed lab node')


class Lab:
    def __init__(self, state, output):
        self.state = state
        self.output = output
        self.kubeconfig = state / 'kubeconfig'
        self.network_created = False
        self.kind_created = False
        self.runner_created = False

    def kube(self, *args, **kwargs):
        return run('kubectl', '--kubeconfig', self.kubeconfig, '--request-timeout=30s', *args, **kwargs)

    def api(self, *args):
        return json.loads(self.kube('get', *args, '-o', 'json').stdout)

    def apply(self, *objects):
        self.kube('apply', '-f', '-', data=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': list(objects)}))

    def vm(self, *args, check=True):
        return run('docker', 'exec', RUNNER, 'python3', '/work/tests/harness/enrollment-vm.py', *args, check=check)

    def setup(self, api_only=False):
        # No default kubecontext, caller-supplied cluster or existing lab is accepted.
        if run('docker', 'network', 'inspect', LAB, check=False).returncode == 0:
            raise ValueError('Lab network already exists; refusing to reuse or clean an unowned lab')
        names = run('docker', 'ps', '-a', '--format', '{{.Names}}').stdout.splitlines()
        if any(name.startswith(LAB + '-') for name in names):
            raise ValueError('Lab containers already exist; refusing to overwrite them')
        run('docker', 'network', 'create', '--label', LABEL + '=true', '--subnet=172.30.80.0/24',
            '--ip-range=172.30.80.128/25', '--aux-address=worker=' + VM_IP, LAB)
        self.network_created = True
        config = self.state / 'kind.yaml'
        config.write_text('''kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerAddress: 127.0.0.1
  disableDefaultCNI: true
  kubeProxyMode: none
  podSubnet: 10.245.0.0/16
  serviceSubnet: 10.97.0.0/16
kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    controllerManager:
      extraArgs:
        - name: cluster-signing-duration
          value: 10m
nodes:
  - role: control-plane
  - role: worker
''')
        self.kind_created = True
        print('Creating the dedicated kubeadm-compatible control plane', flush=True)
        run('kind', 'create', 'cluster', '--name', LAB, '--image', KIND_IMAGE,
            '--config', config, '--kubeconfig', self.kubeconfig,
            env={**os.environ, 'KIND_EXPERIMENTAL_DOCKER_NETWORK': LAB})
        self.kubeconfig.chmod(0o600)
        self.control_plane = LAB + '-control-plane'
        self.api_ip = run('docker', 'inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',
                          self.control_plane).stdout.strip()
        if api_only:
            return
        print('Installing Cilium in the dedicated cluster', flush=True)
        run('helm', '--kubeconfig', self.kubeconfig, 'install', 'cilium',
            'oci://quay.io/cilium/charts/cilium', '--version', '1.20.3', '-n', 'kube-system',
            '-f', ROOT / 'src/cluster/cilium/values.yaml', '--set', 'k8sServiceHost=' + self.api_ip,
            '--set', 'k8sServicePort=6443', '--set', 'bpf.autoMount.enabled=true',
            '--set', 'cgroup.autoMount.enabled=true', '--wait', '--timeout=10m')
        self.kube('wait', '--for=condition=Ready', 'nodes', '--all', '--timeout=300s')

    def configure(self):
        token = run('docker', 'exec', self.control_plane, 'kubeadm', 'token', 'create', '--ttl=30m').stdout.strip()
        self.token_id = token.split('.')[0]
        token_file = self.state / 'token'
        token_file.write_text(token + '\n')
        token_file.chmod(0o600)
        ca = self.state / 'ca.crt'
        ca.write_text(run('docker', 'exec', self.control_plane, 'cat', '/etc/kubernetes/pki/ca.crt').stdout)
        load_script('node-config', BUILD_TOOLS).render('https://' + self.api_ip + ':6443', ca, token_file,
                                         ['10.97.0.10'], 'cluster.local', self.state / 'config')
        run('docker', 'run', '-d', '--name', RUNNER, '--label', LABEL + '=true', '--network', LAB,
            '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--cap-add=NET_RAW', '--cap-add=NET_BIND_SERVICE',
            '--cap-add=DAC_OVERRIDE',
            '--device=/dev/net/tun', '--mount', f'type=bind,src={ROOT},dst=/work,readonly',
            '--mount', f'type=bind,src={self.output},dst=/image,readonly',
            '--mount', f'type=bind,src={self.state},dst=/state', 'outerspace-enrollment:dev', 'sleep', 'infinity')
        self.runner_created = True
        compressed = list(self.output.glob('outerspace-*/*.raw.zst'))
        if len(compressed) != 1:
            raise ValueError('Expected exactly one packaged disk')
        run('docker', 'exec', '--user', f'{os.getuid()}:{os.getgid()}', RUNNER, 'zstd', '-q', '-d', '--sparse',
            '/image/' + str(compressed[0].relative_to(self.output)), '-o', '/state/packaged.raw')
        identity = json.loads((self.output / 'build-identity.json').read_text())
        if digest(self.state / 'packaged.raw') != identity['raw_image_sha256']:
            raise ValueError('The decompressed packaged disk differs from its qualified identity')
        (self.state / 'packaged.raw').chmod(0o400)
        run('docker', 'exec', '--user', f'{os.getuid()}:{os.getgid()}', RUNNER, 'bash', '-euc',
            'umask 077; truncate -s 16M /state/node-config.raw; mkfs.vfat -n OOS_CONFIG /state/node-config.raw; '
            'mcopy -s -i /state/node-config.raw /state/config/* ::/')
        return {'api_server': 'https://' + self.api_ip + ':6443', 'cluster_dns': ['10.97.0.10'],
                'ca_sha256': digest(ca), 'kubelet_config_sha256': digest(self.state / 'config/kubelet.yaml'),
                'bootstrap_ttl': '30m', 'client_signing_duration': '10m (test lab only)',
                'worker_ip': VM_IP, 'kind_image': KIND_IMAGE, 'cilium_chart': '1.20.3',
                'tools': {'kind': run('kind', 'version').stdout.strip(),
                          'kubectl': json.loads(run('kubectl', 'version', '--client', '-o', 'json').stdout)['clientVersion']['gitVersion'],
                          'helm': run('helm', 'version', '--short').stdout.strip()},
                'runner_image': run('docker', 'image', 'inspect', 'outerspace-enrollment:dev', '--format', '{{.Id}}').stdout.strip()}

    def worker(self):
        for node in self.api('nodes')['items']:
            if any(address['address'] == VM_IP for address in node['status'].get('addresses', [])):
                if not node['metadata']['name'].startswith('oos-') or '6.8.0-147' not in node['status']['nodeInfo']['kernelVersion']:
                    raise ValueError('The worker does not use the OuterSpace kernel/identity')
                return node

    def extend_renewal_lifetime(self):
        # Short initial certificates trigger a real renewal promptly; renewed
        # certificates must remain valid throughout a slow emulated cold boot.
        name = 'kube-controller-manager-' + self.control_plane
        previous = self.api('-n', 'kube-system', 'pod', name)['status']['containerStatuses'][0]['containerID']
        run('docker', 'exec', self.control_plane, 'sed', '-i',
            's/cluster-signing-duration=10m/cluster-signing-duration=1h/',
            '/etc/kubernetes/manifests/kube-controller-manager.yaml')
        def restarted():
            result = self.kube('-n', 'kube-system', 'get', 'pod', name, '-o', 'json', check=False)
            if result.returncode:
                return False
            states = json.loads(result.stdout).get('status', {}).get('containerStatuses', [])
            return any(s.get('containerID') != previous and s.get('ready') for s in states)
        wait_for('Extending lab renewal lifetime before the first rotation', restarted)

    def approve_serving(self, node):
        name = node['metadata']['name']
        for csr in self.api('csr')['items']:
            request = csr['spec']
            if (request.get('username') != 'system:node:' + name
                    or request.get('signerName') != 'kubernetes.io/kubelet-serving'
                    or csr.get('status', {}).get('conditions')):
                continue
            validate_serving_csr(request, name)
            self.kube('certificate', 'approve', csr['metadata']['name'])
        return any(csr['spec'].get('username') == 'system:node:' + name
                   and csr['spec'].get('signerName') == 'kubernetes.io/kubelet-serving'
                   and csr.get('status', {}).get('certificate') for csr in self.api('csr')['items'])

    def workloads(self, node):
        self.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': LAB}})
        security = {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']},
                    'readOnlyRootFilesystem': True}
        def pod(name, host, command, root=False):
            container = {'name': name, 'image': PYTHON_IMAGE, 'command': command, 'securityContext': security,
                         'resources': {'requests': {'cpu': '50m', 'memory': '32Mi'},
                                       'limits': {'cpu': '500m', 'memory': '128Mi'}}}
            obj = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': LAB,
                    'labels': {'app': name, 'access': 'allowed'}},
                   'spec': {'nodeName': host, 'automountServiceAccountToken': False,
                            'tolerations': [{'key': key, 'operator': 'Exists', 'effect': 'NoExecute',
                                             'tolerationSeconds': 1800} for key in
                                            ['node.kubernetes.io/not-ready', 'node.kubernetes.io/unreachable']],
                            'securityContext': {'runAsUser': 0 if root else 65534,
                                                'seccompProfile': {'type': 'RuntimeDefault'}},
                            'containers': [container]}}
            if root:
                obj['spec']['volumes'] = [{'name': 'host', 'hostPath': {'path': '/', 'type': 'Directory'}}]
                # Observe newly created emptyDir tmpfs mounts as well as those
                # already present when this read-only lab probe was started.
                container['volumeMounts'] = [{'name': 'host', 'mountPath': '/host', 'readOnly': True,
                                              'mountPropagation': 'HostToContainer'}]
            return obj
        self.apply(pod('probe', node, ['sleep', '3600'], root=True),
                   pod('cpu', node, ['python3', '-u', '-c', (ROOT / 'tests/integration/cpu-smoke.py').read_text()]),
                   pod('client', LAB + '-worker', ['sleep', '3600']),
                   {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'cpu', 'namespace': LAB},
                    'spec': {'selector': {'app': 'cpu'}, 'ports': [{'port': 8080}]}},
                   {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                    'metadata': {'name': 'cpu-deny', 'namespace': LAB},
                    'spec': {'podSelector': {'matchLabels': {'app': 'cpu'}}, 'policyTypes': ['Ingress'], 'ingress': []}})
        self.wait_workloads()

    def wait_workloads(self):
        # Agent readiness precedes endpoint compilation, especially under TCG.
        # Under arm64 TCG, endpoint compilation can consume thirteen minutes
        # before image extraction starts. Allow both phases a bounded budget.
        # Named pods also prevent an empty namespace from satisfying this gate.
        print('Waiting for the probe, CPU server and client pods to be Ready', flush=True)
        self.kube('-n', LAB, 'wait', '--for=condition=Ready',
                  'pod/probe', 'pod/cpu', 'pod/client', '--timeout=1200s', timeout=1230)

    def cilium_ready(self, node):
        pods = self.api('-n', 'kube-system', 'pods', '--field-selector', 'spec.nodeName=' + node)['items']
        required = {'cilium-agent', 'cilium-envoy'}
        ready = set()
        for pod in pods:
            containers = {container['name'] for container in pod['spec']['containers']}
            if any(condition['type'] == 'Ready' and condition['status'] == 'True'
                   for condition in pod.get('status', {}).get('conditions', [])):
                ready.update(required & containers)
        return ready == required

    def probe(self):
        result = self.kube('-n', LAB, 'exec', 'probe', '--', 'python3', '-c',
                           (ROOT / 'tests/integration/node-probe.py').read_text(), check=False)
        return json.loads(result.stdout) if result.returncode == 0 else None

    def client_csr(self, node, probe=None, rotated=False):
        for csr in self.api('csr')['items']:
            pem = csr.get('status', {}).get('certificate')
            if not pem or csr['spec'].get('signerName') != 'kubernetes.io/kube-apiserver-client-kubelet':
                continue
            certificate = base64.b64decode(pem).decode()
            fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()
            if probe and fingerprint != probe['client_certificate_sha256']:
                continue
            user = csr['spec']['username']
            if probe is None:
                if user != 'system:bootstrap:' + self.token_id:
                    continue
                subject = run('openssl', 'x509', '-noout', '-subject', '-nameopt', 'RFC2253', data=certificate).stdout.strip()
                if subject != f'subject=CN=system:node:{node},O=system:nodes':
                    continue
            if rotated and user != 'system:node:' + node:
                raise ValueError('Rotation did not authenticate with the enrolled node identity')
            if not rotated and user != 'system:bootstrap:' + self.token_id:
                raise ValueError('Initial certificate did not use this lab bootstrap token')
            return {'name': csr['metadata']['name'], 'uid': csr['metadata']['uid'],
                    'requester': user, 'certificate_sha256': fingerprint}
        if probe is None:
            return None
        raise ValueError('The active client certificate does not match an issued CSR')

    def network(self):
        client = ['-n', LAB, 'exec', 'client', '--', 'python3', '-c']
        # Confirm DNS independently so an exec/DNS failure cannot count as a policy denial.
        self.kube(*client, 'import socket; assert socket.gethostbyname("cpu.' + LAB + '.svc.cluster.local")')
        wait_for('Verifying cluster DNS from the OuterSpace workload', lambda:
                 self.kube('-n', LAB, 'exec', 'cpu', '--', 'python3', '-c',
                           'import socket; assert socket.gethostbyname("kubernetes.default.svc.cluster.local")',
                           check=False).returncode == 0)
        request = 'import urllib.request; assert urllib.request.urlopen("http://cpu.' + LAB + '.svc.cluster.local:8080", timeout=3).read() == b"outerspace-cpu-ok:1536\\n"'
        denied = ('import socket,sys; s=socket.socket(); s.settimeout(3); '
                  'result=s.connect_ex(("cpu.' + LAB + '.svc.cluster.local",8080)); sys.exit(0 if result in (11,110) else 1)')
        allow = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                    'metadata': {'name': 'cpu-allow', 'namespace': LAB},
                    'spec': {'podSelector': {'matchLabels': {'app': 'cpu'}}, 'policyTypes': ['Ingress'],
                             'ingress': [{'from': [{'podSelector': {'matchLabels': {'app': 'client'}}}],
                                          'ports': [{'protocol': 'TCP', 'port': 8080}]}]}}
        self.apply(allow)
        wait_for('Verifying healthy cross-node service before policy denial',
                 lambda: self.kube(*client, request, check=False).returncode == 0)
        self.kube('-n', LAB, 'delete', 'networkpolicy', 'cpu-allow')
        wait_for('Verifying default-deny on the OuterSpace endpoint',
                 lambda: self.kube(*client, denied, check=False).returncode == 0)
        self.apply(allow)
        wait_for('Verifying restored cross-node DNS/service/CPU response',
                 lambda: self.kube(*client, request, check=False).returncode == 0)

    def revoke_bootstrap(self):
        # Slow emulation can outlive the token TTL. Prove server-side absence
        # even if the token cleaner already removed it; API errors must fail.
        name = 'bootstrap-token-' + self.token_id
        self.kube('-n', 'kube-system', 'delete', 'secret', name, '--ignore-not-found=true')
        result = self.kube('-n', 'kube-system', 'get', 'secret', name, '--ignore-not-found=true', '-o', 'json')
        if result.stdout.strip():
            raise ValueError('Bootstrap token was not revoked')

    def agent_admission(self):
        template = json.loads((ROOT / 'src/cluster/agent/workload-v1.json').read_text())
        result = self.kube('create', '--dry-run=server', '-f', '-', '-o', 'json', data=json.dumps(template))
        if json.loads(result.stdout)['spec']['runtimeClassName'] != 'outerspace-agent-v1':
            raise ValueError('Agent RuntimeClass missing after admission')
        changes = [
            ('runtime', ['spec', 'runtimeClassName'], None),
            ('scheduler', ['spec', 'schedulerName'], 'untrusted-scheduler'),
            ('direct-node', ['spec', 'nodeName'], self.agent_node),
            ('host-network', ['spec', 'hostNetwork'], True),
            ('host-pid', ['spec', 'hostPID'], True),
            ('host-ipc', ['spec', 'hostIPC'], True),
            ('root', ['spec', 'securityContext', 'runAsUser'], 0),
            ('seccomp', ['spec', 'securityContext', 'seccompProfile'], {'type': 'Unconfined'}),
            ('apparmor', ['spec', 'securityContext', 'appArmorProfile'], {'type': 'RuntimeDefault'}),
            ('token', ['spec', 'automountServiceAccountToken'], True),
            ('service-account', ['spec', 'serviceAccountName'], 'default'),
            ('registry-secret', ['spec', 'imagePullSecrets'], [{'name': 'unapproved-registry-key'}]),
            ('priority', ['spec', 'priorityClassName'], 'system-node-critical'),
            ('user-namespace', ['spec', 'hostUsers'], False),
            ('extra-group', ['spec', 'securityContext', 'supplementalGroups'], [0]),
            ('sysctl', ['spec', 'securityContext', 'sysctls'], [{'name': 'net.ipv4.ip_unprivileged_port_start', 'value': '0'}]),
            ('privileged', ['spec', 'containers', 0, 'securityContext', 'privileged'], True),
            ('capability', ['spec', 'containers', 0, 'securityContext', 'capabilities', 'add'], ['NET_ADMIN']),
            ('escalation', ['spec', 'containers', 0, 'securityContext', 'allowPrivilegeEscalation'], True),
            ('writable-root', ['spec', 'containers', 0, 'securityContext', 'readOnlyRootFilesystem'], False),
            ('container-root', ['spec', 'containers', 0, 'securityContext', 'runAsUser'], 0),
            ('container-seccomp', ['spec', 'containers', 0, 'securityContext', 'seccompProfile'], {'type': 'Unconfined'}),
            ('container-apparmor', ['spec', 'containers', 0, 'securityContext', 'appArmorProfile'], {'type': 'Unconfined'}),
            ('mutable-image', ['spec', 'containers', 0, 'image'], 'busybox:latest'),
            ('over-cpu', ['spec', 'containers', 0, 'resources', 'limits', 'cpu'], '2'),
            ('over-memory', ['spec', 'containers', 0, 'resources', 'limits', 'memory'], '512Mi'),
            ('over-storage', ['spec', 'containers', 0, 'resources', 'limits', 'ephemeral-storage'], '128Mi'),
            ('under-reserved-cpu', ['spec', 'containers', 0, 'resources', 'requests', 'cpu'], '50m'),
            ('under-reserved-memory', ['spec', 'containers', 0, 'resources', 'requests', 'memory'], '32Mi'),
            ('under-reserved-storage', ['spec', 'containers', 0, 'resources', 'requests', 'ephemeral-storage'], '8Mi'),
            ('pod-resources', ['spec', 'resources'], {'requests': {'cpu': '1', 'memory': '256Mi'},
                                                     'limits': {'cpu': '1', 'memory': '256Mi'}}),
            ('gpu', ['spec', 'containers', 0, 'resources', 'limits', 'nvidia.com/gpu'], '1'),
            ('unbounded-workspace', ['spec', 'volumes', 0, 'emptyDir', 'sizeLimit'], '1Gi'),
            ('host-files', ['spec', 'volumes', 0], {'name': 'workspace', 'hostPath': {'path': '/'}}),
            ('runtime-socket', ['spec', 'volumes', 0], {'name': 'workspace', 'hostPath': {'path': '/run/containerd/containerd.sock'}}),
            ('external-workspace', ['spec', 'volumes', 0], {'name': 'workspace', 'persistentVolumeClaim': {'claimName': 'other-tenant'}}),
            ('policy-mount', ['spec', 'containers', 0, 'volumeMounts', 0, 'mountPath'], '/etc/apparmor.d'),
            ('mount-propagation', ['spec', 'containers', 0, 'volumeMounts', 0, 'mountPropagation'], 'HostToContainer'),
            ('subpath', ['spec', 'containers', 0, 'volumeMounts', 0, 'subPath'], 'policy'),
            ('init-container', ['spec', 'initContainers'], [{**copy.deepcopy(template['spec']['containers'][0]),
                                                          'name': 'unapproved-init'}]),
        ]
        refusals = {}
        for name, path, value in changes:
            obj = copy.deepcopy(template)
            obj['metadata']['name'] = 'refuse-' + name
            # Spoofed application labels never exempt a pod from admission.
            obj['metadata']['labels'] = {'app': 'trusted-system', 'outerspace-agent-profile': 'disabled'}
            target = obj
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            if name in ['over-cpu', 'over-memory', 'over-storage']:
                # Isolate the ceiling check from the full-reservation check.
                obj['spec']['containers'][0]['resources']['requests'][path[-1]] = value
            if name == 'privileged':
                # Kubernetes rejects privileged + no-new-privileges before the
                # profile can evaluate it; exercise a valid privileged request.
                obj['spec']['containers'][0]['securityContext']['allowPrivilegeEscalation'] = True
            if name == 'priority':
                obj['spec']['preemptionPolicy'] = 'PreemptLowerPriority'
            result = self.kube('create', '--dry-run=server', '-f', '-', data=json.dumps(obj), check=False)
            if (result.returncode == 0 or not any(marker in result.stderr for marker in
                    ['OuterSpace Agent v1', 'violates PodSecurity', "ValidatingAdmissionPolicy 'outerspace-agent-v1'"])):
                raise ValueError(f'Agent admission refusal not proven for {name}: {result.stderr[-1500:]}')
            refusals[name] = result.stderr.strip()
        self.agent_checks['admission_refusals'] = refusals
        # Scheduling gates hold real admitted pods without starting containers.
        # Pending launches consume the same four-slot quota as running agents.
        queued = []
        try:
            for index in range(4):
                obj = copy.deepcopy(template)
                obj['metadata']['name'] = 'quota-slot-' + str(index)
                obj['spec']['schedulingGates'] = [{'name': 'outerspace.sh/qualification'}]
                self.kube('create', '-f', '-', data=json.dumps(obj))
                queued.append(obj['metadata']['name'])
            obj['metadata']['name'] = 'quota-slot-refused'
            refused = self.kube('create', '--dry-run=server', '-f', '-', data=json.dumps(obj), check=False)
            if refused.returncode == 0 or 'exceeded quota' not in refused.stderr or 'pods' not in refused.stderr:
                raise ValueError('Agent launch concurrency/queue quota was not enforced: ' + refused.stderr)
            self.agent_checks['queue_quota'] = {'admitted_slots': 4, 'fifth_refused': refused.stderr.strip()}
        finally:
            if queued:
                self.kube('-n', AGENT_NAMESPACE, 'delete', 'pod', *queued, '--wait=true', '--timeout=60s')
                wait_for('Waiting for deleted launch slots to leave the quota', lambda:
                    self.api('-n', AGENT_NAMESPACE, 'resourcequota', 'outerspace-agent-v1')
                        .get('status', {}).get('used', {}).get('pods') == '0', timeout=60)

    def agent_install(self):
        self.apply(*json.loads((ROOT / 'src/cluster/agent/profile-v1.json').read_text())['items'])
        def policy_ready():
            policy = self.api('validatingadmissionpolicy', 'outerspace-agent-v1')
            status = policy.get('status', {})
            if status.get('typeChecking', {}).get('expressionWarnings'):
                raise ValueError('Agent admission policy has type errors: ' + json.dumps(status))
            return policy if 'typeChecking' in status and status.get('observedGeneration') == policy['metadata']['generation'] else None
        policy = wait_for('Checking native Agent admission expressions', policy_ready, timeout=60)
        self.agent_checks['admission_policy_uid'] = policy['metadata']['uid']
        # Type checking and admission binding propagation are independent.
        # A dry-run sentinel must be denied before any workload is created.
        sentinel = json.loads((ROOT / 'src/cluster/agent/workload-v1.json').read_text())
        sentinel['metadata']['name'] = 'admission-sentinel'
        sentinel['spec'].pop('runtimeClassName')
        def binding_active():
            result = self.kube('create', '--dry-run=server', '-f', '-', data=json.dumps(sentinel), check=False)
            return result.returncode != 0 and 'OuterSpace Agent v1' in result.stderr
        wait_for('Waiting for the Agent admission binding to enforce refusals', binding_active, timeout=60)

    def agent_start(self, node):
        self.agent_node = node
        self.agent_checks = {'profile': 'outerspace-agent-v1', 'phases': {}}
        self.agent_install()
        self.kube('label', 'node', node, AGENT_NODE_LABEL + '=v1')
        self.agent_admission()
        identity = 'system:serviceaccount:' + AGENT_NAMESPACE + ':outerspace-agent-v1'
        result = self.kube('--as=' + identity, 'patch', 'validatingadmissionpolicy', 'outerspace-agent-v1',
                           '--type=merge', '-p', '{"spec":{"failurePolicy":"Ignore"}}', check=False)
        if result.returncode == 0 or 'Forbidden' not in result.stderr:
            raise ValueError('Agent identity can change admission policy or refusal is unproven')
        self.agent_checks['policy_authority_refused'] = True
        result = self.kube('--as=system:node:' + node, '--as-group=system:nodes', '--as-group=system:authenticated',
                           'label', 'node', node, AGENT_NODE_LABEL + '=spoofed', '--overwrite', check=False)
        if result.returncode == 0 or 'Forbidden' not in result.stderr or 'label' not in result.stderr:
            raise ValueError('NodeRestriction did not protect the Agent profile label')
        self.agent_checks['node_label_spoofing_refused'] = True
        workload = json.loads((ROOT / 'src/cluster/agent/workload-v1.json').read_text())
        workload['spec']['containers'][0]['command'] = ['/bin/sh', '-euc',
            "printf 'outerspace-agent-ok\\n' > /workspace/index.html; exec httpd -f -p 8081 -h /workspace"]
        workload['spec']['tolerations'] = [
            {'key': key, 'operator': 'Exists', 'effect': 'NoExecute', 'tolerationSeconds': 1800}
            for key in ['node.kubernetes.io/not-ready', 'node.kubernetes.io/unreachable']]
        launched = time.monotonic()
        self.apply(workload)
        self.kube('-n', AGENT_NAMESPACE, 'wait', '--for=condition=Ready', 'pod/agent', '--timeout=1200s', timeout=1230)
        self.agent_checks['first_create_to_ready_wall_seconds'] = time.monotonic() - launched
        # Check UPDATE and the ephemeral-container subresource, not only CREATE.
        self.kube('-n', AGENT_NAMESPACE, 'label', 'pod', 'agent', 'checked=update', '--dry-run=server')
        changed = self.kube('-n', AGENT_NAMESPACE, 'patch', 'pod', 'agent', '--dry-run=server', '--type=json',
            '-p', '[{"op":"replace","path":"/spec/containers/0/image","value":"busybox:latest"}]', check=False)
        if changed.returncode == 0 or 'OuterSpace Agent v1' not in changed.stderr:
            raise ValueError('Agent image UPDATE did not preserve admission enforcement: ' + changed.stderr)
        ephemeral = self.api('-n', AGENT_NAMESPACE, 'pod', 'agent')
        ephemeral['spec']['ephemeralContainers'] = [{'name': 'unapproved-child',
            'image': workload['spec']['containers'][0]['image'], 'command': ['sleep', '10'],
            'securityContext': copy.deepcopy(workload['spec']['containers'][0]['securityContext'])}]
        changed = self.kube('replace', '--raw', '/api/v1/namespaces/' + AGENT_NAMESPACE +
            '/pods/agent/ephemeralcontainers', '-f', '-', data=json.dumps(ephemeral), check=False)
        if changed.returncode == 0 or 'OuterSpace Agent v1' not in changed.stderr:
            raise ValueError('Agent ephemeral container injection was not refused: ' + changed.stderr)
        self.agent_checks['update_and_ephemeral_refused'] = True
        def resize(cpu):
            resources = copy.deepcopy(workload['spec']['containers'][0]['resources'])
            for kind in ['requests', 'limits']:
                resources[kind]['cpu'] = cpu
            return self.kube('-n', AGENT_NAMESPACE, 'patch', 'pod', 'agent', '--subresource=resize',
                '--dry-run=server', '--type=strategic', '-p', json.dumps({'spec': {'containers': [
                    {'name': 'agent', 'resources': resources}]}}), check=False)
        accepted = resize('600m')
        if accepted.returncode:
            raise ValueError('Bounded Agent resize was not admitted: ' + accepted.stderr)
        refused = resize('2')
        if refused.returncode == 0 or 'OuterSpace Agent v1' not in refused.stderr:
            raise ValueError('Over-budget Agent resize was not refused: ' + refused.stderr)
        self.agent_checks['resize'] = {'bounded_admitted': True, 'over_budget_refused': refused.stderr.strip()}
        # A missing required LSM must fail on the real OS, outside the policy's
        # namespace so admission does not mask the runtime refusal.
        missing = copy.deepcopy(workload)
        missing['metadata'] = {'name': 'missing-agent-lsm', 'namespace': LAB}
        missing['spec'].pop('runtimeClassName')
        missing['spec'].pop('nodeSelector')
        missing['spec']['nodeName'] = node
        missing['spec']['serviceAccountName'] = 'default'
        missing['spec']['securityContext']['appArmorProfile']['localhostProfile'] = 'outerspace-agent-v1-absent'
        self.apply(missing)
        def missing_refused():
            pod = self.api('-n', LAB, 'pod', 'missing-agent-lsm')
            status = pod.get('status', {})
            diagnostics = json.dumps(status)
            return pod if ('AppArmor' in diagnostics or 'apparmor' in diagnostics) and not any(
                state.get('state', {}).get('running') for state in status.get('containerStatuses', [])) else None
        refused = wait_for('Checking runtime refusal of an unloaded Agent AppArmor profile', missing_refused, timeout=120)
        self.agent_checks['missing_lsm_refusal'] = refused['status']
        self.kube('-n', LAB, 'delete', 'pod', 'missing-agent-lsm', '--wait=true', '--timeout=60s')

    def agent_sample(self, phase):
        pod = self.api('-n', AGENT_NAMESPACE, 'pod', 'agent')
        if pod['spec']['nodeName'] != self.agent_node:
            raise ValueError('Agent was not placed on the actual OuterSpace worker')
        result = self.kube('-n', AGENT_NAMESPACE, 'exec', 'agent', '--', '/bin/sh', '-euc',
                           (ROOT / 'tests/integration/agent-isolation.sh').read_text())
        observation = json.loads(result.stdout)
        verify_agent_probe(observation)
        # Prove the HTTP endpoints and explicit allow paths before checking a
        # bounded timeout after the temporary policies are removed.
        service = self.api('-n', LAB, 'service', 'cpu')['spec']['clusterIP']
        self.kube('-n', AGENT_NAMESPACE, 'exec', 'agent', '--', '/bin/sh', '-c',
                  'wget -T 3 -qO- http://127.0.0.1:8081 | grep -qx outerspace-agent-ok')
        allow = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
            'metadata': {'name': 'qualification-allow', 'namespace': AGENT_NAMESPACE},
            'spec': {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress'],
                'ingress': [{'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': LAB}},
                                      'podSelector': {'matchLabels': {'app': 'client'}}}],
                             'ports': [{'protocol': 'TCP', 'port': 8081}]}],
                'egress': [{'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': LAB}},
                                    'podSelector': {'matchLabels': {'app': 'cpu'}}}],
                            'ports': [{'protocol': 'TCP', 'port': 8080}]}]}}
        # The CPU server already has default-deny ingress from the Core test.
        # Keep its narrowly scoped allow throughout the Agent denial probes so
        # a refusal cannot be attributed to the remote server's ingress policy.
        peer_allow = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
            'metadata': {'name': 'agent-qualification-allow', 'namespace': LAB},
            'spec': {'podSelector': {'matchLabels': {'app': 'cpu'}}, 'policyTypes': ['Ingress'],
                'ingress': [{'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': AGENT_NAMESPACE}},
                                      'podSelector': {'matchLabels': {'app': 'agent'}}}],
                             'ports': [{'protocol': 'TCP', 'port': 8080}]}]}}
        self.apply(allow, peer_allow)
        egress = ['-n', AGENT_NAMESPACE, 'exec', 'agent', '--', 'wget', '-T', '3', '-qO-', 'http://' + service + ':8080']
        ingress = ['-n', LAB, 'exec', 'client', '--', 'python3', '-c',
            'import urllib.request; assert urllib.request.urlopen("http://' + pod['status']['podIP'] +
            ':8081",timeout=3).read() == b"outerspace-agent-ok\\n"']
        wait_for('Checking explicit Agent egress allow', lambda: self.kube(*egress, check=False).returncode == 0)
        wait_for('Checking explicit Agent ingress allow', lambda: self.kube(*ingress, check=False).returncode == 0)
        self.kube('-n', AGENT_NAMESPACE, 'delete', 'networkpolicy', 'qualification-allow')
        denied_egress = ['-n', AGENT_NAMESPACE, 'exec', 'agent', '--', '/bin/sh', '-ec',
            'if wget -T 3 -O /scratch/egress http://' + service + ':8080 2>/scratch/egress-error; '
            'then exit 1; fi; grep -q "download timed out" /scratch/egress-error; echo OUTERSPACE_AGENT_EGRESS_DENIED']
        denied_ingress = ['-n', LAB, 'exec', 'client', '--', 'python3', '-c',
            'import socket; s=socket.socket(); s.settimeout(3); result=s.connect_ex(("' +
            pod['status']['podIP'] + '",8081)); assert result in (11,110),result; print("OUTERSPACE_AGENT_INGRESS_DENIED")']
        def egress_denied():
            denied = self.kube(*denied_egress, check=False)
            return denied.returncode == 0 and denied.stdout.strip() == 'OUTERSPACE_AGENT_EGRESS_DENIED'
        def ingress_denied():
            denied = self.kube(*denied_ingress, check=False)
            return denied.returncode == 0 and denied.stdout.strip() == 'OUTERSPACE_AGENT_INGRESS_DENIED'
        wait_for('Checking default-deny Agent egress', egress_denied, timeout=60)
        wait_for('Checking default-deny Agent ingress', ingress_denied, timeout=60)
        self.kube('-n', LAB, 'delete', 'networkpolicy', 'agent-qualification-allow')
        observation.update({'egress_denied': True, 'ingress_denied': True, 'explicit_allow': 'passed',
                            'pod_uid': pod['metadata']['uid'],
                            'container_image_id': pod['status']['containerStatuses'][0]['imageID'],
                            'node_name': self.agent_node})
        self.agent_checks['phases'][phase] = observation
        (self.output / ('agent-isolation-' + phase + '.json')).write_text(json.dumps(pod, indent=2) + '\n')

    def agent_resource_snapshot(self, uids):
        result = self.kube('-n', LAB, 'exec', 'probe', '--', 'python3', '-c',
                           (ROOT / 'tests/integration/node-probe.py').read_text(), json.dumps(uids))
        return json.loads(result.stdout)['resources']

    def agent_resource_pulse(self):
        started = time.monotonic()
        node = self.api('node', self.agent_node)
        conditions = {item['type']: item['status'] for item in node['status']['conditions']}
        if conditions.get('Ready') != 'True' or any(conditions.get(key) != 'False' for key in
                                                   ['MemoryPressure', 'DiskPressure', 'PIDPressure']):
            raise ValueError('Node became unhealthy under Agent resource pressure: ' + json.dumps(conditions))
        api_seconds = time.monotonic() - started
        started = time.monotonic()
        self.kube('-n', AGENT_NAMESPACE, 'exec', 'agent', '--', '/bin/sh', '-ec',
                  'wget -T 3 -qO- http://127.0.0.1:8081 | grep -qx outerspace-agent-ok', timeout=45)
        return {'api_wall_seconds': api_seconds, 'neighbor_wall_seconds': time.monotonic() - started,
                'conditions': conditions}

    def agent_resources(self):
        # No stress tools or benchmark daemon enter the host. The existing
        # privileged lab probe only observes; admitted BusyBox pods create load.
        pods = self.api('pods', '-A', '--field-selector', 'spec.nodeName=' + self.agent_node)['items']
        uids = [pod['metadata']['uid'] for pod in pods]
        initial = self.agent_resource_snapshot(uids)
        time.sleep(5)
        quiet = self.agent_resource_snapshot(uids)
        cases = {}
        previous_uids = []
        for mode in ['cpu', 'scratch', 'oom', 'fork', 'logs']:
            print('Qualifying Agent resource pressure: ' + mode, flush=True)
            workload = json.loads((ROOT / 'src/cluster/agent/workload-v1.json').read_text())
            workload['metadata']['name'] = 'pressure'
            workload['spec']['restartPolicy'] = 'OnFailure' if mode == 'oom' else 'Never'
            workload['spec']['containers'][0]['command'] = ['/bin/sh', '-euc',
                (ROOT / 'tests/integration/agent-resources.sh').read_text(), 'agent-resources', mode]
            started = time.monotonic()
            self.apply(workload)
            uid = self.api('-n', AGENT_NAMESPACE, 'pod', 'pressure')['metadata']['uid']
            if uid in previous_uids:
                raise ValueError('Pressure pod identity was reused')
            previous_uids.append(uid)
            try:
                self.kube('-n', AGENT_NAMESPACE, 'wait', '--for=condition=Ready', 'pod/pressure',
                          '--timeout=600s', timeout=630)
                launch_seconds = time.monotonic() - started
                wait_for('Checking fresh private workspace before pressure', lambda: self.kube(
                    '-n', AGENT_NAMESPACE, 'exec', 'pressure', '--', '/bin/sh', '-ec',
                    'test "$(cat /workspace/ready)" = fresh; test ! -e /workspace/previous-workspace; '
                    'test ! -e /scratch/previous-workspace', check=False).returncode == 0, timeout=60)
                before = self.agent_resource_snapshot([uid])
                diagnostic = self.output / ('agent-resources-' + mode + '-latest.json')
                diagnostic.write_text(json.dumps({'pod_uid': uid, 'before': before}, indent=2) + '\n')
                verify_agent_resource_limits(before['pods'][uid])
                self.kube('-n', AGENT_NAMESPACE, 'exec', 'pressure', '--', 'touch', '/workspace/go')
                pulses = []
                def exercised():
                    pulses.append(self.agent_resource_pulse())
                    sample = self.agent_resource_snapshot([uid])
                    diagnostic.write_text(json.dumps({'pod_uid': uid, 'before': before, 'after': sample,
                                                      'responsiveness': pulses}, indent=2) + '\n')
                    if agent_pressure_observed(mode, before['pods'][uid], sample['pods'][uid]):
                        return sample
                after = wait_for('Observing enforced ' + mode + ' boundary and a responsive neighbor', exercised, timeout=180)
                # Require responsiveness after the boundary has been hit, too.
                pulses.append(self.agent_resource_pulse())
                pod = self.api('-n', AGENT_NAMESPACE, 'pod', 'pressure')
                if pod['spec']['nodeName'] != self.agent_node:
                    raise ValueError('Resource pressure ran on another worker')
                if mode == 'oom':
                    status = pod['status']['containerStatuses'][0]
                    terminated = status.get('lastState', {}).get('terminated', {})
                    if (status['restartCount'] != 1 or terminated.get('reason') != 'OOMKilled'
                            or terminated.get('exitCode') != 137):
                        raise ValueError('Whole-container OOM and a single contained restart were not proven')
                cases[mode] = {'pod_uid': uid, 'warm_create_to_ready_wall_seconds': launch_seconds,
                               'before': before, 'after': after, 'responsiveness': pulses, 'pod': pod}
            finally:
                self.kube('-n', AGENT_NAMESPACE, 'delete', 'pod', 'pressure', '--wait=true', '--timeout=120s', timeout=150)
            def removed():
                snapshot = self.agent_resource_snapshot([uid])
                item = snapshot['pods'][uid]
                return snapshot if (item['path'] is None and not item['processes'] and not item['mounts']
                                    and not item['workspace_present']) else None
            cases[mode]['teardown'] = wait_for('Checking removal of processes, cgroups, mounts and workspace', removed, timeout=120)
        image = json.loads((self.output / 'build-identity.json').read_text())
        compressed = list(self.output.glob('outerspace-*/*.raw.zst'))
        self.agent_resource_checks = {
            'status': 'passed', 'reference': {'vcpus': 4, 'memory_mib': 4096, 'virtualization': 'QEMU UEFI',
                'architecture': image['architecture'], 'disk_compressed_bytes': compressed[0].stat().st_size,
                'disk_apparent_bytes': (self.output / 'outerspace.raw').stat().st_size},
            'quiescent_enrolled': {'before': initial, 'after': quiet, 'pods': [
                {'namespace': pod['metadata']['namespace'], 'name': pod['metadata']['name'],
                 'uid': pod['metadata']['uid'], 'images': [c['image'] for c in pod['spec']['containers']]}
                for pod in pods]},
            'first_agent_create_to_ready_wall_seconds': self.agent_checks['first_create_to_ready_wall_seconds'],
            'cases': cases, 'tested_concurrent_agents': 2,
            'limits': ['Quiescent enrolled node includes Cilium and qualification workloads; not bare idle host',
                       'No matched standard-worker comparison or physical-hardware performance claim',
                       'Density 10/100 and aggregate block-I/O throttling are not qualified',
                       'Log rotation is asynchronous; no hard 2 MiB per-write quota',
                       'No agent dependencies, framework or model loaded by the pressure workload'],
        }

    def cleanup(self):
        failures = []
        volumes = set()

        def remove(description, *command):
            try:
                run(*command)
            except (RuntimeError, subprocess.TimeoutExpired):
                failures.append(description)

        if self.kind_created:
            try:
                containers = run('docker', 'ps', '-aq', '--filter',
                                 'label=io.x-k8s.kind.cluster=' + LAB).stdout.split()
                if containers:
                    for container in json.loads(run('docker', 'inspect', *containers).stdout):
                        volumes.update(mount['Name'] for mount in container.get('Mounts', [])
                                       if mount['Type'] == 'volume' and mount['Destination'] == '/var')
            except (RuntimeError, subprocess.TimeoutExpired, ValueError, KeyError):
                failures.append('kind volume inventory')
        if self.runner_created:
            remove('VM runner', 'docker', 'rm', '-fv', RUNNER)
        if self.kind_created:
            remove('kind control plane', 'kind', 'delete', 'cluster', '--name', LAB,
                   '--kubeconfig', self.kubeconfig)
        if volumes:
            try:
                remaining = set(run('docker', 'volume', 'ls', '-q').stdout.split())
                for volume in sorted(volumes & remaining):
                    remove('kind volume ' + volume, 'docker', 'volume', 'rm', volume)
            except (RuntimeError, subprocess.TimeoutExpired):
                failures.append('kind volume cleanup')
        if self.network_created:
            remove('lab network', 'docker', 'network', 'rm', LAB)
        if failures:
            raise RuntimeError('Lab cleanup failed: ' + ', '.join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=['agent', 'inference'], required=True)
    parser.add_argument('--cpu-serving', action='store_true', help='Also qualify the locked real CPU model on Inference')
    parser.add_argument('--agent-isolation', action='store_true', help='Also qualify the native OCI Agent v1 boundary')
    parser.add_argument('--agent-resources', action='store_true', help='Also exercise Agent resource exhaustion and teardown')
    parser.add_argument('--agent-admission-only', action='store_true', help='Preflight admission on a disposable kind API; no OS qualification')
    args = parser.parse_args()
    args.agent_isolation = args.agent_isolation or args.agent_resources
    if args.cpu_serving and args.profile != 'inference':
        parser.error('--cpu-serving requires the inference profile')
    if (args.agent_isolation or args.agent_admission_only) and args.profile != 'agent':
        parser.error('Agent checks require the agent profile')
    if args.cpu_serving:
        serving_module = load_script('cpu-serving')
        serving_module.validate_lock(json.loads((ROOT / 'tests/benchmarks/cpu-serving.lock.json').read_text()))
    output = args.output.resolve()
    if run('git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=normal').stdout:
        raise ValueError('Commit the qualification harness before running the lab')
    harness_commit = run('git', '-C', ROOT, 'rev-parse', 'HEAD').stdout.strip()
    harness_hashes = {name: digest(ROOT / name) for name in HARNESS_INPUTS}
    if args.agent_admission_only:
        output.mkdir(parents=True, exist_ok=True)
        preflight = output / 'agent-admission.json'
        preflight.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory(prefix='outerspace-agent-admission-') as temporary:
            lab = Lab(Path(temporary), output)
            try:
                lab.setup(api_only=True)
                lab.agent_node = lab.control_plane
                lab.agent_checks = {'profile': 'outerspace-agent-v1', 'phases': {}}
                lab.agent_install()
                lab.agent_admission()
                checks = lab.agent_checks
            finally:
                lab.cleanup()
        preflight.write_text(json.dumps({'status': 'passed', 'harness_commit': harness_commit,
            'harness_sha256': harness_hashes, 'scope': 'kind API admission only; no OS runtime qualification',
            **checks}, indent=2) + '\n')
        print('OUTERSPACE_AGENT_ADMISSION_OK: ' + str(preflight), flush=True)
        return
    # Verify every packaged byte before using its read-only raw disk as the VM backing file.
    metadata = json.loads((output / 'build-identity.json').read_text())
    bundle = output / f'outerspace-{metadata["version"]}-{args.profile}-cpu-{metadata["architecture"]}'
    load_script('prepare-release', BUILD_TOOLS).verify_bundle(bundle, metadata['version'], metadata['commit'],
                                                {'identity': metadata, 'sha256sums': digest(bundle / 'SHA256SUMS')})
    verify_args = ['docker', 'run', '--rm', '--cap-drop=ALL', '--mount', f'type=bind,src={ROOT},dst=/work,readonly',
                   '--mount', f'type=bind,src={output},dst=/out,readonly', 'outerspace-builder:dev',
                   'python3', '-c', 'import sys; from pathlib import Path; sys.path.insert(0,"/work/build/tools"); '
                   'from profiles import verify_identity; verify_identity(Path("/out"),sys.argv[1],"cpu")', args.profile]
    run(*verify_args)
    report = output / 'enrollment.json'
    report.unlink(missing_ok=True)
    if args.cpu_serving:
        (output / 'cpu-serving.json').unlink(missing_ok=True)
    if args.agent_isolation:
        (output / 'agent-isolation.json').unlink(missing_ok=True)
    if args.agent_resources:
        (output / 'agent-resources.json').unlink(missing_ok=True)
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='outerspace-enrollment-') as temporary:
        lab = Lab(Path(temporary), output)
        try:
            lab.setup()
            config = lab.configure()
            lab.vm('start', '--config-drive')
            node = wait_for('Waiting for the real OuterSpace worker', lab.worker, timeout=900)
            node_name = node['metadata']['name']
            initial_csr = wait_for('Recording the initial bootstrap certificate', lambda: lab.client_csr(node_name))
            lab.extend_renewal_lifetime()
            config['client_signing_duration'] = '10m initial bootstrap; 1h renewals (test lab only)'
            lab.kube('wait', '--for=condition=Ready', 'node/' + node_name, '--timeout=900s')
            wait_for('Validating the exact node serving CSR', lambda: lab.approve_serving(node))
            wait_for('Waiting for Cilium and Envoy Ready before workloads',
                     lambda: lab.cilium_ready(node_name), timeout=900)
            lab.workloads(node_name)
            before = wait_for('Reading immutable image and client identity', lab.probe)
            expected_identity = {key: metadata[key] for key in ['schema', 'profile', 'hardware_profile', 'architecture',
                                                               'version', 'commit', 'components_lock_sha256', 'host_features']}
            if before['identity'] != expected_identity:
                raise ValueError('Guest identity differs from the packaged source/profile')
            lab.network()
            if args.agent_isolation:
                lab.agent_start(node_name)
                lab.agent_sample('initial')
                if args.agent_resources:
                    lab.agent_resources()
            if args.cpu_serving:
                serving = serving_module.Serving(lab, node_name, run, wait_for)
                serving.prepare()
                serving.sample('initial')
                serving.restart()
                serving.drain_recover()
            def rotation():
                lab.approve_serving(node)
                probe = lab.probe()
                return probe if probe and probe['client_certificate_sha256'] != initial_csr['certificate_sha256'] else None
            rotated = wait_for('Waiting for actual kubelet client certificate rotation', rotation, timeout=900)
            rotated_csr = lab.client_csr(node_name, rotated, rotated=True)
            lab.revoke_bootstrap()
            lab.vm('poweroff')
            wait_for('Waiting for clean worker poweroff', lambda: run('docker', 'exec', RUNNER, 'sh', '-c',
                     '! kill -0 "$(cat /state/qemu.pid)" 2>/dev/null', check=False).returncode == 0, timeout=180)
            lab.vm('start')
            def recovered():
                current = lab.worker()
                if current and current['status']['nodeInfo']['bootID'] != before['boot_id']:
                    if any(c['type'] == 'Ready' and c['status'] == 'True' for c in current['status']['conditions']):
                        return current
            after_node = wait_for('Waiting for Node Ready after cold boot without config drive', recovered, timeout=900)
            wait_for('Checking serving certificate after recovery', lambda: lab.approve_serving(after_node))
            wait_for('Waiting for Cilium and Envoy Ready after recovery',
                     lambda: lab.cilium_ready(node_name), timeout=900)
            lab.wait_workloads()
            after = wait_for('Reading persisted rotated credentials', lab.probe)
            verify_recovery(before, rotated, after, node, after_node, initial_csr['certificate_sha256'])
            lab.network()
            if args.agent_isolation:
                lab.kube('-n', AGENT_NAMESPACE, 'wait', '--for=condition=Ready', 'pod/agent', '--timeout=1200s', timeout=1230)
                lab.agent_sample('node_recovery')
            if args.cpu_serving:
                serving.sample('node_recovery')
            if digest(output / 'outerspace.raw') != metadata['raw_image_sha256']:
                raise ValueError('The original disk changed during qualification')
            if digest(lab.state / 'packaged.raw') != metadata['raw_image_sha256']:
                raise ValueError('The packaged backing disk changed during qualification')
            evidence = {'schema': 1, 'status': 'passed', 'subject': metadata, 'environment': 'local QEMU UEFI VM',
                        'configuration': config, 'node_uid': node['metadata']['uid'], 'before': before,
                        'before_node_info': node['status']['nodeInfo'], 'after_node_info': after_node['status']['nodeInfo'],
                        'rotated': rotated, 'after': after, 'power_cycles': 2, 'bootstrap_revoked': True,
                        'client_csrs': {'bootstrap': initial_csr, 'rotation': rotated_csr},
                        'harness_commit': harness_commit, 'harness_sha256': harness_hashes,
                        'recovery_config_drive': False, 'network': ['DNS', 'cross-node service', 'default-deny', 'explicit allow'],
                        'cpu_smoke': {'image': PYTHON_IMAGE, 'result': 'outerspace-cpu-ok:1536'},
                        'limits': ['No physical-machine qualification', 'No production model serving qualification',
                                   'No Secure Boot or CIS compliance claim']}
            if args.cpu_serving:
                evidence['cpu_serving'] = serving.evidence()
            if args.agent_isolation:
                evidence['agent_isolation'] = lab.agent_checks
            if args.agent_resources:
                evidence['agent_resources'] = lab.agent_resource_checks
        finally:
            try:
                if lab.kind_created and lab.kubeconfig.exists():
                    for name, command in [('nodes', ['get', 'nodes', '-o', 'json']),
                                          ('system-pods', ['-n', 'kube-system', 'get', 'pods', '-o', 'json']),
                                          ('workload-pods', ['-n', LAB, 'get', 'pods', '-o', 'json']),
                                          ('events', ['get', 'events', '-A', '-o', 'json'])]:
                        result = lab.kube(*command, check=False)
                        (output / ('enrollment-' + name + '.json')).write_text(result.stdout)
                    if args.cpu_serving:
                        for container in ['verify-model', 'server']:
                            result = lab.kube('-n', LAB, 'logs', 'deployment/inference', '-c', container,
                                              '--tail=500', '--timestamps', check=False)
                            (output / ('cpu-serving-final-' + container + '.log')).write_text(result.stdout + result.stderr)
                    if args.agent_isolation:
                        for name, command in [('pods', ['get', 'pods', '-o', 'json']),
                                              ('events', ['get', 'events', '-o', 'json'])]:
                            result = lab.kube('-n', AGENT_NAMESPACE, *command, check=False)
                            (output / ('agent-isolation-' + name + '.json')).write_text(result.stdout)
                        # Keep LSM refusal metadata when teardown itself fails.
                        # Never export the complete audit log or workload input.
                        result = lab.kube('-n', LAB, 'exec', 'probe', '--', 'python3', '-c',
                            'from pathlib import Path; p=Path("/host/var/log/audit/audit.log"); '
                            'print("\\n".join(line for line in p.read_text().splitlines() '
                            'if "apparmor=" in line and "operation=\\\"signal\\\"" in line)[-65536:])', check=False)
                        (output / 'agent-resources-audit.log').write_text(result.stdout + result.stderr)
                    # Preserve the system agent's explanation of slow/failed
                    # endpoint creation; serial logs only contain the CNI client.
                    if 'node_name' in locals():
                        pods = lab.api('-n', 'kube-system', 'pods', '--field-selector', 'spec.nodeName=' + node_name)['items']
                        for pod in pods:
                            for container, stem in [('cilium-agent', 'cilium'), ('cilium-envoy', 'envoy')]:
                                if not any(c['name'] == container for c in pod['spec']['containers']):
                                    continue
                                restarted = any(c['name'] == container and c['restartCount'] > 0
                                                for c in pod['status'].get('containerStatuses', []))
                                for suffix, extra in [('', []), ('-previous', ['--previous'])] if restarted else [('', [])]:
                                    result = lab.kube('-n', 'kube-system', 'logs', pod['metadata']['name'],
                                                      '-c', container, '--tail=300', '--timestamps', *extra, check=False)
                                    (output / f'enrollment-{stem}{suffix}.log').write_text(result.stdout + result.stderr)
                if lab.runner_created:
                    for name in ['boot-enroll.log', 'boot-recover.log', 'qemu-command-enroll.json', 'qemu-command-recover.json']:
                        path = lab.state / name
                        if path.is_file():
                            shutil.copyfile(path, output / ('enrollment-' + name))
            finally:
                lab.cleanup()
    evidence['logs'] = {name: digest(output / name) for name in
                        ['enrollment-boot-enroll.log', 'enrollment-boot-recover.log',
                         'enrollment-qemu-command-enroll.json', 'enrollment-qemu-command-recover.json']}
    if (harness_commit != run('git', '-C', ROOT, 'rev-parse', 'HEAD').stdout.strip()
            or run('git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=normal').stdout
            or harness_hashes != {name: digest(ROOT / name) for name in HARNESS_INPUTS}):
        raise ValueError('Qualification source changed while the lab was running')
    report.write_text(json.dumps(evidence, indent=2) + '\n')
    if args.cpu_serving:
        (output / 'cpu-serving.json').write_text(json.dumps({
            'subject': metadata, 'harness_commit': harness_commit, 'harness_sha256': harness_hashes,
            'enrollment_report_sha256': digest(report), **evidence['cpu_serving']}, indent=2) + '\n')
    if args.agent_isolation:
        (output / 'agent-isolation.json').write_text(json.dumps({
            'subject': metadata, 'harness_commit': harness_commit, 'harness_sha256': harness_hashes,
            'enrollment_report_sha256': digest(report), 'status': 'passed', **evidence['agent_isolation']}, indent=2) + '\n')
    if args.agent_resources:
        (output / 'agent-resources.json').write_text(json.dumps({
            'subject': metadata, 'harness_commit': harness_commit, 'harness_sha256': harness_hashes,
            'enrollment_report_sha256': digest(report), **evidence['agent_resources']}, indent=2) + '\n')
    print('OUTERSPACE_ENROLLMENT_OK: ' + str(report), flush=True)


if __name__ == '__main__':
    main()
