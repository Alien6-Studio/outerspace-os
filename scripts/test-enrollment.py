#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Qualify one packaged worker in an exclusively owned, disposable local VM lab."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
LAB = 'outerspace-enrollment'
RUNNER = LAB + '-vm'
LABEL = 'io.outerspace.enrollment-lab'
KIND_IMAGE = 'kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5'
PYTHON_IMAGE = 'python:3.12-alpine@sha256:b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d'
VM_IP = '172.30.80.10'
HARNESS_INPUTS = ['scripts/test-enrollment.py', 'scripts/enrollment-vm.py',
                  'tests/integration/node-probe.py', 'tests/integration/cpu-smoke.py',
                  'scripts/cpu-serving.py', 'tests/integration/serving-client.py',
                  'benchmarks/cpu-serving.lock.json']


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


def load_script(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
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
        return run('docker', 'exec', RUNNER, 'python3', '/work/scripts/enrollment-vm.py', *args, check=check)

    def setup(self):
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
        run('helm', '--kubeconfig', self.kubeconfig, 'install', 'cilium',
            'oci://quay.io/cilium/charts/cilium', '--version', '1.20.3', '-n', 'kube-system',
            '-f', ROOT / 'cluster/cilium/values.yaml', '--set', 'k8sServiceHost=' + self.api_ip,
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
        load_script('node-config').render('https://' + self.api_ip + ':6443', ca, token_file,
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
                container['volumeMounts'] = [{'name': 'host', 'mountPath': '/host', 'readOnly': True}]
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

    def cleanup(self):
        failures = []
        if self.runner_created:
            if run('docker', 'rm', '-f', RUNNER, check=False).returncode:
                failures.append('VM runner')
        if self.kind_created:
            if run('kind', 'delete', 'cluster', '--name', LAB, '--kubeconfig', self.kubeconfig, check=False).returncode:
                failures.append('kind control plane')
        if self.network_created:
            if run('docker', 'network', 'rm', LAB, check=False).returncode:
                failures.append('lab network')
        if failures:
            raise RuntimeError('Lab cleanup failed: ' + ', '.join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=['agent', 'inference'], required=True)
    parser.add_argument('--cpu-serving', action='store_true', help='Also qualify the locked real CPU model on Inference')
    args = parser.parse_args()
    if args.cpu_serving and args.profile != 'inference':
        parser.error('--cpu-serving requires the inference profile')
    if args.cpu_serving:
        serving_module = load_script('cpu-serving')
        serving_module.validate_lock(json.loads((ROOT / 'benchmarks/cpu-serving.lock.json').read_text()))
    output = args.output.resolve()
    if run('git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=normal').stdout:
        raise ValueError('Commit the qualification harness before running the lab')
    harness_commit = run('git', '-C', ROOT, 'rev-parse', 'HEAD').stdout.strip()
    harness_hashes = {name: digest(ROOT / name) for name in HARNESS_INPUTS}
    # Verify every packaged byte before using its read-only raw disk as the VM backing file.
    metadata = json.loads((output / 'build-identity.json').read_text())
    bundle = output / f'outerspace-{metadata["version"]}-{args.profile}-cpu-{metadata["architecture"]}'
    load_script('prepare-release').verify_bundle(bundle, metadata['version'], metadata['commit'],
                                                {'identity': metadata, 'sha256sums': digest(bundle / 'SHA256SUMS')})
    verify_args = ['docker', 'run', '--rm', '--cap-drop=ALL', '--mount', f'type=bind,src={ROOT},dst=/work,readonly',
                   '--mount', f'type=bind,src={output},dst=/out,readonly', 'outerspace-builder:dev',
                   'python3', '-c', 'import sys; from pathlib import Path; sys.path.insert(0,"/work/scripts"); '
                   'from profiles import verify_identity; verify_identity(Path("/out"),sys.argv[1],"cpu")', args.profile]
    run(*verify_args)
    report = output / 'enrollment.json'
    report.unlink(missing_ok=True)
    if args.cpu_serving:
        (output / 'cpu-serving.json').unlink(missing_ok=True)
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
            lab.kube('-n', 'kube-system', 'delete', 'secret', 'bootstrap-token-' + lab.token_id)
            if lab.kube('-n', 'kube-system', 'get', 'secret', 'bootstrap-token-' + lab.token_id, check=False).returncode == 0:
                raise ValueError('Bootstrap token was not revoked')
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
    print('OUTERSPACE_ENROLLMENT_OK: ' + str(report), flush=True)


if __name__ == '__main__':
    main()
