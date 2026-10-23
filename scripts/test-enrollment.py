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


def run(*args, data=None, check=True, env=None):
    result = subprocess.run(list(map(str, args)), input=data, capture_output=True, text=True,
                            check=False, env=env, timeout=900)
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


def verify_recovery(before, rotated, after, before_node, after_node):
    for key in ['identity', 'hostname', 'machine_id']:
        if not before.get(key) or before[key] != rotated.get(key) or before[key] != after.get(key):
            raise ValueError(f'Node identity did not persist: {key}')
    if before['client_certificate_sha256'] == rotated['client_certificate_sha256']:
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
            '--device=/dev/net/tun', '--mount', f'type=bind,src={ROOT},dst=/work,readonly',
            '--mount', f'type=bind,src={self.output},dst=/image,readonly',
            '--mount', f'type=bind,src={self.state},dst=/state', 'outerspace-enrollment:dev', 'sleep', 'infinity')
        self.runner_created = True
        run('docker', 'exec', RUNNER, 'bash', '-euc',
            'umask 077; truncate -s 16M /state/node-config.raw; mkfs.vfat -n OOS_CONFIG /state/node-config.raw; '
            'mcopy -s -i /state/node-config.raw /state/config/* ::/')
        return {'api_server': 'https://' + self.api_ip + ':6443', 'cluster_dns': ['10.97.0.10'],
                'ca_sha256': digest(ca), 'kubelet_config_sha256': digest(self.state / 'config/kubelet.yaml'),
                'bootstrap_ttl': '30m', 'client_signing_duration': '10m (test lab only)',
                'worker_ip': VM_IP, 'kind_image': KIND_IMAGE, 'cilium_chart': '1.20.3'}

    def worker(self):
        for node in self.api('nodes')['items']:
            if any(address['address'] == VM_IP for address in node['status'].get('addresses', [])):
                if not node['metadata']['name'].startswith('oos-') or '6.8.0-147' not in node['status']['nodeInfo']['kernelVersion']:
                    raise ValueError('The worker does not use the OuterSpace kernel/identity')
                return node

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
        self.kube('-n', LAB, 'wait', '--for=condition=Ready', 'pod', '--all', '--timeout=600s')

    def probe(self):
        result = self.kube('-n', LAB, 'exec', 'probe', '--', 'python3', '-c',
                           (ROOT / 'tests/integration/node-probe.py').read_text(), check=False)
        return json.loads(result.stdout) if result.returncode == 0 else None

    def network(self):
        self.kube('-n', LAB, 'delete', 'networkpolicy', 'cpu-allow', '--ignore-not-found')
        client = ['-n', LAB, 'exec', 'client', '--', 'python3', '-c']
        # Confirm DNS independently so an exec/DNS failure cannot count as a policy denial.
        self.kube(*client, 'import socket; assert socket.gethostbyname("cpu.' + LAB + '.svc.cluster.local")')
        request = 'import urllib.request; assert urllib.request.urlopen("http://cpu.' + LAB + '.svc.cluster.local:8080", timeout=3).read() == b"outerspace-cpu-ok:1536\\n"'
        denied = ('import socket,sys; s=socket.socket(); s.settimeout(3); '
                  'result=s.connect_ex(("cpu.' + LAB + '.svc.cluster.local",8080)); sys.exit(0 if result in (11,110) else 1)')
        wait_for('Verifying default-deny on the OuterSpace endpoint',
                 lambda: self.kube(*client, denied, check=False).returncode == 0)
        self.apply({'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                    'metadata': {'name': 'cpu-allow', 'namespace': LAB},
                    'spec': {'podSelector': {'matchLabels': {'app': 'cpu'}}, 'policyTypes': ['Ingress'],
                             'ingress': [{'from': [{'podSelector': {'matchLabels': {'app': 'client'}}}],
                                          'ports': [{'protocol': 'TCP', 'port': 8080}]}]}})
        wait_for('Verifying allowed cross-node DNS/service/CPU response',
                 lambda: self.kube(*client, request, check=False).returncode == 0)

    def cleanup(self):
        if self.runner_created:
            run('docker', 'rm', '-f', RUNNER, check=False)
        if self.kind_created:
            run('kind', 'delete', 'cluster', '--name', LAB, '--kubeconfig', self.kubeconfig, check=False)
        if self.network_created:
            run('docker', 'network', 'rm', LAB, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=['agent', 'inference'], required=True)
    args = parser.parse_args()
    output = args.output.resolve()
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
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='outerspace-enrollment-') as temporary:
        lab = Lab(Path(temporary), output)
        try:
            lab.setup()
            config = lab.configure()
            lab.vm('start', '--config-drive')
            node = wait_for('Waiting for the real OuterSpace worker', lab.worker, timeout=900)
            node_name = node['metadata']['name']
            lab.kube('wait', '--for=condition=Ready', 'node/' + node_name, '--timeout=900s')
            wait_for('Validating the exact node serving CSR', lambda: lab.approve_serving(node))
            lab.workloads(node_name)
            before = wait_for('Reading immutable image and client identity', lab.probe)
            expected_identity = {key: metadata[key] for key in ['schema', 'profile', 'hardware_profile', 'architecture',
                                                               'version', 'commit', 'components_lock_sha256', 'host_features']}
            if before['identity'] != expected_identity:
                raise ValueError('Guest identity differs from the packaged source/profile')
            lab.network()
            def rotation():
                lab.approve_serving(node)
                probe = lab.probe()
                return probe if probe and probe['client_certificate_sha256'] != before['client_certificate_sha256'] else None
            rotated = wait_for('Waiting for actual kubelet client certificate rotation', rotation, timeout=900)
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
            after = wait_for('Reading persisted rotated credentials', lab.probe)
            verify_recovery(before, rotated, after, node, after_node)
            lab.network()
            if digest(output / 'outerspace.raw') != metadata['raw_image_sha256']:
                raise ValueError('The original disk changed during qualification')
            evidence = {'schema': 1, 'status': 'passed', 'subject': metadata, 'environment': 'local QEMU UEFI VM',
                        'configuration': config, 'node_uid': node['metadata']['uid'], 'before': before,
                        'rotated': rotated, 'after': after, 'power_cycles': 2, 'bootstrap_revoked': True,
                        'recovery_config_drive': False, 'network': ['DNS', 'cross-node service', 'default-deny', 'explicit allow'],
                        'cpu_smoke': {'image': PYTHON_IMAGE, 'result': 'outerspace-cpu-ok:1536'},
                        'limits': ['No physical-machine qualification', 'No production model serving qualification',
                                   'No Secure Boot or CIS compliance claim']}
            report.write_text(json.dumps(evidence, indent=2) + '\n')
            print('OUTERSPACE_ENROLLMENT_OK: ' + str(report), flush=True)
        finally:
            if lab.runner_created:
                for name in ['boot-enroll.log', 'boot-recover.log', 'qemu-command.json']:
                    path = lab.state / name
                    if path.is_file():
                        shutil.copyfile(path, output / ('enrollment-' + name))
            lab.cleanup()


if __name__ == '__main__':
    main()
