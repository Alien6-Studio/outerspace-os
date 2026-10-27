#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Real CPU model serving inside the exclusively owned enrollment laboratory."""
import copy
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
NAMESPACE = 'outerspace-inference-v1'
LAB_NAMESPACE = 'outerspace-enrollment'
# Cold OCI pull/extraction on native-architecture TCG CI can exceed Kubernetes'
# default ten-minute Deployment deadline. Keep the controller, kubectl and
# subprocess budgets consistent; readiness still requires real token generation.
START_TIMEOUT_SECONDS = 1200
SERVER_ARGS = ('--model', '/models/model.gguf', '--host', '0.0.0.0', '--port', '8080',
               '--n-gpu-layers', '0', '--threads', '2', '--ctx-size', '256',
               '--batch-size', '32', '--ubatch-size', '32', '--parallel', '1', '--offline')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate_lock(lock):
    model, runtime, resources = (lock[key] for key in ['model', 'runtime', 'resources'])
    if lock.get('schema') != 1 or not re.fullmatch(r'ghcr\.io/ggml-org/llama\.cpp:server@sha256:[0-9a-f]{64}', runtime['image']):
        raise ValueError('Expected a digest-pinned official CPU server image')
    if (not re.fullmatch(r'[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+', model['repository'])
            or not re.fullmatch(r'[0-9a-f]{40}', model['revision'])
            or not re.fullmatch(r'[0-9a-f]{64}', model['sha256'])
            or Path(model['file']).name != model['file'] or not model['file'].endswith('.gguf')
            or not isinstance(model['bytes'], int) or not 0 < model['bytes'] < 128 * 1024**2):
        raise ValueError('Expected an immutable, bounded GGUF model artifact')
    if (resources != {'cpu_limit': 2, 'memory_mib': 512, 'model_cache_mib': 128,
                      'context_tokens': 256, 'output_tokens': 8, 'concurrency': 1}
            or model['bytes'] > resources['model_cache_mib'] * 1024**2
            or resources['memory_mib'] * 1024**2 < 3 * model['bytes']):
        raise ValueError('Model or runtime exceeds the qualified resource budget')
    if model['license'] != 'Apache-2.0' or runtime['license'] != 'MIT':
        raise ValueError('Review a changed model or runtime license before qualification')


def verify_model(path, model):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != model['bytes']:
        raise ValueError('Model cache entry has an unexpected type or size')
    if digest(path) != model['sha256']:
        raise ValueError('Model artifact SHA256 mismatch')
    with path.open('rb') as stream:
        if stream.read(4) != b'GGUF':
            raise ValueError('Model is not GGUF')


def verify_storage(probe):
    # Leave room for OCI extraction and cache/log growth instead of waiting for
    # kubelet eviction. Filesystem metadata makes usable capacity smaller than
    # the Inference profile's 8 GiB partition.
    if (probe.get('state_capacity_bytes', 0) < 7 * 1024**3
            or probe.get('state_available_bytes', 0) < 2 * 1024**3):
        raise ValueError('CPU serving requires the 8 GiB Inference state disk and at least 2 GiB available')


def fetch_model(lock):
    model = lock['model']
    cache = ROOT / '.cache/models'
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / (model['sha256'] + '.gguf')
    if path.exists() or path.is_symlink():
        verify_model(path, model)
        return path
    url = f'https://huggingface.co/{model["repository"]}/resolve/{model["revision"]}/{model["file"]}'
    temporary = path.with_suffix('.download')
    try:
        with urllib.request.urlopen(url, timeout=120) as source, temporary.open('xb') as output:
            size = 0
            while block := source.read(1024 * 1024):
                size += len(block)
                if size > model['bytes']:
                    raise ValueError('Model download exceeded its locked size')
                output.write(block)
        verify_model(temporary, model)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def summarize(samples):
    if not samples:
        raise ValueError('No inference samples')
    for sample in samples:
        elapsed = sample.get('wall_seconds', 0)
        response = sample.get('response', {})
        if (not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed <= 0
                or not 0 < sample.get('first_token_seconds', 0) <= elapsed
                or not isinstance(response.get('content'), str) or not response['content'].strip()
                or not 0 < response.get('tokens_predicted', 0) <= 8
                or response.get('tokens_evaluated', 0) <= 0
                or response.get('timings', {}).get('predicted_n', 0) <= 0):
            raise ValueError('Incomplete or invalid model generation sample')
    ordered = sorted(sample['wall_seconds'] for sample in samples)
    first = sorted(sample['first_token_seconds'] for sample in samples)
    return {'requests': len(samples), 'latency_p50_seconds': ordered[math.ceil(len(ordered) * .5) - 1],
            'latency_p95_seconds': ordered[math.ceil(len(ordered) * .95) - 1],
            'first_token_p50_seconds': first[math.ceil(len(first) * .5) - 1],
            'first_token_p95_seconds': first[math.ceil(len(first) * .95) - 1],
            'generated_tokens': sum(sample['response']['tokens_predicted'] for sample in samples),
            'tokens_per_request_wall_second': sum(sample['response']['tokens_predicted'] for sample in samples) / sum(ordered),
            'prompt_tokens': [sample['response']['tokens_evaluated'] for sample in samples],
            'scope': 'Single emulated VM; observations, not hardware or comparative performance claims'}


def verify_runtime_pod(pod, node, lock):
    spec = pod['spec']
    security = spec.get('securityContext', {})
    if (spec.get('nodeName') != node or any(spec.get(key) for key in ['hostNetwork', 'hostPID', 'hostIPC'])
            or spec.get('automountServiceAccountToken') is not False
            or security.get('runAsUser') != 65534 or security.get('runAsNonRoot') is not True
            or security.get('seccompProfile', {}).get('type') != 'RuntimeDefault'):
        raise ValueError('Serving pod lacks the required node or process boundary')
    containers = spec['containers']
    if len(containers) != 1:
        raise ValueError('Unexpected serving containers')
    server = containers[0]
    control = server.get('securityContext', {})
    if (server['image'] != lock['runtime']['image']
            or server.get('resources', {}).get('limits') != {'cpu': '2', 'memory': '512Mi'}
            or control.get('allowPrivilegeEscalation') is not False
            or control.get('readOnlyRootFilesystem') is not True
            or control.get('privileged', False)
            or control.get('seccompProfile', security['seccompProfile']).get('type') != 'RuntimeDefault'
            or control.get('capabilities', {}).get('drop') != ['ALL']
            or control.get('capabilities', {}).get('add')
            or not any(v.get('mountPath') == '/models' and v.get('readOnly') for v in server.get('volumeMounts', []))
            or any('hostPath' in volume for volume in spec.get('volumes', []))):
        raise ValueError('Serving pod lacks the locked image, resource or filesystem controls')
    if server.get('command') or server.get('args') != list(SERVER_ARGS):
        raise ValueError('Serving must use the locked local model and CPU execution settings')


class Serving:
    def __init__(self, lab, node, run, wait_for):
        self.lab, self.node, self.run, self.wait_for = lab, node, run, wait_for
        self.namespace = NAMESPACE
        self.lock = json.loads((ROOT / 'tests/benchmarks/cpu-serving.lock.json').read_text())
        validate_lock(self.lock)
        self.observations = {}
        self.model_loads = {}
        self.started = time.monotonic()

    def prepare(self):
        self.storage_before = self.wait_for('Checking model-serving state capacity', self.lab.probe)
        verify_storage(self.storage_before)
        print('Staging the SHA256-verified CPU model inside the private lab', flush=True)
        model = fetch_model(self.lock)
        # This is a reference kind node created by this lab, never the OS host.
        worker = LAB_NAMESPACE + '-worker'
        self.run('docker', 'exec', worker, 'mkdir', '-p', '/var/local/outerspace-model')
        self.run('docker', 'cp', model, worker + ':/var/local/outerspace-model/model.gguf')
        self.run('docker', 'exec', worker, 'chmod', '0444', '/var/local/outerspace-model/model.gguf')
        # Reuse the pinned probe/client image, without adding host dependencies.
        image = self.lab.api('-n', LAB_NAMESPACE, 'pod', 'client')['spec']['containers'][0]['image']
        self.python_image = image
        self.lab.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': self.namespace}})
        self.install_admission(image)
        self.admission_refusals(image)
        self.lab.apply(self.source(image), self.service('model-source', 8090, LAB_NAMESPACE), *self.policies(download=True))
        self.lab.kube('-n', LAB_NAMESPACE, 'wait', '--for=condition=Ready', 'pod/model-source', '--timeout=300s')
        self.model_refusals(image, model)
        print('Starting the locked llama.cpp CPU server on the OuterSpace worker', flush=True)
        self.cold_started = time.monotonic()
        self.lab.apply(self.deployment(image), self.service('inference', 8080))
        self.ready()
        self.source_ip = self.lab.api('-n', LAB_NAMESPACE, 'service', 'model-source')['spec']['clusterIP']
        self.inference_ip = self.lab.api('-n', self.namespace, 'service', 'inference')['spec']['clusterIP']
        self.lab.kube('-n', self.namespace, 'exec', 'deployment/inference', '--',
                      'curl', '--fail', '--silent', '--head', '--max-time', '10',
                      'http://' + self.source_ip + ':8090/model.gguf')
        # The runtime has no egress once its verified model has been staged.
        self.lab.apply(*self.policies(download=False))
        self.observations['cold_start_seconds'] = time.monotonic() - self.cold_started

    def service(self, name, port, namespace=None):
        return {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': name, 'namespace': namespace or self.namespace},
                'spec': {'selector': {'app': name}, 'ports': [{'port': port}]}}

    def security(self):
        return {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']},
                'readOnlyRootFilesystem': True}

    def admission(self, python_image):
        """A lab-only supported entry point; not the shared tenant API of #28."""
        spec = self.deployment(python_image)['spec']['template']['spec']
        server, init = spec['containers'][0], spec['initContainers'][0]
        value = lambda obj: json.dumps(obj, separators=(',', ':'))
        expressions = [
            "size(object.spec.containers) == 1 && size(object.spec.initContainers) == 1 && (!has(object.spec.ephemeralContainers) || size(object.spec.ephemeralContainers) == 0)",
            "(!has(object.spec.hostNetwork) || !object.spec.hostNetwork) && (!has(object.spec.hostPID) || !object.spec.hostPID) && (!has(object.spec.hostIPC) || !object.spec.hostIPC) && (!has(object.spec.shareProcessNamespace) || !object.spec.shareProcessNamespace)",
            "object.spec.automountServiceAccountToken == false && object.spec.serviceAccountName == 'default' && (!has(object.spec.resources)) && (!has(object.spec.resourceClaims) || size(object.spec.resourceClaims) == 0)",
            "object.spec.securityContext.runAsUser == 65534 && object.spec.securityContext.runAsNonRoot == true && object.spec.securityContext.fsGroup == 65534 && object.spec.securityContext.seccompProfile.type == 'RuntimeDefault'",
            "object.spec.nodeSelector == " + value(spec['nodeSelector']) + " && (!has(object.spec.nodeName) || object.spec.nodeName == '' || (request.operation == 'UPDATE' && object.spec.nodeName == oldObject.spec.nodeName))",
            "variables.containers.all(c, c.securityContext.allowPrivilegeEscalation == false && c.securityContext.readOnlyRootFilesystem == true && (!has(c.securityContext.privileged) || !c.securityContext.privileged) && c.securityContext.capabilities.drop == ['ALL'] && (!has(c.securityContext.capabilities.add) || size(c.securityContext.capabilities.add) == 0) && (!has(c.securityContext.seccompProfile) || c.securityContext.seccompProfile.type == 'RuntimeDefault') && (!has(c.securityContext.runAsUser) || c.securityContext.runAsUser == 65534) && (!has(c.securityContext.runAsNonRoot) || c.securityContext.runAsNonRoot) && (!has(c.env) || size(c.env) == 0) && (!has(c.envFrom) || size(c.envFrom) == 0) && (!has(c.volumeDevices) || size(c.volumeDevices) == 0) && (!has(c.lifecycle)) && (!has(c.securityContext.procMount) || c.securityContext.procMount == 'Default'))",
            "size(object.spec.volumes) == 2 && object.spec.volumes.all(v, has(v.emptyDir) && (!has(v.emptyDir.medium) || v.emptyDir.medium == '') && ((v.name == 'model' && quantity(dyn(v.emptyDir).sizeLimit).compareTo(quantity('128Mi')) == 0) || (v.name == 'scratch' && quantity(dyn(v.emptyDir).sizeLimit).compareTo(quantity('16Mi')) == 0)))",
        ]
        for field, expected in [('containers', server), ('initContainers', init)]:
            c = 'object.spec.' + field + '[0]'
            expressions += [c + '.name == ' + value(expected['name']), c + '.image == ' + value(expected['image']),
                'dyn(' + c + '.resources).limits == ' + value(expected['resources']['limits']),
                'dyn(' + c + '.resources).requests == ' + value(expected['resources']['requests'])]
            for key in ['command', 'args']:
                expressions.append(c + '.' + key + ' == ' + value(expected[key]) if key in expected
                                   else '(!has(' + c + '.' + key + ') || size(' + c + '.' + key + ') == 0)')
            mounts = expected['volumeMounts']
            expressions.append('size(' + c + '.volumeMounts) == ' + str(len(mounts)))
            for mount in mounts:
                expressions.append(c + '.volumeMounts.exists(m, m.name == ' + value(mount['name'])
                    + ' && m.mountPath == ' + value(mount['mountPath'])
                    + (' && has(m.readOnly) && m.readOnly == true' if mount.get('readOnly') else ' && (!has(m.readOnly) || !m.readOnly)')
                    + " && (!has(m.subPath) || m.subPath == '') && (!has(m.subPathExpr) || m.subPathExpr == '') && (!has(m.mountPropagation) || m.mountPropagation == 'None'))")
        name = 'outerspace-cpu-serving-lab-v1'
        return [
            {'apiVersion': 'admissionregistration.k8s.io/v1', 'kind': 'ValidatingAdmissionPolicy',
             'metadata': {'name': name}, 'spec': {'failurePolicy': 'Fail',
                'matchConstraints': {'resourceRules': [{'apiGroups': [''], 'apiVersions': ['v1'],
                    'operations': ['CREATE', 'UPDATE'], 'resources': ['pods', 'pods/ephemeralcontainers', 'pods/resize']}]},
                'matchConditions': [{'name': 'serving-namespace', 'expression': 'request.namespace == ' + value(self.namespace)}],
                'variables': [{'name': 'containers', 'expression': 'object.spec.containers + object.spec.initContainers'}],
                'validations': [{'expression': e, 'message': 'OuterSpace CPU serving requires its approved model/runtime and controls.'} for e in expressions]}},
            {'apiVersion': 'admissionregistration.k8s.io/v1', 'kind': 'ValidatingAdmissionPolicyBinding',
             'metadata': {'name': name}, 'spec': {'policyName': name, 'validationActions': ['Deny', 'Audit']}}]

    def test_pod(self, python_image, name):
        pod = copy.deepcopy(self.deployment(python_image)['spec']['template'])
        pod.update(apiVersion='v1', kind='Pod')
        pod['metadata'].update(name=name, namespace=self.namespace)
        pod['spec']['restartPolicy'] = 'Never'
        return pod

    def install_admission(self, python_image):
        self.lab.apply(*self.admission(python_image))
        def established():
            policy = self.lab.api('validatingadmissionpolicy', 'outerspace-cpu-serving-lab-v1')
            status = policy.get('status', {})
            if status.get('observedGeneration') != policy['metadata']['generation']:
                return False
            if status.get('typeChecking', {}).get('expressionWarnings'):
                raise ValueError('Serving admission policy did not type-check: ' + json.dumps(status))
            return True
        self.wait_for('Waiting for checked serving admission policy', established)
        valid = self.test_pod(python_image, 'allowed-preflight')
        invalid = copy.deepcopy(valid)
        invalid['spec']['containers'][0]['securityContext']['readOnlyRootFilesystem'] = False
        def enforced():
            result = self.lab.kube('create', '--dry-run=server', '-f', '-', data=json.dumps(invalid), check=False)
            return result.returncode != 0 and 'OuterSpace CPU serving requires' in result.stderr
        self.wait_for('Waiting for serving policy enforcement', enforced)
        self.lab.kube('create', '--dry-run=server', '-f', '-', data=json.dumps(valid))

    def admission_refusals(self, python_image):
        mutations = {
            'untrusted-runtime': lambda p: p['containers'][0].update(image='runtime:latest'),
            'over-budget-memory': lambda p: p['containers'][0]['resources']['limits'].update(memory='4Gi'),
            'insufficient-model-memory': lambda p: p['containers'][0]['resources'].update(limits={'cpu': '2', 'memory': '16Mi'}, requests={'cpu': '500m', 'memory': '16Mi'}),
            'missing-seccomp': lambda p: p['securityContext'].update(seccompProfile={'type': 'Unconfined'}),
            'writable-root': lambda p: p['containers'][0]['securityContext'].update(readOnlyRootFilesystem=False),
            'public-fallback': lambda p: p['containers'][0]['args'].remove('--offline'),
            'accelerator-fallback': lambda p: p['containers'][0]['args'].extend(['--n-gpu-layers', '1']),
            'untrusted-model-pin': lambda p: p['initContainers'][0]['command'].__setitem__(-1, '0' * 64),
            'writable-model': lambda p: p['containers'][0]['volumeMounts'][0].update(readOnly=False),
        }
        results = {}
        for name, mutate in mutations.items():
            obj = self.test_pod(python_image, 'refusal-' + name)
            mutate(obj['spec'])
            result = self.lab.kube('create', '-f', '-', data=json.dumps(obj), check=False)
            if result.returncode == 0 or 'OuterSpace CPU serving requires' not in result.stderr:
                raise ValueError('Required serving refusal was not enforced: ' + name)
            if self.lab.kube('-n', self.namespace, 'get', 'pod', obj['metadata']['name'], check=False).returncode == 0:
                raise ValueError('Refused serving pod exists')
            results[name] = {'status': 'denied-before-execution', 'api_error': result.stderr[-4000:]}
        self.observations['admission_refusals'] = results

    def model_refusals(self, python_image, model):
        worker = LAB_NAMESPACE + '-worker'
        remote = '/var/local/outerspace-model/model.gguf'
        results = {}
        for name, offset, error in [('incompatible-format', 0, 'Cached model is not GGUF'),
                                    ('untrusted-bytes', self.lock['model']['bytes'] - 4, 'Untrusted cached model SHA256')]:
            obj = self.test_pod(python_image, 'model-refusal-' + name)
            try:
                self.run('docker', 'exec', worker, 'sh', '-ec',
                    'chmod u+w "$1"; printf FAIL | dd of="$1" bs=1 seek="$2" conv=notrunc status=none',
                    'corrupt-owned-fixture', remote, str(offset))
                self.lab.apply(obj)
                def refused():
                    pod = self.lab.api('-n', self.namespace, 'pod', obj['metadata']['name'])
                    states = pod.get('status', {}).get('initContainerStatuses', [])
                    if not states or 'terminated' not in states[0].get('state', {}):
                        return None
                    if states[0]['state']['terminated']['exitCode'] == 0:
                        raise ValueError('Untrusted model passed runtime verification')
                    if any(s.get('containerID') for s in pod['status'].get('containerStatuses', [])):
                        raise ValueError('Model server executed after invalid input')
                    if pod['spec']['nodeName'] != self.node:
                        raise ValueError('Model refusal did not run on the intended worker')
                    logs = self.lab.kube('-n', self.namespace, 'logs', obj['metadata']['name'], '-c', 'verify-model').stdout
                    if error not in logs:
                        raise ValueError('Model failed for an unrelated reason: ' + logs[-2000:])
                    return {'status': 'refused-on-worker', 'pod': pod, 'verification_log': logs[-8000:]}
                results[name] = self.wait_for('Proving model refusal on the worker: ' + name, refused, timeout=900)
            finally:
                self.lab.kube('-n', self.namespace, 'delete', 'pod', obj['metadata']['name'], '--ignore-not-found', '--wait=true', '--timeout=120s')
                self.run('docker', 'cp', model, worker + ':' + remote)
                self.run('docker', 'exec', worker, 'chmod', '0444', remote)
        if self.run('docker', 'exec', worker, 'sha256sum', remote).stdout.split()[0] != self.lock['model']['sha256']:
            raise ValueError('Private model source was not restored')
        self.observations['model_refusals'] = results

    def source(self, image):
        return {'apiVersion': 'v1', 'kind': 'Pod',
                'metadata': {'name': 'model-source', 'namespace': LAB_NAMESPACE, 'labels': {'app': 'model-source'}},
                'spec': {'nodeName': LAB_NAMESPACE + '-worker', 'automountServiceAccountToken': False,
                         'securityContext': {'runAsUser': 65534, 'runAsNonRoot': True,
                                             'seccompProfile': {'type': 'RuntimeDefault'}},
                         'containers': [{'name': 'source', 'image': image, 'securityContext': self.security(),
                                         'command': ['python3', '-m', 'http.server', '8090', '--directory', '/models'],
                                         'resources': {'requests': {'cpu': '25m', 'memory': '32Mi'},
                                                       'limits': {'cpu': '500m', 'memory': '64Mi'}},
                                         'volumeMounts': [{'name': 'model', 'mountPath': '/models', 'readOnly': True}]}],
                         'volumes': [{'name': 'model', 'hostPath': {'path': '/var/local/outerspace-model', 'type': 'Directory'}}]}}

    def policies(self, download):
        dns = {'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
                       'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}],
               'ports': [{'protocol': 'UDP', 'port': 53}, {'protocol': 'TCP', 'port': 53}]}
        source = {'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': LAB_NAMESPACE}},
                          'podSelector': {'matchLabels': {'app': 'model-source'}}}],
                  'ports': [{'protocol': 'TCP', 'port': 8090}]}
        for name, spec in [
            ('inference-boundary', {'podSelector': {'matchLabels': {'app': 'inference'}},
                'policyTypes': ['Ingress', 'Egress'], 'egress': [dns, source] if download else [],
                'ingress': [{'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': LAB_NAMESPACE}},
                                       'podSelector': {'matchLabels': {'app': 'client'}}}],
                             'ports': [{'protocol': 'TCP', 'port': 8080}]}]}),
            ('model-source-boundary', {'podSelector': {'matchLabels': {'app': 'model-source'}},
                'policyTypes': ['Ingress', 'Egress'], 'egress': [],
                'ingress': [{'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': self.namespace}},
                                       'podSelector': {'matchLabels': {'app': 'inference'}}}],
                             'ports': [{'protocol': 'TCP', 'port': 8090}]}]})]:
            yield {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
                   'metadata': {'name': name, 'namespace': LAB_NAMESPACE if name == 'model-source-boundary' else self.namespace}, 'spec': spec}

    def deployment(self, python_image):
        model = self.lock['model']
        stage = (ROOT / 'tests/integration/model-stage.py').read_text()
        # curl is in the digest-pinned server image. Readiness requires real token
        # generation, not merely an open port or loaded model.
        readiness = ('curl --fail --silent --max-time 50 -H "Content-Type: application/json" '
                     '--data \'{"prompt":"Hello","n_predict":1,"temperature":0,"cache_prompt":false}\' '
                     'http://127.0.0.1:8080/completion | grep -Eq \'"tokens_predicted"[[:space:]]*:[[:space:]]*1([,}])\'')
        return {'apiVersion': 'apps/v1', 'kind': 'Deployment',
                'metadata': {'name': 'inference', 'namespace': self.namespace},
                'spec': {'replicas': 1, 'progressDeadlineSeconds': START_TIMEOUT_SECONDS,
                         'strategy': {'type': 'Recreate'},
                         'selector': {'matchLabels': {'app': 'inference'}},
                         'template': {'metadata': {'labels': {'app': 'inference'}}, 'spec': {
                             'nodeSelector': {'kubernetes.io/hostname': self.node},
                             'automountServiceAccountToken': False,
                             'securityContext': {'runAsUser': 65534, 'runAsNonRoot': True, 'fsGroup': 65534,
                                                 'seccompProfile': {'type': 'RuntimeDefault'}},
                             'tolerations': [{'key': key, 'operator': 'Exists', 'effect': 'NoExecute',
                                              'tolerationSeconds': 1800} for key in
                                             ['node.kubernetes.io/not-ready', 'node.kubernetes.io/unreachable']],
                             'initContainers': [{'name': 'verify-model', 'image': python_image,
                                'command': ['python3', '-c', stage, '--path', '/models/model.gguf',
                                            '--url', 'http://model-source.' + LAB_NAMESPACE + ':8090/model.gguf',
                                            '--bytes', str(model['bytes']), '--sha256', model['sha256']],
                                'securityContext': self.security(),
                                'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'},
                                              'limits': {'cpu': '1', 'memory': '256Mi'}},
                                'volumeMounts': [{'name': 'model', 'mountPath': '/models'}]}],
                             'containers': [{'name': 'server', 'image': self.lock['runtime']['image'],
                                'args': list(SERVER_ARGS),
                                'securityContext': self.security(),
                                'resources': {'requests': {'cpu': '500m', 'memory': '256Mi'},
                                              'limits': {'cpu': '2', 'memory': '512Mi'}},
                                'readinessProbe': {'exec': {'command': ['/bin/sh', '-ec', readiness]},
                                                   'periodSeconds': 60, 'timeoutSeconds': 60, 'failureThreshold': 3},
                                'volumeMounts': [{'name': 'model', 'mountPath': '/models', 'readOnly': True},
                                                 {'name': 'scratch', 'mountPath': '/tmp'}]}],
                             'volumes': [{'name': 'model', 'emptyDir': {'sizeLimit': '128Mi'}},
                                         {'name': 'scratch', 'emptyDir': {'sizeLimit': '16Mi'}}]}}}}

    def ready(self):
        print('Waiting for model readiness through actual token generation', flush=True)
        self.lab.kube('-n', self.namespace, 'rollout', 'status', 'deployment/inference',
                      '--timeout=' + str(START_TIMEOUT_SECONDS) + 's', timeout=START_TIMEOUT_SECONDS + 30)

    def snapshot(self):
        pod = self.lab.api('-n', self.namespace, 'pods', '-l', 'app=inference')['items'][0]
        verify_runtime_pod(pod, self.node, self.lock)
        script = (ROOT / 'tests/integration/node-probe.py').read_text()
        result = self.lab.kube('-n', LAB_NAMESPACE, 'exec', 'probe', '--', 'python3', '-c', script,
                              json.dumps([pod['metadata']['uid']]), '--comparison-identity')
        observed = json.loads(result.stdout)
        state = pod['status']['containerStatuses'][0]
        identifier = state['containerID'].removeprefix('containerd://')
        group = observed['resources']['pods'][pod['metadata']['uid']]
        container = group['descendants'].get('cri-containerd-' + identifier + '.scope', {})
        if container.get('cpu.max') != '200000 100000' or container.get('memory.max') != '536870912':
            raise ValueError('Serving runtime cgroup does not enforce its actual CPU/memory budget')
        return {'pod_uid': pod['metadata']['uid'], 'container_id': state['containerID'],
                'image_id': state['imageID'], 'restart_count': state['restartCount'], **observed}

    def sample(self, phase, requests=4, minimum_seconds=0):
        print('Sampling real CPU inference: ' + phase, flush=True)
        self.ready()
        self.wait_for('Verifying model-server egress is denied', lambda:
                      self.lab.kube('-n', self.namespace, 'exec', 'deployment/inference', '--',
                                    'curl', '--silent', '--head', '--connect-timeout', '3', '--max-time', '5',
                                    'http://' + self.source_ip + ':8090/model.gguf', check=False).returncode == 28,
                      timeout=90)
        denied = ('import socket,sys; s=socket.socket(); s.settimeout(3); '
                  f'result=s.connect_ex(("{self.inference_ip}",8080)); sys.exit(0 if result in (11,110) else 1)')
        self.wait_for('Verifying the model endpoint refuses an unapproved pod', lambda:
                      self.lab.kube('-n', LAB_NAMESPACE, 'exec', 'cpu', '--', 'python3', '-c', denied,
                                    check=False).returncode == 0, timeout=90)
        script = (ROOT / 'tests/integration/serving-client.py').read_text()
        before = self.snapshot()
        result = self.lab.kube('-n', LAB_NAMESPACE, 'exec', 'client', '--', 'python3', '-c', script,
                              '--requests', str(requests), '--min-seconds', str(minimum_seconds), timeout=3600)
        raw = json.loads(result.stdout)
        after = self.snapshot()
        if any(before[k] != after[k] for k in ['pod_uid', 'container_id', 'image_id', 'restart_count']):
            raise ValueError('Model server changed or restarted during load')
        if len(raw['samples']) < requests or raw['wall_seconds'] < minimum_seconds:
            raise ValueError('Incomplete serving interval')
        self.observations[phase] = {'raw': raw, 'summary': summarize(raw['samples']),
                                    'resources_before': before, 'resources_after': after,
                                    'egress_denied': True, 'unapproved_ingress_denied': True}
        logs = self.lab.kube('-n', self.namespace, 'logs', 'deployment/inference', '-c', 'server',
                             '--timestamps', '--tail=500', check=False)
        (getattr(self.lab, 'results', self.lab.output) / ('cpu-serving-' + phase + '.log')).write_text(logs.stdout + logs.stderr)
        pod = self.lab.api('-n', self.namespace, 'pods', '-l', 'app=inference')['items'][0]
        started = pod['status']['containerStatuses'][0]['state']['running']['startedAt']
        loaded = [line.split()[0] for line in logs.stdout.splitlines() if 'model loaded' in line]
        if not loaded and after['container_id'] not in self.model_loads:
            raise ValueError('No engine model-load completion in the serving log')
        if not loaded:
            self.observations[phase]['model_load'] = self.model_loads[after['container_id']]
            return
        seconds = (datetime.fromisoformat(loaded[-1].replace('Z', '+00:00'))
                   - datetime.fromisoformat(started.replace('Z', '+00:00'))).total_seconds()
        if seconds < 0:
            raise ValueError('Model-load completion predates runtime startup')
        self.observations[phase]['model_load'] = {
            'container_started_at': started, 'engine_loaded_at': loaded[-1],
            'container_start_to_model_loaded_seconds': seconds,
            'scope': 'Includes container startup; raw engine logs retain finer load diagnostics'}
        self.model_loads[after['container_id']] = self.observations[phase]['model_load']

    def restart(self):
        print('Replacing the serving pod and reloading its verified model cache', flush=True)
        self.lab.apply(*self.policies(download=True))
        started = time.monotonic()
        self.lab.kube('-n', self.namespace, 'rollout', 'restart', 'deployment/inference')
        self.ready()
        self.observations['warm_pod_start_seconds'] = time.monotonic() - started
        self.lab.apply(*self.policies(download=False))
        self.sample('pod_restart')

    def drain_recover(self):
        print('Draining and restoring the serving Deployment on the same worker', flush=True)
        before = self.lab.api('-n', self.namespace, 'pods', '-l', 'app=inference')['items'][0]['metadata']['uid']
        self.lab.apply(*self.policies(download=True))
        try:
            # Only the serving Deployment is selected; the enrollment probe and
            # CPU/network smoke pods retain their identity throughout this test.
            self.lab.kube('drain', self.node, '--pod-selector=app=inference', '--ignore-daemonsets',
                          '--delete-emptydir-data', '--timeout=180s')
            if not self.lab.api('node', self.node)['spec'].get('unschedulable'):
                raise ValueError('Serving drain did not cordon the worker')
        finally:
            self.lab.kube('uncordon', self.node)
        self.ready()
        after = self.lab.api('-n', self.namespace, 'pods', '-l', 'app=inference')['items'][0]['metadata']['uid']
        if before == after:
            raise ValueError('Serving pod was not replaced by the drain')
        self.lab.apply(*self.policies(download=False))
        self.sample('drain_recovery')
        self.observations['drain_recovery'].update(before_uid=before, after_uid=after)

    def evidence(self):
        if not {'initial', 'sustained', 'pod_restart', 'drain_recovery', 'node_recovery',
                'admission_refusals', 'model_refusals'} <= self.observations.keys():
            raise ValueError('Incomplete serving lifecycle qualification')
        pods = self.lab.api('-n', self.namespace, 'pods', '-l', 'app=inference')['items']
        if len(pods) != 1:
            raise ValueError('Model serving moved off the OuterSpace worker')
        verify_runtime_pod(pods[0], self.node, self.lock)
        version = self.lab.kube('-n', self.namespace, 'exec', 'deployment/inference', '--',
                                '/app/llama-server', '--version')
        version_text = version.stdout + version.stderr
        if self.lock['runtime']['commit'][:9] not in version_text:
            raise ValueError('Running llama.cpp version differs from its locked source')
        model_hash = self.lab.kube('-n', self.namespace, 'exec', 'deployment/inference', '--',
                                   'sha256sum', '/models/model.gguf').stdout.split()[0]
        if model_hash != self.lock['model']['sha256']:
            raise ValueError('The running server model differs from its locked artifact')
        return {'schema': 1, 'status': 'passed', 'lock': self.lock,
                'lock_sha256': digest(ROOT / 'tests/benchmarks/cpu-serving.lock.json'),
                'observations': self.observations, 'pod': pods[0], 'runtime_version': version_text.strip(),
                'running_model_sha256': model_hash,
                'state_before': {key: self.storage_before[key] for key in
                                 ['state_capacity_bytes', 'state_available_bytes']},
                'limits': ['QEMU VM only; no physical hardware or performance guarantee',
                           'NUMA topology is recorded; no physical energy counter is available in this TCG reference',
                           'Matched Ubuntu results are a separate image-bound comparison report',
                           'Single-node drain/uncordon recovery tested; multi-node migration not qualified',
                           'Small generative model proves serving, not application-level model quality']}
