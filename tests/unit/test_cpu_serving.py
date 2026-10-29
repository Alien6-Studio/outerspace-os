# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('serving', ROOT / 'tests/harness/cpu-serving.py')
serving = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serving)


class CPUServingTests(unittest.TestCase):
    def setUp(self):
        self.lock = json.loads((ROOT / 'tests/benchmarks/cpu-serving.lock.json').read_text())

    def test_refuses_mutable_unbounded_or_over_budget_artifacts(self):
        serving.validate_lock(self.lock)
        mutations = [('runtime', 'image', 'ghcr.io/ggml-org/llama.cpp:server'),
                     ('model', 'revision', 'main'), ('model', 'file', '../../model.gguf'),
                     ('model', 'repository', 'other/repo/../repo'), ('model', 'sha256', 'bad'),
                     ('model', 'bytes', 512 * 1024**2), ('model', 'license', 'unknown'),
                     ('resources', 'memory_mib', 128), ('resources', 'concurrency', 0)]
        for section, key, value in mutations:
            changed = copy.deepcopy(self.lock)
            changed[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                serving.validate_lock(changed)

    def test_cached_models_are_verified_before_use_and_symlinks_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'model.gguf'
            payload = b'GGUF' + b'valid fixture'
            path.write_bytes(payload)
            model = {'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}
            serving.verify_model(path, model)
            path.write_bytes(payload[:-1] + b'!')
            with self.assertRaises(ValueError):
                serving.verify_model(path, model)
            path.write_bytes(payload)
            link = path.with_name('linked.gguf')
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                serving.verify_model(link, model)
            with self.assertRaises(ValueError):
                serving.verify_model(path, {**model, 'bytes': len(payload) - 1})

    def test_storage_pressure_is_rejected_before_model_staging(self):
        enough = {'state_capacity_bytes': 8 * 1024**3, 'state_available_bytes': 6 * 1024**3}
        serving.verify_storage(enough)
        for probe in [{}, {**enough, 'state_capacity_bytes': 2 * 1024**3},
                      {**enough, 'state_available_bytes': 1024**3}]:
            with self.subTest(probe=probe), self.assertRaises(ValueError):
                serving.verify_storage(probe)

    def pod(self):
        scenario = serving.Serving.__new__(serving.Serving)
        scenario.lock, scenario.node, scenario.namespace = self.lock, 'oos-test', 'outerspace-enrollment'
        pod = scenario.deployment('python@sha256:' + '0' * 64)['spec']['template']
        pod['spec']['nodeName'] = 'oos-test'
        return pod

    def test_refuses_serving_after_required_runtime_controls_are_removed(self):
        pod = self.pod()
        serving.verify_runtime_pod(pod, 'oos-test', self.lock)
        changes = [lambda p: p['spec'].update(nodeName='kind-worker'),
                   lambda p: p['spec'].update(hostNetwork=True),
                   lambda p: p['spec'].update(automountServiceAccountToken=True),
                   lambda p: p['spec']['securityContext'].update(seccompProfile={'type': 'Unconfined'}),
                   lambda p: p['spec']['containers'][0]['securityContext'].update(allowPrivilegeEscalation=True),
                   lambda p: p['spec']['containers'][0]['resources']['limits'].update(memory='4Gi'),
                   lambda p: p['spec']['containers'][0].update(image='runtime:latest'),
                   lambda p: p['spec']['containers'][0]['args'].remove('--offline'),
                   lambda p: p['spec']['containers'][0]['args'].extend(['--n-gpu-layers', '1']),
                   lambda p: p['spec']['containers'][0]['securityContext'].update(seccompProfile={'type': 'Unconfined'}),
                   lambda p: p['spec']['containers'][0].update(command=['/bin/sh']),
                   lambda p: p['spec']['containers'][0].pop('readinessProbe'),
                   lambda p: p['spec']['containers'][0]['readinessProbe'].update(exec={'command': ['true']}),
                   lambda p: p['spec']['containers'][0]['volumeMounts'][0].update(readOnly=False),
                   lambda p: p['spec']['volumes'].append({'name': 'escape', 'hostPath': {'path': '/'}})]
        for index, change in enumerate(changes):
            changed = copy.deepcopy(pod)
            change(changed)
            with self.subTest(index=index), self.assertRaises(ValueError):
                serving.verify_runtime_pod(changed, 'oos-test', self.lock)

    def test_empty_or_forged_measurements_cannot_be_summarized(self):
        with self.assertRaises(ValueError):
            serving.summarize([])
        response = {'content': 'Paris', 'tokens_predicted': 8, 'tokens_evaluated': 5, 'timings': {'predicted_n': 8}}
        samples = [{'wall_seconds': value, 'first_token_seconds': .5, 'response': response} for value in [4, 1, 3, 2]]
        result = serving.summarize(samples)
        self.assertEqual(result['latency_p50_seconds'], 2)
        self.assertEqual(result['latency_p95_seconds'], 4)
        self.assertEqual(result['generated_tokens'], 32)
        for changed in [{**samples[0], 'wall_seconds': float('nan')},
                        {**samples[0], 'response': {**response, 'content': ''}},
                        {**samples[0], 'response': {**response, 'tokens_predicted': 0}},
                        {**samples[0], 'response': {**response, 'tokens_evaluated': 0}},
                        {**samples[0], 'response': {**response, 'timings': {}}}]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                serving.summarize([changed])


class StartupTests(unittest.TestCase):
    # Exercise the actual polling loop with Kubernetes snapshots and a simulated
    # monotonic clock. No real sleep or assumption that Running means Ready.
    def setUp(self):
        self.lock = json.loads((ROOT / 'tests/benchmarks/cpu-serving.lock.json').read_text())
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.now = 0
        self.delivery, self.available = 0, 10
        self.change = lambda deployment, pod: None
        lab = SimpleNamespace(output=Path(directory.name), api=self.api)
        self.scenario = serving.Serving(lab, 'oos-test', None, None)
        self.deployment = self.scenario.deployment('python@sha256:' + '0' * 64)
        self.deployment['metadata'].update(generation=2)
        self.deployment['spec']['template']['metadata']['annotations'] = {'kubectl.kubernetes.io/restartedAt': 'new'}
        self.addCleanup(patch.stopall)
        patch.object(serving.time, 'monotonic', side_effect=lambda: self.now).start()
        patch.object(serving.time, 'sleep', side_effect=self.sleep).start()
        patch('builtins.print').start()

    def sleep(self, seconds):
        self.now += seconds

    def api(self, *args):
        deployment = copy.deepcopy(self.deployment)
        ready = self.now >= self.available
        deployment['status'] = {'observedGeneration': 2, 'replicas': 1, 'updatedReplicas': 1,
                                'readyReplicas': int(ready), 'availableReplicas': int(ready)}
        pod = copy.deepcopy(deployment['spec']['template'])
        pod['metadata']['uid'] = 'pod-1'
        pod['spec']['nodeName'] = 'oos-test'
        state = {'running': {'startedAt': '2026-10-29T00:00:00Z'}} if self.now >= self.delivery else {'waiting': {'reason': 'ContainerCreating'}}
        pod['status'] = {'containerStatuses': [{'name': 'server', 'state': state, 'ready': ready,
                                                'containerID': 'containerd://1', 'restartCount': 0}],
                         'conditions': [{'type': 'Ready', 'status': 'True' if ready else 'False'}]}
        self.change(deployment, pod)
        return deployment if 'deployment' in args else {'items': [pod]}

    def record(self):
        return json.loads((self.scenario.lab.output / 'enrollment-serving-startup.json').read_text())[-1]

    def test_cold_delivery_can_exceed_old_deadline_without_accepting_running(self):
        self.delivery, self.available = 1500, 1600
        self.scenario.ready()
        self.assertEqual(self.now, 1600)
        self.assertEqual(self.record()['server_running_observed_seconds'], 1500)
        self.assertEqual(self.record()['readiness_wait_seconds'], 100)
        self.assertEqual(self.record()['status'], 'passed')

    def test_repeated_pull_attempts_do_not_extend_delivery_deadline(self):
        self.delivery = self.available = float('inf')
        def change(deployment, pod):
            pod['status']['containerStatuses'][0]['state']['waiting']['reason'] = ['ErrImagePull', 'ImagePullBackOff'][int(self.now / 5) % 2]
        self.change = change
        with self.assertRaisesRegex(TimeoutError, 'OCI delivery'):
            self.scenario.ready()
        self.assertEqual(self.now, serving.DELIVERY_TIMEOUT_SECONDS)
        self.assertEqual(self.record()['status'], 'failed')

    def test_running_without_token_readiness_has_its_own_fixed_deadline(self):
        self.delivery, self.available = 1500, float('inf')
        with self.assertRaisesRegex(TimeoutError, 'token-generation readiness'):
            self.scenario.ready()
        self.assertEqual(self.now, 1500 + serving.READINESS_TIMEOUT_SECONDS)

    def test_old_rollout_cannot_satisfy_new_generation(self):
        for stale in ['generation', 'pod']:
            self.now = 0
            def change(deployment, pod):
                if stale == 'generation':
                    deployment['status']['observedGeneration'] = 1
                else:
                    pod['metadata']['annotations']['kubectl.kubernetes.io/restartedAt'] = 'old'
            self.change = change
            with self.subTest(stale=stale), self.assertRaisesRegex(TimeoutError, 'OCI delivery'):
                self.scenario.ready()

    def test_replaced_runtime_is_not_accepted_as_ready(self):
        for field in ['pod', 'container']:
            self.now = 0
            def change(deployment, pod):
                if self.now >= 5:
                    if field == 'pod':
                        pod['metadata']['uid'] = 'replacement'
                    else:
                        pod['status']['containerStatuses'][0].update(containerID='containerd://2', restartCount=1)
            self.change = change
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'was replaced'):
                self.scenario.ready()
            self.assertEqual(self.now, 5)

    def test_crashed_runtime_fails_without_waiting_for_full_budget(self):
        def change(deployment, pod):
            pod['status']['containerStatuses'][0]['state'] = {'waiting': {'reason': 'CrashLoopBackOff'}}
        self.change = change
        with self.assertRaisesRegex(RuntimeError, 'runtime failed'):
            self.scenario.ready()
        self.assertEqual(self.now, 0)

    def test_pod_ready_and_available_deployment_are_both_required(self):
        self.available = 0
        for missing in ['pod', 'deployment']:
            self.now = 0
            def change(deployment, pod):
                if missing == 'pod':
                    pod['status']['conditions'][0]['status'] = 'False'
                else:
                    deployment['status']['availableReplicas'] = 0
            self.change = change
            with self.subTest(missing=missing), self.assertRaisesRegex(TimeoutError, 'token-generation readiness'):
                self.scenario.ready()
