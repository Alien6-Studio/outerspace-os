# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('serving', ROOT / 'scripts/cpu-serving.py')
serving = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serving)


class CPUServingTests(unittest.TestCase):
    def setUp(self):
        self.lock = json.loads((ROOT / 'benchmarks/cpu-serving.lock.json').read_text())

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
