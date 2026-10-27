# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

harness = Path(__file__).resolve().parents[1] / 'harness'
sys.path.insert(0, str(harness))
spec = importlib.util.spec_from_file_location('serving_comparison', harness / 'serving-comparison.py')
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


class ServingComparisonTests(unittest.TestCase):
    def result(self):
        worker = {'kernel_version': '6.8', 'kernel_notes_sha256': 'a', 'runtime_sha256': {'containerd': 'b'},
                  'config_sha256': {'kubelet': 'c'}, 'clock_ticks_per_second': 100, 'vcpus': 4, 'os_release': 'ID=ubuntu\n'}
        sample = {'wall_seconds': 2, 'first_token_seconds': .5,
                  'response': {'content': 'Paris', 'tokens_predicted': 8, 'tokens_evaluated': 5,
                               'timings': {'predicted_n': 8}}}
        raw = {'concurrency': 1, 'output_token_limit': 8, 'cache_prompt': False, 'temperature': 0, 'seed': 42,
               'prompt': 'The capital of France is', 'samples': [sample] * 30, 'wall_seconds': 60}
        phase = {'raw': raw, 'summary': comparison.serving.summarize(raw['samples']),
                 'resources_before': {'image_id': 'sha256:fixed'}}
        return {'worker': worker, 'serving': {'lock': {'model': 'fixed'}, 'lock_sha256': 'd',
            'running_model_sha256': 'e', 'runtime_version': 'fixed',
            'observations': {name: copy.deepcopy(phase) for name in
                ['initial', 'sustained', 'pod_restart', 'drain_recovery', 'node_recovery']}}}

    def test_rejects_changed_workload_or_missing_sustained_interval(self):
        first = self.result()
        self.assertEqual(len(comparison.compare_results(first, first)), 5)
        mutations = [lambda r: r['serving'].update(running_model_sha256='changed'),
                     lambda r: r['serving'].update(runtime_version='changed'),
                     lambda r: r['worker'].update(kernel_notes_sha256='changed'),
                     lambda r: r['serving']['observations']['sustained']['raw'].update(wall_seconds=59),
                     lambda r: r['serving']['observations']['initial']['raw'].update(cache_prompt=True),
                     lambda r: r['serving']['observations']['initial']['resources_before'].update(image_id='changed'),
                     lambda r: r['serving']['observations']['node_recovery']['summary'].update(latency_p95_seconds=0)]
        for mutate in mutations:
            second = copy.deepcopy(first)
            mutate(second)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                comparison.compare_results(first, second)

    def test_fewer_than_thirty_samples_cannot_claim_sustained_serving(self):
        first, second = self.result(), self.result()
        phase = second['serving']['observations']['sustained']
        phase['raw']['samples'] = phase['raw']['samples'][:4]
        phase['summary'] = comparison.serving.summarize(phase['raw']['samples'])
        with self.assertRaises(ValueError):
            comparison.compare_results(first, second)
