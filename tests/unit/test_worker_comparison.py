# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
import sys
import tempfile
from pathlib import Path
import unittest

harness = Path(__file__).resolve().parents[1] / 'harness'
sys.path.insert(0, str(harness))
spec = importlib.util.spec_from_file_location('comparison', harness / 'worker-comparison.py')
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


class ComparisonTests(unittest.TestCase):
    def test_reuse_protocol_excludes_boot_timeout_but_binds_observer_and_workload_loop(self):
        source = (harness / 'worker-comparison.py').read_text()
        expected = comparison.measurement_protocol(source)
        self.assertEqual(expected, comparison.measurement_protocol(source.replace(
            'timeout=3600 if self.reference else 1200', 'timeout=7200 if self.reference else 1200')))
        for before, after in [('time.sleep(10)', 'time.sleep(1)'),
                              ('range(1, 5)', 'range(1, 4)'),
                              ("'--comparison-identity'", "'--other-observer'")]:
            with self.subTest(change=before):
                self.assertNotEqual(expected, comparison.measurement_protocol(source.replace(before, after)))

    def test_reuse_refuses_changed_evidence_before_loading_or_starting_a_lab(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'observations.json'
            path.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                comparison.reuse_outerspace(path, '0' * 64, '0' * 40, {})

    def test_mismatched_kernel_runtime_policy_or_cpu_refuses_comparison(self):
        worker = {'kernel_version': '6.8', 'kernel_notes_sha256': 'a',
                  'runtime_sha256': {'containerd': 'b'}, 'config_sha256': {'kubelet': 'c'},
                  'clock_ticks_per_second': 100, 'vcpus': 4, 'os_release': 'ID=ubuntu\n'}
        comparison.matched(worker, worker)
        for key in worker:
            changed = copy.deepcopy(worker)
            changed[key] = 'changed'
            with self.subTest(key=key), self.assertRaises(ValueError):
                comparison.matched(worker, changed)

    def test_accounting_ignores_guest_double_count_and_requires_full_intervals(self):
        samples = [{'uptime_seconds': 100 + 10 * n,
                    'cpu_ticks': [100 * n, 0, 0, 0, 0, 0, 0, 0, 99 * n, 0],
                    'memory_bytes': {'MemTotal': 4 * 1024**3, 'MemAvailable': 3 * 1024**3}}
                   for n in range(4)]
        result = comparison.summarize(samples, 100, 4)
        self.assertEqual(result['guest_busy_cpu_percent']['median'], 2.5)
        self.assertEqual(result['memory_unavailable_bytes']['median'], 1024**3)
        for change in ['short', 'regression', 'capacity', 'memory']:
            changed = copy.deepcopy(samples)
            if change == 'short':
                changed[1]['uptime_seconds'] = 109
            elif change == 'regression':
                changed[-1]['cpu_ticks'][0] = 0
            elif change == 'capacity':
                changed[-1]['cpu_ticks'][0] = 100000
            else:
                changed[-1]['memory_bytes']['MemTotal'] = 2 * 1024**3
            with self.subTest(change=change), self.assertRaises(ValueError):
                comparison.summarize(changed, 100, 4)
