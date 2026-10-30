# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

harness = Path(__file__).resolve().parents[1] / 'harness'
sys.path.insert(0, str(harness))
spec = importlib.util.spec_from_file_location('comparison', harness / 'worker-comparison.py')
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)
reference_runtimes = comparison.native.load_script('reference-runtimes')


class ComparisonTests(unittest.TestCase):
    def test_reference_reuses_exact_disk_binaries_and_rejects_altered_payloads(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / 'payload'; source.mkdir()
            lock = base / 'components.json'; lock.write_text('{}')
            identity = {'architecture': 'arm64', 'raw_image_sha256': 'a' * 64,
                        'components_lock_sha256': reference_runtimes.digest(lock)}
            records = []
            for name, component in reference_runtimes.RUNTIMES.items():
                (source / name).write_bytes(('qualified bytes of ' + name).encode())
                records.append({'path': '/usr/bin/' + name, 'component': component,
                                'sha256': reference_runtimes.digest(source / name)})
            evidence = {'status': 'inventoried', 'identity': identity, 'runtimes': records}
            manifest = reference_runtimes.inventory(identity, evidence, lock)
            (source / 'runtimes.json').write_text(comparison.json.dumps(manifest))
            reference_runtimes.install(source, base / 'guest', 'arm64')
            for name in reference_runtimes.RUNTIMES:
                self.assertEqual((base / 'guest/usr/bin' / name).read_bytes(), (source / name).read_bytes())
            for changed in [{**evidence, 'identity': {**identity, 'raw_image_sha256': 'b' * 64}},
                            {**evidence, 'runtimes': records[:-1]},
                            {**evidence, 'runtimes': records + [records[0]]}]:
                with self.subTest(evidence=changed), self.assertRaises(ValueError):
                    reference_runtimes.inventory(identity, changed, lock)
            with self.assertRaises(ValueError):
                reference_runtimes.install(source, base / 'wrong-arch', 'amd64')
            for symlink in [False, True]:
                target = source / 'ctr'; target.unlink()
                if symlink:
                    target.symlink_to(source / 'containerd')
                else:
                    target.write_bytes(b'unqualified replacement')
                destination = base / ('rejected-' + str(symlink))
                with self.subTest(symlink=symlink), self.assertRaises(ValueError):
                    reference_runtimes.install(source, destination, 'arm64')
                self.assertFalse(destination.exists())

    def samples(self):
        return [{'uptime_seconds': 100 + 10 * n,
                 'cpu_ticks': [100 * n, 0, 0, 0, 0, 0, 0, 0, 99 * n, 0],
                 'memory_bytes': {'MemTotal': 4 * 1024**3, 'MemAvailable': 3 * 1024**3}}
                for n in range(4)]

    def pod(self):
        return {'metadata': {'uid': 'pod-uid'}, 'spec': {'nodeName': 'worker'},
                'status': {'phase': 'Running', 'qosClass': 'Guaranteed', 'containerStatuses': [
                    {'ready': True, 'restartCount': 0, 'state': {'running': {'startedAt': 'now'}},
                     'lastState': {}, 'containerID': 'containerd://' + 'a' * 64, 'imageID': 'sha256:busybox'}]}}

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
        samples = self.samples()
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

    def test_invalid_guest_counters_cannot_produce_a_summary(self):
        for change in [lambda s: s.update(uptime_seconds=float('nan')),
                       lambda s: s.update(uptime_seconds=float('inf')),
                       lambda s: s.update(cpu_ticks=[0]),
                       lambda s: s['cpu_ticks'].__setitem__(0, True),
                       lambda s: s['cpu_ticks'].__setitem__(3, -1),
                       lambda s: s['memory_bytes'].update(MemAvailable=-1),
                       lambda s: s['memory_bytes'].update(MemAvailable=5 * 1024**3),
                       lambda s: s['memory_bytes'].update(MemTotal=float('nan'))]:
            samples = self.samples()
            change(samples[-1])
            with self.subTest(change=change), self.assertRaises(ValueError):
                comparison.summarize(samples, 100, 4)
        for clock in [True, 0, float('nan')]:
            with self.assertRaises(ValueError):
                comparison.summarize(self.samples(), clock, 4)

    def test_restarted_replaced_or_misplaced_agent_invalidates_density(self):
        original = self.pod()
        comparison.verify_running_agent(original, 'worker')
        for mutate in [lambda p: p['status']['containerStatuses'][0].update(restartCount=1),
                       lambda p: p['status']['containerStatuses'][0].update(ready=False),
                       lambda p: p['status']['containerStatuses'][0].update(containerID='containerd://' + 'b' * 64),
                       lambda p: p['metadata'].update(uid='replacement'),
                       lambda p: p['spec'].update(nodeName='different-worker'),
                       lambda p: p['status'].update(phase='Failed'),
                       lambda p: p['status'].update(qosClass='Burstable')]:
            changed = copy.deepcopy(original)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                comparison.verify_running_agent(changed, 'worker', original)

    def test_corrupted_or_symlinked_reference_cache_is_rejected(self):
        lock = comparison.json.loads(comparison.LOCK.read_text())
        name = 'noble-server-cloudimg-arm64.img'
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            (cache / 'SHA256SUMS').write_text(lock['images']['arm64'] + ' *' + name + '\n')
            for entry in ['SHA256SUMS.gpg', 'signing-key.asc', name]:
                (cache / entry).write_text('fixture')
            verified = comparison.native.subprocess.CompletedProcess([], 0,
                '[GNUPG:] VALIDSIG ' + lock['signing_fingerprint'] + ' 2026-01-01', '')
            with patch.object(comparison, 'run', return_value=verified):
                with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                    comparison.signed_image(cache, 'arm64')
                verified.stdout = '[GNUPG:] VALIDSIG ' + '0' * 40 + ' 2026-01-01'
                with self.assertRaisesRegex(ValueError, 'pinned Canonical key'):
                    comparison.signed_image(cache, 'arm64')
            (cache / 'SHA256SUMS').unlink()
            (cache / 'SHA256SUMS').symlink_to(cache / name)
            with self.assertRaisesRegex(ValueError, 'regular file'):
                comparison.signed_image(cache, 'arm64')
