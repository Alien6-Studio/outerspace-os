# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from image_fixtures import profiles, idle_log

spec = importlib.util.spec_from_file_location('package_image', Path(__file__).resolve().parents[2] / 'build/tools/package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class BootEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        for name in ['outerspace.raw', 'outerspace.efi', 'outerspace.manifest', 'outerspace-source.tar']:
            (self.output / name).write_bytes(name.encode())
        self.hash_patch = patch.object(profiles, 'root_hash', return_value='f' * 64)
        self.hash_patch.start()
        self.addCleanup(self.hash_patch.stop)
        self.identity = profiles.stamp(self.output, profiles.image_identity('agent', 'cpu', profiles.architecture(), 'a' * 40))
        content = ''.join(idle_log(self.identity, phase) for phase in ['prepare', 'verify'])
        logs = ['boot-smoke.log', 'boot-uefi-prepare.log', 'boot-uefi-verify.log']
        for name in logs:
            (self.output / name).write_text(content if name == 'boot-smoke.log' else idle_log(self.identity, name.removeprefix('boot-uefi-').removesuffix('.log')))
        self.report = {'schema': 2, 'identity': self.identity, 'status': 'passed', 'power_cycles': 2,
                       'image_sha256': profiles.sha256(self.output / 'outerspace.raw'),
                       'idle_host': package.idle_host_report({phase: idle_log(self.identity, phase) for phase in ['prepare', 'verify']}, self.identity),
                       'logs': {name: profiles.sha256(self.output / name) for name in logs}}
        self.report['host_regression'] = package.idle_host_budget(self.report['idle_host'], self.identity)
        self.save_report()

    def verify(self, profile='agent', commit='a' * 40):
        return package.verify_boot_report(self.output, profile, 'cpu', commit)

    def save_report(self):
        (self.output / 'uefi-smoke.json').write_text(json.dumps(self.report))

    def test_accepts_complete_evidence(self):
        self.assertEqual(self.verify(), self.report)

    def test_rejects_a_different_disk_or_one_boot(self):
        self.report['power_cycles'] = 1
        self.save_report()
        with self.assertRaises(ValueError):
            self.verify()
        self.report['power_cycles'] = 2
        self.save_report()
        (self.output / 'outerspace.raw').write_bytes(b'untested replacement')
        with self.assertRaises(ValueError):
            self.verify()

    def test_split_kernel_or_failed_logs_are_not_release_evidence(self):
        for content in ['OUTERSPACE_SELFTEST_OK', (self.output / 'boot-smoke.log').read_text() + 'OUTERSPACE_SELFTEST_FAIL']:
            (self.output / 'boot-smoke.log').write_text(content)
            with self.assertRaises(ValueError):
                self.verify()

    def test_rejects_cross_profile_source_uki_and_log_reuse(self):
        with self.assertRaises(ValueError): self.verify(profile='inference')
        with self.assertRaises(ValueError): self.verify(commit='b' * 40)
        (self.output / 'boot-uefi-verify.log').write_text('modified log')
        with self.assertRaisesRegex(ValueError, 'log integrity'): self.verify()
        (self.output / 'outerspace.efi').write_bytes(b'changed UKI')
        with self.assertRaisesRegex(ValueError, 'integrity'): self.verify()

    def test_rejects_a_forged_idle_summary_even_when_boot_log_hashes_are_intact(self):
        self.report['idle_host']['boots']['prepare']['guest_busy_cpu_percent']['median'] = 0
        self.save_report()
        with self.assertRaisesRegex(ValueError, 'differs from'):
            self.verify()

    def test_regression_result_is_required_and_cannot_hide_a_changed_threshold(self):
        self.report.pop('host_regression')
        self.save_report()
        with self.assertRaisesRegex(ValueError, 'regression evidence'):
            self.verify()
        self.report['host_regression'] = package.idle_host_budget(self.report['idle_host'], self.identity)
        self.report['host_regression']['limits']['memory_unavailable_bytes'] *= 2
        self.save_report()
        with self.assertRaisesRegex(ValueError, 'regression evidence'):
            self.verify()

    def test_regression_gate_checks_both_boots_and_each_metric_for_all_four_images(self):
        import copy
        policy = json.loads(package.IDLE_POLICY.read_text())
        for key, budget in policy['budgets'].items():
            profile, hardware, arch = key.split('-')
            subject = {**self.identity, 'profile': profile, 'hardware_profile': hardware, 'architecture': arch}
            baseline = copy.deepcopy(self.report['idle_host'])
            for boot in baseline['boots'].values():
                boot['memory_unavailable_bytes']['max'] = budget['memory_limit_bytes']
                boot['guest_busy_cpu_percent']['max'] = budget['cpu_limit_percent']
            self.assertEqual(package.idle_host_budget(baseline, subject)['status'], 'passed')
            for phase in ['prepare', 'verify']:
                for metric in ['memory_unavailable_bytes', 'guest_busy_cpu_percent']:
                    changed = copy.deepcopy(baseline)
                    changed['boots'][phase][metric]['max'] += 1
                    with self.subTest(image=key, phase=phase, metric=metric), self.assertRaisesRegex(ValueError, 'exceeded'):
                        package.idle_host_budget(changed, subject)
        with self.assertRaisesRegex(ValueError, 'No qualified'):
            package.idle_host_budget(self.report['idle_host'], {**self.identity, 'hardware_profile': 'cpu-full-firmware'})
