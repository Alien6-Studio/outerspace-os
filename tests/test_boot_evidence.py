# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('package_image', Path(__file__).resolve().parents[1] / 'scripts/package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class BootEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        (self.output / 'outerspace.raw').write_bytes(b'tested disk')
        self.report = {'schema': 1, 'status': 'passed', 'power_cycles': 2,
                       'image_sha256': hashlib.sha256(b'tested disk').hexdigest()}
        self.save_report()
        (self.output / 'boot-smoke.log').write_text(
            'OUTERSPACE_SELFTEST_OK\nOUTERSPACE_UEFI_OK\n'
            'OUTERSPACE_PERSISTENCE_PREPARE_OK\nOUTERSPACE_PERSISTENCE_VERIFY_OK\n')

    def save_report(self):
        (self.output / 'uefi-smoke.json').write_text(json.dumps(self.report))

    def test_accepts_complete_evidence(self):
        self.assertEqual(package.verify_boot_report(self.output), self.report)

    def test_rejects_a_different_disk_or_one_boot(self):
        self.report['power_cycles'] = 1
        self.save_report()
        with self.assertRaises(ValueError):
            package.verify_boot_report(self.output)
        self.report['power_cycles'] = 2
        self.save_report()
        (self.output / 'outerspace.raw').write_bytes(b'untested replacement')
        with self.assertRaises(ValueError):
            package.verify_boot_report(self.output)

    def test_split_kernel_or_failed_logs_are_not_release_evidence(self):
        for content in ['OUTERSPACE_SELFTEST_OK', (self.output / 'boot-smoke.log').read_text() + 'OUTERSPACE_SELFTEST_FAIL']:
            (self.output / 'boot-smoke.log').write_text(content)
            with self.assertRaises(ValueError):
                package.verify_boot_report(self.output)
