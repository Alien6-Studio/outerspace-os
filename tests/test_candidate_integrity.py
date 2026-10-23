# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('prepare_release', SCRIPTS / 'prepare-release.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class CandidateIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.bundle = Path(self.directory.name)
        (self.bundle / 'image.raw.zst').write_bytes(b'qualified image')
        (self.bundle / 'build-metadata.json').write_text(json.dumps({'version': '0.1.0-alpha.1', 'commit': 'a' * 40, 'architecture': 'arm64'}))
        self.inventory = self.bundle / 'SHA256SUMS'
        self.inventory.write_text(''.join(f'{prepare.sha256(p)}  {p.name}\n' for p in sorted(self.bundle.iterdir())))
        self.digest = prepare.sha256(self.inventory)

    def verify(self, digest=None):
        prepare.verify_bundle(self.bundle, '0.1.0-alpha.1', 'a' * 40, 'arm64', digest or self.digest)

    def test_accepts_qualified_exact_bytes(self):
        self.verify()

    def test_rejects_tampering_after_qualification(self):
        (self.bundle / 'image.raw.zst').write_bytes(b'replacement image')
        with self.assertRaisesRegex(ValueError, 'integrity failure'):
            self.verify()

    def test_rejects_unverified_extra_file(self):
        (self.bundle / 'unexpected.sh').write_text('unqualified')
        with self.assertRaisesRegex(ValueError, 'extra file'):
            self.verify()

    def test_inventory_must_be_bound_to_evidence(self):
        with self.assertRaisesRegex(ValueError, 'exact SHA256SUMS'):
            self.verify('0' * 64)

    def test_rejects_other_architecture(self):
        with self.assertRaisesRegex(ValueError, 'does not match'):
            prepare.verify_bundle(self.bundle, '0.1.0-alpha.1', 'a' * 40, 'amd64', self.digest)

    def test_rejects_traversal_and_symlinks(self):
        with self.subTest('traversal'):
            self.inventory.write_text('0' * 64 + '  ../image.raw.zst\n')
            with self.assertRaisesRegex(ValueError, 'Invalid checksum'):
                self.verify(prepare.sha256(self.inventory))
        with self.subTest('symlink'):
            self.inventory.write_text('0' * 64 + '  link\n')
            (self.bundle / 'link').symlink_to('/etc/passwd')
            with self.assertRaisesRegex(ValueError, 'integrity failure'):
                self.verify(prepare.sha256(self.inventory))
