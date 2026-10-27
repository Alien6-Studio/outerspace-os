# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from image_fixtures import identity, inventory

BUILD_TOOLS = Path(__file__).resolve().parents[2] / 'build/tools'
sys.path.insert(0, str(BUILD_TOOLS))
spec = importlib.util.spec_from_file_location('prepare_release', BUILD_TOOLS / 'prepare-release.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class CandidateIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.bundle = Path(self.directory.name)
        (self.bundle / 'image.raw.zst').write_bytes(b'qualified image')
        self.artifact = {'identity': identity('agent', 'arm64')}
        supply_chain = inventory(self.bundle, self.artifact['identity'])
        (self.bundle / 'build-metadata.json').write_text(json.dumps({'schema': 2, 'identity': self.artifact['identity'],
                                                                  'supply_chain': supply_chain}))
        self.inventory = self.bundle / 'SHA256SUMS'
        self.inventory.write_text(''.join(f'{prepare.sha256(p)}  {p.name}\n' for p in sorted(self.bundle.iterdir())))
        self.digest = prepare.sha256(self.inventory)
        self.artifact['sha256sums'] = self.digest

    def verify(self, digest=None):
        prepare.verify_bundle(self.bundle, '0.1.0-alpha.1', 'a' * 40, {**self.artifact, 'sha256sums': digest or self.digest})

    def test_accepts_qualified_exact_bytes(self):
        # These validators have independent boundary tests; this fixture focuses
        # on the immutable candidate inventory and mandatory release calls.
        with patch.object(prepare.supply_chain, 'verify', return_value=None) as sources, \
             patch.object(prepare.security, 'verify', return_value=None) as security, \
             patch.object(prepare.redistribution, 'verify', return_value=None) as licenses:
            self.verify()
        sources.assert_called_once()
        self.assertTrue(security.call_args.kwargs['require_pass'])
        self.assertTrue(licenses.call_args.kwargs['require_pass'])

    def test_missing_distribution_review_cannot_promote(self):
        with self.assertRaisesRegex(ValueError, 'regular file'):
            self.verify()

    def test_development_runtime_qualification_still_verifies_all_evidence(self):
        subject = identity('agent', 'arm64', version='0.1.0-dev.0')
        base = inventory(self.bundle, subject)
        (self.bundle / 'build-metadata.json').write_text(json.dumps({'schema': 2, 'identity': subject, 'supply_chain': base}))
        self.inventory.write_text(''.join(f'{prepare.sha256(p)}  {p.name}\n' for p in sorted(self.bundle.iterdir())
                                         if p != self.inventory))
        artifact = {'identity': subject, 'sha256sums': prepare.sha256(self.inventory)}
        with patch.object(prepare.supply_chain, 'verify', return_value=None) as sources, \
             patch.object(prepare.security, 'verify', return_value=None) as security, \
             patch.object(prepare.redistribution, 'verify', return_value=None) as licenses:
            prepare.verify_bundle(self.bundle, subject['version'], subject['commit'], artifact, development=True)
            sources.assert_called_once()
            self.assertFalse(security.call_args.kwargs['require_pass'])
            self.assertFalse(licenses.call_args.kwargs['require_pass'])
            security.side_effect = ValueError('stale security evidence')
            with self.assertRaisesRegex(ValueError, 'stale security evidence'):
                prepare.verify_bundle(self.bundle, subject['version'], subject['commit'], artifact, development=True)

    def test_public_candidate_cannot_opt_into_development_qualification(self):
        with self.assertRaisesRegex(ValueError, 'Only development'):
            prepare.verify_bundle(self.bundle, '0.1.0-alpha.1', 'a' * 40, self.artifact, development=True)

    def test_blocked_security_cannot_promote(self):
        with patch.object(prepare.supply_chain, 'verify', return_value=None), \
             patch.object(prepare.security, 'verify', side_effect=ValueError('unresolved vulnerability')):
            with self.assertRaisesRegex(ValueError, 'unresolved vulnerability'):
                self.verify()

    def test_rejects_tampering_after_qualification(self):
        (self.bundle / 'image.raw.zst').write_bytes(b'replacement image')
        with self.assertRaisesRegex(ValueError, 'integrity failure'):
            self.verify()

    def test_rejects_unverified_extra_file(self):
        (self.bundle / 'unexpected.sh').write_text('unqualified')
        with self.assertRaisesRegex(ValueError, 'extra file'):
            self.verify()

    def test_promotion_requires_inventory_even_if_checksum_list_is_rewritten(self):
        (self.bundle / 'sbom-evidence.json').unlink()
        self.inventory.write_text(''.join(f'{prepare.sha256(p)}  {p.name}\n' for p in sorted(self.bundle.iterdir())
                                          if p != self.inventory))
        with self.assertRaisesRegex(ValueError, 'regular file'):
            self.verify(prepare.sha256(self.inventory))

    def test_promotion_rejects_forged_supply_chain_summary(self):
        path = self.bundle / 'build-metadata.json'
        metadata = json.loads(path.read_text())
        metadata['supply_chain']['coverage']['license_review'] = 'passed'
        path.write_text(json.dumps(metadata))
        self.inventory.write_text(''.join(f'{prepare.sha256(p)}  {p.name}\n' for p in sorted(self.bundle.iterdir())
                                          if p != self.inventory))
        with self.assertRaisesRegex(ValueError, 'Candidate SBOM'):
            self.verify(prepare.sha256(self.inventory))

    def test_inventory_must_be_bound_to_evidence(self):
        with self.assertRaisesRegex(ValueError, 'exact SHA256SUMS'):
            self.verify('0' * 64)

    def test_rejects_other_architecture(self):
        for field, value in [('architecture', 'amd64'), ('profile', 'inference'), ('hardware_profile', 'gpu-nvidia'),
                             ('raw_image_sha256', '0' * 64), ('commit', 'c' * 40)]:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'does not match'):
                artifact = {**self.artifact, 'identity': {**self.artifact['identity'], field: value}}
                prepare.verify_bundle(self.bundle, '0.1.0-alpha.1', 'a' * 40, artifact)

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
