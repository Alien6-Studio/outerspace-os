# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from image_fixtures import identity
import redistribution
import security
from sbom import write_json


class SourceNoticeDecisionTests(unittest.TestCase):
    def setUp(self):
        self.index = {'source_lock_sha256': 'b' * 64, 'entries': [
            {'name': 'example', 'version': '1.0', 'sha256': 'c' * 64, 'kind': 'cargo-registry',
             'licenses': {'notices': [], 'declared_licenses': ['Apache-2.0 OR MIT']}}],
            'cargo_relationship': 'synthetic source closure'}
        self.decision = {'name': 'example', 'version': '1.0', 'source_sha256': 'c' * 64,
            'scope': {'hardware_profile': 'cpu'}, 'decision': 'select-declared-license',
            'declared_license': 'Apache-2.0 OR MIT', 'selected_license': 'Apache-2.0',
            'approved_by': 'test approver', 'approved_at': '2026-10-30T12:00:00Z',
            'rationale': 'Synthetic source-specific license selection for tests only. This does not approve redistribution of any actual image.',
            'evidence': ['https://example.invalid/original-manifest'],
            'distributed_license': {'path': 'license.txt', 'sha256': 'd' * 64}}
        self.policy = {'approvers': ['test approver'], 'reviews': [], 'notice_decisions': [self.decision]}

    def assess(self, subject=None):
        return redistribution.assess(subject or identity(), {'packages': []}, self.index, self.policy)

    def test_source_choice_resolves_notice_without_approving_whole_distribution(self):
        result = self.assess()
        self.assertEqual(result['status'], 'review-required')
        self.assertEqual(result['unresolved_source_notices'], [])
        self.assertEqual(len(result['source_archives_without_notice_files']), 1)
        self.assertEqual(result['resolved_notice_decisions'], [self.decision])
        self.decision['source_sha256'] = 'e' * 64
        self.assertEqual(len(self.assess()['unresolved_source_notices']), 1)
        self.decision['source_sha256'] = 'c' * 64
        subject = identity(); subject['hardware_profile'] = 'gpu'
        self.assertEqual(len(self.assess(subject)['unresolved_source_notices']), 1)

    def test_selection_requires_exact_grant_approver_and_unambiguous_record(self):
        for key, value in [('selected_license', 'GPL-3.0-only'), ('declared_license', 'MIT'),
                           ('approved_by', 'someone else'), ('version', '1.1')]:
            previous = self.decision[key]; self.decision[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.assess()
            self.decision[key] = previous
        self.policy['notice_decisions'].append(copy.deepcopy(self.decision))
        with self.assertRaisesRegex(ValueError, 'Ambiguous'): self.assess()
        self.policy['notice_decisions'].pop()
        self.decision['declared_license'] = 'Apache-2.0 AND MIT'
        self.index['entries'][0]['licenses']['declared_licenses'] = ['Apache-2.0 AND MIT']
        with self.assertRaisesRegex(ValueError, 'not granted'): self.assess()

    def test_missing_changed_or_linked_license_text_cannot_qualify(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); license_file = root / 'license.txt'
            license_file.write_text('synthetic license text')
            self.decision['distributed_license']['sha256'] = redistribution.sha256(license_file)
            write_json(root / 'policy.json', self.policy)
            write_json(root / 'build-identity.json', identity())
            write_json(root / 'apt-inputs.json', {'packages': []})
            write_json(root / 'source-index.json', self.index)
            with patch.object(redistribution, 'POLICY', root / 'policy.json'):
                redistribution.generate(root)
                redistribution.verify(root, identity())
                with self.assertRaisesRegex(ValueError, 'before publication'):
                    redistribution.verify(root, identity(), require_pass=True)
                license_file.write_text('altered license')
                with self.assertRaisesRegex(ValueError, 'missing or changed'):
                    redistribution.verify(root, identity())
                license_file.unlink()
                with self.assertRaisesRegex(ValueError, 'missing or changed'):
                    redistribution.verify(root, identity())
                (root / 'outside.txt').write_text('synthetic license text')
                license_file.symlink_to(root / 'outside.txt')
                with self.assertRaisesRegex(ValueError, 'missing or changed'):
                    redistribution.verify(root, identity())


class ExceptionBinaryBindingTests(unittest.TestCase):
    def test_changed_missing_or_duplicate_executable_invalidates_decision(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = {'location': {'path': '/usr/bin/example'}, 'metadata': {'type': 'RegularFile'},
                      'digests': [{'algorithm': 'sha256', 'value': 'a' * 64}]}
            review = {'decisions': [{'exception': {'binary_sha256': {'/usr/bin/example': 'a' * 64}}},
                                    {'exception': None}]}
            write_json(root / 'distribution.sbom.syft.json', {'files': [record]})
            security.verify_exception_binaries(root, review)
            for files in [[], [record, record], [{**record, 'digests': [{'algorithm': 'sha256', 'value': 'b' * 64}]}],
                          [{**record, 'metadata': {'type': 'SymbolicLink'}}]]:
                write_json(root / 'distribution.sbom.syft.json', {'files': files})
                with self.subTest(files=files), self.assertRaisesRegex(ValueError, 'executable bytes'):
                    security.verify_exception_binaries(root, review)
