# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from image_fixtures import qualification

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('release', ROOT / 'build/tools/release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / 'build/release/policy.json').read_text())
        self.evidence = qualification(self.policy)

    def validate(self):
        return release.validate_release('0.1.0-alpha.1', 'v0.1.0-alpha.1', 'a' * 40, self.evidence, self.policy)

    def test_complete_independent_profile_evidence_passes(self):
        self.assertEqual(self.validate(), 'alpha')

    def test_no_dev_snapshot_can_be_mistaken_for_a_release(self):
        with self.assertRaises(ValueError):
            release.validate_release('0.1.0-dev.0', 'v0.1.0-dev.0', 'a' * 40, {}, self.policy)

    def test_each_required_image_and_capability_is_mandatory(self):
        for mutation in ['missing-artifact', 'duplicate', 'missing-capability', 'missing-serving-gate', 'unknown-capability']:
            with self.subTest(mutation=mutation):
                self.evidence = qualification(self.policy)
                if mutation == 'missing-artifact': self.evidence['artifacts'].pop()
                if mutation == 'duplicate': self.evidence['artifacts'].append(copy.deepcopy(self.evidence['artifacts'][0]))
                if mutation == 'missing-capability': self.evidence['artifacts'][0]['capabilities'] = []
                if mutation == 'missing-serving-gate': self.evidence['artifacts'][-1]['gates'].pop('inference_cpu_serving')
                if mutation == 'unknown-capability': self.evidence['artifacts'][0]['capabilities'].append('magic')
                with self.assertRaises(ValueError): self.validate()

    def test_reused_evidence_is_refused_for_every_identity_dimension(self):
        for field, replacement in [('profile', 'inference'), ('architecture', 'arm64'), ('hardware_profile', 'gpu-nvidia'),
                                   ('commit', 'c' * 40), ('raw_image_sha256', 'c' * 64),
                                   ('uki_sha256', 'c' * 64), ('verity_root_hash', 'c' * 64)]:
            with self.subTest(field=field):
                self.evidence = qualification(self.policy)
                self.evidence['artifacts'][0]['gates']['boot']['subject'][field] = replacement
                with self.assertRaisesRegex(ValueError, 'boot'): self.validate()

    def test_optional_capability_requires_its_own_evidence(self):
        self.evidence['artifacts'][0]['capabilities'].append('openshell')
        with self.assertRaisesRegex(ValueError, 'openshell_compatibility'): self.validate()
        artifact = self.evidence['artifacts'][0]
        artifact['gates']['openshell_compatibility'] = {'status': 'passed', 'evidence': 'synthetic-test-only',
                                                       'subject': copy.deepcopy(artifact['identity'])}
        self.validate()

    def test_gpu_cannot_be_claimed_on_a_cpu_candidate(self):
        self.evidence['artifacts'][-1]['capabilities'].append('inference_gpu_serving')
        with self.assertRaisesRegex(ValueError, 'Unsupported capability'): self.validate()

    def test_phase_gates_remain_cumulative(self):
        self.policy['stages']['alpha'].extend(['signed_boot', 'cis_audit'])
        with self.assertRaisesRegex(ValueError, 'signed_boot'): self.validate()

    def test_failed_or_unbound_gate_is_not_evidence(self):
        for value in [{'status': 'failed', 'evidence': 'synthetic-test-only'},
                      {'status': 'passed', 'evidence': ''}, {'status': 'passed', 'evidence': 'synthetic-test-only'}]:
            with self.subTest(value=value):
                self.evidence = qualification(self.policy)
                self.evidence['artifacts'][0]['gates']['boot'] = value
                with self.assertRaises(ValueError): self.validate()

    def test_rejects_reused_source_tag_and_legacy_global_evidence(self):
        for change in ['source', 'tag', 'schema']:
            self.evidence = qualification(self.policy)
            if change == 'source': self.evidence['commit'] = 'c' * 40
            if change == 'schema': self.evidence['schema'] = 1
            with self.subTest(change=change), self.assertRaises(ValueError):
                release.validate_release('0.1.0-alpha.1', 'v0.1.0' if change == 'tag' else 'v0.1.0-alpha.1',
                                         'a' * 40, self.evidence, self.policy)

    def test_rejects_ambiguous_versions(self):
        for version in ['latest', '01.0.0', '1.0', 'v1.0.0', '1.0.0-beta', '1.0.0-rc.0']:
            with self.subTest(version=version), self.assertRaises(ValueError): release.parse_version(version)
