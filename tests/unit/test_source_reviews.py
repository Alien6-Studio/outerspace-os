# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import kernel_review
import redistribution
import runtime_review
import security
from image_fixtures import identity
from sbom import write_json


class KernelSourceReviewTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.subject = identity(); self.subject['architecture'] = 'arm64'
        self.base = 'usr/lib/modules/test-kernel/'
        self.proof = {'version': '6.18.60', 'release': 'test-kernel', 'receipt_sha256': 'c' * 64,
                      'files': {self.base + 'vmlinuz': 'a' * 64, self.base + 'config': 'b' * 64}}
        self.case = {'id': 'CVE-TEST-1', 'decision': 'not-affected', 'config': {'CONFIG_SND': 'n'},
                     'rationale': 'Synthetic decision for the isolated test fixture only.',
                     'evidence': ['https://example.invalid/advisory']}
        self.review = {'schema': 1, 'scope': {'hardware_profile': 'cpu', 'profiles': ['agent', 'inference'],
                       'architectures': ['amd64', 'arm64']}, 'approved_by': 'test reviewer', 'owner': 'test reviewer',
                       'reviewed_at': '2026-10-30T12:00:00Z', 'expires_at': '2026-11-01T12:00:00Z',
                       'materials': {'source': 'd' * 64}, 'cases': [self.case]}
        self.policy = {'exception_approvers': ['test reviewer'], 'kernel_reviews': [self.review]}
        self.scan = {'matches': [{'vulnerability': {'id': 'CVE-TEST-1', 'namespace': 'nvd:cpe',
                     'severity': 'High', 'dataSource': 'https://example.invalid/advisory'},
                     'artifact': {'name': 'linux_kernel', 'version': '6.18.60', 'type': 'binary',
                     'purl': 'pkg:generic/linux@6.18.60', 'locations': [{'path': '/' + self.base + 'vmlinuz'}]}}]}
        for name, value in [('distribution.sbom.syft.json', {'files': [], 'artifacts': []}),
                            ('source-index.json', {}), ('kernel-build.json', {'patches': []})]:
            write_json(self.root / name, value)
        (self.root / 'kernel.config').write_text('# CONFIG_SND is not set\n')

    def apply(self):
        with patch.object(kernel_review.kernel_inventory, 'correspondence', return_value=self.proof), \
                patch.object(kernel_review, 'material_identity', return_value={'source': 'd' * 64}):
            return kernel_review.materialize(self.root, self.subject, self.scan, self.policy,
                                               {'test': 'scope'}, security.finding)

    def test_only_reviewed_source_and_findings_receive_exact_binary_bindings(self):
        result = self.apply()
        self.assertEqual(result[0]['binary_sha256'], {'/' + k: v for k, v in self.proof['files'].items()})
        self.scan['matches'].append(copy.deepcopy(self.scan['matches'][0]))
        self.scan['matches'][1]['vulnerability']['id'] = 'CVE-UNREVIEWED'
        self.assertEqual(len(self.apply()), 1)
        self.review['materials']['source'] = 'e' * 64
        self.assertEqual(self.apply(), [])

    def test_changed_config_foreign_package_and_unauthorized_owner_fail(self):
        (self.root / 'kernel.config').write_text('CONFIG_SND=m\n')
        with self.assertRaisesRegex(ValueError, 'configuration'): self.apply()
        (self.root / 'kernel.config').write_text('# CONFIG_SND is not set\n')
        self.scan['matches'][0]['artifact']['version'] = '6.18.59'
        with self.assertRaisesRegex(ValueError, 'source identity'): self.apply()
        self.scan['matches'][0]['artifact']['version'] = '6.18.60'
        self.review['approved_by'] = 'unauthorized'
        with self.assertRaisesRegex(ValueError, 'Unaccountable'): self.apply()

    def test_patch_kaslr_and_vpn_restrictions_cannot_be_silently_lost(self):
        case = {**self.case, 'patch_sha256': 'f' * 64}
        with self.assertRaisesRegex(ValueError, 'correction'):
            kernel_review.predicates(case, 'arm64', {}, {'patches': []}, {}, [])
        case = {**self.case, 'kaslr_required': True}
        with self.assertRaisesRegex(ValueError, 'disabled'):
            kernel_review.predicates(case, 'amd64', {'CONFIG_RANDOMIZE_BASE': 'y'}, {}, {}, ['nokaslr'])
        case = {**self.case, 'stock_network_only': True}
        with self.assertRaisesRegex(ValueError, 'explicit risk acceptance'):
            kernel_review.predicates(case, 'arm64', {}, {}, {}, [])
        case['decision'] = 'accepted-risk'
        for raw in [{'artifacts': [{'name': 'openvpn'}], 'files': []},
                    {'artifacts': [], 'files': [{'location': {'path': '/etc/systemd/network/vpn.netdev'}}]}]:
            with self.assertRaisesRegex(ValueError, 'stock-network'):
                kernel_review.predicates(case, 'arm64', {}, {}, raw, [])


class RuntimeSourceReviewTests(unittest.TestCase):
    def test_dnssec_feature_or_executable_change_invalidates_prior_approval(self):
        raw = {'files': [{'location': {'path': '/usr/bin/dfdaemon'}, 'metadata': {'type': 'RegularFile'},
                         'digests': [{'algorithm': 'sha256', 'value': 'a' * 64}]}]}
        case = {'predicate': 'dnssec-not-compiled', 'binary_paths': ['/usr/bin/dfdaemon'],
                'compiled_features': {'hickory-proto@0.25.2': ['std']}}
        receipt = {'binary_sha256': 'a' * 64, 'compiled_artifacts': [
            {'package_id': 'registry#hickory-proto@0.25.2', 'features': ['std']}]}
        with patch.object(runtime_review.runtime_build, 'verify_receipt', return_value=receipt):
            self.assertEqual(runtime_review.predicates(case, Path('.'), identity(), raw, {}),
                             {'/usr/bin/dfdaemon': 'a' * 64})
            receipt['compiled_artifacts'][0]['features'].append('dnssec-ring')
            with self.assertRaisesRegex(ValueError, 'changed'):
                runtime_review.predicates(case, Path('.'), identity(), raw, {})
            receipt['compiled_artifacts'][0]['features'] = ['std']; receipt['binary_sha256'] = 'b' * 64
            with self.assertRaisesRegex(ValueError, 'changed'):
                runtime_review.predicates(case, Path('.'), identity(), raw, {})

    def test_docker_server_symbols_cannot_inherit_api_only_decision(self):
        raw = {'files': [{'location': {'path': '/usr/bin/crictl'}, 'metadata': {'type': 'RegularFile'},
                         'digests': [{'algorithm': 'sha256', 'value': 'a' * 64}]}],
               'artifacts': [{'name': 'github.com/docker/docker', 'locations': [{'path': '/usr/bin/crictl'}],
                              'metadata': {'symbols': {'github.com/docker/docker/daemon': ['AuthZ']}}}]}
        case = {'predicate': 'docker-daemon-absent', 'binary_paths': ['/usr/bin/crictl'],
                'compiled_packages': ['github.com/docker/docker/api/types/time']}
        with patch.object(runtime_review.go_runtime_build, 'verify_receipt', return_value={'binary_sha256': 'a' * 64}):
            with self.assertRaisesRegex(ValueError, 'API-only'):
                runtime_review.predicates(case, Path('.'), identity(), raw, {})


class RedistributionMaterialReviewTests(unittest.TestCase):
    def test_cross_profile_review_requires_identical_sources_and_original_notices(self):
        apt = {'packages': [{'name': 'example', 'version': '1', 'source': 'example',
                             'source_version': '1', 'notice_sha256': 'a' * 64}]}
        index = {'source_lock_sha256': 'b' * 64, 'entries': [], 'cargo_relationship': 'test fixture'}
        policy = {'approvers': ['test reviewer'], 'reviews': []}
        first = redistribution.assess(identity(), apt, index, policy)
        policy['material_reviews'] = [{'materials_sha256': first['materials_sha256'],
            'scope': {'hardware_profile': 'cpu', 'profiles': ['agent', 'inference'], 'architectures': ['amd64', 'arm64']},
            'approved_by': 'test reviewer', 'decision': 'redistributable',
            'rationale': 'Synthetic approval covering identical source archives and notices in this isolated test fixture only.',
            'evidence': ['https://example.invalid/licenses'], 'unresolved_notices': [], 'notice_resolutions': {}}]
        other = identity('inference'); other['architecture'] = 'amd64'
        reviewed = redistribution.assess(other, apt, index, policy)
        self.assertEqual(reviewed['status'], 'passed')
        self.assertNotEqual(first['subject_sha256'], reviewed['subject_sha256'])
        apt['packages'][0]['notice_sha256'] = 'c' * 64
        self.assertEqual(redistribution.assess(other, apt, index, policy)['status'], 'review-required')
        apt['packages'][0]['notice_sha256'] = 'a' * 64
        index['entries'].append({'name': 'new', 'kind': 'ubuntu-source', 'sha256': 'd' * 64})
        self.assertEqual(redistribution.assess(other, apt, index, policy)['status'], 'review-required')


if __name__ == '__main__':
    unittest.main()
