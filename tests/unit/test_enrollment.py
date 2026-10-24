# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import base64
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('enrollment', Path(__file__).resolve().parents[2] / 'tests/harness/enrollment.py')
enrollment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enrollment)


class EnrollmentEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.before = {'identity': {'profile': 'agent'}, 'hostname': 'oos-test', 'machine_id': 'machine',
                       'boot_id': 'first', 'client_certificate_sha256': 'initial',
                       'bootstrap_present': True, 'accounts_locked': True}
        self.rotated = {**self.before, 'client_certificate_sha256': 'rotated'}
        self.after = {**self.rotated, 'boot_id': 'second', 'bootstrap_present': False}
        self.node = {'metadata': {'uid': 'stable-node-uid'}}

    def test_requires_real_rotation_and_a_cold_boot_with_persisted_identity(self):
        enrollment.verify_recovery(self.before, self.rotated, self.after, self.node, self.node)
        for key, value in [('identity', {'profile': 'inference'}), ('hostname', 'other'), ('machine_id', 'other'),
                           ('boot_id', 'first'), ('client_certificate_sha256', 'initial'),
                           ('bootstrap_present', True), ('accounts_locked', False)]:
            after = {**self.after, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                enrollment.verify_recovery(self.before, self.rotated, after, self.node, self.node)
        with self.assertRaises(ValueError):
            enrollment.verify_recovery(self.before, self.before, self.after, self.node, self.node)
        with self.assertRaises(ValueError):
            enrollment.verify_recovery(self.before, self.rotated, self.after, self.node, {'metadata': {'uid': 'new'}})

    def csr(self, directory, san='DNS:oos-test,IP:172.30.80.10', subject='/O=system:nodes/CN=system:node:oos-test'):
        result = subprocess.run(['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                                 '-nodes', '-keyout', str(directory / 'key.pem'), '-subj', subject,
                                 '-addext', 'subjectAltName=' + san], capture_output=True, check=True)
        return {'username': 'system:node:oos-test', 'signerName': 'kubernetes.io/kubelet-serving',
                'usages': ['digital signature', 'server auth'], 'request': base64.b64encode(result.stdout).decode()}

    def test_rotation_can_finish_before_the_first_host_probe(self):
        enrollment.verify_recovery(self.rotated, self.rotated, self.after, self.node, self.node,
                                   bootstrap_certificate_sha256='initial')
        with self.assertRaises(ValueError):
            enrollment.verify_recovery(self.before, self.rotated, self.after, self.node, self.node,
                                       bootstrap_certificate_sha256='rotated')

    def test_revocation_requires_proven_absence_and_never_accepts_an_api_failure(self):
        lab = enrollment.Lab(Path('/unused'), Path('/unused'))
        lab.token_id = 'abcdef'
        empty = subprocess.CompletedProcess([], 0, stdout='', stderr='')
        present = subprocess.CompletedProcess([], 0, stdout='{"kind":"Secret"}', stderr='')
        with patch.object(lab, 'kube', side_effect=[empty, empty]):
            lab.revoke_bootstrap()
        with patch.object(lab, 'kube', side_effect=[empty, present]), self.assertRaises(ValueError):
            lab.revoke_bootstrap()
        for results in [[RuntimeError('API unavailable')], [empty, RuntimeError('API unavailable')]]:
            with patch.object(lab, 'kube', side_effect=results), self.assertRaises(RuntimeError):
                lab.revoke_bootstrap()

    def test_serving_approval_refuses_wrong_identity_san_signer_and_usage(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            request = self.csr(directory)
            enrollment.validate_serving_csr(request, 'oos-test')
            for key, value in [('username', 'system:node:other'), ('signerName', 'other'), ('usages', ['client auth'])]:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    enrollment.validate_serving_csr({**request, key: value}, 'oos-test')
            for san in ['DNS:oos-test,IP:172.30.80.11', 'DNS:oos-test,IP:172.30.80.10,DNS:api.cluster.test',
                        'DNS:oos-test,IP:172.30.80.10,URI:https://other.test']:
                with self.subTest(san=san), self.assertRaises(ValueError):
                    enrollment.validate_serving_csr(self.csr(directory, san), 'oos-test')
            with self.assertRaises(ValueError):
                enrollment.validate_serving_csr(self.csr(directory, subject='/O=system:nodes/CN=system:node:other'), 'oos-test')
