# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import base64
import importlib.util
import json
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

    def test_cleanup_removes_only_owned_node_volumes_and_continues_after_failure(self):
        lab = enrollment.Lab(Path('/unused'), Path('/unused'))
        lab.runner_created = lab.kind_created = lab.network_created = True
        mounts = [{'Type': 'volume', 'Destination': '/var', 'Name': 'owned'},
                  {'Type': 'bind', 'Destination': '/var', 'Source': '/host'},
                  {'Type': 'volume', 'Destination': '/other', 'Name': 'unrelated'}]
        commands = []

        def run(*args, **kwargs):
            commands.append(args)
            if args[:2] == ('docker', 'ps'):
                self.assertIn('label=io.x-k8s.kind.cluster=' + enrollment.LAB, args)
                output = 'owned-node\n'
            elif args[:2] == ('docker', 'inspect'):
                self.assertEqual(args[2:], ('owned-node',))
                output = json.dumps([{'Mounts': mounts}])
            elif args[:3] == ('docker', 'volume', 'ls'):
                output = 'owned\nunrelated\n'
            elif args[:2] == ('docker', 'rm'):
                raise subprocess.TimeoutExpired('docker', 1)
            else:
                output = ''
            return subprocess.CompletedProcess(args, 0, stdout=output, stderr='')

        with patch.object(enrollment, 'run', side_effect=run), self.assertRaisesRegex(RuntimeError, 'VM runner'):
            lab.cleanup()
        self.assertIn(('docker', 'volume', 'rm', 'owned'), commands)
        self.assertNotIn(('docker', 'volume', 'rm', 'unrelated'), commands)
        self.assertIn(('docker', 'network', 'rm', enrollment.LAB), commands)

    def test_cleanup_accepts_volumes_already_removed_by_kind(self):
        lab = enrollment.Lab(Path('/unused'), Path('/unused'))
        lab.kind_created = True
        outputs = ['node\n', json.dumps([{'Mounts': [
            {'Type': 'volume', 'Destination': '/var', 'Name': 'owned'}]}]), '', 'unrelated\n']
        with patch.object(enrollment, 'run', side_effect=[
                subprocess.CompletedProcess([], 0, stdout=value, stderr='') for value in outputs]) as run:
            lab.cleanup()
        self.assertFalse(any(call.args[:3] == ('docker', 'volume', 'rm') for call in run.call_args_list))

    def test_failed_volume_inventory_still_tears_down_the_lab_and_fails_qualification(self):
        lab = enrollment.Lab(Path('/unused'), Path('/unused'))
        lab.kind_created = lab.network_created = True
        with patch.object(enrollment, 'run', side_effect=[RuntimeError('Docker unavailable'),
                subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0)]) as run:
            with self.assertRaisesRegex(RuntimeError, 'kind volume inventory'):
                lab.cleanup()
        self.assertEqual(run.call_args_list[-1].args, ('docker', 'network', 'rm', enrollment.LAB))

    def test_agent_admission_never_counts_api_errors_as_a_security_refusal(self):
        lab = enrollment.Lab(Path('/unused'), Path('/unused'))
        lab.agent_node = 'oos-test'
        lab.agent_checks = {}
        template = (enrollment.ROOT / 'src/cluster/agent/workload-v1.json').read_text()
        accepted = subprocess.CompletedProcess([], 0, stdout=template, stderr='')
        for error in ['Unable to connect to the server', 'Error from server (InternalError): unavailable']:
            refused = subprocess.CompletedProcess([], 1, stdout='', stderr=error)
            with patch.object(lab, 'kube', side_effect=[accepted, refused]), self.assertRaises(ValueError):
                lab.agent_admission()
        with patch.object(lab, 'kube', side_effect=[accepted, accepted]), self.assertRaises(ValueError):
            lab.agent_admission()

    def test_agent_probe_requires_every_running_boundary_and_rejects_missing_or_forged_values(self):
        observation = {'status': 'passed', 'uid': 65534, 'gid': 65534,
            'apparmor': 'outerspace-agent-v1 (enforce)', 'seccomp': 2,
            'no_new_privileges': True, 'read_only_root': True, 'capabilities': 'none',
            'workspace': 'passed', 'host_access': 'denied', 'privilege_escalation': 'denied',
            'policy_change': 'denied', 'child_confinement': 'passed'}
        enrollment.verify_agent_probe(observation)
        for key in observation:
            missing = dict(observation)
            del missing[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                enrollment.verify_agent_probe(missing)
        for key, value in [('uid', 0), ('apparmor', 'unconfined'), ('seccomp', 0),
                           ('no_new_privileges', 1), ('read_only_root', False), ('capabilities', 'SYS_ADMIN')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                enrollment.verify_agent_probe({**observation, key: value})
