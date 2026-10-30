# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import base64
import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('enrollment', Path(__file__).resolve().parents[2] / 'tests/harness/enrollment.py')
enrollment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enrollment)


class EnrollmentEvidenceTests(unittest.TestCase):
    def io_pod(self):
        identifier = 'a' * 64
        return {'path': 'pod', 'container_id': 'containerd://' + identifier,
                'files': {'cpu.max': '50000 100000', 'memory.max': '134217728', 'pids.max': '256'},
                'io_policy': {'class': 'outerspace-agent-v1', 'device': '252:0',
                              'limits': {'rbps': 8388608, 'wbps': 4194304, 'riops': 256, 'wiops': 256}},
                'descendants': {'cri-containerd-' + identifier + '.scope': {
                    'io.max': '252:0 rbps=8388608 wbps=4194304 riops=256 wiops=256',
                    'io.stat': '252:0 rbytes=0 wbytes=0 rios=0 wios=0'}}}

    def test_io_requires_limits_on_the_actual_workload_and_backing_device(self):
        pod = self.io_pod()
        enrollment.verify_agent_io_limits(pod, pod['container_id'])
        scope = next(iter(pod['descendants']))
        for value in ['', '252:1 rbps=8388608 wbps=4194304 riops=256 wiops=256',
                      '252:0 rbps=max wbps=4194304 riops=256 wiops=256']:
            changed = copy.deepcopy(pod)
            changed['descendants'][scope]['io.max'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                enrollment.verify_agent_io_limits(changed, pod['container_id'])
        with self.assertRaises(ValueError):
            enrollment.verify_agent_io_limits(pod, 'containerd://' + 'b' * 64)

    def test_io_does_not_count_pause_or_stacked_device_bytes(self):
        before = self.io_pod()
        after = copy.deepcopy(before)
        scope = next(iter(after['descendants']))
        after['descendants']['pause.scope'] = {'io.stat': '252:0 rbytes=99999999 wbytes=0'}
        after['descendants'][scope]['io.stat'] = '253:0 rbytes=99999999 wbytes=0'
        self.assertFalse(enrollment.agent_pressure_observed('io', before, after))
        after['descendants'][scope]['io.stat'] += '\n252:0 rbytes=16777216 wbytes=0'
        self.assertTrue(enrollment.agent_pressure_observed('io', before, after))
        after['result'] = 'io-direct-failed'
        with self.assertRaises(ValueError):
            enrollment.agent_pressure_observed('io', before, after)

    def test_io_device_can_exist_before_any_counter_has_been_recorded(self):
        before = self.io_pod()
        scope = next(iter(before['descendants']))
        before['descendants'][scope]['io.stat'] = '252:0'
        self.assertEqual(enrollment.agent_io_bytes(before), 0)
        after = copy.deepcopy(before)
        after['descendants'][scope]['io.stat'] = '252:0 rbytes=48758784 wbytes=0 rios=372 wios=0'
        self.assertTrue(enrollment.agent_pressure_observed('io', before, after))

    def test_lab_renewal_cannot_roll_again_during_the_ci_job(self):
        timeouts = re.findall(r'^\s+timeout-minutes:\s*(\d+)\s*$',
            (enrollment.ROOT / '.github/workflows/ci.yml').read_text(), re.MULTILINE)
        self.assertTrue(timeouts, 'The native job must have an explicit time budget')
        config = enrollment.load_script('node-config', enrollment.BUILD_TOOLS)
        # Kubernetes may rotate with 30% of certificate lifetime remaining.
        earliest_renewal = config.duration_seconds(enrollment.LAB_RENEWAL_DURATION) * 0.7
        self.assertGreater(earliest_renewal, max(map(int, timeouts)) * 60)

    def test_observer_client_and_phase_worker_outlive_the_bounded_job(self):
        maximum_job = max(map(int, re.findall(r'^\s+timeout-minutes:\s*(\d+)\s*$',
            (enrollment.ROOT / '.github/workflows/ci.yml').read_text(), re.MULTILINE))) * 60
        lab = object.__new__(enrollment.Lab)
        lab.apply, lab.wait_workloads = Mock(), Mock()
        lab.workloads('test-worker')
        pods = {obj['metadata']['name']: obj for call in lab.apply.call_args_list
                for obj in call.args if obj['kind'] == 'Pod'}
        phases = enrollment.load_script('agent-phase-benchmark')
        phase_lab = object.__new__(phases.PhaseLab)
        phase_lab.apply, phase_lab.kube, phase_lab.register = Mock(), Mock(), Mock()
        phase_lab.create('phase-worker')
        pods['phase-worker'] = phase_lab.apply.call_args.args[0]
        for name in ['probe', 'client', 'phase-worker']:
            command = pods[name]['spec']['containers'][0]['command']
            with self.subTest(pod=name):
                self.assertEqual(command[0], 'sleep')
                self.assertGreater(int(command[1]), maximum_job)
                self.assertLessEqual(int(command[1]), 24 * 60 * 60)

    def test_pressure_events_can_be_recorded_on_the_container_below_the_pod_limit(self):
        before = {'path': 'pod', 'files': {'cpu.max': '50000 100000', 'memory.max': '134217728',
                  'pids.max': '256', 'pids.current': '2', 'pids.events': 'max 0',
                  'cpu.stat': 'usage_usec 0\nnr_throttled 0'},
                  'descendants': {'container': {'cpu.stat': 'nr_throttled 0', 'pids.events': 'max 0'}}}
        after = copy.deepcopy(before)
        after['files']['pids.current'] = '255'
        after['files']['cpu.stat'] = 'usage_usec 500000\nnr_throttled 0'
        self.assertFalse(enrollment.agent_pressure_observed('fork', before, after))
        self.assertFalse(enrollment.agent_pressure_observed('cpu', before, after))
        after['descendants']['container'] = {'cpu.stat': 'nr_throttled 3', 'pids.events': 'max 1'}
        self.assertTrue(enrollment.agent_pressure_observed('fork', before, after))
        self.assertTrue(enrollment.agent_pressure_observed('cpu', before, after))
        after['files']['pids.current'] = '257'
        self.assertFalse(enrollment.agent_pressure_observed('fork', before, after))

    def test_resource_pressure_requires_actual_limits_and_kernel_events(self):
        pod = {'path': 'kubepods.slice/test', 'files': {
            'cpu.max': '50000 100000', 'memory.max': '134217728', 'pids.max': '256',
            'cpu.stat': 'usage_usec 0\nnr_throttled 0', 'pids.events': 'max 0',
            'pids.current': '1', 'memory.events': 'oom_kill 0'},
            'result': None, 'log_files': {}}
        for mode in ['cpu', 'fork', 'oom', 'scratch', 'logs']:
            with self.subTest(mode=mode):
                self.assertFalse(enrollment.agent_pressure_observed(mode, pod, pod))
        observed = copy.deepcopy(pod)
        observed['files']['cpu.stat'] = 'usage_usec 500000\nnr_throttled 5'
        self.assertTrue(enrollment.agent_pressure_observed('cpu', pod, observed))
        observed['files']['pids.events'] = 'max 1'
        observed['files']['pids.current'] = '256'
        self.assertTrue(enrollment.agent_pressure_observed('fork', pod, observed))
        observed['files']['memory.events'] = 'oom_kill 1'
        self.assertFalse(enrollment.agent_pressure_observed('oom', pod, observed))
        observed['result'] = 'oom-container-restarted'
        self.assertTrue(enrollment.agent_pressure_observed('oom', pod, observed))
        observed['scratch'] = {'capacity_bytes': 16 * 1024**2, 'used_bytes': 16 * 1024**2}
        observed['result'] = 'scratch-full'
        self.assertTrue(enrollment.agent_pressure_observed('scratch', pod, observed))
        observed['result'] = 'logs-written'
        observed['log_files'] = {'0.log': 20 * 1024**2}
        self.assertFalse(enrollment.agent_pressure_observed('logs', pod, observed))
        observed['log_files'] = {'0.log': 0, '0.log.rotated': 20 * 1024**2}
        self.assertTrue(enrollment.agent_pressure_observed('logs', pod, observed))
        observed['log_files']['0.log.rotated'] = 25 * 1024**2
        self.assertFalse(enrollment.agent_pressure_observed('logs', pod, observed))
        for file in ['cpu.max', 'memory.max', 'pids.max']:
            changed = copy.deepcopy(observed)
            changed['files'][file] = 'max'
            with self.subTest(file=file), self.assertRaises(ValueError):
                enrollment.agent_pressure_observed('cpu', pod, changed)

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
            'mounts': 'denied', 'device_creation': 'denied',
            'policy_change': 'denied', 'termination_log_write': 'denied', 'child_confinement': 'passed'}
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
