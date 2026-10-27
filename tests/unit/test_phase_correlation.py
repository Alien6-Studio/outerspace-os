# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid


def load(relative):
    path = Path(__file__).resolve().parents[1] / relative
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


correlation = load('harness/phase-correlation.py')
probe = load('integration/phase-probe.py')


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.session = correlation.Session(b'k' * 32, str(uuid.uuid4()), str(uuid.uuid4()), 'a' * 64)
        self.agent, self.tool = str(uuid.uuid4()), str(uuid.uuid4())
        self.identity = {'pod_uid': str(uuid.uuid4()), 'node_uid': str(uuid.uuid4()),
                         'container_id': 'b' * 64, 'image_id': 'c' * 64,
                         'boot_id': str(uuid.uuid4()), 'restart_count': 0}
        self.scope = self.session.register(self.identity)

    def begin(self, scope=None):
        return self.session.boundary('start', agent_id=self.agent, tool_id=self.tool, scope_id=scope)

    def observe(self, tick, cpu, **overrides):
        data = {'pod_uid': self.identity['pod_uid'], 'container_id': self.identity['container_id'],
                'boot_id': self.identity['boot_id'], 'scope_instance': 'd' * 64, 'status': 'observed',
                'started_monotonic_ns': tick * 1000000000, 'finished_monotonic_ns': tick * 1000000000 + 50,
                'cpu_usec': {'usage_usec': cpu}, 'io': {'8:0': {'rbytes': cpu, 'wbytes': 0, 'rios': 1, 'wios': 0}},
                'memory_current_bytes': 10, 'memory_lifetime_peak_bytes': 40,
                'detached_processes': [], 'gaps': [], **overrides}
        self.session.sample(self.scope, data, tick * 1000000000, tick * 1000000000 + 100)

    def test_forgery_replay_and_cross_run_are_refused(self):
        self.begin(self.scope)
        original = self.session.events[0]
        for field, value in [('operation_id', str(uuid.uuid4())), ('scope_id', str(uuid.uuid4())),
                             ('agent_id', str(uuid.uuid4())), ('policy_sha256', 'e' * 64)]:
            forged = copy.deepcopy(original)
            forged['event'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'Unauthenticated'):
                self.session.accept(forged)
        with self.assertRaisesRegex(ValueError, 'replayed'):
            self.session.accept(original)
        another = correlation.Session(b'k' * 32, str(uuid.uuid4()), self.session.issuer_id, 'a' * 64)
        with self.assertRaisesRegex(ValueError, 'cross-run'):
            another.accept(original)

    def test_even_authenticated_prompt_or_path_fields_are_forbidden(self):
        self.begin(self.scope)
        payload = copy.deepcopy(self.session.events[0]['event'])
        payload.update(sequence=2, prompt='/tenant/private/secret')
        with self.assertRaises(ValueError):
            self.session.accept(self.session.sign(payload))

    def test_overlapping_tools_never_duplicate_scope_cpu_or_peak(self):
        self.observe(1, 10)
        first, second = self.begin(self.scope), self.begin(self.scope)
        self.observe(2, 1000010)
        self.session.boundary('end', first)
        self.observe(3, 2000010)
        self.session.boundary('end', second)
        report = self.session.report()
        self.assertEqual(sum(i['cpu_seconds'] for i in report['scopes'][self.scope]['intervals']), 2)
        self.assertEqual(len(report['scopes']), 1)
        self.assertTrue(all(span['tool_metrics'] is None for span in report['spans']))
        self.assertEqual(report['scopes'][self.scope]['attribution'], 'scope-only')
        with self.assertRaisesRegex(ValueError, 'already registered'):
            self.session.register(self.identity)

    def test_reused_worker_does_not_attribute_lifetime_peak_to_next_tool(self):
        self.observe(1, 0)
        first = self.begin(self.scope)
        self.observe(2, 20, memory_current_bytes=40)
        self.session.boundary('end', first)
        second = self.begin(self.scope)
        self.observe(3, 30, memory_current_bytes=2)
        self.session.boundary('end', second)
        self.assertIsNone(self.session.report()['spans'][1]['tool_metrics'])
        self.assertEqual(self.session.report()['scopes'][self.scope]['samples'][-1]
                         ['observation']['memory_lifetime_peak_bytes'], 40)

    def test_restarts_missing_scopes_and_detached_descendants_are_partial(self):
        self.observe(1, 100)
        self.observe(2, 1, scope_instance='e' * 64)
        self.observe(3, 2, status='missing', gaps=['cgroup-disappeared'])
        self.observe(4, 3, detached_processes=[{'pid': 10, 'start_ticks': 20}])
        item = self.session.report()['scopes'][self.scope]
        self.assertEqual(item['status'], 'partial')
        self.assertEqual(item['intervals'], [])
        self.assertIn('scope-restart-or-node-reboot', item['reasons'])
        self.assertIn('observed-detached-process', item['reasons'])

    def test_external_provider_and_unfinished_cancellation_have_no_invented_counters(self):
        external = self.begin()
        self.session.boundary('end', external, outcome='cancelled')
        self.begin(self.scope)
        report = self.session.report()
        self.assertEqual(report['spans'][0]['attribution'], 'external-provider-unknown')
        self.assertIn('unfinished-operation', report['scopes'][self.scope]['reasons'])

    def test_counter_regression_is_not_negative_work(self):
        self.observe(1, 100)
        self.observe(2, 10)
        item = self.session.report()['scopes'][self.scope]
        self.assertEqual(item['intervals'], [])
        self.assertIn('counter-regression-or-clock-gap', item['reasons'])

    def test_exhaustion_stops_accepting_measurements(self):
        with patch.object(correlation, 'MAX_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'buffer budget'):
                self.begin(self.scope)
        self.assertTrue(self.session.failed)
        with self.assertRaisesRegex(ValueError, 'failed closed'):
            self.begin(self.scope)

    def test_scope_exhaustion_retains_evidence_and_closes_existing_scopes(self):
        self.begin(self.scope)
        self.observe(1, 100)
        next_identity = {**self.identity, 'pod_uid': str(uuid.uuid4()), 'container_id': 'e' * 64}
        with patch.object(correlation, 'MAX_SCOPES', 1):
            with self.assertRaisesRegex(ValueError, 'scope buffer budget'):
                self.session.register(next_identity)
        report = self.session.report()
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(len(report['scopes']), 1)
        self.assertEqual(len(report['scopes'][self.scope]['samples']), 1)
        self.assertIn('unfinished-operation', report['scopes'][self.scope]['reasons'])
        with self.assertRaisesRegex(ValueError, 'failed closed'):
            self.begin(self.scope)
        with self.assertRaisesRegex(ValueError, 'failed closed'):
            self.observe(2, 200)

    def test_probe_rejects_path_injection_and_unbounded_process_lists(self):
        for request in [dict(pod_uid='../../secret', container_id='b' * 64, known_processes=[]),
                        dict(pod_uid=self.identity['pod_uid'], container_id='b' * 64,
                             known_processes=[{'pid': 2, 'start_ticks': 3}] * 129)]:
            with self.assertRaises(ValueError):
                probe.snapshot(Path('/does-not-exist'), request)

    def test_pressure_retains_totals_and_averages(self):
        self.assertEqual(probe.pressure('some avg10=0.00 avg60=1.20 avg300=2.30 total=45\n'),
                         {'some': {'avg10': 0., 'avg60': 1.2, 'avg300': 2.3, 'total': 45}})

    def test_probe_keeps_descendants_but_excludes_paths_and_process_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cgroups = root / 'sys/fs/cgroup'
            parent = cgroups / 'kubepods.slice' / ('kubepods-pod' + self.identity['pod_uid'].replace('-', '_') + '.slice')
            group = parent / ('cri-containerd-' + self.identity['container_id'] + '.scope')
            group.mkdir(parents=True)
            (root / 'proc/sys/kernel/random').mkdir(parents=True)
            (root / 'proc/sys/kernel/random/boot_id').write_text(self.identity['boot_id'])
            for name, text in {'cpu.stat': 'usage_usec 123\nuser_usec 100\nsystem_usec 23\n',
                'memory.current': '42', 'memory.peak': '100', 'memory.events': 'oom 1\noom_kill 1\n',
                'memory.stat': 'anon 10\nfile 20\nshmem 5\nkernel 7\n',
                'io.stat': '8:0 rbytes=10 wbytes=20 rios=1 wios=2\n', 'cgroup.procs': '0\n'}.items():
                (group / name).write_text(text)
            for kind in ['cpu', 'memory', 'io']:
                (group / (kind + '.pressure')).write_text('some avg10=0.10 avg60=0.00 avg300=0.00 total=20\n')
            child = group / 'child'
            child.mkdir()
            (child / 'cgroup.procs').write_text('0\n')
            for pid, path in [(21, group), (22, child), (23, cgroups / 'unrelated-private-tenant')]:
                proc = root / 'proc' / str(pid)
                proc.mkdir()
                (proc / 'stat').write_text(str(pid) + ' (private ) prompt name) S ' + '0 ' * 18 + '99 0\n')
                (proc / 'cgroup').write_text('0::/../../' + str(path.relative_to(cgroups)) + '\n')
            request = {'pod_uid': self.identity['pod_uid'], 'container_id': self.identity['container_id'],
                       'known_processes': [{'pid': 23, 'start_ticks': 99}]}
            result = probe.snapshot(root, request)
            self.assertEqual(result['status'], 'observed')
            self.assertEqual([p['pid'] for p in result['processes']], [21, 22])
            self.assertEqual(result['detached_processes'], [{'pid': 23, 'start_ticks': 99}])
            self.assertEqual(result['memory_events']['oom_kill'], 1)
            for forbidden in ['private', str(root), 'kubepods', 'cri-containerd', 'prompt']:
                self.assertNotIn(forbidden, json.dumps(result))
