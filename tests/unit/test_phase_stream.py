# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('phase_stream', ROOT / 'tests/harness/phase-stream.py')
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
READY = json.dumps({'schema': transport.SCHEMA, 'status': 'ready'})


class PhaseStreamTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        boot = self.root / 'proc/sys/kernel/random/boot_id'
        boot.parent.mkdir(parents=True)
        boot.write_text(str(uuid.uuid4()))
        self.request = {'pod_uid': str(uuid.uuid4()), 'container_id': 'a' * 64, 'known_processes': []}

    def server(self, source=None, **kwargs):
        if source is None:
            source = ('import runpy,sys\nfrom pathlib import Path\n'
                      'probe=runpy.run_path(sys.argv[1])\n'
                      'probe["stream"](Path(sys.argv[2]),sys.stdin.buffer,sys.stdout)\n')
        client = transport.ProbeStream([sys.executable, '-u', '-c', source,
            str(ROOT / 'tests/integration/phase-probe.py'), str(self.root)], **kwargs)
        self.addCleanup(client.close)
        return client

    def test_real_collector_reuses_process_and_preserves_each_scope_identity(self):
        client = self.server()
        pid = client.process.pid
        first = client.request(self.request)
        second_request = {**self.request, 'pod_uid': str(uuid.uuid4())}
        second = client.request(second_request)
        self.assertEqual(first['pod_uid'], self.request['pod_uid'])
        self.assertEqual(second['pod_uid'], second_request['pod_uid'])
        self.assertEqual(client.process.pid, pid)
        self.assertIsNone(client.process.poll())
        self.assertEqual(client.sequence, 2)
        self.assertEqual(second['status'], 'missing')
        self.assertGreaterEqual(second['collector']['process_cpu_seconds'], first['collector']['process_cpu_seconds'])
        self.assertLessEqual(second['collector']['cpu_seconds'], second['collector']['process_cpu_seconds'])
        client.close()
        self.assertIsNotNone(client.process.poll())

    def test_cold_start_has_separate_deadline_from_each_sampling_request(self):
        source = ('import json,sys,time\ntime.sleep(.15)\n'
                  f'print({READY!r},flush=True)\n'
                  'for line in sys.stdin:\n'
                  ' r=json.loads(line); print(json.dumps({"sequence":r["sequence"],"observation":{}}),flush=True)\n')
        client = self.server(source, startup_timeout=2, request_timeout=.1)
        self.assertGreater(client.startup_wall_seconds, .1)
        self.assertEqual(client.request(self.request), {})

    def test_timeout_lost_collector_and_replayed_response_stop_without_reconnect(self):
        for behavior, error in [('time.sleep(.3)', TimeoutError),
                                ('sys.exit(0)', RuntimeError),
                                ('print(json.dumps({"sequence":0,"observation":{}}),flush=True)', ValueError)]:
            source = ('import json,sys,time\n' + f'print({READY!r},flush=True)\n'
                      'sys.stdin.readline()\n' + behavior + '\n')
            client = self.server(source, request_timeout=.05)
            with self.subTest(behavior=behavior), self.assertRaises(error):
                client.request(self.request)
            self.assertTrue(client.closed)
            self.assertEqual(client.sequence, 0)
            with self.assertRaisesRegex(RuntimeError, 'refusing reconnect'):
                client.request(self.request)

    def test_request_and_response_buffers_are_bounded(self):
        client = self.server()
        with self.assertRaisesRegex(ValueError, 'request budget'):
            client.request({'value': 'x' * transport.MAX_REQUEST_BYTES})
        source = ('import sys\n' + f'print({READY!r},flush=True)\n'
                  'sys.stdin.readline()\n' + f'print("x"*{transport.MAX_RESPONSE_BYTES + 1},flush=True)\n')
        client = self.server(source)
        with self.assertRaisesRegex(ValueError, 'response budget'):
            client.request(self.request)

    def test_probe_rejects_replayed_or_truncated_requests(self):
        source = ('import runpy,sys\nfrom pathlib import Path\n'
                  'probe=runpy.run_path(sys.argv[1])\n'
                  'probe["stream"](Path(sys.argv[2]),sys.stdin.buffer,sys.stdout)\n')
        for payload in [json.dumps({'sequence': 2, 'request': self.request}) + '\n', '{"sequence":']:
            result = subprocess.run([sys.executable, '-u', '-c', source,
                str(ROOT / 'tests/integration/phase-probe.py'), str(self.root)],
                input=payload, text=True, capture_output=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout), json.loads(READY))
