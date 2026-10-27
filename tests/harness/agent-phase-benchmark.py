#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Compare trusted phase collection with the same unprofiled Agent OCI workload."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
from pathlib import Path
import secrets
import shutil
import tempfile
import time
import uuid
import enrollment as native

correlation = native.load_script('phase-correlation')
comparison = native.load_script('worker-comparison')
ROOT, run, digest, wait_for = native.ROOT, native.run, native.digest, native.wait_for
NS = native.AGENT_NAMESPACE
PHASES = ['cpu-burst', 'memory-spike', 'io', 'remote-llm-wait']
INPUTS = comparison.INPUTS + ['tests/harness/agent-phase-benchmark.py',
    'tests/harness/phase-correlation.py', 'tests/integration/phase-probe.py',
    'tests/integration/agent-phases.sh']


class PhaseLab(comparison.ComparisonLab):
    def initialize(self, enabled):
        self.enabled = enabled
        self.agent_id = str(uuid.uuid4())
        self.tools = {name: str(uuid.uuid4()) for name in PHASES +
                      ['cached-read', 'shared-memory', 'reuse-shared-memory', 'background', 'oom-restart', 'cancellation']}
        self.session = correlation.Session(secrets.token_bytes(32), str(uuid.uuid4()), str(uuid.uuid4()),
                                            digest(ROOT / 'src/cluster/agent/profile-v1.json'))
        self.scope_by_name, self.known = {}, {}
        node = wait_for('Waiting for the real Agent phase worker', self.worker, timeout=1200)
        self.node = node['metadata']['name']
        self.node_uid = node['metadata']['uid']
        self.extend_renewal_lifetime()
        self.kube('wait', '--for=condition=Ready', 'node/' + self.node, '--timeout=1200s', timeout=1230)
        wait_for('Approving Agent phase serving CSR', lambda: self.approve_serving(node))
        wait_for('Waiting for phase worker networking', lambda: self.cilium_ready(self.node), timeout=1200)
        self.workloads(self.node)
        self.agent_node, self.agent_checks = self.node, {'profile': 'outerspace-agent-v1', 'phases': {}}
        self.agent_install()
        self.kube('label', 'node', self.node, native.AGENT_NODE_LABEL + '=v1')
        self.agent_admission()
        self.identity = self.snapshot([], identity=True)['worker']
        expected = json.loads((self.output / 'build-identity.json').read_text())
        if self.identity['outerspace_identity'] != native.load_script('profiles', native.BUILD_TOOLS).image_identity(
                'agent', 'cpu', expected['architecture'], expected['commit']):
            raise ValueError('Phase worker is not the packaged Agent image')
        self.provider()

    def provider(self):
        # Known, synthetic remote wait; no claim about provider-executed model work.
        code = ('import time\nfrom http.server import BaseHTTPRequestHandler,ThreadingHTTPServer\n'
                'class Handler(BaseHTTPRequestHandler):\n'
                ' def do_GET(self):\n'
                '  time.sleep(2); self.send_response(200); self.end_headers(); '
                'self.wfile.write(b"synthetic-provider-response")\n'
                ' def log_message(self,*args): pass\n'
                'ThreadingHTTPServer(("0.0.0.0",8092),Handler).serve_forever()\n')
        self.apply({'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'phase-provider',
            'namespace': native.LAB, 'labels': {'app': 'phase-provider'}}, 'spec': {
            'nodeName': native.LAB + '-worker', 'automountServiceAccountToken': False,
            'securityContext': {'runAsUser': 65534, 'runAsNonRoot': True, 'seccompProfile': {'type': 'RuntimeDefault'}},
            'containers': [{'name': 'provider', 'image': native.PYTHON_IMAGE, 'command': ['python3', '-c', code],
                'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                    'capabilities': {'drop': ['ALL']}},
                'resources': {'limits': {'cpu': '500m', 'memory': '64Mi'}}}]}},
            {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'phase-provider', 'namespace': native.LAB},
             'spec': {'selector': {'app': 'phase-provider'}, 'ports': [{'port': 8092}]}},
            {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'phase-exporter', 'namespace': native.LAB},
             'data': {'contract': correlation.SCHEMA, 'failure': 'stop-and-retain-partial', 'buffer_bytes': str(correlation.MAX_BYTES)}},
            {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
             'metadata': {'name': 'phase-provider', 'namespace': NS}, 'spec': {'podSelector': {},
                'policyTypes': ['Egress'], 'egress': [{'to': [{'namespaceSelector': {'matchLabels':
                    {'kubernetes.io/metadata.name': native.LAB}}, 'podSelector': {'matchLabels': {'app': 'phase-provider'}}}],
                    'ports': [{'protocol': 'TCP', 'port': 8092}]}]}})
        self.kube('-n', native.LAB, 'wait', '--for=condition=Ready', 'pod/phase-provider', '--timeout=300s')
        self.provider_url = 'http://' + self.api('-n', native.LAB, 'service', 'phase-provider')['spec']['clusterIP'] + ':8092/'

    def create(self, name):
        pod = json.loads((ROOT / 'src/cluster/agent/workload-v1.json').read_text())
        pod['metadata']['name'] = name
        pod['spec']['containers'][0]['command'] = ['/bin/sh', '-ec', 'exec sleep 3600']
        started = time.monotonic()
        self.apply(pod)
        self.kube('-n', NS, 'wait', '--for=condition=Ready', 'pod/' + name, '--timeout=900s', timeout=930)
        elapsed = time.monotonic() - started
        self.register(name)
        return elapsed

    def register(self, name, expected_restart=0):
        pod = self.api('-n', NS, 'pod', name)
        state = pod['status']['containerStatuses'][0]
        expected_image = json.loads((ROOT / 'src/cluster/agent/workload-v1.json').read_text())['spec']['containers'][0]['image']
        if (pod['spec']['nodeName'] != self.node or pod['status'].get('qosClass') != 'Guaranteed'
                or pod['status'].get('phase') != 'Running' or not state.get('ready')
                or not state.get('state', {}).get('running') or state['restartCount'] != expected_restart
                or pod['spec']['containers'][0]['image'] != expected_image):
            raise ValueError('Unexpected Agent execution identity or restart')
        metadata = {'pod_uid': pod['metadata']['uid'], 'node_uid': self.node_uid,
                    'boot_id': self.identity['boot_id'], 'container_id': state['containerID'].removeprefix('containerd://'),
                    'image_id': state['imageID'].split('sha256:')[-1], 'restart_count': state['restartCount']}
        self.scope_by_name[name] = self.session.register(metadata)
        self.known[self.scope_by_name[name]] = []
        return self.scope_by_name[name]

    def observe(self, scope, missing=False):
        identity = self.session.scopes[scope]
        request = {'pod_uid': identity['pod_uid'], 'container_id': identity['container_id'],
                   'known_processes': self.known[scope]}
        before = time.monotonic_ns()
        try:
            result = self.kube('-n', native.LAB, 'exec', 'probe', '--', 'python3', '-c',
                (ROOT / 'tests/integration/phase-probe.py').read_text(), json.dumps(request), timeout=60)
            observation = json.loads(result.stdout)
            self.session.sample(scope, observation, before, time.monotonic_ns())
            self.known[scope] = observation['processes']
            if observation['status'] != 'observed' and not missing:
                raise ValueError('Required execution scope disappeared; cancel benchmark work')
            return observation
        except Exception:
            self.session.failed = True
            raise

    def common(self, name):
        # Endpoint observer common to both arms; strip host/tenant paths and logs.
        identity = self.session.scopes[self.scope_by_name[name]]
        current = self.api('-n', NS, 'pod', name)
        status = current['status']['containerStatuses'][0]
        if (current['metadata']['uid'] != identity['pod_uid'] or current['spec']['nodeName'] != self.node
                or status.get('containerID') != 'containerd://' + identity['container_id']
                or status.get('restartCount') != identity['restart_count'] or not status.get('ready')):
            raise ValueError('Workload changed execution scope during the benchmark')
        uid = identity['pod_uid']
        raw = self.agent_resource_snapshot([uid])
        pod = raw['pods'][uid]
        native.verify_agent_resource_limits(pod)
        native.verify_agent_io_limits(pod, 'containerd://' + self.session.scopes[self.scope_by_name[name]]['container_id'])
        return {'uptime_seconds': raw['uptime_seconds'], 'cpu_ticks': raw['cpu_ticks'],
                'host_memory_bytes': raw['memory_bytes'], 'pod_counters': {k: v for k, v in pod['files'].items()
                    if k in ['cpu.stat', 'memory.current', 'memory.peak', 'memory.events', 'io.stat', 'io.pressure']}}

    def execute(self, name, phase, check=True):
        return self.kube('-n', NS, 'exec', name, '--', '/bin/sh', '-euc',
            (ROOT / 'tests/integration/agent-phases.sh').read_text(), 'agent-phases', phase,
            self.provider_url, check=check, timeout=120)

    def operation(self, name, phase):
        scope = self.scope_by_name[name]
        before = self.common(name)
        started = time.monotonic()
        operation = None
        if self.enabled:
            operation = self.session.boundary('start', agent_id=self.agent_id, tool_id=self.tools[phase], scope_id=scope)
            self.observe(scope)
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self.execute, name, phase)
                try:
                    while not future.done():
                        time.sleep(.5)
                        self.observe(scope)
                    future.result()
                except Exception:
                    self.kube('-n', NS, 'delete', 'pod', name, '--wait=false', check=False)
                    raise
            self.observe(scope)
            self.session.boundary('end', operation)
        else:
            self.execute(name, phase)
        elapsed = time.monotonic() - started
        after = self.common(name)
        before_cpu = int(dict(line.split() for line in before['pod_counters']['cpu.stat'].splitlines())['usage_usec'])
        after_cpu = int(dict(line.split() for line in after['pod_counters']['cpu.stat'].splitlines())['usage_usec'])
        if after_cpu <= before_cpu:
            raise ValueError('Tool execution did not produce measurable scope CPU work')
        if phase == 'memory-spike' and int(after['pod_counters']['memory.peak']) < int(before['pod_counters']['memory.current']) + 8 * 1024**2:
            raise ValueError('Memory spike was not observed in the actual cgroup')
        return {'phase': phase, 'operation_id': operation, 'scope_id': scope, 'gateway_wall_seconds': elapsed,
                'before': before, 'after': after}

    def refusals(self, name):
        account = 'system:serviceaccount:' + NS + ':outerspace-agent-v1'
        cases = {
            'exporter-configuration': ['patch', 'configmap', 'phase-exporter', '-n', native.LAB,
                '--type=merge', '-p', '{"data":{"failure":"ignore"}}'],
            'other-tenant-pods': ['get', 'pods', '-n', native.LAB],
            'trusted-observer-exec': ['-n', native.LAB, 'exec', 'probe', '--', 'true'],
        }
        for case, args in cases.items():
            result = self.kube('--as=' + account, '--as-group=system:serviceaccounts',
                '--as-group=system:serviceaccounts:' + NS, '--as-group=system:authenticated', *args, check=False)
            if result.returncode == 0 or 'Forbidden' not in result.stderr:
                raise ValueError('Agent authority refusal was not proven: ' + case)
        self.kube('-n', NS, 'exec', name, '--', '/bin/sh', '-euc',
            'test ! -e /host; test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token; '
            'if (echo 0 > /sys/fs/cgroup/memory.peak) 2>/dev/null; then exit 91; fi; '
            'if (echo 1 > /sys/fs/cgroup/cgroup.procs) 2>/dev/null; then exit 92; fi')
        operation = self.session.boundary('start', agent_id=self.agent_id, tool_id=self.tools['cpu-burst'],
                                           scope_id=self.scope_by_name[name])
        forged = copy.deepcopy(self.session.events[-1])
        forged['event']['sequence'] += 1
        forged['mac'] = '0' * 64
        emitted = self.kube('-n', NS, 'exec', name, '--', 'printf', '%s', json.dumps(forged)).stdout
        try:
            self.session.accept(json.loads(emitted))
        except ValueError:
            pass
        else:
            raise ValueError('Agent forged a trusted phase boundary')
        self.session.boundary('end', operation)
        return {**{k: 'refused' for k in cases}, 'counter-reset-and-cgroup-escape': 'refused',
                'agent-emitted-forged-boundary': 'refused'}

    def edge_cases(self):
        name = 'phase-edge'
        self.create(name)
        scope = self.scope_by_name[name]
        refusals = self.refusals(name)
        initial = self.observe(scope)
        for phase in ['shared-memory', 'reuse-shared-memory', 'cached-read', 'background']:
            self.operation(name, phase)
        background = self.observe(scope)
        original = {(p['pid'], p['start_ticks']) for p in initial['processes']}
        retained = [p for p in background['processes'] if (p['pid'], p['start_ticks']) not in original]
        if not retained:
            raise ValueError('Background descendant did not cross its operation boundary')
        operations = [self.session.boundary('start', agent_id=self.agent_id, tool_id=self.tools[phase], scope_id=scope)
                      for phase in ['cpu-burst', 'remote-llm-wait']]
        with ThreadPoolExecutor(max_workers=2) as executor:
            pending = {executor.submit(self.execute, name, phase): op for phase, op in
                       zip(['cpu-burst', 'remote-llm-wait'], operations)}
            while pending:
                self.observe(scope)
                for future in list(pending):
                    if future.done():
                        future.result()
                        self.session.boundary('end', pending.pop(future))
                time.sleep(.5)
        external = self.session.boundary('start', agent_id=str(uuid.uuid4()), parent_agent_id=self.agent_id,
                                          tool_id=self.tools['remote-llm-wait'], scope_id=None)
        self.session.boundary('end', external)
        # A second agent reads the same immutable image: cache charging remains
        # shared/unknown, even though these OCI cgroups are distinct.
        self.create('phase-neighbor')
        self.operation('phase-neighbor', 'cached-read')
        self.operation(name, 'cached-read')
        self.kube('-n', NS, 'delete', 'pod', 'phase-neighbor', '--wait=true', '--timeout=90s')
        before = self.api('-n', NS, 'pod', name)['status']['containerStatuses'][0]
        oom_operation = self.session.boundary('start', agent_id=self.agent_id,
            tool_id=self.tools['oom-restart'], scope_id=scope)
        self.execute(name, 'oom-restart', check=False)
        def restarted():
            status = self.api('-n', NS, 'pod', name)['status']['containerStatuses'][0]
            return status if status.get('ready') and status['restartCount'] == before['restartCount'] + 1 else None
        after = wait_for('Waiting for an observed whole-container OOM restart', restarted, timeout=180)
        if after.get('lastState', {}).get('terminated', {}).get('reason') != 'OOMKilled':
            raise ValueError('Expected a native OOMKilled restart')
        lost = self.observe(scope, missing=True)
        self.session.boundary('end', oom_operation, outcome='error')
        if lost['status'] == 'observed':
            raise ValueError('Retired container unexpectedly retained its original scope')
        self.register(name, expected_restart=after['restartCount'])
        self.operation(name, 'cpu-burst')
        new_scope = self.scope_by_name[name]
        prior_processes = {(p['pid'], p['start_ticks']) for p in self.observe(new_scope)['processes']}
        cancellation = self.session.boundary('start', agent_id=self.agent_id,
            tool_id=self.tools['cancellation'], scope_id=new_scope)
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self.execute, name, 'cancellation', False)
            def cancellation_started():
                observed = self.observe(new_scope)
                return [p for p in observed['processes'] if (p['pid'], p['start_ticks']) not in prior_processes]
            running_cancelled = wait_for('Observing the running tool before cancellation', cancellation_started, timeout=60)
            self.kube('-n', NS, 'delete', 'pod', name, '--wait=true', '--timeout=90s')
            if future.result().returncode == 0:
                raise ValueError('Cancelled workload unexpectedly completed successfully')
        cancelled = self.observe(new_scope, missing=True)
        self.session.boundary('end', cancellation, outcome='cancelled')
        if cancelled['status'] == 'observed':
            raise ValueError('Cancelled execution retained a live measurement scope')
        # A real missing collector must stop subsequent work, retain partial
        # evidence and remove the disposable execution scope.
        self.create('phase-collector-loss')
        scope = self.scope_by_name['phase-collector-loss']
        self.observe(scope)
        self.kube('-n', native.LAB, 'delete', 'pod', 'probe', '--wait=true', '--timeout=90s')
        try:
            self.observe(scope)
        except RuntimeError as error:
            if not self.session.failed or 'NotFound' not in str(error) or '"probe"' not in str(error):
                raise
        else:
            raise ValueError('Missing collector was silently accepted')
        self.kube('-n', NS, 'delete', 'pod', 'phase-collector-loss', '--wait=true', '--timeout=90s')
        return {'refusals': refusals, 'background_descendants_after_boundary': retained,
                'overlapping_operations': operations, 'external_provider_operation': external,
                'oom_restart': {'before': before['containerID'], 'after': after['containerID'],
                                'reason': after['lastState']['terminated']['reason']},
                'cancellation': {'operation_id': cancellation, 'running_processes': running_cancelled},
                'collector_loss': 'stopped-and-retained-partial-trace'}

    def measure(self, enabled, repetitions):
        self.initialize(enabled)
        samples = []
        for index in range(repetitions):
            print('Measuring Agent phases: ' + ('profiled' if enabled else 'baseline') + ' ' + str(index + 1), flush=True)
            name = 'phase-worker'
            start = self.create(name)
            try:
                samples.append({'iteration': index, 'sandbox_create_to_ready_seconds': start,
                                'image_cache': 'first-pull' if index == 0 else 'already-pulled',
                                'phases': [self.operation(name, phase) for phase in PHASES]})
            finally:
                self.kube('-n', NS, 'delete', 'pod', name, '--wait=true', '--timeout=90s')
        edges = self.edge_cases() if enabled else None
        return {'worker': self.identity, 'profiled': enabled, 'samples': samples, 'edge_cases': edges,
                'execution_scopes': self.session.scopes,
                'trace': self.session.report() if enabled else None}


def summarize(observations):
    first, second = observations['baseline'], observations['profiled']
    for key in ['kernel_version', 'kernel_notes_sha256', 'runtime_sha256', 'config_sha256', 'vcpus']:
        if first['worker'][key] != second['worker'][key]:
            raise ValueError('Profiler control workers differ: ' + key)
    if len({scope['image_id'] for observed in observations.values() for scope in observed['execution_scopes'].values()}) != 1:
        raise ValueError('Benchmark arms ran different OCI bytes')
    result = {}
    for mode, observed in observations.items():
        if len(observed['samples']) < 10:
            raise ValueError('At least ten repeats per arm are required')
        if (observed['profiled'] != (mode == 'profiled') or
                [s['iteration'] for s in observed['samples']] != list(range(len(observed['samples']))) or
                any([s['phase'] for s in item['phases']] != PHASES for item in observed['samples'])):
            raise ValueError('Incomplete or unmatched repeated tool workload')
        result[mode] = {'first_image_pull_create_to_ready_seconds': observed['samples'][0]['sandbox_create_to_ready_seconds'],
            'cached_image_fresh_sandbox_seconds': correlation.quantiles([
                item['sandbox_create_to_ready_seconds'] for item in observed['samples'][1:]]),
            'phases': {phase: correlation.quantiles([sample['gateway_wall_seconds'] for item in observed['samples']
                        for sample in item['phases'] if sample['phase'] == phase]) for phase in PHASES}}
        resource_samples = [sample for item in observed['samples'] for sample in item['phases']]
        def cpu(value):
            return int(dict(line.split() for line in value.splitlines())['usage_usec']) / 1e6
        result[mode]['endpoint_resource_observer'] = {
            'pod_cpu_seconds': correlation.quantiles([cpu(s['after']['pod_counters']['cpu.stat']) -
                cpu(s['before']['pod_counters']['cpu.stat']) for s in resource_samples]),
            'host_busy_cpu_seconds': correlation.quantiles([sum(s['after']['cpu_ticks'][i] - s['before']['cpu_ticks'][i]
                for i in [0, 1, 2, 5, 6]) / observed['worker']['clock_ticks_per_second'] for s in resource_samples]),
            'host_unavailable_memory_bytes': correlation.quantiles([s['after']['host_memory_bytes']['MemTotal'] -
                s['after']['host_memory_bytes']['MemAvailable'] for s in resource_samples]),
            'pod_current_memory_bytes': correlation.quantiles([int(s['after']['pod_counters']['memory.current']) for s in resource_samples]),
            'pod_lifetime_peak_bytes': correlation.quantiles([int(s['after']['pod_counters']['memory.peak']) for s in resource_samples])}
    collected = [sample['observation']['collector'] for scope in second['trace']['scopes'].values() for sample in scope['samples']]
    result['profiled']['collector'] = {
        'process_cpu_seconds_total': sum(c['cpu_seconds'] for c in collected),
        'peak_rss_bytes': correlation.quantiles([c['peak_rss_bytes'] for c in collected]),
        'read_wall_seconds': correlation.quantiles([c['wall_seconds'] for c in collected])}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repetitions', type=int, default=10, choices=range(10, 21))
    args = parser.parse_args()
    if run('git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=normal').stdout:
        raise ValueError('Commit the phase harness before native qualification')
    commit = run('git', '-C', ROOT, 'rev-parse', 'HEAD').stdout.strip()
    hashes = {name: digest(ROOT / name) for name in INPUTS}
    image_output, output = args.image_output.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = output / 'phase-benchmark.json'
    report.unlink(missing_ok=True)
    metadata = json.loads((image_output / 'build-identity.json').read_text())
    if (metadata['profile'] != 'agent' or metadata['hardware_profile'] != 'cpu'
            or metadata['architecture'] != native.load_script('profiles', native.BUILD_TOOLS).architecture()
            or metadata['components_lock_sha256'] != digest(ROOT / 'src/components.lock.json')):
        raise ValueError('A matched native Agent CPU candidate is required')
    bundle = image_output / f'outerspace-{metadata["version"]}-agent-cpu-{metadata["architecture"]}'
    native.load_script('prepare-release', native.BUILD_TOOLS).verify_bundle(bundle, metadata['version'], metadata['commit'],
        {'identity': metadata, 'sha256sums': digest(bundle / 'SHA256SUMS')}, development='-dev.' in metadata['version'])
    observations = {}
    os.umask(0o077)
    for mode in ['baseline', 'profiled']:
        result_dir = output / mode
        result_dir.mkdir(exist_ok=True)
        (result_dir / 'observations.json').unlink(missing_ok=True)
        (result_dir / 'partial-trace.json').unlink(missing_ok=True)
        with tempfile.TemporaryDirectory(prefix='outerspace-agent-phases-') as temporary:
            lab = PhaseLab(Path(temporary), image_output, result_dir)
            try:
                lab.setup()
                config = lab.configure()
                lab.vm('start', '--config-drive')
                observations[mode] = {'configuration': config, **lab.measure(mode == 'profiled', args.repetitions)}
                (result_dir / 'observations.json').write_text(json.dumps(observations[mode], indent=2) + '\n')
                if digest(lab.state / 'packaged.raw') != metadata['raw_image_sha256']:
                    raise ValueError('Immutable benchmark candidate changed')
            finally:
                try:
                    if hasattr(lab, 'session'):
                        (result_dir / 'partial-trace.json').write_text(json.dumps(lab.session.report(), indent=2) + '\n')
                    for name in ['boot-enroll.log', 'qemu-command-enroll.json']:
                        if (lab.state / name).is_file():
                            shutil.copyfile(lab.state / name, result_dir / name)
                finally:
                    lab.cleanup()
    summary = summarize(observations)
    if (commit != run('git', '-C', ROOT, 'rev-parse', 'HEAD').stdout.strip()
            or run('git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=normal').stdout
            or hashes != {name: digest(ROOT / name) for name in INPUTS}):
        raise ValueError('Phase harness changed during qualification')
    report.write_text(json.dumps({'schema': 1, 'status': 'passed', 'image': metadata, 'harness_commit': commit,
        'harness_sha256': hashes, 'observations': observations, 'summary': summary,
        'logs_sha256': {str(path.relative_to(output)): digest(path) for mode in observations
                       for path in sorted((output / mode).iterdir()) if path.is_file()},
        'limits': ['Serial native QEMU TCG VMs; no hardware efficiency or energy claim',
                   'Baseline has the same endpoint benchmark observer but no phase collection or boundaries',
                   'Profiled durations include gateway correlation, API exec and periodic observer costs',
                   'First image delivery has one observation per arm; repeated fresh sandboxes use a cached image',
                   'HTTP wait is synthetic; provider model work and detached unobserved processes remain unknown',
                   'Scope counters include wrappers and descendants; no exact per-tool allocation or private RSS',
                   'The deliberately lost collector makes the retained final trace failed/partial; it proves stop behavior']}, indent=2) + '\n')
    print('OUTERSPACE_AGENT_PHASES_OK: ' + str(report), flush=True)


if __name__ == '__main__':
    main()
