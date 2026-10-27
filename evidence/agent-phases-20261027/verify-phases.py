import argparse
import hashlib
import json
import math
from pathlib import Path

PHASES = ['cpu-burst', 'memory-spike', 'io', 'remote-llm-wait']

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def canonical_size(value):
    return len(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())

def quantiles(values):
    ordered = sorted(values)
    assert ordered and all(math.isfinite(v) and v >= 0 for v in ordered)
    return {'samples': len(values), 'p50': ordered[math.ceil(.5 * len(values)) - 1],
            'p95': ordered[math.ceil(.95 * len(values)) - 1], 'min': ordered[0], 'max': ordered[-1]}

def verify_trace(trace):
    assert trace['schema'] == 'outerspace.phase.v1' and trace['status'] == 'failed'
    assert len(trace['events']) <= 1024 and len(trace['scopes']) <= 32
    assert trace['buffer_bytes'] <= 8 * 1024 * 1024
    total_bytes = sum(canonical_size(s['identity']) for s in trace['scopes'].values())
    total_bytes += sum(canonical_size(e) for e in trace['events'])
    identities = set()
    operations = {}
    for sequence, envelope in enumerate(trace['events'], 1):
        event = envelope['event']
        assert event['sequence'] == sequence
        assert event['run_id'] == trace['run_id'] and event['issuer_id'] == trace['issuer_id']
        assert event['policy_sha256'] == trace['policy_sha256']
        assert len(envelope['mac']) == 64 and canonical_size(event) <= 4096
        bounds = operations.setdefault(event['operation_id'], {})
        assert event['event'] not in bounds
        bounds[event['event']] = event
    collectors = []
    for scope_id, scope in trace['scopes'].items():
        identity = scope['identity']
        pair = (identity['pod_uid'], identity['container_id'])
        assert pair not in identities
        identities.add(pair)
        assert scope['attribution'] == 'scope-only' and len(scope['samples']) <= 256
        total_bytes += sum(canonical_size(s) for s in scope['samples'])
        assert scope['operation_ids'] == [op for op, bounds in operations.items() if bounds['start']['scope_id'] == scope_id]
        observations = []
        for sample in scope['samples']:
            observed = sample['observation']
            assert sample['gateway_before_ns'] <= sample['gateway_after_ns']
            assert observed['pod_uid'] == identity['pod_uid'] and observed['container_id'] == identity['container_id']
            assert len(observed['processes']) <= 128
            assert all(set(p) == {'pid', 'start_ticks'} for p in observed['processes'])
            assert observed['boot_id'] == identity['boot_id']
            if observed['status'] == 'observed':
                assert {'cpu', 'memory', 'io'} <= observed['pressure'].keys()
                assert {'oom', 'oom_kill'} <= observed['memory_events'].keys()
                assert {'anon', 'file', 'shmem', 'kernel'} == observed['memory_charges_bytes'].keys()
                assert 0 <= observed['memory_current_bytes'] <= observed['memory_lifetime_peak_bytes']
            observations.append(observed)
            collectors.append(observed['collector'])
        intervals = []
        for first, last in zip(observations, observations[1:]):
            if first['status'] != 'observed' or last['status'] != 'observed':
                continue
            if first.get('scope_instance') != last.get('scope_instance') or first['boot_id'] != last['boot_id']:
                continue
            seconds = (last['started_monotonic_ns'] - first['started_monotonic_ns']) / 1e9
            cpu = last['cpu_usec']['usage_usec'] - first['cpu_usec']['usage_usec']
            io = {device: {key: last['io'].get(device, {}).get(key, 0) - first['io'].get(device, {}).get(key, 0)
                          for key in ['rbytes', 'wbytes', 'rios', 'wios']}
                  for device in first['io'].keys() | last['io'].keys()}
            if seconds <= 0 or cpu < 0 or any(v < 0 for dev in io.values() for v in dev.values()):
                continue
            intervals.append({'wall_seconds': seconds, 'cpu_seconds': cpu / 1e6, 'io': io})
        assert scope['intervals'] == intervals
    assert trace['buffer_bytes'] == total_bytes
    assert len(trace['spans']) == len(operations)
    for span, (op, bounds) in zip(trace['spans'], operations.items()):
        first, last = bounds['start'], bounds.get('end')
        assert span['tool_metrics'] is None and span['attribution_status'] == 'unknown'
        assert span['attributes']['outerspace.operation.id'] == op
        assert span['attributes']['outerspace.scope.id'] == first['scope_id']
        assert span['traceId'] == first['trace_id'] and span['spanId'] == first['span_id']
        if last:
            assert first['monotonic_ns'] <= last['monotonic_ns']
            for key in ['agent_id', 'parent_agent_id', 'tool_id', 'trace_id', 'span_id', 'parent_span_id', 'scope_id']:
                assert first[key] == last[key]
    return operations, collectors

def verify(path, source, expected_commit):
    report = json.loads(path.read_text())
    assert report['status'] == 'passed' and report['harness_commit'] == expected_commit
    assert report['image']['commit'] == expected_commit and report['image']['profile'] == 'agent'
    for name, value in report['harness_sha256'].items():
        assert digest(source / name) == value, name
    for name, value in report['logs_sha256'].items():
        assert digest(path.parent / name) == value, name
    baseline, profiled = report['observations']['baseline'], report['observations']['profiled']
    for key in ['kernel_version', 'kernel_notes_sha256', 'runtime_sha256', 'config_sha256', 'vcpus']:
        assert baseline['worker'][key] == profiled['worker'][key], key
    assert len({scope['image_id'] for arm in [baseline, profiled] for scope in arm['execution_scopes'].values()}) == 1
    for mode, arm in report['observations'].items():
        assert arm == json.loads((path.parent / mode / 'observations.json').read_text())
        assert arm['profiled'] is (mode == 'profiled') and len(arm['samples']) >= 10
        assert [s['iteration'] for s in arm['samples']] == list(range(len(arm['samples'])))
        summary = report['summary'][mode]
        assert summary['first_image_pull_create_to_ready_seconds'] == arm['samples'][0]['sandbox_create_to_ready_seconds']
        assert summary['cached_image_fresh_sandbox_seconds'] == quantiles([s['sandbox_create_to_ready_seconds'] for s in arm['samples'][1:]])
        for sample in arm['samples']:
            assert [p['phase'] for p in sample['phases']] == PHASES
            for phase in sample['phases']:
                assert phase['scope_id'] in arm['execution_scopes']
                assert (phase['operation_id'] is not None) == (mode == 'profiled')
                before, after = (phase[k]['pod_counters'] for k in ['before', 'after'])
                cpu_before, cpu_after = (int(dict(line.split() for line in p['cpu.stat'].splitlines())['usage_usec'])
                                         for p in [before, after])
                assert cpu_after > cpu_before
                if phase['phase'] == 'memory-spike':
                    assert int(after['memory.peak']) >= int(before['memory.current']) + 8 * 1024**2
                if phase['phase'] == 'io':
                    def reads(value):
                        return {line.split()[0]: int(dict(x.split('=') for x in line.split()[1:]).get('rbytes', 0))
                                for line in value.splitlines()}
                    first, last = reads(before['io.stat']), reads(after['io.stat'])
                    # Sixteen 512-KiB direct reads must reach a block device.
                    # Do not sum duplicated charges across stacked devices.
                    assert any(last.get(device, 0) - first.get(device, 0) >= 8 * 1024**2
                               for device in first.keys() | last.keys())
                if phase['phase'] == 'remote-llm-wait':
                    assert phase['gateway_wall_seconds'] >= 2
        for phase in PHASES:
            assert summary['phases'][phase] == quantiles([p['gateway_wall_seconds'] for s in arm['samples'] for p in s['phases'] if p['phase'] == phase])
        endpoints = [phase for sample in arm['samples'] for phase in sample['phases']]
        def cpu(value):
            return int(dict(line.split() for line in value.splitlines())['usage_usec']) / 1e6
        assert summary['endpoint_resource_observer'] == {
            'pod_cpu_seconds': quantiles([cpu(s['after']['pod_counters']['cpu.stat']) -
                                         cpu(s['before']['pod_counters']['cpu.stat']) for s in endpoints]),
            'host_busy_cpu_seconds': quantiles([sum(s['after']['cpu_ticks'][i] - s['before']['cpu_ticks'][i]
                for i in [0, 1, 2, 5, 6]) / arm['worker']['clock_ticks_per_second'] for s in endpoints]),
            'host_unavailable_memory_bytes': quantiles([s['after']['host_memory_bytes']['MemTotal'] -
                s['after']['host_memory_bytes']['MemAvailable'] for s in endpoints]),
            'pod_current_memory_bytes': quantiles([int(s['after']['pod_counters']['memory.current']) for s in endpoints]),
            'pod_lifetime_peak_bytes': quantiles([int(s['after']['pod_counters']['memory.peak']) for s in endpoints])}
    operations, collectors = verify_trace(profiled['trace'])
    assert profiled['trace'] == json.loads((path.parent / 'profiled/partial-trace.json').read_text())
    edges = profiled['edge_cases']
    assert len(edges['refusals']) == 5 and set(edges['refusals'].values()) == {'refused'}
    assert edges['background_descendants_after_boundary']
    assert len(edges['overlapping_operations']) == 2
    overlapping = [operations[k] for k in edges['overlapping_operations']]
    assert overlapping[0]['start']['scope_id'] == overlapping[1]['start']['scope_id']
    assert max(o['start']['monotonic_ns'] for o in overlapping) <= min(o['end']['monotonic_ns'] for o in overlapping)
    assert operations[edges['external_provider_operation']]['start']['scope_id'] is None
    assert edges['oom_restart']['reason'] == 'OOMKilled' and edges['oom_restart']['before'] != edges['oom_restart']['after']
    assert edges['cancellation']['running_processes']
    assert operations[edges['cancellation']['operation_id']]['end']['outcome'] == 'cancelled'
    assert edges['collector_loss'] == 'stopped-and-retained-partial-trace'
    assert report['summary']['profiled']['collector'] == {
        'process_cpu_seconds_total': sum(c['cpu_seconds'] for c in collectors),
        'peak_rss_bytes': quantiles([c['peak_rss_bytes'] for c in collectors]),
        'read_wall_seconds': quantiles([c['wall_seconds'] for c in collectors])}
    return {'status': 'passed', 'path': str(path), 'report_sha256': digest(path),
            'source_inputs_verified': len(report['harness_sha256']), 'bound_files_verified': len(report['logs_sha256']),
            'image': report['image'], 'harness_commit': report['harness_commit'],
            'scope_count': len(profiled['trace']['scopes']), 'operation_count': len(operations),
            'summary': report['summary'],
            'scope': 'Source, raw observations, counter intervals, operation links and checksums verified; HMAC keys are deliberately absent from exported datasets'}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.report, args.source, args.expected_commit)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(result['status'], result['scope_count'], 'scopes,', result['operation_count'], 'operations')
