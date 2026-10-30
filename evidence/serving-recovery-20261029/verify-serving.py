import argparse
import hashlib
import json
import math
from pathlib import Path
import subprocess

PHASES = ['initial', 'sustained', 'pod_restart', 'drain_recovery', 'node_recovery']

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def quantile(values, percentile):
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * percentile) - 1]

def verify_certificate_rotation(report):
    # The first workload probe can occur after automatic rotation on a slow
    # TCG runner. The initial bootstrap CSR, recorded before workload startup,
    # is the reference for rotation, not the later workload probe.
    initial, renewal = (report['client_csrs'][key] for key in ['bootstrap', 'rotation'])
    before, rotated, after = (report[key] for key in ['before', 'rotated', 'after'])
    assert initial['certificate_sha256'] != renewal['certificate_sha256']
    assert initial['uid'] != renewal['uid'] and initial['name'] != renewal['name']
    assert initial['requester'].startswith('system:bootstrap:')
    assert renewal['requester'] == 'system:node:' + before['hostname']
    assert renewal['validity_seconds'] > initial['validity_seconds'] > 0
    assert before['client_certificate_sha256'] in {initial['certificate_sha256'], renewal['certificate_sha256']}
    assert rotated['client_certificate_sha256'] == after['client_certificate_sha256'] == renewal['certificate_sha256']
    assert before['boot_id'] == rotated['boot_id'] != after['boot_id']
    assert before['bootstrap_present'] is True and after['bootstrap_present'] is False

def verify_startup_records(waits, directory):
    assert len(waits) == 8
    assert json.loads((directory / 'enrollment-serving-startup.json').read_text()) == waits
    for wait in waits:
        assert wait['status'] == 'passed'
        assert wait['delivery_budget_seconds'] == 3600 and wait['readiness_budget_seconds'] == 1200
        assert 0 <= wait['server_running_observed_seconds'] < 3600
        assert 0 <= wait['readiness_wait_seconds'] < 1200
        assert wait['elapsed_seconds'] < 4800
        assert wait['server_running_observed_seconds'] + wait['readiness_wait_seconds'] <= wait['elapsed_seconds'] + 1e-6
        samples = wait['transitions']
        assert samples and all(a['elapsed_seconds'] <= b['elapsed_seconds'] for a, b in zip(samples, samples[1:]))
        assert samples[-1]['ready'] is True and 'running' in samples[-1]['state']
        assert samples[-1]['observed_generation'] >= wait['deployment_generation']
    recovery = waits[-1]
    old = recovery['recovery_from']
    current = recovery['transitions'][-1]
    assert old['boot_id'] and recovery['recovered_boot_id'] and recovery['recovered_boot_id'] != old['boot_id']
    assert current['pod_uid'] == old['pod_uid']
    assert current['container_id'] and current['container_id'] != old['container_id']
    assert current['restart_count'] == old['restart_count'] + 1
    assert all('recovery_from' not in wait for wait in waits[:-1])
    return {'status': 'passed', 'waits': len(waits),
            'delivery_to_running_seconds': [w['server_running_observed_seconds'] for w in waits],
            'token_readiness_seconds': [w['readiness_wait_seconds'] for w in waits]}

def verify_startup_waits(report, directory):
    result = verify_startup_records(report['cpu_serving']['observations']['startup_waits'], directory)
    pods = json.loads((directory / 'enrollment-serving-pods.json').read_text())['items']
    assert len(pods) == 1 and pods[0]['metadata']['uid'] == report['cpu_serving']['pod']['metadata']['uid']
    deployment = json.loads((directory / 'enrollment-serving-deployments.json').read_text())['items']
    assert len(deployment) == 1 and deployment[0]['spec']['progressDeadlineSeconds'] == 4800
    assert deployment[0]['status']['availableReplicas'] == 1
    return {**result,
            'diagnostic_sha256': {name: digest(directory / name) for name in [
                'enrollment-serving-startup.json', 'enrollment-serving-pods.json', 'enrollment-serving-deployments.json']}}

def verify_serving(evidence):
    assert evidence['status'] == 'passed'
    assert evidence['running_model_sha256'] == evidence['lock']['model']['sha256']
    assert evidence['lock']['runtime']['commit'][:9] in evidence['runtime_version']
    observations = evidence['observations']
    waits = observations.get('startup_waits', [])
    if waits and 'recovery_from' in waits[-1]:
        old = observations['drain_recovery']['resources_after']
        new = observations['node_recovery']['resources_before']
        recovery = waits[-1]
        assert recovery['recovery_from'] == {**{k: old[k] for k in
            ['pod_uid', 'container_id', 'restart_count']}, 'boot_id': old['worker']['boot_id']}
        assert recovery['recovered_boot_id'] == new['worker']['boot_id']
        final = recovery['transitions'][-1]
        assert all(final[k] == new[k] for k in ['pod_uid', 'container_id', 'restart_count'])
    assert set(observations['admission_refusals']) == {
        'untrusted-runtime', 'over-budget-memory', 'insufficient-model-memory',
        'missing-seccomp', 'writable-root', 'public-fallback',
        'accelerator-fallback', 'untrusted-model-pin', 'writable-model'}
    assert set(observations['model_refusals']) == {'incompatible-format', 'untrusted-bytes'}
    result = {}
    for phase in PHASES:
        observed = observations[phase]
        raw, summary = observed['raw'], observed['summary']
        assert raw['concurrency'] == 1 and raw['output_token_limit'] == 8
        assert raw['cache_prompt'] is False and raw['temperature'] == 0 and raw['seed'] == 42
        assert raw['prompt'] == 'The capital of France is'
        samples = raw['samples']
        assert [s['index'] for s in samples] == list(range(len(samples)))
        assert len(samples) >= (30 if phase == 'sustained' else 4)
        assert raw['wall_seconds'] >= (60 if phase == 'sustained' else 0)
        assert all(0 < s['first_token_seconds'] <= s['wall_seconds'] and
                   0 < s['response']['tokens_predicted'] <= 8 and
                   s['response']['content'].strip() and s['response']['tokens_evaluated'] > 0
                   for s in samples)
        tokens = sum(s['response']['tokens_predicted'] for s in samples)
        assert summary['requests'] == len(samples) and summary['generated_tokens'] == tokens
        assert summary['prompt_tokens'] == [s['response']['tokens_evaluated'] for s in samples]
        for name, key in [('latency', 'wall_seconds'), ('first_token', 'first_token_seconds')]:
            for label, percentile in [('p50', .5), ('p95', .95)]:
                assert summary[f'{name}_{label}_seconds'] == quantile([s[key] for s in samples], percentile)
        assert math.isclose(summary['tokens_per_request_wall_second'], tokens / sum(s['wall_seconds'] for s in samples), rel_tol=1e-12)
        assert observed['egress_denied'] is True and observed['unapproved_ingress_denied'] is True
        before, after = observed['resources_before'], observed['resources_after']
        for key in ['pod_uid', 'container_id', 'image_id', 'restart_count']:
            assert before[key] == after[key]
        assert before['restart_count'] == (1 if phase == 'node_recovery' else 0)
        charges = {}
        for name, endpoint in [('before', before), ('after', after)]:
            group = endpoint['resources']['pods'][endpoint['pod_uid']]['descendants'][
                'cri-containerd-' + endpoint['container_id'].removeprefix('containerd://') + '.scope']
            assert group['cpu.max'] == '200000 100000' and group['memory.max'] == '536870912'
            events = dict(line.split() for line in group['memory.events'].splitlines())
            assert int(events['oom']) == int(events['oom_kill']) == 0
            current, peak = int(group['memory.current']), int(group['memory.peak'])
            assert 0 < current <= peak <= 536870912
            charges[name] = {'current_bytes': current, 'lifetime_peak_bytes': peak}
        assert observed['model_load']['container_start_to_model_loaded_seconds'] >= 0
        result[phase] = {'summary': summary, 'wall_seconds': raw['wall_seconds'],
                         'memory': charges, 'model_load': observed['model_load']}
    assert observations['initial']['resources_before']['pod_uid'] == observations['sustained']['resources_before']['pod_uid']
    assert observations['initial']['resources_before']['pod_uid'] != observations['pod_restart']['resources_before']['pod_uid']
    assert observations['drain_recovery']['before_uid'] != observations['drain_recovery']['after_uid']
    assert observations['drain_recovery']['resources_before']['pod_uid'] == observations['node_recovery']['resources_before']['pod_uid']
    assert observations['drain_recovery']['resources_before']['container_id'] != observations['node_recovery']['resources_before']['container_id']
    return {'requests': sum(r['summary']['requests'] for r in result.values()),
            'tokens': sum(r['summary']['generated_tokens'] for r in result.values()),
            'cold_start_seconds': observations['cold_start_seconds'],
            'warm_pod_start_seconds': observations['warm_pod_start_seconds'], 'phases': result}

def source_hashes(source, record):
    for name, expected in record['harness_sha256'].items():
        assert digest(source / name) == expected, name
    return len(record['harness_sha256'])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--comparison', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-startup', action='store_true')
    args = parser.parse_args()
    path = args.comparison
    data = json.loads(path.read_text())
    assert data['status'] == 'passed'
    assert data['harness_commit'] == subprocess.check_output(['git', '-C', str(args.source), 'rev-parse', 'HEAD'], text=True).strip()
    inputs = source_hashes(args.source, data)
    for name, expected in data['logs_sha256'].items():
        assert digest(path.parent / name) == expected, name
    verified = {}
    a, b = (data['observations'][name] for name in ['outerspace', 'ubuntu'])
    for key in ['kernel_version', 'kernel_notes_sha256', 'runtime_sha256', 'config_sha256', 'clock_ticks_per_second', 'vcpus']:
        assert a['worker'][key] == b['worker'][key], key
    assert a['worker']['vcpus'] == 4 and b['worker']['outerspace_identity'] is None
    assert a['worker']['outerspace_identity']['commit'] == data['outerspace_image']['commit']
    for key in ['lock', 'lock_sha256', 'running_model_sha256', 'runtime_version']:
        assert a['serving'][key] == b['serving'][key], key
    for subject, observed in data['observations'].items():
        assert observed == json.loads((path.parent / subject / 'observations.json').read_text())
        assert observed['node_before']['bootID'] != observed['node_after']['bootID']
        verified[subject] = verify_serving(observed['serving'])
        if args.require_startup:
            verified[subject]['startup_waits'] = verify_startup_records(
                observed['serving']['observations']['startup_waits'], path.parent / subject)
        for phase in PHASES:
            assert data['comparison'][phase][subject] == verified[subject]['phases'][phase]['summary']
            assert a['serving']['observations'][phase]['resources_before']['image_id'] == b['serving']['observations'][phase]['resources_before']['image_id']
        assert observed['worker']['numa'] and observed['worker']['power']['available'] is False
    result = {'status': 'passed', 'report_sha256': digest(path), 'harness_commit': data['harness_commit'],
              'source_inputs_verified': inputs, 'bound_files_verified': len(data['logs_sha256']),
              'image': data['outerspace_image'], 'subjects': verified,
              'scope': 'Independent raw-sample, source, identity, lifecycle and checksum verification; no physical-hardware claim'}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ['subjects', 'image']}, indent=2))

if __name__ == '__main__':
    main()
