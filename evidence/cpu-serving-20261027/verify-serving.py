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

def verify_serving(evidence):
    assert evidence['status'] == 'passed'
    assert evidence['running_model_sha256'] == evidence['lock']['model']['sha256']
    assert evidence['lock']['runtime']['commit'][:9] in evidence['runtime_version']
    observations = evidence['observations']
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
