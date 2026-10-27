#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Qualify CPU serving and a matched Ubuntu baseline on two serial native VMs."""
import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import enrollment as native

comparison = native.load_script('worker-comparison')
serving = native.load_script('cpu-serving')
ROOT = native.ROOT
run, digest, wait_for = native.run, native.digest, native.wait_for
INPUTS = comparison.INPUTS + ['tests/harness/serving-comparison.py']


def compare_results(outerspace, ubuntu):
    comparison.matched(outerspace['worker'], ubuntu['worker'])
    a, b = outerspace['serving'], ubuntu['serving']
    for key in ['lock', 'lock_sha256', 'running_model_sha256', 'runtime_version']:
        if a[key] != b[key]:
            raise ValueError('Model serving comparison mismatch: ' + key)
    results = {}
    for phase in ['initial', 'sustained', 'pod_restart', 'drain_recovery', 'node_recovery']:
        samples = [x['observations'][phase] for x in [a, b]]
        for sample in samples:
            raw = sample['raw']
            if (sample['summary'] != serving.summarize(raw['samples']) or raw['concurrency'] != 1
                    or raw['output_token_limit'] != 8 or raw['cache_prompt'] is not False
                    or raw['prompt'] != 'The capital of France is' or raw['temperature'] != 0 or raw['seed'] != 42
                    or (phase == 'sustained' and (len(raw['samples']) < 30 or raw['wall_seconds'] < 60))):
                raise ValueError('Incomplete or unmatched serving measurements')
        if samples[0]['resources_before']['image_id'] != samples[1]['resources_before']['image_id']:
            raise ValueError('Workers ran different OCI image bytes')
        results[phase] = {'outerspace': samples[0]['summary'], 'ubuntu': samples[1]['summary']}
    return results


class ServingLab(comparison.ComparisonLab):
    def probe(self):
        # The Ubuntu reference retains its own identity. Never fabricate an OS
        # image identity or require a nonexistent OuterSpace provisioned account.
        return self.snapshot([], identity=True)

    def measure(self):
        node = wait_for('Waiting for the serving worker', self.worker, timeout=3600 if self.reference else 1200)
        name = node['metadata']['name']
        self.extend_renewal_lifetime()
        self.kube('wait', '--for=condition=Ready', 'node/' + name, '--timeout=1200s', timeout=1230)
        wait_for('Approving the exact serving CSR', lambda: self.approve_serving(node))
        wait_for('Waiting for matched Cilium/Envoy readiness', lambda: self.cilium_ready(name), timeout=1200)
        self.workloads(name)
        identity = self.snapshot([], identity=True)['worker']
        expected = json.loads((self.output / 'build-identity.json').read_text())
        if self.reference:
            if identity['outerspace_identity'] is not None:
                raise ValueError('Reference identity was replaced with an OuterSpace identity')
        elif identity['outerspace_identity'] != native.load_script('profiles', native.BUILD_TOOLS).image_identity(
                'inference', 'cpu', expected['architecture'], expected['commit']):
            raise ValueError('Guest differs from the qualified Inference image')
        scenario = serving.Serving(self, name, run, wait_for)
        scenario.prepare()
        scenario.sample('initial')
        scenario.sample('sustained', requests=30, minimum_seconds=60)
        scenario.restart()
        scenario.drain_recover()
        before = self.api('node', name)
        self.revoke_bootstrap()
        started = time.monotonic()
        self.vm('poweroff')
        wait_for('Waiting for clean serving worker poweroff', lambda: run('docker', 'exec', native.RUNNER, 'sh', '-c',
            '! kill -0 "$(cat /state/qemu.pid)" 2>/dev/null', check=False).returncode == 0, timeout=600)
        if 'reboot: Power down' not in (self.state / 'boot-enroll.log').read_text():
            raise ValueError('Serving worker did not confirm clean poweroff')
        self.vm('start', *(['--ubuntu-reference'] if self.reference else []))
        def recovered():
            current = self.worker()
            if current and current['status']['nodeInfo']['bootID'] != before['status']['nodeInfo']['bootID']:
                if any(c['type'] == 'Ready' and c['status'] == 'True' for c in current['status']['conditions']):
                    return current
        after = wait_for('Waiting for serving Node Ready after cold boot', recovered, timeout=1200)
        if after['metadata']['uid'] != before['metadata']['uid']:
            raise ValueError('Cold recovery replaced the registered worker')
        wait_for('Approving recovered serving CSR', lambda: self.approve_serving(after))
        wait_for('Waiting for recovered Cilium/Envoy', lambda: self.cilium_ready(name), timeout=1200)
        self.wait_workloads()
        scenario.sample('node_recovery')
        scenario.observations['node_recovery']['poweroff_to_sampled_seconds'] = time.monotonic() - started
        return {'worker': identity, 'node_before': before['status']['nodeInfo'],
                'node_after': after['status']['nodeInfo'], 'node_uid': after['metadata']['uid'],
                'serving': scenario.evidence()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-output', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=ROOT / '.cache/ubuntu-reference')
    parser.add_argument('--admission-only', action='store_true')
    args = parser.parse_args()
    if run('git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=normal').stdout:
        raise ValueError('Commit the serving harness before qualification')
    commit = run('git', '-C', ROOT, 'rev-parse', 'HEAD').stdout.strip()
    hashes = {name: digest(ROOT / name) for name in INPUTS}
    if args.admission_only:
        args.output.mkdir(parents=True, exist_ok=True)
        report = args.output / 'serving-admission.json'
        report.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory(prefix='outerspace-serving-admission-') as temporary:
            lab = native.Lab(Path(temporary), args.output.resolve())
            try:
                lab.setup(api_only=True)
                lab.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': serving.NAMESPACE}})
                scenario = serving.Serving(lab, 'native-worker-required', run, wait_for)
                scenario.install_admission(native.PYTHON_IMAGE)
                scenario.admission_refusals(native.PYTHON_IMAGE)
            finally:
                lab.cleanup()
        report.write_text(json.dumps({'status': 'passed', 'harness_commit': commit, 'harness_sha256': hashes,
            'scope': 'API preflight only; not native worker qualification', **scenario.observations}, indent=2) + '\n')
        return
    if not args.image_output:
        parser.error('--image-output is required for native qualification')
    image_output, output, cache = args.image_output.resolve(), args.output.resolve(), args.cache.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = output / 'serving-comparison.json'
    report.unlink(missing_ok=True)
    metadata = json.loads((image_output / 'build-identity.json').read_text())
    if (metadata['architecture'] != native.load_script('profiles', native.BUILD_TOOLS).architecture()
            or metadata['profile'] != 'inference' or metadata['hardware_profile'] != 'cpu'):
        raise ValueError('A qualified native Inference CPU image is required')
    bundle = image_output / f'outerspace-{metadata["version"]}-inference-cpu-{metadata["architecture"]}'
    verifier = native.load_script('prepare-release', native.BUILD_TOOLS)
    verifier.verify_bundle(bundle, metadata['version'], metadata['commit'],
        {'identity': metadata, 'sha256sums': digest(bundle / 'SHA256SUMS')},
        development='-dev.' in metadata['version'])
    if digest(ROOT / 'src/components.lock.json') != metadata['components_lock_sha256']:
        raise ValueError('Comparison runtime pins differ from the qualified image')
    image, provenance = comparison.signed_image(cache, metadata['architecture'], download=False)
    observations = {}
    os.umask(0o077)
    for subject in ['outerspace', 'ubuntu']:
        result_dir = output / subject
        result_dir.mkdir(exist_ok=True)
        (result_dir / 'observations.json').unlink(missing_ok=True)
        with tempfile.TemporaryDirectory(prefix='outerspace-serving-comparison-') as temporary:
            lab = ServingLab(Path(temporary), image_output, result_dir, subject == 'ubuntu')
            try:
                lab.setup()
                config = lab.configure(bootstrap_ttl='2h' if lab.reference else '30m')
                if lab.reference:
                    image, provenance = comparison.signed_image(cache, metadata['architecture'])
                    lab.reference_seed(image, cache, metadata['architecture'], profile='inference')
                lab.vm('start', '--config-drive', *(['--ubuntu-reference'] if lab.reference else []))
                observations[subject] = {'configuration': config, **lab.measure()}
                observations[subject]['configuration']['client_signing_duration'] = '10m bootstrap; 4h renewals (lab only)'
                (result_dir / 'observations.json').write_text(json.dumps(observations[subject], indent=2) + '\n')
                if digest(lab.state / 'packaged.raw') != metadata['raw_image_sha256']:
                    raise ValueError('Immutable candidate changed during serving qualification')
            finally:
                try:
                    for name in ['boot-enroll.log', 'boot-recover.log', 'qemu-command-enroll.json', 'qemu-command-recover.json', 'dnsmasq.log']:
                        if (lab.state / name).is_file():
                            shutil.copyfile(lab.state / name, result_dir / name)
                    if lab.kind_created:
                        for resource in ['nodes', 'pods', 'events']:
                            result = lab.kube('get', resource, '-A', '-o', 'json', check=False)
                            (result_dir / (resource + '.json')).write_text(result.stdout)
                        for container in ['verify-model', 'server']:
                            result = lab.kube('-n', serving.NAMESPACE, 'logs', 'deployment/inference', '-c', container,
                                              '--tail=500', '--timestamps', check=False)
                            (result_dir / ('final-' + container + '.log')).write_text(result.stdout + result.stderr)
                finally:
                    try:
                        lab.cleanup()
                    finally:
                        run('docker', 'image', 'prune', '--force', '--filter', 'label=io.outerspace.tooling=true')
    results = compare_results(observations['outerspace'], observations['ubuntu'])
    if (commit != run('git', '-C', ROOT, 'rev-parse', 'HEAD').stdout.strip()
            or run('git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=normal').stdout
            or hashes != {name: digest(ROOT / name) for name in INPUTS}):
        raise ValueError('Serving harness changed during qualification')
    report.write_text(json.dumps({'schema': 1, 'status': 'passed', 'harness_commit': commit,
        'harness_sha256': hashes, 'outerspace_image': metadata, 'ubuntu_provenance': provenance,
        'observations': observations, 'comparison': results,
        'logs_sha256': {str(path.relative_to(output)): digest(path) for subject in observations
                       for path in sorted((output / subject).iterdir()) if path.is_file()},
        'reference': {'vcpus': 4, 'memory_mib': 4096, 'acceleration': 'QEMU TCG'},
        'limits': ['Native architecture in serial QEMU TCG VMs; not physical-machine throughput or energy qualification',
                   'One model, one server slot, 30+ requests over 60+ seconds sustained; not production endurance',
                   'Same kernel notes, runtime bytes, CPU/memory, CNI and model configuration; writable Ubuntu root versus verity OS',
                   'Same-worker drain/uncordon, not multi-node migration; no GPU or public-network fallback',
                   'Power unavailable in this VM; NUMA topology and actual cgroup limits/counters recorded']}, indent=2) + '\n')
    print('OUTERSPACE_SERVING_COMPARISON_OK: ' + str(report), flush=True)


if __name__ == '__main__':
    main()
