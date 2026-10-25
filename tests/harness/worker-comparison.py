#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Compare a qualified Agent image and a signed Ubuntu worker in serial QEMU labs."""
import argparse
import ast
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import statistics
import tempfile
import time
import enrollment as native

ROOT = native.ROOT
run, digest, wait_for = native.run, native.digest, native.wait_for
LOCK = ROOT / 'tests/benchmarks/ubuntu-reference.lock.json'
INPUTS = native.HARNESS_INPUTS + ['tests/harness/worker-comparison.py',
    'tests/integration/ubuntu-reference.sh', 'tests/benchmarks/ubuntu-reference.lock.json',
    'src/components.lock.json', 'build/tools/install-components.py']


def signed_image(cache, architecture, download=True):
    """Recheck the pinned image against Canonical's detached, full-fingerprint signature."""
    lock = json.loads(LOCK.read_text())
    cache.mkdir(parents=True, exist_ok=True)
    def fetch(name, url):
        path = cache / name
        if not path.exists():
            partial = path.with_suffix(path.suffix + '.partial')
            try:
                run('curl', '-fsSL', '--proto', '=https', '--retry', '3', '--max-time', '1200',
                    '-o', partial, url, timeout=1230)
                partial.replace(path)
            finally:
                partial.unlink(missing_ok=True)
        return path
    sums = fetch('SHA256SUMS', lock['base_url'] + 'SHA256SUMS')
    signature = fetch('SHA256SUMS.gpg', lock['base_url'] + 'SHA256SUMS.gpg')
    key = fetch('signing-key.asc', 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x' + lock['signing_fingerprint'])
    with tempfile.TemporaryDirectory(prefix='outerspace-ubuntu-key-') as temporary:
        run('gpg', '--homedir', temporary, '--batch', '--import', key)
        verification = run('gpg', '--homedir', temporary, '--batch', '--status-fd', '1', '--verify', signature, sums)
        if not any(line.startswith('[GNUPG:] VALIDSIG ' + lock['signing_fingerprint'] + ' ')
                   for line in verification.stdout.splitlines()):
            raise ValueError('Ubuntu signature did not use the pinned Canonical key')
    name = 'noble-server-cloudimg-' + architecture + '.img'
    expected = lock['images'][architecture]
    if sums.read_text().splitlines().count(expected + ' *' + name) != 1:
        raise ValueError('Ubuntu image pin differs from the signed inventory')
    image = fetch(name, lock['base_url'] + name) if download else cache / name
    if download and digest(image) != expected:
        raise ValueError('Ubuntu image checksum mismatch')
    return image, {'lock': lock, 'image_sha256': expected, 'signed_inventory_sha256': digest(sums),
                   'signature_sha256': digest(signature)}


def matched(a, b):
    """Reject a nominal comparison with different kernels, runtime bytes or policy."""
    for key in ['kernel_version', 'kernel_notes_sha256', 'runtime_sha256', 'config_sha256',
                'clock_ticks_per_second', 'vcpus']:
        if not a.get(key) or a[key] != b.get(key):
            raise ValueError('Workers do not match: ' + key)
    if a['vcpus'] != 4 or 'ID=ubuntu\n' not in b['os_release']:
        raise ValueError('Expected the four-vCPU official Ubuntu reference')


def summarize(samples, ticks_per_second, vcpus):
    if len(samples) != 4 or ticks_per_second <= 0 or vcpus != 4:
        raise ValueError('Four samples on the fixed reference are required')
    def summary(values):
        if any(not math.isfinite(v) or v < 0 for v in values):
            raise ValueError('Invalid observation')
        return {'samples': len(values), 'min': min(values), 'median': statistics.median(values), 'max': max(values)}
    cpu = []
    for before, after in zip(samples, samples[1:]):
        seconds = after['uptime_seconds'] - before['uptime_seconds']
        work = [after['cpu_ticks'][i] - before['cpu_ticks'][i] for i in [0, 1, 2, 5, 6]]
        if seconds < 10 or any(value < 0 for value in work):
            raise ValueError('Short interval or regressed CPU counter')
        cpu.append(100 * sum(work) / (ticks_per_second * seconds * vcpus))
    if any(value > 100 for value in cpu):
        raise ValueError('Guest CPU work exceeds the reference capacity')
    total = {s['memory_bytes']['MemTotal'] for s in samples}
    if len(total) != 1 or not 3 * 1024**3 <= next(iter(total)) <= 4 * 1024**3:
        raise ValueError('Guest RAM differs from the four-GiB reference')
    return {'memory_unavailable_bytes': summary([s['memory_bytes']['MemTotal'] - s['memory_bytes']['MemAvailable']
                                                for s in samples]), 'guest_busy_cpu_percent': summary(cpu)}


def measurement_protocol(source):
    """Bind reuse to the same observer, workload loop and calculations, excluding boot preparation."""
    tree = ast.parse(source)
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    lab = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'ComparisonLab')
    methods = {node.name: node for node in lab.body if isinstance(node, ast.FunctionDef)}
    body = methods['measure'].body
    starts = [i for i, node in enumerate(body) if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Attribute) and target.attr == 'identity' for target in node.targets)]
    if len(starts) != 1:
        raise ValueError('Cannot identify the complete measurement protocol')
    nodes = [functions['matched'], functions['summarize'], methods['snapshot'], methods['collect'], *body[starts[0]:]]
    canonical = ast.dump(ast.Module(body=nodes, type_ignores=[]), include_attributes=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def reuse_outerspace(path, expected_sha, commit, metadata):
    """Explicit operator binding of a completed phase; never accept a partial or changed protocol."""
    if path.is_symlink() or digest(path) != expected_sha:
        raise ValueError('Reused observation checksum mismatch')
    if len(commit) != 40 or any(c not in '0123456789abcdef' for c in commit):
        raise ValueError('Reuse requires a full harness commit')
    run('git', '-C', ROOT, 'merge-base', '--is-ancestor', commit, 'HEAD')
    old_source = run('git', '-C', ROOT, 'show', commit + ':tests/harness/worker-comparison.py').stdout
    protocol = measurement_protocol((ROOT / 'tests/harness/worker-comparison.py').read_text())
    if measurement_protocol(old_source) != protocol:
        raise ValueError('Reused measurement protocol differs')
    hashes = {}
    for name in INPUTS:
        if name == 'tests/harness/worker-comparison.py':
            continue
        content = run('git', '-C', ROOT, 'show', commit + ':' + name).stdout
        hashes[name] = hashlib.sha256(content.encode()).hexdigest()
        if hashes[name] != digest(ROOT / name):
            raise ValueError('Reused observer, runtime or workload input differs: ' + name)
    observation = json.loads(path.read_text())
    identity = observation['worker']['outerspace_identity']
    profiles = native.load_script('profiles', native.BUILD_TOOLS)
    if identity != profiles.image_identity('agent', 'cpu', metadata['architecture'], metadata['commit']):
        raise ValueError('Reused observation belongs to another candidate')
    if set(observation['stages']) != {'0', '1', '2', '4'} or observation['concurrent_agents'] != [1, 2, 4]:
        raise ValueError('Reused observation did not complete every density stage')
    launches = observation['launches']
    if len(launches) != 4 or len({item['pod']['metadata']['uid'] for item in launches}) != 4:
        raise ValueError('Reused Agent identities are incomplete')
    for count, stage in observation['stages'].items():
        if stage['summary'] != summarize(stage['raw'], observation['worker']['clock_ticks_per_second'], 4):
            raise ValueError('Reused summary differs from its raw observations')
        for sample in stage['raw']:
            for item in launches[:int(count)]:
                pod = item['pod']
                group = sample['pods'][pod['metadata']['uid']]
                native.verify_agent_resource_limits(group)
                native.verify_agent_io_limits(group, pod['status']['containerStatuses'][0]['containerID'])
    return observation, {'binding': 'explicit operator-supplied checksum and original harness commit',
        'harness_commit': commit, 'observations_sha256': expected_sha,
        'measurement_protocol_sha256': protocol, 'unchanged_inputs_sha256': hashes}


class ComparisonLab(native.Lab):
    def __init__(self, state, image_output, output, reference=False):
        super().__init__(state, image_output)
        self.results = output
        self.reference = reference

    def worker(self):
        if not self.reference:
            return super().worker()
        for node in self.api('nodes')['items']:
            if any(item['address'] == native.VM_IP for item in node['status'].get('addresses', [])):
                if not node['metadata']['name'].startswith('ubuntu-reference-'):
                    raise ValueError('Unexpected Ubuntu worker identity')
                return node

    def snapshot(self, uids, identity=False):
        result = self.kube('-n', native.LAB, 'exec', 'probe', '--', 'python3', '-c',
            (ROOT / 'tests/integration/node-probe.py').read_text(), json.dumps(uids),
            '--comparison-identity' if identity else '--comparison')
        return json.loads(result.stdout)

    def reference_seed(self, image, cache, architecture):
        payload = self.state / 'payload'
        payload.mkdir()
        source = ROOT / 'src/image/mkosi.extra'
        files = {
            'install-components.py': ROOT / 'build/tools/install-components.py',
            'setup.sh': ROOT / 'tests/integration/ubuntu-reference.sh',
            'containerd.toml': source / 'etc/containerd/config.toml',
            'containerd.service': source / 'usr/lib/systemd/system/containerd.service',
            'kubelet.service': source / 'usr/lib/systemd/system/kubelet.service',
            'outerspace-agent-profile.service': source / 'usr/lib/systemd/system/outerspace-agent-profile.service',
            'agent-v1': source / 'usr/share/outerspace/apparmor/agent-v1',
            'agent-io': source / 'usr/lib/outerspace/agent-io',
            '90-outerspace.conf': source / 'etc/sysctl.d/90-outerspace.conf',
            'modules.conf': source / 'etc/modules-load.d/outerspace.conf',
        }
        for name, path in files.items():
            shutil.copyfile(path, payload / name)
        config = (payload / 'containerd.toml').read_text()
        config += '\n[plugins.\'io.containerd.service.v1.tasks-service\']\n  blockio_config_file = "/run/outerspace/agent-blockio.json"\n'
        (payload / 'containerd.toml').write_text(config)
        components = json.loads((ROOT / 'src/components.lock.json').read_text())
        # P2P is inactive in this benchmark; don't add it to a standard worker.
        del components['components']['dfdaemon']
        lock = payload / 'components.lock.json'
        lock.write_text(json.dumps(components))
        installer = native.load_script('install-components', native.BUILD_TOOLS)
        (cache / 'components').mkdir(exist_ok=True)
        for component in components['components'].values():
            sha = component['artifacts'][architecture]['sha256']
            existing = cache.parent / 'components' / sha
            if existing.is_file():
                installer.verify(existing, sha)
                shutil.copyfile(existing, cache / 'components' / sha)
        installer.fetch(cache / 'components', {'amd64': 'x86-64', 'arm64': 'arm64'}[architecture], lock)
        (payload / 'cache').mkdir()
        for component in components['components'].values():
            sha = component['artifacts'][architecture]['sha256']
            shutil.copyfile(cache / 'components' / sha, payload / 'cache' / sha)
        (payload / 'meta-data').write_text('instance-id: ubuntu-reference-' + os.urandom(6).hex() + '\n'
                                           'local-hostname: ubuntu-reference-worker\n')
        (payload / 'user-data').write_text('''#cloud-config
ssh_pwauth: false
disable_root: true
runcmd:
  - [mkdir, -p, /mnt/reference]
  - [mount, -o, "ro,nosuid,nodev,noexec", /dev/disk/by-label/CIDATA, /mnt/reference]
  - [bash, /mnt/reference/setup.sh]
''')
        shutil.copyfile(image, self.state / 'ubuntu.img')
        (self.state / 'ubuntu.img').chmod(0o400)
        size = sum(p.stat().st_size for p in payload.rglob('*') if p.is_file()) + 32 * 1024**2
        with (self.state / 'reference-seed.raw').open('wb') as stream:
            stream.truncate(math.ceil(size / 1024**2) * 1024**2)
        run('docker', 'exec', native.RUNNER, 'bash', '-euc',
            'mkfs.vfat -n CIDATA /state/reference-seed.raw; mcopy -s -i /state/reference-seed.raw /state/payload/* ::/')

    def collect(self, uids):
        time.sleep(60)
        samples = [self.snapshot(uids)['resources']]
        for unused in range(3):
            time.sleep(10)
            samples.append(self.snapshot(uids)['resources'])
        return {'raw': samples, 'summary': summarize(samples, self.identity['clock_ticks_per_second'], 4)}

    def measure(self):
        node = wait_for('Waiting for the comparison worker', self.worker, timeout=3600 if self.reference else 1200)
        name = node['metadata']['name']
        self.extend_renewal_lifetime()
        self.kube('wait', '--for=condition=Ready', 'node/' + name, '--timeout=1200s', timeout=1230)
        wait_for('Approving the exact worker serving CSR', lambda: self.approve_serving(node))
        wait_for('Waiting for identical Cilium/Envoy readiness', lambda: self.cilium_ready(name), timeout=1200)
        self.workloads(name)
        self.identity = self.snapshot([], identity=True)['worker']
        if self.reference:
            if self.identity['outerspace_identity'] is not None:
                raise ValueError('Ubuntu reference must retain its own OS identity')
        else:
            expected = json.loads((self.output / 'build-identity.json').read_text())
            actual = self.identity['outerspace_identity']
            if not actual or any(actual.get(key) != expected[key] for key in actual):
                raise ValueError('Guest image identity differs from the packaged Agent candidate')
        self.agent_node = name
        self.agent_checks = {}
        self.agent_install()
        self.kube('label', 'node', name, native.AGENT_NODE_LABEL + '=v1')
        stages = {'0': self.collect([])}
        launches = []
        for count in range(1, 5):
            obj = json.loads((ROOT / 'src/cluster/agent/workload-v1.json').read_text())
            obj['metadata']['name'] = 'density-' + str(count)
            started = time.monotonic()
            self.apply(obj)
            self.kube('-n', native.AGENT_NAMESPACE, 'wait', '--for=condition=Ready',
                      'pod/' + obj['metadata']['name'], '--timeout=1200s', timeout=1230)
            pod = self.api('-n', native.AGENT_NAMESPACE, 'pod', obj['metadata']['name'])
            if pod['spec']['nodeName'] != name:
                raise ValueError('Agent scheduled on another worker')
            launches.append({'pod': pod, 'create_to_ready_wall_seconds': time.monotonic() - started,
                             'cache': 'first pull' if count == 1 else 'same image already running'})
            if count in [1, 2, 4]:
                uids = [item['pod']['metadata']['uid'] for item in launches]
                stages[str(count)] = self.collect(uids)
                for item in launches:
                    pod = item['pod']
                    for sample in stages[str(count)]['raw']:
                        group = sample['pods'][pod['metadata']['uid']]
                        native.verify_agent_resource_limits(group)
                        native.verify_agent_io_limits(group, pod['status']['containerStatuses'][0]['containerID'])
        pods = self.api('pods', '-A', '--field-selector', 'spec.nodeName=' + name)['items']
        return {'worker': self.identity, 'node_info': node['status']['nodeInfo'], 'stages': stages, 'launches': launches,
                'platform_pods': pods, 'concurrent_agents': [1, 2, 4]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=ROOT / '.cache/ubuntu-reference')
    parser.add_argument('--reuse-outerspace', type=Path, help='Reuse only a complete, explicitly bound OuterSpace phase')
    parser.add_argument('--reuse-outerspace-sha256')
    parser.add_argument('--reuse-harness-commit')
    args = parser.parse_args()
    if any([args.reuse_outerspace, args.reuse_outerspace_sha256, args.reuse_harness_commit]) and not all(
            [args.reuse_outerspace, args.reuse_outerspace_sha256, args.reuse_harness_commit]):
        parser.error('Reuse requires the observation path, its SHA256 and original harness commit')
    if run('git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=normal').stdout:
        raise ValueError('Commit the comparison harness before running it')
    commit = run('git', '-C', ROOT, 'rev-parse', 'HEAD').stdout.strip()
    hashes = {name: digest(ROOT / name) for name in INPUTS}
    image_output, output, cache = args.image_output.resolve(), args.output.resolve(), args.cache.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = output / 'worker-comparison.json'
    report.unlink(missing_ok=True)
    metadata = json.loads((image_output / 'build-identity.json').read_text())
    if metadata['architecture'] != native.load_script('profiles', native.BUILD_TOOLS).architecture():
        raise ValueError('The candidate architecture must match the native lab runner')
    if metadata['profile'] != 'agent' or metadata['hardware_profile'] != 'cpu':
        raise ValueError('A qualified Agent CPU image is required')
    bundle = image_output / f'outerspace-{metadata["version"]}-agent-cpu-{metadata["architecture"]}'
    native.load_script('prepare-release', native.BUILD_TOOLS).verify_bundle(bundle, metadata['version'], metadata['commit'],
        {'identity': metadata, 'sha256sums': digest(bundle / 'SHA256SUMS')})
    if digest(ROOT / 'src/components.lock.json') != metadata['components_lock_sha256']:
        raise ValueError('Runtime pins differ from the qualified image')
    image, provenance = signed_image(cache, metadata['architecture'], download=False)
    observations = {}
    reuse = None
    if args.reuse_outerspace:
        observations['outerspace'], reuse = reuse_outerspace(args.reuse_outerspace.resolve(),
            args.reuse_outerspace_sha256, args.reuse_harness_commit, metadata)
        saved = output / 'outerspace'
        saved.mkdir(exist_ok=True)
        for name in ['observations.json', 'boot-enroll.log', 'qemu-command-enroll.json', 'dnsmasq.log']:
            source = args.reuse_outerspace.resolve().parent / name
            if source.is_symlink():
                raise ValueError('Reused evidence must be regular files')
            shutil.copyfile(source, saved / name)
    for subject in ['ubuntu'] if reuse else ['outerspace', 'ubuntu']:
        result_dir = output / subject
        result_dir.mkdir(exist_ok=True)
        (result_dir / 'observations.json').unlink(missing_ok=True)
        with tempfile.TemporaryDirectory(prefix='outerspace-comparison-') as temporary:
            os.chmod(temporary, 0o700)
            lab = ComparisonLab(Path(temporary), image_output, result_dir, subject == 'ubuntu')
            try:
                lab.setup()
                config = lab.configure()
                if lab.reference:
                    image, provenance = signed_image(cache, metadata['architecture'])
                    lab.reference_seed(image, cache, metadata['architecture'])
                lab.vm('start', '--config-drive', *(['--ubuntu-reference'] if lab.reference else []))
                observations[subject] = {'configuration': config, **lab.measure()}
                observations[subject]['configuration']['client_signing_duration'] = '10m initial bootstrap; 4h renewals (test lab only)'
                (result_dir / 'observations.json').write_text(json.dumps(observations[subject], indent=2) + '\n')
            finally:
                try:
                    for name in ['boot-enroll.log', 'qemu-command-enroll.json', 'dnsmasq.log']:
                        if (lab.state / name).is_file():
                            shutil.copyfile(lab.state / name, result_dir / name)
                    if lab.kind_created:
                        for resource in ['nodes', 'pods', 'events']:
                            result = lab.kube('get', resource, '-A', '-o', 'json', check=False)
                            (result_dir / (resource + '.json')).write_text(result.stdout)
                finally:
                    try:
                        lab.cleanup()
                    finally:
                        run('docker', 'image', 'prune', '--force', '--filter', 'label=io.outerspace.tooling=true')
    matched(observations['outerspace']['worker'], observations['ubuntu']['worker'])
    if commit != run('git', '-C', ROOT, 'rev-parse', 'HEAD').stdout.strip() or run('git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=normal').stdout or hashes != {name: digest(ROOT / name) for name in INPUTS}:
        raise ValueError('Comparison source changed during observation')
    report.write_text(json.dumps({'schema': 1, 'status': 'observed', 'harness_commit': commit,
        'subject_harness_commits': {'outerspace': reuse['harness_commit'] if reuse else commit, 'ubuntu': commit},
        'reused_outerspace': reuse,
        'harness_sha256': hashes, 'outerspace_image': metadata, 'ubuntu_provenance': provenance,
        'observations': observations, 'logs_sha256': {
            str(path.relative_to(output)): digest(path) for subject in observations
            for name in ['observations.json', 'boot-enroll.log', 'qemu-command-enroll.json', 'dnsmasq.log']
            for path in [output / subject / name]},
        'reference': {'vcpus': 4, 'memory_mib': 4096, 'acceleration': 'QEMU TCG'},
        'limits': ['Serial local emulated VMs; not physical-hardware throughput or a statistical capacity claim',
                   'Four samples per stage after 60s settling, three guest intervals >=10s; observer included',
                   'Same CNI and qualification pods on both workers, no model or agent framework',
                   'Ubuntu uses a writable 12-GiB root disk; OuterSpace has verity root and separate state',
                   'First launch includes registry delivery, later launches reuse the running image',
                   'Density 10/100 untested: reference namespace quota is four Agents']}, indent=2) + '\n')
    print('OUTERSPACE_WORKER_COMPARISON_OBSERVED: ' + str(report), flush=True)


if __name__ == '__main__':
    main()
