#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Compare a qualified Agent image and a signed Ubuntu worker in serial QEMU labs."""
import argparse
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
    'src/image/mkosi.extra/usr/lib/systemd/system/kubelet.service',
    'src/image/mkosi.extra/etc/modules-load.d/outerspace.conf',
    'src/image/mkosi.extra/etc/sysctl.d/90-outerspace.conf',
    'src/components.lock.json', 'tests/harness/reference-runtimes.py', 'build/tools/sbom.py']


def signed_image(cache, architecture, download=True):
    """Recheck the pinned image against Canonical's detached, full-fingerprint signature."""
    lock = json.loads(LOCK.read_text())
    cache.mkdir(parents=True, exist_ok=True)
    def fetch(name, url):
        path = cache / name
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise ValueError('Reference cache entry must be a regular file: ' + name)
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
    if (len(samples) != 4 or type(ticks_per_second) is not int
            or ticks_per_second <= 0 or type(vcpus) is not int or vcpus != 4):
        raise ValueError('Four samples on the fixed reference are required')
    for sample in samples:
        uptime = sample['uptime_seconds']
        ticks = sample['cpu_ticks']
        memory = sample['memory_bytes']
        if (type(uptime) not in (int, float) or not math.isfinite(uptime) or uptime <= 0
                or len(ticks) != 10 or any(type(value) is not int or value < 0 for value in ticks)
                or any(type(memory[key]) is not int for key in ['MemTotal', 'MemAvailable'])
                or not 0 <= memory['MemAvailable'] <= memory['MemTotal']):
            raise ValueError('Incomplete or invalid guest counters')
    def summary(values):
        if any(not math.isfinite(v) or v < 0 for v in values):
            raise ValueError('Invalid observation')
        return {'samples': len(values), 'min': min(values), 'median': statistics.median(values), 'max': max(values)}
    cpu = []
    for before, after in zip(samples, samples[1:]):
        seconds = after['uptime_seconds'] - before['uptime_seconds']
        work = [after['cpu_ticks'][i] - before['cpu_ticks'][i] for i in [0, 1, 2, 5, 6]]
        if seconds < 10 or any(a < b for a, b in zip(after['cpu_ticks'], before['cpu_ticks'])):
            raise ValueError('Short interval or regressed CPU counter')
        cpu.append(100 * sum(work) / (ticks_per_second * seconds * vcpus))
    if any(value > 100 for value in cpu):
        raise ValueError('Guest CPU work exceeds the reference capacity')
    total = {s['memory_bytes']['MemTotal'] for s in samples}
    if len(total) != 1 or not 3 * 1024**3 <= next(iter(total)) <= 4 * 1024**3:
        raise ValueError('Guest RAM differs from the four-GiB reference')
    return {'memory_unavailable_bytes': summary([s['memory_bytes']['MemTotal'] - s['memory_bytes']['MemAvailable']
                                                for s in samples]), 'guest_busy_cpu_percent': summary(cpu)}


def verify_running_agent(pod, node, original=None):
    statuses = pod.get('status', {}).get('containerStatuses', [])
    if (pod['spec'].get('nodeName') != node or pod['status'].get('phase') != 'Running'
            or pod['status'].get('qosClass') != 'Guaranteed' or len(statuses) != 1
            or statuses[0].get('ready') is not True or statuses[0].get('restartCount') != 0
            or not statuses[0].get('state', {}).get('running') or statuses[0].get('lastState')
            or not statuses[0].get('containerID', '').startswith('containerd://')
            or not statuses[0].get('imageID')):
        raise ValueError('Density Agent is misplaced, unhealthy or restarted')
    if original and (pod['metadata']['uid'] != original['metadata']['uid']
            or statuses[0]['containerID'] != original['status']['containerStatuses'][0]['containerID']):
        raise ValueError('Density Agent identity changed during measurement')


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

    def reference_seed(self, image, cache, architecture, profile='agent'):
        if profile not in ('agent', 'inference'):
            raise ValueError('Unsupported reference profile')
        payload = self.state / 'payload'
        payload.mkdir()
        source = ROOT / 'src/image/mkosi.extra'
        files = {
            'reference-runtimes.py': ROOT / 'tests/harness/reference-runtimes.py',
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
        if profile == 'agent':
            config += '\n[plugins.\'io.containerd.service.v1.tasks-service\']\n  blockio_config_file = "/run/outerspace/agent-blockio.json"\n'
        (payload / 'containerd.toml').write_text(config)
        (payload / 'profile').write_text(profile + '\n')
        # Reuse the already verified disk bytes, including patched source builds.
        # P2P remains absent from the standard Ubuntu comparison worker.
        run('docker', 'exec', '--user', f'{os.getuid()}:{os.getgid()}', native.RUNNER,
            'python3', '/work/tests/harness/reference-runtimes.py', 'extract',
            '--image', '/state/packaged.raw', '--evidence-directory', '/image',
            '--output', '/state/payload/runtimes', '--components', '/work/src/components.lock.json')
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
        started = self.snapshot(uids)['resources']['uptime_seconds']
        def after_guest_seconds(previous, seconds):
            sample = self.snapshot(uids)['resources']
            return sample if sample['uptime_seconds'] - previous >= seconds else None
        time.sleep(60)
        samples = [wait_for('Settling the comparison worker for 60 guest seconds',
            lambda: after_guest_seconds(started, 60), timeout=600)]
        health = [self.health()]
        for unused in range(3):
            time.sleep(10)
            previous = samples[-1]['uptime_seconds']
            samples.append(wait_for('Sampling after at least ten guest seconds',
                lambda: after_guest_seconds(previous, 10), timeout=180))
            health.append(self.health())
        return {'settle_started_uptime_seconds': started, 'raw': samples, 'health': health,
                'summary': summarize(samples, self.identity['clock_ticks_per_second'], 4)}

    def health(self):
        started = time.monotonic()
        node = self.api('node', self.agent_node)
        conditions = {item['type']: item['status'] for item in node['status']['conditions']}
        if conditions.get('Ready') != 'True' or any(conditions.get(key) != 'False' for key in
                                                   ['MemoryPressure', 'DiskPressure', 'PIDPressure']):
            raise ValueError('Comparison worker became unhealthy: ' + json.dumps(conditions))
        agents = self.api('-n', native.AGENT_NAMESPACE, 'pods')['items']
        expected = {item['pod']['metadata']['uid']: item['pod'] for item in self.launches}
        if {pod['metadata']['uid'] for pod in agents} != set(expected):
            raise ValueError('Density Agent population changed')
        for pod in agents:
            verify_running_agent(pod, self.agent_node, expected[pod['metadata']['uid']])
        if agents:
            self.kube('-n', native.AGENT_NAMESPACE, 'exec', agents[0]['metadata']['name'],
                '--', '/bin/sh', '-ec', 'test "$(id -u)" = 65534; test -w /workspace', timeout=45)
        return {'conditions': conditions, 'responsive_agents': len(agents),
                'api_and_exec_wall_seconds': time.monotonic() - started}

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
            profiles = native.load_script('profiles', native.BUILD_TOOLS)
            if actual != profiles.image_identity('agent', 'cpu', expected['architecture'], expected['commit']):
                raise ValueError('Guest image identity differs from the packaged Agent candidate')
        self.agent_node = name
        self.agent_checks = {}
        self.agent_install()
        self.kube('label', 'node', name, native.AGENT_NODE_LABEL + '=v1')
        self.launches = launches = []
        stages = {'0': self.collect([])}
        for count in range(1, 5):
            obj = json.loads((ROOT / 'src/cluster/agent/workload-v1.json').read_text())
            obj['metadata']['name'] = 'density-' + str(count)
            started = time.monotonic()
            self.apply(obj)
            self.kube('-n', native.AGENT_NAMESPACE, 'wait', '--for=condition=Ready',
                      'pod/' + obj['metadata']['name'], '--timeout=1200s', timeout=1230)
            pod = self.api('-n', native.AGENT_NAMESPACE, 'pod', obj['metadata']['name'])
            verify_running_agent(pod, name)
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
        self.kube('-n', native.AGENT_NAMESPACE, 'delete', 'pod',
            *[item['pod']['metadata']['name'] for item in launches], '--wait=true', '--timeout=120s', timeout=150)
        uids = [item['pod']['metadata']['uid'] for item in launches]
        def removed():
            snapshot = self.snapshot(uids)['resources']
            return snapshot if all(group['path'] is None and not group['processes'] and not group['mounts']
                and not group['workspace_present'] for group in snapshot['pods'].values()) else None
        teardown = wait_for('Checking density workload teardown', removed, timeout=120)
        return {'worker': self.identity, 'node_info': node['status']['nodeInfo'], 'stages': stages, 'launches': launches,
                'platform_pods': pods, 'concurrent_agents': [1, 2, 4], 'teardown': teardown}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-output', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=ROOT / '.cache/ubuntu-reference')
    args = parser.parse_args()
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
        {'identity': metadata, 'sha256sums': digest(bundle / 'SHA256SUMS')},
        development='-dev.' in metadata['version'])
    if digest(ROOT / 'src/components.lock.json') != metadata['components_lock_sha256']:
        raise ValueError('Runtime pins differ from the qualified image')
    image, provenance = signed_image(cache, metadata['architecture'], download=False)
    observations = {}
    for subject in ['outerspace', 'ubuntu']:
        result_dir = output / subject
        result_dir.mkdir(exist_ok=True)
        (result_dir / 'observations.json').unlink(missing_ok=True)
        with tempfile.TemporaryDirectory(prefix='outerspace-comparison-') as temporary:
            os.chmod(temporary, 0o700)
            lab = ComparisonLab(Path(temporary), image_output, result_dir, subject == 'ubuntu')
            try:
                lab.setup()
                config = lab.configure(bootstrap_ttl='2h' if lab.reference else '30m')
                if lab.reference:
                    image, provenance = signed_image(cache, metadata['architecture'])
                    lab.reference_seed(image, cache, metadata['architecture'])
                lab.vm('start', '--config-drive', *(['--ubuntu-reference'] if lab.reference else []))
                observations[subject] = {'configuration': config, **lab.measure()}
                observations[subject]['configuration']['client_signing_duration'] = '10m initial bootstrap; ' + native.LAB_RENEWAL_DURATION + ' renewals (test lab only)'
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
