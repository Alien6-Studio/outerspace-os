# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Read-only lab probe. Never output a token or a private key."""
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import sys

root = Path('/host')
state = os.statvfs(root / 'var')
pki = root / 'var/lib/kubelet/pki'
current = pki / 'kubelet-client-current.pem'
target = current.readlink()
if target.name != str(target).split('/')[-1] or '..' in target.parts:
    raise ValueError('Unexpected certificate path')
pem = (pki / target.name).read_text()
certificate = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem, re.S).group()
fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()
shadow = {line.split(':')[0]: line.split(':')[1] for line in (root / 'etc/shadow').read_text().splitlines()}
config = (root / 'var/lib/kubelet/kubeconfig').read_text()
assert 'kubelet-client-current.pem' in config and not re.search(r'^\s*token:', config, re.M)
assert all(shadow[name].startswith(('!', '*')) for name in ['root', 'outerspace'])
observation = {
    'identity': json.loads((root / 'usr/share/outerspace/image-identity.json').read_text()),
    'hostname': (root / 'var/lib/outerspace/hostname').read_text().strip(),
    'machine_id': (root / 'etc/machine-id').read_text().strip(),
    'boot_id': (root / 'proc/sys/kernel/random/boot_id').read_text().strip(),
    'client_certificate_sha256': fingerprint,
    'bootstrap_present': (root / 'var/lib/kubelet/bootstrap-kubeconfig').exists(),
    'accounts_locked': True,
    'state_capacity_bytes': state.f_blocks * state.f_frsize,
    'state_available_bytes': state.f_bavail * state.f_frsize,
}
if len(sys.argv) == 2:
    # Read-only observation from the disposable lab's existing probe workload.
    # These are host cgroups, not the probe container's own /proc or /sys.
    uids = json.loads(sys.argv[1])
    assert isinstance(uids, list) and all(re.fullmatch(r'[a-f0-9-]{36}', uid) for uid in uids)
    cgroup_root = root / 'sys/fs/cgroup'
    files = ['cpu.max', 'cpu.stat', 'memory.max', 'memory.current', 'memory.peak',
             'memory.events', 'pids.max', 'pids.current', 'pids.events', 'cgroup.procs',
             'io.max', 'io.stat', 'io.pressure']
    io_policy = None
    if observation['identity']['profile'] == 'agent':
        policy = json.loads((root / 'run/outerspace/agent-blockio.json').read_text())
        parameters = policy['Classes']['outerspace-agent-v1'][0]
        device = parameters['Devices'][0]
        assert re.fullmatch(r'/dev/[A-Za-z0-9_-]+', device)
        io_policy = {'class': 'outerspace-agent-v1', 'device_path': device,
                     'device': (root / 'sys/class/block' / Path(device).name / 'dev').read_text().strip(),
                     'limits': {key: int(parameters[name]) for key, name in
                         [('rbps', 'ThrottleReadBps'), ('wbps', 'ThrottleWriteBps'),
                          ('riops', 'ThrottleReadIOPS'), ('wiops', 'ThrottleWriteIOPS')]}}
    def read_group(path):
        values = {}
        for name in files:
            try:
                values[name] = (path / name).read_text().strip()
            except FileNotFoundError:
                pass  # A runtime scope can disappear during OOM or teardown.
        return values
    groups = {}
    for uid in uids:
        paths = list((cgroup_root / 'kubepods.slice').rglob('*pod' + uid.replace('-', '_') + '.slice'))
        assert len(paths) <= 1
        workspace = root / 'var/lib/kubelet/pods' / uid
        logs = root / 'var/log/pods'
        log_files = {}
        for directory in logs.glob('*_' + uid):
            for path in directory.rglob('*'):
                try:
                    if path.is_file():
                        log_files[str(path.relative_to(logs))] = path.stat().st_size
                except FileNotFoundError:
                    pass  # The kubelet can rotate a log during this snapshot.
        mounts = [line for line in (root / 'proc/1/mountinfo').read_text().splitlines() if uid in line]
        processes = []
        for path in (root / 'proc').glob('[0-9]*/cgroup'):
            try:
                content = path.read_text()
            except (FileNotFoundError, ProcessLookupError):
                continue
            if uid.replace('-', '_') in content or uid in content:
                processes.append(int(path.parent.name))
        groups[uid] = {'path': str(paths[0].relative_to(cgroup_root)) if paths else None,
                       'files': read_group(paths[0]) if paths else {},
                       'descendants': {str(path.relative_to(paths[0])): read_group(path)
                                       for path in paths[0].rglob('*.scope')} if paths else {},
                       'processes': processes, 'mounts': mounts,
                       'workspace_present': workspace.exists(), 'log_files': log_files,
                       'io_policy': io_policy}
        scratch = workspace / 'volumes/kubernetes.io~empty-dir/scratch'
        if scratch.is_mount():
            fs = os.statvfs(scratch)
            groups[uid]['scratch'] = {'capacity_bytes': fs.f_blocks * fs.f_frsize,
                                      'used_bytes': (fs.f_blocks - fs.f_bfree) * fs.f_frsize}
        result = workspace / 'volumes/kubernetes.io~empty-dir/workspace/result'
        groups[uid]['result'] = result.read_text().strip() if result.is_file() else None
    meminfo = {line.split(':')[0]: int(line.split()[1]) * 1024
               for line in (root / 'proc/meminfo').read_text().splitlines() if line.endswith(' kB')}
    rootfs = os.statvfs(root)
    observation['resources'] = {
        'uptime_seconds': float((root / 'proc/uptime').read_text().split()[0]),
        'cpu_ticks': [int(item) for item in (root / 'proc/stat').read_text().splitlines()[0].split()[1:]],
        'memory_bytes': {key: meminfo[key] for key in ['MemTotal', 'MemAvailable']},
        'rootfs_capacity_bytes': rootfs.f_blocks * rootfs.f_frsize,
        'rootfs_used_bytes': (rootfs.f_blocks - rootfs.f_bfree) * rootfs.f_frsize,
        'services': {name: read_group(cgroup_root / 'system.slice' / (name + '.service'))
                     for name in ['kubelet', 'containerd', 'systemd-journald', 'dfdaemon']},
        'pods': groups,
    }
print(json.dumps(observation))
