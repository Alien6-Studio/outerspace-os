# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Bounded, read-only cgroup snapshot for an authenticated benchmark gateway.

Executed in the lab's trusted observer through Kubernetes exec, never in the
agent or on the OS image. Output contains IDs and counters, not host paths,
process arguments, environment, prompts, logs, or credentials.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import sys
import time

UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
HEX = re.compile(r'[0-9a-f]{64}')


def pairs(text):
    result = {}
    for line in text.splitlines():
        key, value = line.split()
        result[key] = int(value)
    return result


def pressure(text):
    return {line.split()[0]: {k: float(v) if k.startswith('avg') else int(v)
            for k, v in (item.split('=') for item in line.split()[1:])}
            for line in text.splitlines()}


def process(root, pid):
    # stat's comm can contain spaces and parentheses; never export it.
    stat = (root / 'proc' / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
    group = (root / 'proc' / str(pid) / 'cgroup').read_text().strip()
    return {'pid': int(pid), 'start_ticks': int(stat[19])}, group


def snapshot(root, request):
    if set(request) != {'pod_uid', 'container_id', 'known_processes'}:
        raise ValueError('Unsupported snapshot fields')
    uid, container = request['pod_uid'], request['container_id']
    if not UUID.fullmatch(uid) or not HEX.fullmatch(container):
        raise ValueError('Invalid OCI execution identity')
    known = request['known_processes']
    if len(known) > 128 or any(set(p) != {'pid', 'start_ticks'} or
            any(type(v) is not int or v <= 0 for v in p.values()) for p in known):
        raise ValueError('Unbounded process identity request')
    started = time.monotonic_ns()
    boot = (root / 'proc/sys/kernel/random/boot_id').read_text().strip()
    cgroups = root / 'sys/fs/cgroup'
    parents = list((cgroups / 'kubepods.slice').rglob('*pod' + uid.replace('-', '_') + '.slice'))
    if len(parents) > 1:
        raise ValueError('Ambiguous Pod cgroup')
    paths = list(parents[0].rglob('cri-containerd-' + container + '.scope')) if parents else []
    if len(paths) > 1:
        raise ValueError('Ambiguous container cgroup')
    result = {'boot_id': boot, 'pod_uid': uid, 'container_id': container,
              'started_monotonic_ns': started, 'status': 'missing', 'processes': [],
              'detached_processes': [], 'gaps': []}
    if paths:
        path = paths[0]
        try:
            inode = path.stat().st_ino
            result['scope_instance'] = hashlib.sha256((boot + ':' + str(inode)).encode()).hexdigest()
            result['cpu_usec'] = pairs((path / 'cpu.stat').read_text())
            result['memory_current_bytes'] = int((path / 'memory.current').read_text())
            result['memory_lifetime_peak_bytes'] = int((path / 'memory.peak').read_text())
            result['memory_events'] = pairs((path / 'memory.events').read_text())
            stat = pairs((path / 'memory.stat').read_text())
            result['memory_charges_bytes'] = {k: stat[k] for k in ['anon', 'file', 'shmem', 'kernel']}
            result['pressure'] = {name: pressure((path / (name + '.pressure')).read_text())
                                  for name in ['cpu', 'memory', 'io']}
            result['io'] = {line.split()[0]: dict((key, int(value)) for key, value in
                           (field.split('=') for field in line.split()[1:]))
                           for line in (path / 'io.stat').read_text().splitlines()}
            pids = set()
            for group in [path, *path.rglob('*')]:
                if group.is_dir():
                    pids.update((group / 'cgroup.procs').read_text().split())
                    if len(pids) > 128:
                        raise ValueError('Process observation budget exceeded')
            relative = '/' + str(path.relative_to(cgroups))
            for pid in sorted(pids, key=int):
                try:
                    identity, group = process(root, pid)
                    if group.removeprefix('0::') == relative or group.removeprefix('0::').startswith(relative + '/'):
                        result['processes'].append(identity)
                    else:
                        result['gaps'].append('process-moved-during-snapshot')
                except (FileNotFoundError, ProcessLookupError):
                    result['gaps'].append('process-exited-during-snapshot')
            for previous in known:
                try:
                    current, group = process(root, previous['pid'])
                    if current == previous and not (group.removeprefix('0::') == relative or
                                                    group.removeprefix('0::').startswith(relative + '/')):
                        result['detached_processes'].append(current)
                except (FileNotFoundError, ProcessLookupError):
                    pass
            if path.stat().st_ino != inode:
                raise ValueError('Cgroup identity changed while reading')
            result['status'] = 'observed'
        except (FileNotFoundError, ProcessLookupError):
            result['status'] = 'lost-during-snapshot'
            result['gaps'].append('cgroup-disappeared')
    result['finished_monotonic_ns'] = time.monotonic_ns()
    usage = resource.getrusage(resource.RUSAGE_SELF)
    # This script runs in a Linux OCI image; ru_maxrss is KiB there.
    result['collector'] = {'cpu_seconds': usage.ru_utime + usage.ru_stime,
                           'peak_rss_bytes': usage.ru_maxrss * 1024,
                           'wall_seconds': (time.monotonic_ns() - started) / 1e9}
    return result


if __name__ == '__main__':
    if len(sys.argv) != 2 or len(sys.argv[1]) > 16384:
        raise ValueError('Expected one bounded execution identity')
    print(json.dumps(snapshot(Path('/host'), json.loads(sys.argv[1])), separators=(',', ':')))
