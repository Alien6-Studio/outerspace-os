# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Bounded, read-only cgroup snapshot for an authenticated benchmark gateway.

Executed in the lab's trusted observer through Kubernetes exec, never in the
agent or on the OS image. Output contains IDs and counters, not host paths,
process arguments, environment, prompts, logs, or credentials.
"""
import hashlib
from itertools import islice
import json
import os
from pathlib import Path
import re
import resource
import select
import sys
import time

UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
HEX = re.compile(r'[0-9a-f]{64}')
SCHEMA = 'outerspace.phase-probe.v1'
MAX_REQUEST_BYTES = 16384


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
    usage_before = resource.getrusage(resource.RUSAGE_SELF)
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
            # cgroup.procs translates PIDs into the observer's PID namespace;
            # foreign containers appear as 0. Use the host procfs mount, just as
            # the native enrollment probe does. Match kernel-provided cgroup
            # components, including a possible cgroup-namespace-relative prefix.
            def belongs(group):
                parts = group.removeprefix('0::').split('/')
                return ('cri-containerd-' + container + '.scope' in parts and
                        any(part.endswith('pod' + uid.replace('-', '_') + '.slice') for part in parts))
            entries = list(islice((root / 'proc').glob('[0-9]*/cgroup'), 4097))
            if len(entries) > 4096:
                raise ValueError('Host process enumeration budget exceeded')
            for entry in entries:
                try:
                    if not belongs(entry.read_text().strip()):
                        continue
                except (FileNotFoundError, ProcessLookupError):
                    continue  # An unrelated host process can exit at any time.
                try:
                    identity, group = process(root, entry.parent.name)
                    if belongs(group):
                        result['processes'].append(identity)
                        if len(result['processes']) > 128:
                            raise ValueError('Process observation budget exceeded')
                    else:
                        result['gaps'].append('process-moved-during-snapshot')
                except (FileNotFoundError, ProcessLookupError):
                    result['gaps'].append('process-exited-during-snapshot')
            result['processes'].sort(key=lambda p: p['pid'])
            for previous in known:
                try:
                    current, group = process(root, previous['pid'])
                    if current == previous and not belongs(group):
                        result['detached_processes'].append(current)
                except (FileNotFoundError, ProcessLookupError):
                    pass
            if path.stat().st_ino != inode:
                raise ValueError('Cgroup identity changed while reading')
            result['status'] = 'observed'
        except (FileNotFoundError, ProcessLookupError) as exc:
            if path.is_dir():
                counter = Path(exc.filename).name if exc.filename else 'unknown'
                raise ValueError('Kernel lacks required phase accounting counter: ' + counter) from None
            result['status'] = 'lost-during-snapshot'
            result['gaps'].append('cgroup-disappeared')
    result['finished_monotonic_ns'] = time.monotonic_ns()
    usage = resource.getrusage(resource.RUSAGE_SELF)
    # This script runs in a Linux OCI image; ru_maxrss is KiB there.
    result['collector'] = {'cpu_seconds': usage.ru_utime + usage.ru_stime - usage_before.ru_utime - usage_before.ru_stime,
                           'process_cpu_seconds': usage.ru_utime + usage.ru_stime,
                           'peak_rss_bytes': usage.ru_maxrss * 1024,
                           'wall_seconds': (time.monotonic_ns() - started) / 1e9}
    return result


def stream(root, reader, writer):
    """No listener or credentials: the authenticated exec owns this channel."""
    writer.write(json.dumps({'schema': SCHEMA, 'status': 'ready'}) + '\n')
    writer.flush()
    sequence = 0
    while True:
        # Exit abandoned execs even if the transport never delivers EOF.
        deadline, line = time.monotonic() + 900, b''
        while b'\n' not in line:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([reader], [], [], remaining)[0]:
                raise TimeoutError('Phase collector idle deadline exceeded')
            chunk = os.read(reader.fileno(), 4096)
            if not chunk:
                if line:
                    raise ValueError('Truncated phase collector request')
                return
            line += chunk
            if len(line) > MAX_REQUEST_BYTES:
                raise ValueError('Unbounded phase collector request')
        if not line.endswith(b'\n') or line.count(b'\n') != 1:
            raise ValueError('Only one phase request may be in flight')
        message = json.loads(line)
        if (set(message) != {'sequence', 'request'} or type(message['sequence']) is not int
                or message['sequence'] != sequence + 1):
            raise ValueError('Invalid or replayed phase collector request')
        sequence = message['sequence']
        result = {'sequence': sequence, 'observation': snapshot(root, message['request'])}
        writer.write(json.dumps(result, separators=(',', ':'), allow_nan=False) + '\n')
        writer.flush()


if __name__ == '__main__':
    if len(sys.argv) != 2 or len(sys.argv[1]) > 16384:
        raise ValueError('Expected one bounded execution identity')
    if sys.argv[1] == '--stream':
        stream(Path('/host'), sys.stdin.buffer, sys.stdout)
    else:
        print(json.dumps(snapshot(Path('/host'), json.loads(sys.argv[1])), separators=(',', ':')))
