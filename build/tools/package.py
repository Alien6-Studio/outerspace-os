#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Package a verified build with its exact input identity and SHA256 inventory."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import uuid
from profiles import PROFILES, HARDWARE, marker, verify_identity
from sbom import FILES as SBOM_FILES, REPORT as SBOM_REPORT, verify_inventory

ROOT = Path(__file__).resolve().parents[2]


IDLE_MEMORY = {'MemTotal', 'MemAvailable', 'Buffers', 'Cached', 'AnonPages', 'Slab',
               'SReclaimable', 'KernelStack', 'PageTables', 'Unevictable'}
IDLE_SERVICES = {'containerd', 'systemd-journald', 'systemd-networkd', 'systemd-resolved',
                 'outerspace-selftest'}
IDLE_POLICY = ROOT / 'tests/benchmarks/idle-host.lock.json'


def idle_host_budget(baseline, identity):
    """Fail closed on an unsupported reference or a regression in either cold boot."""
    policy = json.loads(IDLE_POLICY.read_text())
    key = '-'.join(identity[field] for field in ['profile', 'hardware_profile', 'architecture'])
    if (policy.get('schema') != 1 or baseline.get('reference') != policy['reference']
            or key not in policy['budgets'] or set(baseline.get('boots', {})) != {'prepare', 'verify'}):
        raise ValueError('No qualified idle-host regression budget for this reference')
    budget = policy['budgets'][key]
    derivation = policy['derivation']
    quantum = derivation['memory_round_up_bytes']
    memory = math.ceil(budget['memory_max_bytes'] * derivation['memory_factor'] / quantum) * quantum
    quantum = derivation['cpu_round_up_percent']
    cpu = math.ceil(budget['cpu_max_percent'] * derivation['cpu_factor'] / quantum) * quantum
    if memory != budget['memory_limit_bytes'] or cpu != budget['cpu_limit_percent']:
        raise ValueError('Idle-host budget differs from its documented derivation')
    thresholds = {'memory_unavailable_bytes': memory, 'guest_busy_cpu_percent': cpu}
    for boot in baseline['boots'].values():
        if any(type(boot[name]['max']) not in (int, float) or not math.isfinite(boot[name]['max'])
               or not 0 <= boot[name]['max'] <= limit for name, limit in thresholds.items()):
            raise ValueError('Idle-host regression budget exceeded: ' + json.dumps({'boot': boot, 'limits': thresholds}))
    observed = {name: max(boot[name]['max'] for boot in baseline['boots'].values()) for name in thresholds}
    return {'schema': 1, 'status': 'passed', 'policy_sha256': sha256(IDLE_POLICY), 'budget': key,
            'observed_max': observed, 'limits': thresholds}


def idle_host_report(logs, identity):
    """Derive measurements from both source-bound guest logs; never trust a summary."""
    def integer(value):
        if type(value) is not int or value < 0:
            raise ValueError('Idle host requires nonnegative integer counters')
        return value

    def number(value):
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError('Idle host requires finite nonnegative timestamps')
        return value

    def summary(values):
        return {'samples': len(values), 'min': min(values), 'median': statistics.median(values), 'max': max(values)}

    def fields(value, required):
        if type(value) is not dict or not set(required) <= set(value):
            raise ValueError('Idle host record is incomplete')

    boots = {}
    for phase in ['prepare', 'verify']:
        records = [line.split('OUTERSPACE_IDLE_HOST ', 1)[1] for line in logs[phase].splitlines()
                   if 'OUTERSPACE_IDLE_HOST ' in line]
        if len(records) != 1:
            raise ValueError('Idle host requires exactly one complete record per boot')
        record = json.loads(records[0])
        fields(record, ['schema', 'nonce', 'hostname', 'machine_id', 'boot_id', 'clock_ticks_per_second',
                        'settle_started_uptime_seconds', 'samples'])
        expected = {'schema': 1, 'phase': phase, 'vcpus': 4, 'settle_seconds': 60,
                    'interval_seconds': 10, 'sandboxes': 0, 'containers': 0, 'kubelet_active': False, 'p2p_active': False,
                    **{key: identity[key] for key in ['profile', 'hardware_profile', 'architecture', 'commit']}}
        if any(type(record.get(key)) is not type(value) or record[key] != value for key, value in expected.items()):
            raise ValueError('Idle host identity, reference or empty-workload state differs')
        if (not re.fullmatch('[a-f0-9]{32}', record['nonce'])
                or not re.fullmatch('[a-f0-9]{32}', record['machine_id'])
                or not re.fullmatch('[A-Za-z0-9.-]+', record['hostname'])
                or str(uuid.UUID(record['boot_id'])) != record['boot_id']):
            raise ValueError('Idle host has an invalid boot identity')
        ticks_per_second = integer(record['clock_ticks_per_second'])
        if not ticks_per_second:
            raise ValueError('Idle host CPU clock frequency is missing')
        samples = record['samples']
        if type(samples) is not list or len(samples) != 4:
            raise ValueError('Idle host requires four samples and three intervals per boot')
        for sample in samples:
            fields(sample, ['uptime_seconds', 'cpu_ticks', 'memory_bytes', 'filesystems', 'services'])
            number(sample['uptime_seconds'])
            if len(sample['cpu_ticks']) != 10:
                raise ValueError('Idle host CPU counters are incomplete')
            for value in sample['cpu_ticks']:
                integer(value)
            memory = sample['memory_bytes']
            fields(memory, IDLE_MEMORY)
            for value in memory.values():
                integer(value)
            if set(memory) != IDLE_MEMORY or any(v > memory['MemTotal'] for v in memory.values()):
                raise ValueError('Idle host memory counters are incomplete or impossible')
            if not 3 * 1024**3 <= memory['MemTotal'] <= 4 * 1024**3:
                raise ValueError('Idle host memory does not match the four-GiB reference')
            if set(sample['filesystems']) != {'/', '/var'}:
                raise ValueError('Idle host filesystem counters are incomplete')
            for filesystem in sample['filesystems'].values():
                fields(filesystem, ['capacity_bytes', 'used_bytes', 'available_bytes'])
                if set(filesystem) != {'capacity_bytes', 'used_bytes', 'available_bytes'}:
                    raise ValueError('Idle host filesystem counters are incomplete')
                for value in filesystem.values():
                    integer(value)
                if any(v > filesystem['capacity_bytes'] for v in filesystem.values()):
                    raise ValueError('Idle host filesystem counters are impossible')
            services = sample['services']
            if set(services) != IDLE_SERVICES or any(services[key] is None for key in
                                                    ['containerd', 'systemd-journald', 'outerspace-selftest']):
                raise ValueError('Idle host runtime or observer accounting is missing')
            for service in services.values():
                if service is not None:
                    if set(service) != {'memory_current_bytes', 'memory_anon_bytes', 'memory_file_bytes', 'memory_kernel_bytes', 'cpu_usage_usec'}:
                        raise ValueError('Idle host service accounting is incomplete')
                    for value in service.values():
                        integer(value)
        if samples[0]['uptime_seconds'] - number(record['settle_started_uptime_seconds']) + 1e-6 < 60:
            raise ValueError('Idle host stabilization was shortened')
        if len({sample['memory_bytes']['MemTotal'] for sample in samples}) != 1:
            raise ValueError('Idle host memory changed during measurement')
        intervals = []
        for before, after in zip(samples, samples[1:]):
            elapsed = after['uptime_seconds'] - before['uptime_seconds']
            if elapsed + 1e-6 < 10:
                raise ValueError('Idle host observation interval was shortened')
            # user/nice/system/irq/softirq; guest is already in user, and
            # idle/iowait/steal do not measure CPU work performed by this OS.
            busy_ticks = sum(after['cpu_ticks'][i] - before['cpu_ticks'][i] for i in [0, 1, 2, 5, 6])
            busy_seconds = busy_ticks / ticks_per_second
            percent = 100 * busy_seconds / (elapsed * record['vcpus'])
            if busy_ticks < 0 or not 0 <= percent <= 100:
                raise ValueError('Idle host CPU counters regressed or exceed the reference')
            services = {}
            for service in sorted(IDLE_SERVICES):
                a, b = before['services'][service], after['services'][service]
                services[service] = None if a is None or b is None else (b['cpu_usage_usec'] - a['cpu_usage_usec']) / 1e6
                if services[service] is not None and services[service] < 0:
                    raise ValueError('Idle host service restarted during measurement')
            intervals.append({'elapsed_guest_seconds': elapsed, 'guest_busy_cpu_seconds': busy_seconds,
                              'guest_busy_cpu_percent': percent, 'service_cpu_seconds': services})
        boots[phase] = {'raw': record, 'intervals': intervals,
                        'memory_unavailable_bytes': summary([s['memory_bytes']['MemTotal'] - s['memory_bytes']['MemAvailable'] for s in samples]),
                        'guest_busy_cpu_percent': summary([item['guest_busy_cpu_percent'] for item in intervals])}
    a, b = boots['prepare']['raw'], boots['verify']['raw']
    if any(a[key] != b[key] for key in ['nonce', 'hostname', 'machine_id', 'clock_ticks_per_second']) or a['boot_id'] == b['boot_id']:
        raise ValueError('Idle host measurements do not prove two boots of the same worker')
    return {'schema': 1, 'status': 'observed', 'reference': {'vcpus': 4, 'memory_mib': 4096, 'acceleration': 'QEMU TCG'},
            'boots': boots,
            'limits': ['Unconfigured host: CRI running, no kubelet, CNI, P2P peer, Agent or model workload',
                       'Existing opt-in selftest observer is included; its cgroup is reported, not subtracted',
                       'Guest CPU counters and MemTotal minus MemAvailable; not physical host CPU or process RSS',
                       'Two cold guest boots, three intervals each; not cold physical storage or a statistical capacity claim',
                       'No matched Ubuntu worker, physical-hardware comparison, density claim or performance threshold']}


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_boot_report(output, profile, hardware, commit):
    identity = verify_identity(output, profile, hardware, commit)
    report = json.loads((output / 'uefi-smoke.json').read_text())
    if (report.get('schema') != 2 or report.get('status') != 'passed'
            or report.get('power_cycles') != 2
            or report.get('identity') != identity
            or report.get('image_sha256') != sha256(output / 'outerspace.raw')):
        raise ValueError('UEFI evidence must bind two successful boots to this exact disk')
    content = (output / 'boot-smoke.log').read_text(errors='replace')
    required = ['OUTERSPACE_SELFTEST_OK', 'OUTERSPACE_UEFI_OK',
                'OUTERSPACE_PERSISTENCE_PREPARE_OK', 'OUTERSPACE_PERSISTENCE_VERIFY_OK']
    if 'OUTERSPACE_SELFTEST_FAIL' in content or any(marker not in content for marker in required):
        raise ValueError('Complete UEFI and persistence boot logs are required')
    for name in ['boot-smoke.log', 'boot-uefi-prepare.log', 'boot-uefi-verify.log']:
        path = output / name
        if path.is_symlink() or report.get('logs', {}).get(name) != sha256(path):
            raise ValueError('Boot evidence log integrity failure')
        if marker(identity) not in path.read_text(errors='replace'):
            raise ValueError('Boot log belongs to another profile/source')
    baseline = idle_host_report({phase: (output / f'boot-uefi-{phase}.log').read_text(errors='replace')
                                 for phase in ['prepare', 'verify']}, identity)
    if report.get('idle_host') != baseline:
        raise ValueError('Idle host report differs from the source-bound boot logs')
    if report.get('host_regression') != idle_host_budget(baseline, identity):
        raise ValueError('Idle-host regression evidence is missing or altered')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('/out'))
    parser.add_argument('--commit', required=True)
    parser.add_argument('--profile', required=True, choices=PROFILES)
    parser.add_argument('--hardware', default='cpu', choices=HARDWARE)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.commit):
        parser.error('commit must be a full Git SHA')
    output = args.output
    log = output / 'boot-smoke.log'
    try:
        boot_report = verify_boot_report(output, args.profile, args.hardware, args.commit)
    except (ValueError, OSError) as error:
        parser.error(f'Cannot package unqualified disk: {error}')
    identity = boot_report['identity']
    supply_chain = verify_inventory(output, identity, output / 'outerspace.manifest', ROOT / 'src/components.lock.json')
    arch = identity['architecture']
    version = (ROOT / 'VERSION').read_text().strip()
    bundle = output / f'outerspace-{version}-{args.profile}-{args.hardware}-{arch}'
    bundle.mkdir(exist_ok=False)
    stem = bundle / bundle.name
    subprocess.run(['zstd', '-T0', '-q', str(output / 'outerspace.raw'), '-o', str(stem) + '.raw.zst'], check=True)
    for extension in ['efi', 'manifest']:
        shutil.copyfile(output / f'outerspace.{extension}', Path(str(stem) + '.' + extension))
    shutil.copyfile(log, bundle / 'boot-smoke.log')
    shutil.copyfile(output / 'uefi-smoke.json', bundle / 'uefi-smoke.json')
    shutil.copyfile(output / 'build-identity.json', bundle / 'build-identity.json')
    for phase in ['prepare', 'verify']:
        shutil.copyfile(output / f'boot-uefi-{phase}.log', bundle / f'boot-uefi-{phase}.log')
    shutil.copyfile(ROOT / 'src/components.lock.json', bundle / 'components.lock.json')
    shutil.copyfile(IDLE_POLICY, bundle / 'idle-host.lock.json')
    for name in (*SBOM_FILES, SBOM_REPORT):
        shutil.copyfile(output / name, bundle / name)
    shutil.copyfile(ROOT / 'build/sbom/syft.lock.json', bundle / 'syft.lock.json')
    shutil.copyfile(ROOT / 'build/sbom/syft.yaml', bundle / 'syft.yaml')
    subprocess.run(['zstd', '-q', str(output / 'outerspace-source.tar'), '-o', str(bundle / 'source.tar.zst')], check=True)
    metadata = {'schema': 2, 'identity': identity,
                'channel': 'development' if '-dev.' in version else 'candidate',
                'boot_test': 'QEMU UEFI disk boot and state/identity persistence across two power cycles; Secure Boot disabled',
                'raw_image_sha256': boot_report['image_sha256'],
                'ubuntu_inputs': 'signed Noble repositories, not snapshot-locked',
                'manifest_sha256': sha256(output / 'outerspace.manifest'),
                'components_lock_sha256': sha256(ROOT / 'src/components.lock.json'),
                'host_regression': boot_report['host_regression'],
                'supply_chain': supply_chain,
                'files': {p.name: sha256(p) for p in sorted(bundle.iterdir())}}
    (bundle / 'build-metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    files = sorted(bundle.iterdir())
    (bundle / 'SHA256SUMS').write_text(''.join(f'{sha256(p)}  {p.name}\n' for p in files))
    print(bundle)


if __name__ == '__main__':
    main()
