# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
import copy
import hashlib
import json
from pathlib import Path
import sys

BUILD_TOOLS = Path(__file__).resolve().parents[2] / 'build/tools'
sys.path.insert(0, str(BUILD_TOOLS))
import profiles
import sbom


def idle_record(subject, phase):
    memory = {'MemTotal': 3900 * 1024**2, 'MemAvailable': 3700 * 1024**2,
              'Buffers': 1024, 'Cached': 2048, 'AnonPages': 4096, 'Slab': 8192,
              'SReclaimable': 4096, 'KernelStack': 1024, 'PageTables': 2048, 'Unevictable': 0}
    services = {name: {'memory_current_bytes': 1024**2, 'memory_anon_bytes': 512*1024,
                      'memory_file_bytes': 256*1024, 'memory_kernel_bytes': 256*1024, 'cpu_usage_usec': 10000}
                for name in ['containerd', 'systemd-journald', 'systemd-networkd', 'systemd-resolved', 'outerspace-selftest']}
    return {'schema': 1, **{key: subject[key] for key in ['profile', 'hardware_profile', 'architecture', 'commit']},
            'phase': phase, 'nonce': 'd' * 32, 'hostname': 'oos-idle', 'machine_id': 'e' * 32,
            'boot_id': '11111111-1111-4111-8111-' + ('1' if phase == 'prepare' else '2') * 12,
            'vcpus': 4, 'clock_ticks_per_second': 100, 'settle_started_uptime_seconds': 60,
            'settle_seconds': 60, 'interval_seconds': 10, 'sandboxes': 0, 'containers': 0,
            'kubelet_active': False, 'p2p_active': False,
            'samples': [{'uptime_seconds': 120 + i * 10,
                         'cpu_ticks': [100 + i * 10, 0, 50 + i * 5, 20000 + i * 3985, 100 - i, 0, 0, 0, 25, 0],
                         'memory_bytes': {**memory, 'MemAvailable': memory['MemAvailable'] - i * 1024},
                         'filesystems': {name: {'capacity_bytes': 2 * 1024**3, 'used_bytes': 600 * 1024**2, 'available_bytes': 1024**3}
                                         for name in ['/', '/var']},
                         'services': {key: {**value, 'cpu_usage_usec': value['cpu_usage_usec'] + i * 1000}
                                      for key, value in services.items()}} for i in range(4)]}


def idle_log(subject, phase):
    return profiles.marker(subject) + '\n' + (
        'OUTERSPACE_SELFTEST_OK\nOUTERSPACE_UEFI_OK\n'
        f'OUTERSPACE_PERSISTENCE_{phase.upper()}_OK\nOUTERSPACE_IDLE_HOST ' + json.dumps(idle_record(subject, phase)) + '\n')


def identity(profile='agent', arch=None, version='0.1.0-alpha.1'):
    value = profiles.image_identity(profile, 'cpu', arch or profiles.architecture(), 'a' * 40)
    value['version'] = version
    for field in ['raw_image_sha256', 'uki_sha256', 'verity_root_hash', 'manifest_sha256', 'source_archive_sha256']:
        value[field] = hashlib.sha256(f'{profile}:{value["architecture"]}:{field}'.encode()).hexdigest()
    return value


def qualification(policy):
    evidence = {'schema': 2, 'version': '0.1.0-alpha.1', 'commit': 'a' * 40, 'artifacts': []}
    for selected in policy['artifacts']:
        subject = identity(selected['profile'], selected['architecture'])
        capabilities = policy['profiles'][selected['profile']]['required_capabilities'][:]
        gates = set(policy['stages']['alpha'])
        for capability in capabilities:
            gates.update(policy['capabilities'][capability]['gates'])
        evidence['artifacts'].append({'identity': subject, 'capabilities': capabilities, 'sha256sums': 'b' * 64,
                                     'gates': {gate: {'status': 'passed', 'evidence': 'synthetic-test-only',
                                                      'subject': copy.deepcopy(subject)} for gate in gates}})
    return evidence


def inventory(directory, subject):
    """Small synthetic inventory for exercising candidate integrity boundaries."""
    manifest = {'manifest_version': 1, 'config': {'architecture': subject['architecture'],
        'version': subject['version']}, 'packages': [{'type': 'deb', 'name': 'systemd',
        'version': '255-test', 'architecture': subject['architecture']}]}
    sbom.write_json(directory / 'image.manifest', manifest)
    components = sbom.read_json(profiles.ROOT / 'src/components.lock.json')
    (directory / 'components.lock.json').write_bytes((profiles.ROOT / 'src/components.lock.json').read_bytes())
    subject['manifest_sha256'] = profiles.sha256(directory / 'image.manifest')
    runtimes = [{'component': n, 'version': v, 'artifact': a, 'path': p, 'sha256': 'b' * 64}
                for n, v, a, m, p, archive in sbom.runtime_files(components, subject['architecture'])]
    raw = {'descriptor': {'name': 'syft', 'version': sbom.read_json(sbom.LOCK)['version']},
           'source': {'type': 'directory'}, 'artifacts': [{'type': 'go-module', 'name': 'example.org/library',
               'locations': [{'path': '/usr/bin/containerd'}]}],
           'files': [{'location': {'path': r['path']}, 'metadata': {'type': 'RegularFile'},
                      'digests': [{'algorithm': 'sha256', 'value': r['sha256']}]} for r in runtimes]}
    scan = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'component': {'bom-ref': 'scan-root', 'type': 'file', 'name': 'scan'}},
            'components': [{'bom-ref': 'package-1', 'type': 'library', 'name': 'example.org/library'}],
            'dependencies': [{'ref': 'scan-root', 'dependsOn': ['package-1']}]}
    for name, value in zip(sbom.FILES, [raw, scan, sbom.compose(scan, manifest, subject, runtimes)]):
        sbom.write_json(directory / name, value)
    lock = sbom.read_json(sbom.LOCK)
    evidence = {'schema': 1, 'status': 'inventoried', 'identity': subject,
        'scanner_lock_sha256': profiles.sha256(sbom.LOCK), 'scanner_config_sha256': profiles.sha256(sbom.CONFIG),
        'scanner': {'version': lock['version'], 'architecture': subject['architecture'],
            'artifact': lock['artifacts'][subject['architecture']], 'binary_sha256': 'c' * 64},
        'runtimes': runtimes, 'coverage': sbom.inventory_summary(raw, manifest, components, subject, runtimes),
        'files': {name: profiles.sha256(directory / name) for name in sbom.FILES}}
    sbom.write_json(directory / sbom.REPORT, evidence)
    return sbom.verify_inventory(directory, subject, directory / 'image.manifest', directory / 'components.lock.json')
