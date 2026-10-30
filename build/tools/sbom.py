#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Inventory the final read-only disk; bind observed software to each candidate."""
import argparse
from collections import Counter
from contextlib import contextmanager
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
from urllib.parse import quote
import runtime_build
import go_runtime_build

from profiles import ROOT, architecture, sha256, verify_identity

LOCK = ROOT / 'build/sbom/syft.lock.json'
CONFIG = ROOT / 'build/sbom/syft.yaml'
FILES = ('sbom.syft.json', 'sbom.scan.cdx.json', 'sbom.cdx.json')
REPORT = 'sbom-evidence.json'
HEX = re.compile('[a-f0-9]{64}')


def read_json(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Inventory input must be a regular file: ' + str(path))
    return json.loads(path.read_text())


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, capture_output=True, text=True, **kwargs)


def partitions(table, size, architecture):
    """Only the known whole-image layout is supported; never mount arbitrary paths."""
    types = {'esp': 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b',
             'OOS_STATE': '0fc63daf-8483-4772-8e79-3d69d8477de4',
             'OOS_ROOT': {'amd64': '4f68bce3-e8cd-4db1-96e7-fbcaf984b709',
                          'arm64': 'b921b045-1df0-41c3-af44-4c6f280d3fae'}[architecture],
             'OOS_VERITY': {'amd64': '2c7357ed-ebd2-46d9-aec1-23d437ec2bf5',
                            'arm64': 'df3300ce-d69f-4c92-978c-9bfb0f38d820'}[architecture]}
    entries = table['partitions']
    if (table.get('label') != 'gpt' or table.get('unit') != 'sectors'
            or table.get('sectorsize') != 512 or len(entries) != 4
            or {p['name'] for p in entries} != set(types)):
        raise ValueError('Unsupported SBOM disk layout')
    end = 34 * 512
    for p in sorted(entries, key=lambda p: p['start']):
        if (type(p['start']) is not int or type(p['size']) is not int or p['size'] <= 0
                or p['start'] * 512 < end or (p['start'] + p['size']) * 512 > size - 33 * 512
                or p['type'].lower() != types[p['name']]):
            raise ValueError('Invalid SBOM disk partition')
        end = (p['start'] + p['size']) * 512
    return {p['name']: {'offset': p['start'] * 512, 'size': p['size'] * 512} for p in entries}


@contextmanager
def mounted_image(image, architecture):
    table = json.loads(run('sfdisk', '--json', image).stdout)['partitiontable']
    layout = partitions(table, image.stat().st_size, architecture)
    with tempfile.TemporaryDirectory(prefix='outerspace-sbom-mount-') as directory:
        root = Path(directory)
        mounts = []
        try:
            for name, target, filesystem in [('OOS_ROOT', root, 'ext4'),
                                              ('OOS_STATE', root / 'var', 'ext4'),
                                              ('esp', root / 'efi', 'vfat')]:
                if target.is_symlink() or not target.is_dir():
                    raise ValueError('Unsafe image mountpoint')
                p = layout[name]
                options = f'ro,nodev,nosuid,noexec,loop,offset={p["offset"]},sizelimit={p["size"]}'
                if filesystem == 'ext4':
                    options += ',noload'
                run('mount', '-t', filesystem, '-o', options, image, target)
                mounts.append(target)
            yield root, layout
        finally:
            # Reverse order and attempt every unmount, even after one failure.
            failures = []
            for target in reversed(mounts):
                try:
                    run('umount', target)
                except subprocess.CalledProcessError as error:
                    failures.append(error)
            if failures:
                raise RuntimeError('SBOM image cleanup failed') from failures[0]


def runtime_files(components, architecture):
    for name, component in sorted(components['components'].items()):
        artifact = component['artifacts'][architecture]
        binaries = artifact.get('binaries', component.get('binaries'))
        for member in binaries or [name]:
            yield name, component['version'], artifact, member, '/usr/bin/' + Path(member).name, bool(binaries)


def verified_runtimes(root, components, architecture, cache, output=None):
    result = []
    for name, version, artifact, member, path, archive in runtime_files(components, architecture):
        if artifact.get('source_build'):
            if name not in ['dfdaemon', 'crictl'] or output is None:
                raise ValueError('Missing source runtime build evidence')
            builder = runtime_build if name == 'dfdaemon' else go_runtime_build
            receipt = builder.verify_receipt(output, architecture, packaged=True)
            installed = root / path.lstrip('/')
            if (installed.is_symlink() or not installed.resolve().is_relative_to(root.resolve())
                    or sha256(installed) != receipt['binary_sha256']
                    or (name == 'dfdaemon' and runtime_build.audit_data(installed, architecture) != receipt['dependencies'])):
                raise ValueError('Installed runtime differs from verified source build')
            result.append({'component': name, 'version': version, 'path': path,
                           'sha256': receipt['binary_sha256'], 'artifact': artifact})
            continue
        source = cache / artifact['sha256']
        if source.is_symlink() or not source.is_file() or sha256(source) != artifact['sha256']:
            raise ValueError('Runtime cache differs from approved input: ' + name)
        if archive:
            with tarfile.open(source) as tar:
                entries = [m for m in tar if m.name == member]
                if len(entries) != 1 or not entries[0].isfile():
                    raise ValueError('Invalid runtime archive: ' + name)
                with tar.extractfile(entries[0]) as stream:
                    expected = hashlib.file_digest(stream, 'sha256').hexdigest()
        else:
            expected = artifact['sha256']
        installed = root / path.lstrip('/')
        if (installed.is_symlink() or not installed.resolve().is_relative_to(root.resolve())
                or sha256(installed) != expected):
            raise ValueError('Installed runtime differs from approved input: ' + path)
        result.append({'component': name, 'version': version, 'path': path, 'sha256': expected,
                       'artifact': artifact})
    return result


def inventory_summary(raw, manifest, components, identity, runtimes):
    lock = read_json(LOCK)
    if (raw.get('descriptor', {}).get('name') != 'syft'
            or raw['descriptor'].get('version') != lock['version']
            or raw.get('source', {}).get('type') != 'directory'
            or not raw.get('artifacts') or not raw.get('files')):
        raise ValueError('Missing or unexpected scanner inventory')
    if (manifest.get('manifest_version') != 1 or not manifest.get('packages')
            or architecture(manifest['config']['architecture']) != identity['architecture']
            or manifest['config']['version'] != identity['version']):
        raise ValueError('Package manifest does not match the image')
    packages = [(p['name'], p['version'], p['architecture']) for p in manifest['packages']]
    if (len(set(packages)) != len(packages) or any(p.get('type') != 'deb' for p in manifest['packages'])
            or any(a not in ['all', identity['architecture']] or not n or not v for n, v, a in packages)):
        raise ValueError('Invalid package manifest')
    expected = [(n, v, a, p) for n, v, a, m, p, archive in runtime_files(components, identity['architecture'])]
    actual = [(r['component'], r['version'], r['artifact'], r['path']) for r in runtimes]
    if actual != expected:
        raise ValueError('Runtime inventory differs from locked components')
    files = {f['location']['path']: f for f in raw['files']}
    if len(files) != len(raw['files']):
        raise ValueError('Duplicate scanner file path')
    dependencies = {}
    for r in runtimes:
        f = files.get(r['path'], {})
        if (not HEX.fullmatch(r['sha256']) or f.get('metadata', {}).get('type') != 'RegularFile'
                or {'algorithm': 'sha256', 'value': r['sha256']} not in f.get('digests', [])):
            raise ValueError('Runtime hash missing from disk scan: ' + r['path'])
        dependencies[r['path']] = sum(1 for p in raw['artifacts']
            if p['type'] in ['go-module', 'rust-crate'] and any(l['path'] == r['path'] for l in p['locations']))
    return {'apt_packages': len(packages), 'scanner_packages_by_type': dict(sorted(Counter(
            p['type'] for p in raw['artifacts']).items())), 'files': len(files),
            'runtime_embedded_dependencies': dependencies,
            'runtime_dependency_gaps': [p for p, count in dependencies.items() if count == 0],
            'complete_dependency_graph': False, 'license_review': 'pending',
            'vulnerability_review': 'pending', 'corresponding_source_review': 'pending'}


def compose(scan, manifest, identity, runtimes):
    if scan.get('bomFormat') != 'CycloneDX' or scan.get('specVersion') != '1.6' or not scan.get('components'):
        raise ValueError('Expected a nonempty CycloneDX 1.6 scan')
    result = copy.deepcopy(scan)
    root_ref = 'outerspace:image:' + identity['raw_image_sha256']
    old_ref = result['metadata']['component']['bom-ref']
    result['metadata']['component'] = {'type': 'operating-system', 'bom-ref': root_ref,
        'name': 'outerspace-' + identity['profile'], 'version': identity['version'],
        'hashes': [{'alg': 'SHA-256', 'content': identity['raw_image_sha256']}],
        'properties': [{'name': 'outerspace:' + k, 'value': str(v)} for k, v in identity.items()
                       if isinstance(v, (str, int))]}
    for dep in result.get('dependencies', []):
        if dep['ref'] == old_ref:
            dep['ref'] = root_ref
        dep['dependsOn'] = [root_ref if ref == old_ref else ref for ref in dep.get('dependsOn', [])]
    # mkosi removes dpkg metadata from the final image. Preserve its exact,
    # independently hash-bound installed inventory, not ELF-note guesses.
    for p in manifest['packages']:
        purl = f'pkg:deb/ubuntu/{quote(p["name"], safe="")}@{quote(p["version"], safe="")}?' + \
               f'arch={p["architecture"]}&distro=ubuntu-24.04'
        result['components'].append({'type': 'library', 'bom-ref': 'outerspace:apt:' + purl,
            'name': p['name'], 'version': p['version'], 'purl': purl,
            'properties': [{'name': 'outerspace:inventory-source', 'value': 'mkosi-installed-manifest'},
                           {'name': 'outerspace:architecture', 'value': p['architecture']}]})
    for r in runtimes:
        ref = 'outerspace:runtime:' + r['path']
        result['components'].append({'type': 'application', 'bom-ref': ref,
            'name': Path(r['path']).name, 'version': r['version'],
            'hashes': [{'alg': 'SHA-256', 'content': r['sha256']}],
            'externalReferences': [{'type': 'distribution', 'url': r['artifact']['url'],
                'hashes': [{'alg': 'SHA-256', 'content': r['artifact']['sha256']}]}],
            'properties': [{'name': 'outerspace:runtime-component', 'value': r['component']},
                           {'name': 'outerspace:installed-path', 'value': r['path']}]})
    refs = [c['bom-ref'] for c in result['components']]
    if len(refs) != len(set(refs)) or root_ref in refs:
        raise ValueError('Duplicate SBOM component identity')
    # Containment is deliberately not a claim of a complete dependency graph.
    result['compositions'] = [{'aggregate': 'incomplete', 'assemblies': [root_ref]}]
    result['metadata'].setdefault('properties', []).append({
        'name': 'outerspace:coverage', 'value': 'Observed software plus installed APT manifest; '
        'embedded dependency discovery is partial. Licenses, source and vulnerabilities require separate review.'})
    return result


def verify_inventory(directory, identity, manifest_path, components_path):
    evidence = read_json(directory / REPORT)
    if (evidence.get('schema') != 1 or evidence.get('status') != 'inventoried'
            or evidence.get('identity') != identity
            or evidence.get('scanner_lock_sha256') != sha256(LOCK)
            or evidence.get('scanner_config_sha256') != sha256(CONFIG)
            or set(evidence.get('files', {})) != set(FILES)):
        raise ValueError('SBOM evidence does not match this image or scanner policy')
    for name in FILES:
        path = directory / name
        if path.is_symlink() or not path.is_file() or sha256(path) != evidence['files'][name]:
            raise ValueError('SBOM file integrity failure: ' + name)
    if sha256(manifest_path) != identity['manifest_sha256'] or sha256(components_path) != identity['components_lock_sha256']:
        raise ValueError('SBOM source inventory integrity failure')
    manifest, components = read_json(manifest_path), read_json(components_path)
    raw = read_json(directory / FILES[0])
    summary = inventory_summary(raw, manifest, components, identity, evidence['runtimes'])
    if summary != evidence['coverage']:
        raise ValueError('SBOM coverage differs from raw inventory')
    expected = compose(read_json(directory / FILES[1]), manifest, identity, evidence['runtimes'])
    if expected != read_json(directory / FILES[2]):
        raise ValueError('SBOM document differs from its bound inputs')
    receipt = evidence['scanner']
    lock = read_json(LOCK)
    if (receipt['version'] != lock['version'] or receipt['architecture'] != identity['architecture']
            or receipt['artifact'] != lock['artifacts'][identity['architecture']]
            or not HEX.fullmatch(receipt['binary_sha256'])):
        raise ValueError('Scanner differs from pinned input')
    return {'evidence_sha256': sha256(directory / REPORT), 'cyclonedx_sha256': evidence['files'][FILES[2]],
            'coverage': summary}


def generate(output, destination, profile, hardware, commit, cache):
    identity = verify_identity(output, profile, hardware, commit)
    scanner = Path('/usr/local/bin/syft')
    receipt = read_json(scanner.with_suffix('.json'))
    lock = read_json(LOCK)
    if (receipt['version'] != lock['version'] or receipt['architecture'] != identity['architecture']
            or receipt['artifact'] != lock['artifacts'][identity['architecture']]
            or receipt['binary_sha256'] != sha256(scanner)):
        raise ValueError('Rebuild the builder with the pinned scanner')
    # Atomic completion marker; a failed regeneration must not leave old success.
    destination.mkdir(parents=True, exist_ok=True)
    (destination / REPORT).unlink(missing_ok=True)
    components_path = ROOT / 'src/components.lock.json'
    components = read_json(components_path)
    manifest = read_json(output / 'outerspace.manifest')
    with tempfile.TemporaryDirectory(prefix='outerspace-sbom-output-') as directory:
        staging = Path(directory)
        with mounted_image(output / 'outerspace.raw', identity['architecture']) as (root, layout):
            embedded = read_json(root / 'usr/share/outerspace/image-identity.json')
            if any(identity.get(k) != v for k, v in embedded.items()) or not embedded:
                raise ValueError('Mounted disk identity differs from the candidate')
            runtimes = verified_runtimes(root, components, identity['architecture'], cache, output)
            # Explicit config plus a minimal environment; no developer override,
            # registry access, update check or external license lookup is allowed.
            run(scanner, 'scan', 'dir:' + str(root), '--config', CONFIG,
                '--source-name', 'outerspace-' + profile, '--source-version', identity['version'],
                '-o', 'syft-json=' + str(staging / FILES[0]),
                '-o', 'cyclonedx-json@1.6=' + str(staging / FILES[1]),
                env={'PATH': '/usr/bin:/bin', 'HOME': directory, 'LANG': 'C.UTF-8'}, timeout=900)
        # Ensure the readonly scan did not mutate the image or input identity.
        if verify_identity(output, profile, hardware, commit) != identity:
            raise ValueError('Image changed during inventory')
        raw = read_json(staging / FILES[0])
        summary = inventory_summary(raw, manifest, components, identity, runtimes)
        write_json(staging / FILES[2], compose(read_json(staging / FILES[1]), manifest, identity, runtimes))
        evidence = {'schema': 1, 'status': 'inventoried', 'identity': identity,
            'scanner': receipt, 'scanner_lock_sha256': sha256(LOCK), 'scanner_config_sha256': sha256(CONFIG),
            'partitions': layout, 'runtimes': runtimes, 'coverage': summary,
            'files': {name: sha256(staging / name) for name in FILES}}
        write_json(staging / REPORT, evidence)
        verify_inventory(staging, identity, output / 'outerspace.manifest', components_path)
        for name in (*FILES, REPORT):
            # Temporary outputs and destination may live on different filesystems.
            temporary = destination / (name + '.partial')
            with (staging / name).open('rb') as source, temporary.open('xb') as target:
                shutil.copyfileobj(source, target)
            temporary.replace(destination / name)
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--destination', type=Path)
    parser.add_argument('--profile', required=True)
    parser.add_argument('--hardware', default='cpu')
    parser.add_argument('--commit', required=True)
    parser.add_argument('--cache', type=Path, default=Path('/cache/components'))
    args = parser.parse_args()
    generate(args.output, args.destination or args.output, args.profile, args.hardware, args.commit, args.cache)
