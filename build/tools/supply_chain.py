#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Bind preserved APT metadata and declared source dependencies to the disk scan."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import quote

from profiles import ROOT, sha256
from sbom import read_json, write_json, verify_inventory, compose

spec = importlib.util.spec_from_file_location('source_bundle', ROOT / 'build/tools/source-bundle.py')
sources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sources)

FILES = ('apt-inputs.json', 'apt-notices.tar', 'apt.sbom.syft.json', 'source-index.json',
         'corresponding-source.tar.zst', 'distribution.sbom.syft.json', 'distribution.sbom.cdx.json',
         'build-provenance.json', 'builder-packages.tsv')
REPORT = 'supply-chain.json'
POLICIES = {'inputs.lock.json': ROOT / 'build/inputs.lock.json',
            'apt.sources': ROOT / 'build/apt.sources',
            'cyclonedx-1.6-licenses.json': ROOT / 'build/sbom/cyclonedx-1.6-licenses.json',
            'sources.lock.json': ROOT / 'build/sbom/sources.lock.json'}


def schema_licenses(document):
    """Preserve newer SPDX identifiers as names when the selected schema lacks them."""
    supported = set(read_json(POLICIES['cyclonedx-1.6-licenses.json'])['ids'])
    result = copy.deepcopy(document)
    def visit(value):
        if isinstance(value, dict):
            license = value.get('license')
            if isinstance(license, dict) and 'id' in license and license['id'] not in supported:
                license['name'] = license.pop('id')
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(result)
    return result


def apt_inventory(apt, manifest, native):
    def packages(items):
        values = [(p['name'], p['version'], p['architecture']) for p in items]
        if len(set(values)) != len(values):
            raise ValueError('Duplicate installed package')
        return set(values)
    expected = packages(manifest['packages'])
    if packages(apt['packages']) != expected:
        raise ValueError('Preserved APT inventory differs from final manifest')
    observed = [(p['name'], p['version'], p['metadata']['architecture']) for p in native['artifacts']]
    if set(observed) != expected or len(observed) != len(expected):
        raise ValueError('Native APT inventory differs from final manifest')
    metadata = {p['name']: p for p in apt['packages']}
    source_keys = {(s['name'], s['version']) for s in apt['sources']}
    for p in native['artifacts']:
        installed = metadata[p['name']]
        if p['type'] != 'deb' or (installed['source'], installed['source_version']) not in source_keys:
            raise ValueError('APT corresponding source is missing')
        m = p['metadata']
        if (m.get('source') or p['name'], m.get('sourceVersion') or p['version']) != (installed['source'], installed['source_version']):
            raise ValueError('Native APT source identity differs')


def compose_native(raw, apt, native, manifest, index):
    apt_inventory(apt, manifest, native)
    result = copy.deepcopy(raw)
    # ELF note guesses are replaced by the signed-package database preserved
    # before cleanup. The unmodified disk scan remains separately available.
    removed = {a['id'] for a in result['artifacts'] if a['type'] == 'deb'}
    result['artifacts'] = [a for a in result['artifacts'] if a['id'] not in removed]
    result['artifactRelationships'] = [r for r in result.get('artifactRelationships', [])
                                       if r['parent'] not in removed and r['child'] not in removed]
    result['artifacts'].extend(copy.deepcopy(native['artifacts']))
    for entry in index['entries']:
        if entry['kind'] not in ['cargo-registry', 'cargo-git']:
            continue
        purl = f'pkg:cargo/{quote(entry["name"], safe="")}@{quote(entry["version"], safe="")}'
        result['artifacts'].append({'id': 'outerspace-source:' + purl,
            'name': entry['name'], 'version': entry['version'], 'type': 'rust-crate',
            'foundBy': 'outerspace-cargo-lock-source-closure', 'locations': [],
            'language': 'rust', 'licenses': [{'value': expression, 'spdxExpression': '',
                'type': 'declared', 'urls': [], 'locations': []}
                for expression in entry.get('licenses', {}).get('declared_licenses', [])],
            'cpes': [], 'purl': purl})
    ids = [a['id'] for a in result['artifacts']]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate combined SBOM identity')
    return result


def source_correspondence(raw, apt, index, runtimes, components):
    locked = read_json(POLICIES['sources.lock.json'])['sources']
    entries = {e['name']: e for e in index['entries'] if e['kind'] == 'runtime-source'}
    runtime_paths = {r['path']: r['component'] for r in runtimes}
    for name, component in components['components'].items():
        if name not in locked or locked[name].get('version') != component['version']:
            raise ValueError('Runtime source lock does not match binary version: ' + name)
    covered = 0
    for p in raw['artifacts']:
        if p['type'] != 'go-module':
            continue
        metadata = p.get('metadata', {})
        if metadata.get('goCompiledVersion') not in locked:
            raise ValueError('Go standard-library source is not archived')
        for location in p['locations']:
            path = location['path']
            name = runtime_paths.get(path)
            if name is None:
                if path not in apt['executable_owners']:
                    raise ValueError('Go executable has no corresponding-source owner: ' + path)
                covered += 1
                continue
            source = entries[name]
            main = metadata.get('mainModule')
            if p['name'] not in ['stdlib', main]:
                vendor = source['go_vendor_modules'].get(p['name'], {})
                if vendor.get('version') != p['version'] and not (vendor.get('workspace_source') and p['version'] == 'UNKNOWN'):
                    raise ValueError('Embedded Go dependency differs from vendored source: ' + p['name'])
            settings = {s['key']: s['value'] for s in metadata.get('goBuildSettings', [])}
            if settings.get('vcs.revision') and settings['vcs.revision'] != source['commit']:
                raise ValueError('Embedded source revision differs from archived source')
            if settings.get('vcs.modified') == 'true':
                raise ValueError('Runtime declares unarchived source modifications')
            covered += 1
    return {'go_package_locations': covered, 'runtime_source_versions': {n: locked[n]['version'] for n in entries},
            'rust': index['cargo_relationship']}


def provenance(identity, builder, packages):
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', builder):
        raise ValueError('An immutable builder image ID is required')
    return {'schema': 1, 'identity': identity, 'builder_image_id': builder,
            'builder_packages_sha256': sha256(packages),
            'inputs': {name: sha256(path) for name, path in POLICIES.items()},
            'source_archive_sha256': identity['source_archive_sha256'],
            'recipe': 'build/build.sh -> build/assemble.sh; tools outside target OS',
            'reproducibility': 'Input-locked; bit-for-bit reproducibility requires a separate comparison'}


def generate(output):
    identity = read_json(output / 'build-identity.json')
    base = verify_inventory(output, identity, output / 'outerspace.manifest', ROOT / 'src/components.lock.json')
    apt, native, manifest, index, raw = [read_json(output / n) for n in
        ['apt-inputs.json', 'apt.sbom.syft.json', 'outerspace.manifest', 'source-index.json', 'sbom.syft.json']]
    if apt['notices_sha256'] != sha256(output / 'apt-notices.tar'):
        raise ValueError('APT notices were modified')
    write_json(output / 'distribution.sbom.syft.json', compose_native(raw, apt, native, manifest, index))
    converted = json.loads(subprocess.check_output(['syft', 'convert',
        str(output / 'distribution.sbom.syft.json'), '--config', str(ROOT / 'build/sbom/syft.yaml'),
        '-o', 'cyclonedx-json@1.6'], text=True))
    evidence = read_json(output / 'sbom-evidence.json')
    correspondence = source_correspondence(raw, apt, index, evidence['runtimes'], read_json(ROOT / 'src/components.lock.json'))
    cdx = schema_licenses(compose(converted, {'packages': []}, identity, evidence['runtimes']))
    cdx['metadata']['properties'] = [p for p in cdx['metadata']['properties'] if p['name'] != 'outerspace:coverage']
    cdx['metadata']['properties'].append({'name': 'outerspace:coverage', 'value':
        'Final disk scan, preserved installed DPKG metadata and conservative Cargo source closure. '
        'A complete linked dependency graph and redistribution approval are not implied.'})
    cdx['metadata']['properties'].append({'name': 'outerspace:cargo-coverage', 'value': index['cargo_relationship']})
    write_json(output / 'distribution.sbom.cdx.json', cdx)
    shutil.copyfile('/opt/outerspace/builder-packages.tsv', output / 'builder-packages.tsv')
    write_json(output / 'build-provenance.json', provenance(identity, os.environ['OUTERSPACE_BUILDER_ID'],
                                                          output / 'builder-packages.tsv'))
    source_result = sources.verify(output, apt)
    report = {'schema': 1, 'identity': identity, 'base_inventory': base,
              'files': {n: sha256(output / n) for n in FILES},
              'policies': {n: sha256(p) for n, p in POLICIES.items()}, 'sources': source_result,
              'apt_source_packages': len(apt['sources']),
              'declared_cargo_packages': sum(e['kind'].startswith('cargo-') for e in index['entries'])}
    report['correspondence'] = correspondence
    write_json(output / REPORT, report)
    verify(output, identity, output / 'outerspace.manifest')


def verify(directory, identity, manifest_path):
    report = read_json(directory / REPORT)
    if (report.get('schema') != 1 or report.get('identity') != identity
            or report.get('policies') != {n: sha256(p) for n, p in POLICIES.items()}
            or set(report.get('files', {})) != set(FILES)):
        raise ValueError('Supply chain identity or policy differs')
    for name, digest in report['files'].items():
        path = directory / name
        if path.is_symlink() or not path.is_file() or sha256(path) != digest:
            raise ValueError('Supply chain integrity failure: ' + name)
    if report.get('base_inventory') != verify_inventory(directory, identity, manifest_path, ROOT / 'src/components.lock.json'):
        raise ValueError('Supply chain disk inventory differs')
    apt, native, manifest, index, raw = [read_json(p) for p in
        [directory / 'apt-inputs.json', directory / 'apt.sbom.syft.json', manifest_path,
         directory / 'source-index.json', directory / 'sbom.syft.json']]
    if (apt.get('inputs_lock_sha256') != sha256(POLICIES['inputs.lock.json'])
            or apt.get('snapshot') != read_json(POLICIES['inputs.lock.json'])['ubuntu_snapshot']
            or apt.get('notices_sha256') != sha256(directory / 'apt-notices.tar')):
        raise ValueError('APT snapshot or notices differ')
    if compose_native(raw, apt, native, manifest, index) != read_json(directory / 'distribution.sbom.syft.json'):
        raise ValueError('Combined SBOM differs from its source evidence')
    p = read_json(directory / 'build-provenance.json')
    if p != provenance(identity, p['builder_image_id'], directory / 'builder-packages.tsv'):
        raise ValueError('Build provenance differs from this image')
    if sources.verify(directory, apt) != report['sources']:
        raise ValueError('Corresponding source inventory differs')
    evidence = read_json(directory / 'sbom-evidence.json')
    if source_correspondence(raw, apt, index, evidence['runtimes'], read_json(ROOT / 'src/components.lock.json')) != report['correspondence']:
        raise ValueError('Runtime/source correspondence differs')
    cdx = read_json(directory / 'distribution.sbom.cdx.json')
    if cdx['metadata']['component']['hashes'] != [{'alg': 'SHA-256', 'content': identity['raw_image_sha256']}]:
        raise ValueError('Distribution SBOM targets another image')
    return {'report_sha256': sha256(directory / REPORT), 'sources': report['sources'],
            'cyclonedx_sha256': sha256(directory / 'distribution.sbom.cdx.json')}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    generate(parser.parse_args().output)
