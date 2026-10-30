# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Pinned Go module updates, complete sources and an offline file proxy."""
import hashlib
import json
import re
import shutil

from profiles import ROOT, sha256

LOCK = ROOT / 'build/runtime/crictl-dependencies.lock.json'


def escape(value):
    if not re.fullmatch(r'[A-Za-z0-9_./+~-]+', value) or any(
            part in ['', '.', '..'] for part in value.split('/')):
        raise ValueError('Unsafe Go module path or version')
    return ''.join('!' + c.lower() if c.isupper() else c for c in value)


def read_lock(expected_digest):
    if sha256(LOCK) != expected_digest:
        raise ValueError('Go dependency update differs from its source lock')
    config = json.loads(LOCK.read_text())
    if (config.get('schema') != 1 or config.get('component') != 'crictl'
            or set(config['manifests']) != {'go.mod', 'go.sum', 'vendor/modules.txt'}):
        raise ValueError('Invalid Go dependency update')
    for name, digest in config['manifests'].items():
        path = LOCK.parent / 'crictl' / name
        if path.is_symlink() or sha256(path) != digest:
            raise ValueError('Go dependency manifest differs from its lock')
        config['manifests'][name] = path.read_text()
    validate(config)
    return config


def validate(config):
    seen = set()
    sums = set(config['manifests']['go.sum'].splitlines())
    for module in config['modules']:
        name, version = module['path'], module['version']
        if name in seen or not version.startswith('v') or set(module['files']) != {'zip', 'mod', 'info'}:
            raise ValueError('Duplicate or incomplete Go module input')
        seen.add(name)
        for suffix, key in [('', 'sum'), ('/go.mod', 'go_mod_sum')]:
            if name + ' ' + version + suffix + ' ' + module[key] not in sums:
                raise ValueError('Go module input differs from pinned go.sum')
        for extension, entry in module['files'].items():
            expected = f'https://proxy.golang.org/{escape(name)}/@v/{escape(version)}.{extension}'
            if (entry['url'] != expected or not re.fullmatch('[a-f0-9]{64}', entry['sha256'])
                    or not isinstance(entry['size'], int) or entry['size'] <= 0):
                raise ValueError('Invalid Go module source input')
    selected = {m['path']: m['version'] for m in config['modules']}
    if any(selected.get(name) != record['version'] for name, record in vendor_modules(config).items()):
        raise ValueError('Vendored Go dependency has no pinned source')


def vendor_modules(config):
    result = {}
    for line in config['manifests']['vendor/modules.txt'].splitlines():
        if line.startswith('# '):
            fields = line.split()
            if len(fields) != 3 or not fields[2].startswith('v') or fields[1] in result:
                raise ValueError('Unsupported replacement or duplicate vendored Go module')
            result[fields[1]] = {'version': fields[2]}
    if not result:
        raise ValueError('Empty vendored Go module inventory')
    return result


def build_inputs(config):
    return {name: hashlib.sha256(data.encode()).hexdigest() for name, data in config['manifests'].items()}


def source_entries(config):
    return [{**entry, 'name': module['path'], 'version': module['version'], 'for_component': 'crictl',
             'kind': 'go-module-source' if extension == 'zip' else 'go-module-metadata',
             'format': extension}
            for module in config['modules'] for extension, entry in module['files'].items()]


def stage(config, cache, source, proxy):
    """Supply Go with only hash-verified, frozen module inputs; no network fallback."""
    for module in config['modules']:
        directory = proxy / escape(module['path']) / '@v'
        directory.mkdir(parents=True, exist_ok=True)
        for extension, entry in module['files'].items():
            path = cache / entry['sha256']
            if path.is_symlink() or sha256(path) != entry['sha256'] or path.stat().st_size != entry['size']:
                raise ValueError('Go module source cache corruption')
            shutil.copyfile(path, directory / (escape(module['version']) + '.' + extension))
    for name in ['go.mod', 'go.sum']:
        path = source / name
        if path.is_symlink():
            raise ValueError('Unsafe Go manifest')
        path.write_text(config['manifests'][name])
    shutil.rmtree(source / 'vendor')
