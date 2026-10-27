#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Archive checksum-verified Ubuntu, runtime, vendored and Cargo sources."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile
import tomllib
from urllib.parse import urlsplit

from profiles import ROOT, sha256

LOCK = ROOT / 'build/sbom/sources.lock.json'


def fetch(cache, entry):
    digest = entry['sha256']
    if not re.fullmatch('[a-f0-9]{64}', digest) or urlsplit(entry['url']).scheme != 'https':
        raise ValueError('Sources require an approved SHA256 and HTTPS origin')
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / digest
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('Unsafe source cache entry')
    if not path.exists():
        with tempfile.NamedTemporaryFile(dir=cache, prefix='fetch-', delete=False) as stream:
            temporary = Path(stream.name)
        try:
            subprocess.run(['curl', '-fsSL', '--proto', '=https', '--proto-redir', '=https', '--retry', '3',
                '--max-time', '900', '--speed-limit', '1024', '--speed-time', '90',
                '-o', str(temporary), entry['url']], check=True)
            if sha256(temporary) != digest:
                raise ValueError('Corresponding source checksum mismatch: ' + entry['url'])
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    if sha256(path) != digest or ('size' in entry and path.stat().st_size != entry['size']):
        raise ValueError('Corresponding source cache corruption: ' + entry['url'])
    return path


def archive_file(path, suffix):
    with tarfile.open(path) as tar:
        members = [m for m in tar if m.name.endswith('/' + suffix)]
        if len(members) != 1 or not members[0].isfile():
            raise ValueError('Missing or ambiguous source file: ' + suffix)
        return tar.extractfile(members[0]).read()


def cargo_inventory(source, git_sources):
    lock = tomllib.loads(archive_file(source, 'Cargo.lock').decode())
    packages = []
    for p in lock['package']:
        origin = p.get('source')
        if not origin:
            continue  # Workspace source is already in the complete repository archive.
        if origin == 'registry+https://github.com/rust-lang/crates.io-index':
            if not re.fullmatch('[A-Za-z0-9_-]+', p['name']) or not re.fullmatch('[A-Za-z0-9.+_-]+', p['version']):
                raise ValueError('Unsafe Cargo package name/version')
            entry = {'name': p['name'], 'version': p['version'], 'sha256': p['checksum'],
                     'url': f'https://static.crates.io/crates/{p["name"]}/{p["name"]}-{p["version"]}.crate',
                     'kind': 'cargo-registry', 'declared_by': 'dfdaemon/Cargo.lock'}
        elif origin in git_sources:
            entry = {**git_sources[origin], 'name': p['name'], 'version': p['version'],
                     'kind': 'cargo-git', 'declared_by': 'dfdaemon/Cargo.lock'}
        else:
            raise ValueError('Unapproved Cargo source: ' + origin)
        packages.append(entry)
    return packages


def license_evidence(path):
    """Keep declarations and exact notice bytes; never invent license decisions."""
    declarations = []
    notices = []
    with tarfile.open(path) as tar:
        for member in tar:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts:
                raise ValueError('Unsafe source archive path')
            if not member.isfile():
                continue
            leaf = name.name.upper()
            if (leaf.startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'COPYRIGHT'))
                    or leaf == 'AUTHORS'):
                data = tar.extractfile(member).read()
                notices.append({'path': str(name), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)})
            if name.name == 'Cargo.toml' and len(name.parts) == 2:
                manifest = tomllib.loads(tar.extractfile(member).read().decode())
                package = manifest.get('package', {})
                if isinstance(package.get('license'), str):
                    declarations.append(package['license'])
    return {'declared_licenses': sorted(set(declarations)), 'notices': notices}


def go_vendor_inventory(path):
    with tarfile.open(path) as tar:
        matches = [m for m in tar if len(PurePosixPath(m.name).parts) == 3 and m.name.endswith('/vendor/modules.txt')]
        if len(matches) != 1 or not matches[0].isfile():
            raise ValueError('Missing vendored Go dependency sources')
        modules = {}
        root = PurePosixPath(matches[0].name).parts[0]
        for line in tar.extractfile(matches[0]).read().decode().splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[0] == '#' and fields[2].startswith('v'):
                record = {'version': fields[2]}
                if len(fields) == 5 and fields[3] == '=>' and fields[4].startswith('./'):
                    path = PurePosixPath(fields[4])
                    if '..' in path.parts or path.is_absolute():
                        raise ValueError('Unsafe vendored workspace path')
                    member = tar.getmember(str(PurePosixPath(root) / path / 'go.mod'))
                    if not member.isfile():
                        raise ValueError('Missing vendored workspace source')
                    record['workspace_source'] = str(path)
                modules[fields[1]] = record
        return modules


def collect(cache, apt_inputs=None):
    lock = json.loads(LOCK.read_text())
    entries = [{**entry, 'name': name, 'kind': 'runtime-source' if 'commit' in entry else 'go-standard-library'}
               for name, entry in lock['sources'].items()]
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda e: fetch(cache, e), entries))
    cargo = cargo_inventory(cache / lock['sources']['dfdaemon']['sha256'], lock.get('cargo_git_sources', {}))
    entries.extend(cargo)
    entries.extend({**e, 'kind': 'supplemental-notice-source'} for e in lock.get('supplemental_sources', []))
    if apt_inputs:
        for source in apt_inputs['sources']:
            for entry in source['files']:
                entries.append({**entry, 'kind': 'ubuntu-source', 'package': source['name'], 'version': source['version']})
    unique = {entry['sha256']: entry for entry in entries}
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda e: fetch(cache, e), unique.values()))
    print('Verified source objects:', len(unique), flush=True)
    for supplement in lock.get('supplemental_sources', []):
        for digest in supplement['for_crates']:
            if digest not in {e['sha256'] for e in cargo}:
                raise ValueError('Supplemental notice refers to an unknown crate')
            vcs = json.loads(archive_file(cache / digest, '.cargo_vcs_info.json'))
            if vcs['git']['sha1'] != supplement['commit']:
                raise ValueError('Supplemental notice source is not the crate publication revision')
    for entry in entries:
        if entry['kind'] != 'ubuntu-source':
            entry['licenses'] = license_evidence(cache / entry['sha256'])
        if entry['kind'] == 'runtime-source' and entry['name'] in ['containerd', 'kubelet', 'crictl']:
            entry['go_vendor_modules'] = go_vendor_inventory(cache / entry['sha256'])
    return {'schema': 1, 'source_lock_sha256': sha256(LOCK), 'entries': entries,
            'cargo_relationship': 'Source-declared lockfile closure including target/build/test dependencies; '
                                  'not proof that every crate is linked into the stripped upstream binary'}


def verify(directory, apt_inputs, lock_path=LOCK):
    """Verify contents, not just a self-reported archive digest, at promotion."""
    index_path = directory / 'source-index.json'
    archive = directory / 'corresponding-source.tar.zst'
    if any(p.is_symlink() or not p.is_file() for p in [index_path, archive]):
        raise ValueError('Missing or unsafe corresponding source')
    index = json.loads(index_path.read_text())
    lock = json.loads(lock_path.read_text())
    if index.get('schema') != 1 or index.get('source_lock_sha256') != sha256(lock_path):
        raise ValueError('Sources differ from approved source lock')
    entries = index['entries']
    actual = {e['sha256']: e for e in entries}
    required = (list(lock['sources'].values()) + lock.get('supplemental_sources', [])
                + [f for s in apt_inputs['sources'] for f in s['files']])
    if any(e['sha256'] not in actual or any(actual[e['sha256']].get(k) != v for k, v in e.items()) for e in required):
        raise ValueError('Corresponding source is incomplete or changed')
    seen = set()
    cargo_lock = None
    with subprocess.Popen(['zstd', '-dc', str(archive)], stdout=subprocess.PIPE) as decoder:
        try:
            with tarfile.open(fileobj=decoder.stdout, mode='r|') as tar:
                for member in tar:
                    if not member.isfile() or member.name in seen:
                        raise ValueError('Unsafe or duplicate corresponding source entry')
                    seen.add(member.name)
                    stream = tar.extractfile(member)
                    if member.name == 'source-index.json':
                        if stream.read() != index_path.read_bytes():
                            raise ValueError('Embedded source index differs')
                        continue
                    digest = member.name.removeprefix('objects/')
                    if member.name != 'objects/' + digest or digest not in actual:
                        raise ValueError('Unexpected corresponding source object')
                    # dfdaemon's source proves the registry closure, including
                    # crates without dependency metadata in the stripped binary.
                    runtime = next((e for e in entries if e['sha256'] == digest and e['kind'] == 'runtime-source'), None)
                    if runtime:
                        data = stream.read()
                        if hashlib.sha256(data).hexdigest() != digest:
                            raise ValueError('Source object checksum mismatch')
                        with tempfile.NamedTemporaryFile() as temporary:
                            temporary.write(data); temporary.flush()
                            if runtime['name'] == 'dfdaemon':
                                cargo_lock = cargo_inventory(Path(temporary.name), lock.get('cargo_git_sources', {}))
                            elif runtime['name'] in ['containerd', 'kubelet', 'crictl']:
                                if runtime.get('go_vendor_modules') != go_vendor_inventory(Path(temporary.name)):
                                    raise ValueError('Vendored Go source inventory differs')
                    elif hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                        raise ValueError('Source object checksum mismatch')
                    if 'size' in actual[digest] and member.size != actual[digest]['size']:
                        raise ValueError('Source object size mismatch')
            if decoder.wait():
                raise ValueError('Corresponding source decompression failed')
        finally:
            if decoder.poll() is None:
                decoder.terminate(); decoder.wait()
    if seen != {'source-index.json'} | {'objects/' + d for d in actual} or cargo_lock is None:
        raise ValueError('Incomplete corresponding source archive')
    if any(e['sha256'] not in actual or any(actual[e['sha256']].get(k) != v for k, v in e.items()) for e in cargo_lock):
        raise ValueError('Missing or altered transitive Cargo source')
    return {'objects': len(actual), 'archive_sha256': sha256(archive), 'index_sha256': sha256(index_path)}


def bundle(cache, output, index):
    objects = {e['sha256']: e for e in index['entries']}
    destination = output / 'corresponding-source.tar.zst'
    temporary = destination.with_suffix('.partial')
    if temporary.exists() or temporary.is_symlink():
        raise ValueError('Remove interrupted source archive before regeneration')
    try:
        with subprocess.Popen(['zstd', '-T0', '-q', '-o', str(temporary)], stdin=subprocess.PIPE) as compressor:
            with tarfile.open(fileobj=compressor.stdin, mode='w|') as tar:
                for digest, entry in sorted(objects.items()):
                    path = fetch(cache, entry)
                    member = tarfile.TarInfo('objects/' + digest)
                    member.size = path.stat().st_size
                    member.mode = 0o644
                    with path.open('rb') as stream:
                        tar.addfile(member, stream)
                data = (json.dumps(index, indent=2) + '\n').encode()
                member = tarfile.TarInfo('source-index.json')
                member.size = len(data)
                member.mode = 0o644
                tar.addfile(member, io.BytesIO(data))
            compressor.stdin.close()
            if compressor.wait():
                raise ValueError('Source archive compression failed')
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return sha256(destination)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--apt-inputs', type=Path)
    parser.add_argument('--download-only', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    apt_inputs = json.loads(args.apt_inputs.read_text()) if args.apt_inputs else None
    index = collect(args.cache, apt_inputs)
    (args.output / 'source-index.json').write_text(json.dumps(index, indent=2) + '\n')
    if not args.download_only:
        bundle(args.cache, args.output, index)
        verify(args.output, apt_inputs or {'sources': []})
