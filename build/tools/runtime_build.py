#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Build the Dragonfly daemon offline from verified source and compiler inputs."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import tomllib
import zlib

from profiles import ROOT, architecture, sha256

LOCK = ROOT / 'build/runtime/dragonfly.lock.json'
EVIDENCE_FILES = ('dfdaemon-build.json', 'dfdaemon-build-packages.tsv', 'dfdaemon-LICENSE')
spec = importlib.util.spec_from_file_location('runtime_sources', ROOT / 'build/tools/source-bundle.py')
sources = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sources)


def read_lock():
    lock = json.loads(LOCK.read_text())
    source_lock = json.loads(sources.LOCK.read_text())
    if (lock['schema'] != 1 or lock['component'] != 'dfdaemon'
            or lock['source'] != source_lock['sources']['dfdaemon']
            or lock['version'] != lock['source']['version']
            or set(lock['targets']) != {'amd64', 'arm64'}):
        raise ValueError('Runtime build and corresponding-source locks differ')
    return lock, source_lock


def source_entries(cache, lock, source_lock):
    archive = sources.fetch(cache / 'source-inputs', lock['source'])
    return sources.cargo_inventory(archive, source_lock.get('cargo_git_sources', {}))


def fetch(cache, arch):
    lock, source_lock = read_lock()
    cargo = source_entries(cache, lock, source_lock)
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda e: sources.fetch(cache / 'source-inputs', e), cargo))
        list(pool.map(lambda e: sources.fetch(cache / 'runtime-tools', e), lock['targets'][arch]['tools'].values()))


def extract(archive, destination, prefix=None):
    """Extract only regular source files and directories under one known root."""
    destination.mkdir(parents=True, exist_ok=False)
    seen, roots = set(), set()
    with tarfile.open(archive) as tar:
        for member in tar:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not path.parts or str(path) in seen:
                raise ValueError('Unsafe or duplicate build source path')
            seen.add(str(path))
            roots.add(path.parts[0])
            relative = PurePosixPath(*path.parts[1:])
            if prefix is not None:
                if not relative.is_relative_to(prefix):
                    continue
                relative = relative.relative_to(prefix)
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif (member.isfile() or member.issym()) and str(relative) != '.':
                content = member
                if member.issym():
                    linked = posixpath.normpath(str(path.parent / member.linkname))
                    if (PurePosixPath(member.linkname).is_absolute()
                            or not linked.startswith(path.parts[0] + '/')):
                        raise ValueError('Build source link escapes its approved archive')
                    content = tar.getmember(linked)
                    if not content.isfile():
                        raise ValueError('Build source link must target a regular archived file')
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(content) as src, target.open('xb') as dst:
                    shutil.copyfileobj(src, dst)
                target.chmod(0o755 if content.mode & 0o111 else 0o644)
            else:
                raise ValueError('Unsupported build source entry: ' + str(archive) + ':' + member.name)
    if len(roots) != 1:
        raise ValueError('Build source must have a single archive root')


def vendor(cache, destination, cargo, git_sources):
    destination.mkdir()
    for entry in cargo:
        prefix = None
        if entry['kind'] == 'cargo-git':
            # Locate the exact package in the approved git archive; no checkout,
            # live branch, index refresh or generated workspace substitution.
            with tarfile.open(cache / entry['sha256']) as tar:
                matches = []
                for member in tar:
                    if member.isfile() and member.name.endswith('/Cargo.toml'):
                        package = tomllib.loads(tar.extractfile(member).read().decode()).get('package', {})
                        if (package.get('name'), package.get('version')) == (entry['name'], entry['version']):
                            matches.append(PurePosixPath(*PurePosixPath(member.name).parts[1:-1]))
                if len(matches) != 1:
                    raise ValueError('Missing or ambiguous locked git package')
                prefix = matches[0]
        directory = destination / (entry['name'] + '-' + entry['version'])
        extract(cache / entry['sha256'], directory, prefix)
        files = {str(p.relative_to(directory)): sha256(p) for p in sorted(directory.rglob('*')) if p.is_file()}
        (directory / '.cargo-checksum.json').write_text(json.dumps({
            'files': files, 'package': entry['sha256'] if entry['kind'] == 'cargo-registry' else None}))
    config = '[source.crates-io]\nreplace-with = "outerspace-vendor"\n\n'
    config += '[source.outerspace-vendor]\ndirectory = ' + json.dumps(str(destination)) + '\n'
    for number, origin in enumerate(git_sources):
        match = re.fullmatch(r'git\+(.+)\?rev=([a-f0-9]{40})#\2', origin)
        if not match:
            raise ValueError('Only full-revision git dependencies are supported')
        config += (f'\n[source.outerspace-git-{number}]\ngit = {json.dumps(match[1])}\n'
                   f'rev = {json.dumps(match[2])}\nreplace-with = "outerspace-vendor"\n')
    return config


def audit_data(binary, arch):
    """Read the bounded audit section from a little-endian ELF64 without executing it."""
    size = binary.stat().st_size
    with binary.open('rb') as stream:
        header = stream.read(64)
        if (len(header) != 64 or header[:7] != b'\x7fELF\x02\x01\x01'
                or struct.unpack_from('<H', header, 18)[0] != {'amd64': 62, 'arm64': 183}[arch]):
            raise ValueError('Runtime is not an ELF64 executable for the selected architecture')
        offset = struct.unpack_from('<Q', header, 40)[0]
        entry_size, count, names_index = struct.unpack_from('<HHH', header, 58)
        if entry_size != 64 or not 0 < names_index < count <= 4096 or offset + count * 64 > size:
            raise ValueError('Invalid ELF section table')
        stream.seek(offset)
        sections = [struct.unpack('<IIQQQQIIQQ', stream.read(64)) for _ in range(count)]
        names = sections[names_index]
        if names[4] + names[5] > size or names[5] > 1024 * 1024:
            raise ValueError('Invalid ELF section names')
        stream.seek(names[4])
        strings = stream.read(names[5])
        matches = [s for s in sections if s[0] < len(strings) and strings[s[0]:].split(b'\0', 1)[0] == b'.dep-v0']
        if len(matches) != 1 or matches[0][4] + matches[0][5] > size or matches[0][5] > 1024 * 1024:
            raise ValueError('Missing or invalid embedded Rust dependency inventory')
        section = matches[0]
        stream.seek(section[4])
        decoder = zlib.decompressobj()
        payload = decoder.decompress(stream.read(section[5]), 8 * 1024 * 1024)
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError('Invalid or oversized compressed dependency inventory')
    data = json.loads(payload)
    validate_graph(data)
    return data


def validate_graph(data):
    if type(data.get('format', 0)) is not int or data.get('format', 0) not in [0, 1, 8]:
        raise ValueError('Unsupported Rust dependency metadata format')
    packages = data.get('packages', [])
    if not isinstance(packages, list) or not 1 <= len(packages) <= 10000:
        raise ValueError('Invalid Rust package inventory')
    roots = [i for i, p in enumerate(packages) if p.get('root') is True]
    if len(roots) != 1:
        raise ValueError('Expected one Rust dependency root')
    edges, keys = [], set()
    for package in packages:
        key = tuple(package.get(k) for k in ['name', 'version', 'source'])
        if (any(not isinstance(v, str) or not v for v in key) or key in keys
                or package.get('kind', 'runtime') not in ['runtime', 'build']):
            raise ValueError('Invalid or duplicate Rust package')
        keys.add(key)
        children = package.get('dependencies', [])
        if (not isinstance(children, list) or any(type(i) is not int or not 0 <= i < len(packages) for i in children)
                or len(children) != len(set(children))):
            raise ValueError('Invalid Rust dependency edge')
        edges.append(children)
    visited, active = set(), set()
    stack = [(roots[0], False)]
    while stack:
        current, leaving = stack.pop()
        if leaving:
            active.remove(current)
            visited.add(current)
        elif current in active:
            raise ValueError('Cyclic Rust dependency graph')
        elif current not in visited:
            active.add(current)
            stack.append((current, True))
            stack.extend((child, False) for child in reversed(edges[current]))
    if len(visited) != len(packages):
        raise ValueError('Disconnected Rust dependency inventory')


def verify_receipt(directory, arch, *, packaged=False):
    """Reconcile a build receipt with the currently approved source and tool inputs."""
    lock, _ = read_lock()
    names = EVIDENCE_FILES if packaged else ('runtime-build.json', 'native-build-packages.tsv', 'LICENSE')
    paths = [directory / name for name in names]
    if any(p.is_symlink() or not p.is_file() for p in paths):
        raise ValueError('Missing or unsafe runtime build evidence')
    report = json.loads(paths[0].read_text())
    target = lock['targets'][arch]
    if (report.get('schema') != 1 or report.get('architecture') != arch
            or report.get('target') != target['triple'] or report.get('source') != lock['source']
            or report.get('recipe_sha256') != sha256(LOCK)
            or report.get('builder_script_sha256') != sha256(Path(__file__))
            or report.get('compiler_inputs') != target['tools']
            or report.get('native_packages_sha256') != sha256(paths[1])
            or report.get('license_sha256') != sha256(paths[2])):
        raise ValueError('Runtime build evidence differs from approved inputs')
    validate_graph(report.get('dependencies', {}))
    return report


def verify(directory, arch, *, binary=None):
    """Also inspect the executable; the receipt alone cannot authorize installation."""
    report = verify_receipt(directory, arch)
    path = binary or directory / 'dfdaemon'
    if path.is_symlink() or not path.is_file() or sha256(path) != report.get('binary_sha256'):
        raise ValueError('Runtime executable differs from its build evidence')
    if audit_data(path, arch) != report.get('dependencies'):
        raise ValueError('Runtime dependency inventory differs from executable bytes')
    return report


def cache_directory(cache, arch):
    builder = os.environ.get('OUTERSPACE_BUILDER_ID', '')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', builder):
        raise ValueError('A source runtime build requires an immutable builder image ID')
    subject = {'architecture': arch, 'builder': builder, 'recipe': sha256(LOCK),
               'script': sha256(Path(__file__)), 'source_tool': sha256(Path(sources.__file__))}
    key = hashlib.sha256(json.dumps(subject, sort_keys=True).encode()).hexdigest()
    return cache / 'runtime-builds' / arch / key


def prepare(cache, output, arch, jobs):
    directory = cache_directory(cache, arch)
    if directory.exists():
        report = verify(directory, arch)
        if report.get('builder_image_id') != os.environ['OUTERSPACE_BUILDER_ID']:
            raise ValueError('Cached runtime was built by another builder')
    else:
        directory.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='pending-', dir=directory.parent) as temporary:
            staging = Path(temporary) / 'result'
            build(cache, staging, arch, jobs)
            staging.rename(directory)
    output.mkdir(parents=True, exist_ok=True)
    for name, destination in [('runtime-build.json', 'dfdaemon-build.json'),
                              ('native-build-packages.tsv', 'dfdaemon-build-packages.tsv'),
                              ('LICENSE', 'dfdaemon-LICENSE')]:
        shutil.copyfile(directory / name, output / destination)
    return directory


def install_tools(cache, tools, work):
    prefix = work / 'toolchain'
    for name, entry in tools.items():
        archive = cache / entry['sha256']
        if sha256(archive) != entry['sha256']:
            raise ValueError('Compiler input checksum mismatch')
        directory = work / name
        # Official compiler distributions contain internal symlinks. Python's
        # data filter refuses traversal, devices and escaping link targets.
        directory.mkdir()
        with tarfile.open(archive) as tar:
            tar.extractall(directory, filter='data')
        if name == 'cargo-auditable':
            binaries = list(directory.rglob('cargo-auditable'))
            if len(binaries) != 1 or not binaries[0].is_file() or binaries[0].is_symlink():
                raise ValueError('Ambiguous cargo-auditable input')
            shutil.copyfile(binaries[0], prefix / 'bin/cargo-auditable')
            (prefix / 'bin/cargo-auditable').chmod(0o755)
        else:
            installers = list(directory.glob('*/install.sh'))
            if len(installers) != 1:
                raise ValueError('Missing compiler installer')
            subprocess.run(['bash', str(installers[0]), '--prefix=' + str(prefix), '--disable-ldconfig'],
                           check=True, stdout=subprocess.DEVNULL)
    return prefix


def build(cache, output, arch, jobs):
    lock, source_lock = read_lock()
    if architecture() != arch:
        raise ValueError('Runtime compilation requires the native target architecture')
    output.mkdir(parents=True, exist_ok=False)
    target = lock['targets'][arch]
    archive = cache / 'source-inputs' / lock['source']['sha256']
    if sha256(archive) != lock['source']['sha256']:
        raise ValueError('Runtime source checksum mismatch')
    cargo = sources.cargo_inventory(archive, source_lock.get('cargo_git_sources', {}))
    for entry in cargo:
        if sha256(cache / 'source-inputs' / entry['sha256']) != entry['sha256']:
            raise ValueError('Locked Cargo source checksum mismatch')
    with tempfile.TemporaryDirectory(prefix='outerspace-runtime-') as temporary:
        work = Path(temporary)
        source = work / 'source'
        extract(archive, source)
        original_lock = sha256(source / 'Cargo.lock')
        config = vendor(cache / 'source-inputs', work / 'vendor', cargo, source_lock.get('cargo_git_sources', {}))
        cargo_home = work / 'cargo-home'
        cargo_home.mkdir()
        (cargo_home / 'config.toml').write_text(config)
        toolchain = install_tools(cache / 'runtime-tools', target['tools'], work)
        env = {'PATH': str(toolchain / 'bin') + ':/usr/bin:/bin', 'HOME': str(work),
               'CARGO_HOME': str(cargo_home), 'CARGO_NET_OFFLINE': 'true', 'CARGO_INCREMENTAL': '0',
               'LANG': 'C.UTF-8', 'RUSTFLAGS': '--remap-path-prefix=' + str(work) + '=/outerspace-build'}
        command = ['cargo', 'auditable', 'build', '--frozen', '--release', '--target', target['triple'],
                   '--package', lock['package'], '--bin', lock['binary'], '--jobs', str(jobs),
                   '--message-format=json-render-diagnostics']
        if not lock['default_features']:
            command.append('--no-default-features')
        if lock['features']:
            command.extend(['--features', ','.join(lock['features'])])
        with (output / 'cargo-build.jsonl').open('w') as stdout:
            subprocess.run(command, cwd=source, env=env, stdout=stdout, check=True)
        if sha256(source / 'Cargo.lock') != original_lock:
            raise ValueError('Runtime build changed the approved Cargo lock')
        binary = output / 'dfdaemon'
        shutil.copyfile(source / 'target' / target['triple'] / 'release' / 'dfdaemon', binary)
        binary.chmod(0o755)
        dependencies = audit_data(binary, arch)
        if not any(p.get('root') and (p['name'], p['version']) == (lock['package'], lock['version'])
                   for p in dependencies['packages']):
            raise ValueError('Embedded dependency root differs from the selected runtime')
        compiled = [json.loads(line) for line in (output / 'cargo-build.jsonl').read_text().splitlines()]
        compiled = [{k: p[k] for k in ['package_id', 'target', 'features', 'profile']}
                    for p in compiled if p.get('reason') == 'compiler-artifact']
        # Cargo's stable metadata can conservatively include extra dependencies.
        # Keep actual compiler artifacts alongside it; never claim exact linked
        # machine-code attribution from this metadata alone.
        for item in compiled:
            item['target']['src_path'] = item['target']['src_path'].replace(str(work), '/outerspace-build')
        native_packages = subprocess.check_output(
            ['dpkg-query', '--show', '--showformat=${Package}\t${Version}\t${Architecture}\n'])
        (output / 'native-build-packages.tsv').write_bytes(native_packages)
        shutil.copyfile(source / 'LICENSE', output / 'LICENSE')
        report = {'schema': 1, 'architecture': arch, 'target': target['triple'],
                  'recipe_sha256': sha256(LOCK), 'builder_script_sha256': sha256(Path(__file__)),
                  'source': lock['source'], 'cargo_lock_sha256': original_lock,
                  'compiler_inputs': target['tools'], 'command': command,
                  'native_packages_sha256': sha256(output / 'native-build-packages.tsv'),
                  'license_sha256': sha256(output / 'LICENSE'),
                  'builder_image_id': os.environ.get('OUTERSPACE_BUILDER_ID'),
                  'binary_sha256': sha256(binary), 'dependencies': dependencies,
                  'compiled_artifacts': compiled,
                  'dependency_scope': 'Embedded Cargo build graph; compiler artifacts retained separately. '
                                      'Stable Cargo metadata may conservatively include extra dependencies.',
                  'cargo_sources': [{k: e[k] for k in ['name', 'version', 'sha256', 'kind']} for e in cargo]}
        (output / 'runtime-build.json').write_text(json.dumps(report, indent=2) + '\n')
        verify(output, arch)
        print(json.dumps({'binary_sha256': report['binary_sha256'], 'packages': len(dependencies['packages']),
                          'compiler_artifacts': len(compiled)}), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['fetch', 'build', 'prepare', 'path'])
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--architecture', choices=['amd64', 'arm64'], required=True)
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if args.action == 'fetch':
        fetch(args.cache, args.architecture)
    elif args.action == 'path':
        print(cache_directory(args.cache, args.architecture))
    elif args.output is None or args.jobs < 1:
        parser.error('Build requires --output and positive --jobs')
    elif args.action == 'build':
        build(args.cache, args.output, args.architecture, args.jobs)
    else:
        prepare(args.cache, args.output, args.architecture, args.jobs)
