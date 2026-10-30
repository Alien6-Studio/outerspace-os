#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Compile crictl from locked vendored source with a patched, offline Go toolchain."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from profiles import ROOT, architecture, sha256
import runtime_build

LOCK = ROOT / 'build/runtime/crictl.lock.json'
EVIDENCE_FILES = ('crictl-build.json', 'crictl-LICENSE')
sources = runtime_build.sources


def read_lock():
    lock = json.loads(LOCK.read_text())
    upstream = json.loads(sources.LOCK.read_text())['sources']
    if (lock.get('schema') != 1 or lock.get('component') != 'crictl'
            or lock['source'] != upstream['crictl']
            or lock['go_source'] != upstream[lock['go_version']]
            or set(lock['toolchains']) != {'amd64', 'arm64'}):
        raise ValueError('Go runtime recipe differs from corresponding-source locks')
    return lock


def fetch(cache, arch):
    lock = read_lock()
    sources.fetch(cache / 'source-inputs', lock['source'])
    sources.fetch(cache / 'runtime-tools', lock['toolchains'][arch])


def build_info(text, arch, lock):
    lines = text.splitlines()
    if not lines or not lines[0].endswith(': ' + lock['go_version']):
        raise ValueError('Runtime was compiled by another Go version')
    result = {'go_version': lock['go_version'], 'modules': {}, 'settings': {}}
    for line in lines[1:]:
        fields = line.strip().split('\t')
        if fields[0] == 'path' and len(fields) == 2 and 'path' not in result:
            result['path'] = fields[1]
        elif fields[0] in ['mod', 'dep'] and len(fields) in [3, 4]:
            if fields[1] in result['modules']:
                raise ValueError('Duplicate Go module in binary')
            result['modules'][fields[1]] = fields[2]
        elif fields[0] == 'build' and len(fields) == 2 and '=' in fields[1]:
            key, value = fields[1].split('=', 1)
            if key in result['settings']:
                raise ValueError('Duplicate Go build setting')
            result['settings'][key] = value
        else:
            # No replacements or unverifiable local dependency substitutions.
            raise ValueError('Unsupported Go build information')
    expected = {'CGO_ENABLED': '0', 'GOOS': 'linux', 'GOARCH': arch, '-trimpath': 'true'}
    if (result.get('path') != 'sigs.k8s.io/cri-tools/cmd/crictl'
            or result['modules'].get('sigs.k8s.io/cri-tools') != '(devel)'
            or any(result['settings'].get(k) != v for k, v in expected.items())):
        raise ValueError('Go runtime target or compilation settings differ')
    return result


def verify_receipt(directory, arch, *, packaged=False):
    lock = read_lock()
    names = EVIDENCE_FILES if packaged else ('runtime-build.json', 'LICENSE')
    paths = [directory / name for name in names]
    if any(p.is_symlink() or not p.is_file() for p in paths):
        raise ValueError('Missing or unsafe Go runtime evidence')
    report = json.loads(paths[0].read_text())
    if (report.get('schema') != 1 or report.get('architecture') != arch
            or report.get('recipe_sha256') != sha256(LOCK)
            or report.get('builder_script_sha256') != sha256(Path(__file__))
            or report.get('extraction_script_sha256') != sha256(Path(runtime_build.__file__))
            or report.get('source') != lock['source'] or report.get('go_source') != lock['go_source']
            or report.get('compiler_input') != lock['toolchains'][arch]
            or report.get('license_sha256') != sha256(paths[1])
            or not re.fullmatch('sha256:[a-f0-9]{64}', report.get('builder_image_id', ''))
            or not re.fullmatch('[a-f0-9]{64}', report.get('binary_sha256', ''))
            or report.get('build_info') != build_info(report.get('go_version_m', ''), arch, lock)):
        raise ValueError('Go runtime build evidence differs from approved inputs')
    return report


def verify(directory, arch, *, binary=None, packaged=False):
    report = verify_receipt(directory, arch, packaged=packaged)
    path = binary or directory / 'crictl'
    if path.is_symlink() or not path.is_file() or sha256(path) != report['binary_sha256']:
        raise ValueError('Go runtime executable differs from its build evidence')
    return report


def cache_directory(cache, arch):
    builder = os.environ.get('OUTERSPACE_BUILDER_ID', '')
    if not re.fullmatch('sha256:[a-f0-9]{64}', builder):
        raise ValueError('Go runtime compilation requires an immutable builder image ID')
    subject = {'architecture': arch, 'builder': builder, 'recipe': sha256(LOCK),
               'script': sha256(Path(__file__)), 'extractor': sha256(Path(runtime_build.__file__))}
    key = hashlib.sha256(json.dumps(subject, sort_keys=True).encode()).hexdigest()
    return cache / 'go-runtime-builds' / arch / key


def build(cache, output, arch, jobs):
    lock = read_lock()
    if architecture() != arch:
        raise ValueError('Go runtime compilation requires the native target architecture')
    cache_directory(cache, arch)  # Also enforce immutable builder identity on direct builds.
    output.mkdir(parents=True, exist_ok=False)
    source_archive = cache / 'source-inputs' / lock['source']['sha256']
    compiler = cache / 'runtime-tools' / lock['toolchains'][arch]['sha256']
    if sha256(source_archive) != lock['source']['sha256'] or sha256(compiler) != lock['toolchains'][arch]['sha256']:
        raise ValueError('Go runtime source or toolchain checksum mismatch')
    with tempfile.TemporaryDirectory(prefix='outerspace-go-runtime-') as temporary:
        work = Path(temporary)
        source, toolchain = work / 'source', work / 'go'
        runtime_build.extract(source_archive, source)
        runtime_build.extract(compiler, toolchain)
        inputs = {n: sha256(source / n) for n in ['go.mod', 'go.sum', 'vendor/modules.txt']}
        env = {'PATH': str(toolchain / 'bin') + ':/usr/bin:/bin', 'HOME': str(work), 'LANG': 'C.UTF-8',
               'GOROOT': str(toolchain), 'GOCACHE': str(work / 'cache'), 'GOPATH': str(work / 'gopath'),
               'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOENV': 'off',
               'CGO_ENABLED': '0', 'GOOS': 'linux', 'GOARCH': arch}
        if subprocess.check_output(['go', 'version'], env=env, text=True).strip() != 'go version ' + lock['go_version'] + ' linux/' + arch:
            raise ValueError('Go toolchain version differs from recipe')
        flags = '-X sigs.k8s.io/cri-tools/pkg/version.Version=v' + lock['source']['version']
        binary = output / 'crictl'
        command = ['go', 'build', '-mod=vendor', '-trimpath', '-buildvcs=false', '-p', str(jobs),
                   '-ldflags', flags, '-o', str(binary), './cmd/crictl']
        subprocess.run(command, cwd=source, env=env, check=True)
        if inputs != {n: sha256(source / n) for n in inputs}:
            raise ValueError('Go runtime build modified vendored dependency inputs')
        info = subprocess.check_output(['go', 'version', '-m', str(binary)], env=env, text=True)
        info = 'crictl' + info[info.index(':'):]
        parsed = build_info(info, arch, lock)
        version = subprocess.check_output([str(binary), '--version'], text=True).strip()
        if version != 'crictl version v' + lock['source']['version']:
            raise ValueError('Compiled crictl reports an unexpected version')
        shutil.copyfile(source / 'LICENSE', output / 'LICENSE')
        report = {'schema': 1, 'architecture': arch, 'source': lock['source'], 'go_source': lock['go_source'],
                  'compiler_input': lock['toolchains'][arch], 'recipe_sha256': sha256(LOCK),
                  'builder_script_sha256': sha256(Path(__file__)),
                  'extraction_script_sha256': sha256(Path(runtime_build.__file__)),
                  'builder_image_id': os.environ['OUTERSPACE_BUILDER_ID'],
                  'command': command[:-2] + ['<output>/crictl', './cmd/crictl'],
                  'source_inputs': inputs, 'binary_sha256': sha256(binary),
                  'license_sha256': sha256(output / 'LICENSE'), 'go_version_m': info, 'build_info': parsed,
                  'reported_version': version}
        (output / 'runtime-build.json').write_text(json.dumps(report, indent=2) + '\n')
        verify(output, arch)
        print(json.dumps({'component': 'crictl', 'binary_sha256': report['binary_sha256'],
                          'go_version': parsed['go_version'], 'modules': len(parsed['modules'])}), flush=True)


def prepare(cache, output, arch, jobs):
    directory = cache_directory(cache, arch)
    if directory.exists():
        if verify(directory, arch)['builder_image_id'] != os.environ['OUTERSPACE_BUILDER_ID']:
            raise ValueError('Cached Go runtime was built by another builder')
    else:
        directory.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='pending-', dir=directory.parent) as temporary:
            staging = Path(temporary) / 'result'
            build(cache, staging, arch, jobs)
            staging.rename(directory)
    output.mkdir(parents=True, exist_ok=True)
    for source, destination in zip(('runtime-build.json', 'LICENSE'), EVIDENCE_FILES):
        shutil.copyfile(directory / source, output / destination)
    return directory


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
