#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Compile pinned Go runtimes and dependency updates with an offline toolchain."""
import argparse
from concurrent.futures import ThreadPoolExecutor
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
import go_dependencies

LOCK = ROOT / 'build/runtime/crictl.lock.json'
EVIDENCE_FILES = ('crictl-build.json', 'crictl-LICENSE')
sources = runtime_build.sources
COMPONENTS = {
    'crictl': {'module': 'sigs.k8s.io/cri-tools', 'binaries': ['crictl']},
    'containerd': {'module': 'github.com/containerd/containerd/v2',
                   'binaries': ['containerd', 'ctr', 'containerd-shim-runc-v2']},
}


def recipe_path(component='crictl'):
    if component not in COMPONENTS:
        raise ValueError('Unsupported source-built Go runtime')
    return LOCK if component == 'crictl' else ROOT / 'build/runtime' / (component + '.lock.json')


def evidence_files(component='crictl'):
    recipe_path(component)
    return (component + '-build.json', component + '-LICENSE')


def build_tags(component, binary):
    if component == 'crictl':
        return []
    tags = ['urfave_cli_no_docs', 'osusergo', 'netgo', 'static_build']
    return tags + (['no_grpc'] if binary == 'containerd-shim-runc-v2' else [])


def read_lock(component='crictl'):
    lock = json.loads(recipe_path(component).read_text())
    source_lock = json.loads(sources.LOCK.read_text())
    upstream = source_lock['sources']
    if (lock.get('schema') != 1 or lock.get('component') != component
            or lock['source'] != upstream[component]
            or lock['go_source'] != upstream[lock['go_version']]
            or lock.get('dependency_lock_sha256') != source_lock.get('go_dependency_updates', {}).get(component)
            or set(lock['toolchains']) != {'amd64', 'arm64'}):
        raise ValueError('Go runtime recipe differs from corresponding-source locks')
    go_dependencies.read_lock(lock['dependency_lock_sha256'], component)
    return lock


def fetch(cache, arch, component='crictl'):
    lock = read_lock(component)
    sources.fetch(cache / 'source-inputs', lock['source'])
    sources.fetch(cache / 'runtime-tools', lock['toolchains'][arch])
    config = go_dependencies.read_lock(lock['dependency_lock_sha256'], component)
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda e: sources.fetch(cache / 'source-inputs', e), go_dependencies.source_entries(config)))


def build_info(text, arch, lock, binary=None):
    component = lock['component']
    binary = binary or component
    if binary not in COMPONENTS[component]['binaries']:
        raise ValueError('Unexpected Go runtime executable')
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
    tags = build_tags(component, binary)
    if tags:
        expected['-tags'] = ','.join(tags)
    module = COMPONENTS[component]['module']
    if (result.get('path') != module + '/cmd/' + binary
            or result['modules'].get(module) != '(devel)'
            or any(result['settings'].get(k) != v for k, v in expected.items())):
        raise ValueError('Go runtime target or compilation settings differ')
    return result


def verify_receipt(directory, arch, *, packaged=False, component='crictl'):
    lock = read_lock(component)
    names = evidence_files(component) if packaged else ('runtime-build.json', 'LICENSE')
    paths = [directory / name for name in names]
    if any(p.is_symlink() or not p.is_file() for p in paths):
        raise ValueError('Missing or unsafe Go runtime evidence')
    report = json.loads(paths[0].read_text())
    if (report.get('schema') != 1 or report.get('architecture') != arch
            or report.get('recipe_sha256') != sha256(recipe_path(component))
            or report.get('builder_script_sha256') != sha256(Path(__file__))
            or report.get('extraction_script_sha256') != sha256(Path(runtime_build.__file__))
            or report.get('dependency_script_sha256') != sha256(Path(go_dependencies.__file__))
            or report.get('dependency_lock_sha256') != lock['dependency_lock_sha256']
            or report.get('source_inputs') != go_dependencies.build_inputs(
                go_dependencies.read_lock(lock['dependency_lock_sha256'], component))
            or report.get('source') != lock['source'] or report.get('go_source') != lock['go_source']
            or report.get('compiler_input') != lock['toolchains'][arch]
            or report.get('license_sha256') != sha256(paths[1])
            or not re.fullmatch('sha256:[a-f0-9]{64}', report.get('builder_image_id', ''))
            or not re.fullmatch('[a-f0-9]{64}', report.get('binary_sha256', ''))
            or report.get('build_info') != build_info(report.get('go_version_m', ''), arch, lock)):
        raise ValueError('Go runtime build evidence differs from approved inputs')
    additional = report.get('additional_binaries', {})
    if set(additional) != set(COMPONENTS[component]['binaries']) - {component}:
        raise ValueError('Go runtime build is missing an executable')
    for name, record in additional.items():
        if (not re.fullmatch('[a-f0-9]{64}', record.get('sha256', ''))
                or record.get('build_info') != build_info(record.get('go_version_m', ''), arch, lock, name)):
            raise ValueError('Additional Go runtime build evidence differs')
    return report


def verify(directory, arch, *, binary=None, packaged=False, component='crictl'):
    report = verify_receipt(directory, arch, packaged=packaged, component=component)
    path = binary or directory / component
    if path.is_symlink() or not path.is_file() or sha256(path) != report['binary_sha256']:
        raise ValueError('Go runtime executable differs from its build evidence')
    for name, record in report.get('additional_binaries', {}).items():
        extra = path.parent / name
        if extra.is_symlink() or not extra.is_file() or sha256(extra) != record['sha256']:
            raise ValueError('Additional Go runtime executable differs from its build evidence')
    return report


def cache_directory(cache, arch, component='crictl'):
    builder = os.environ.get('OUTERSPACE_BUILDER_ID', '')
    if not re.fullmatch('sha256:[a-f0-9]{64}', builder):
        raise ValueError('Go runtime compilation requires an immutable builder image ID')
    subject = {'architecture': arch, 'builder': builder, 'recipe': sha256(recipe_path(component)),
               'script': sha256(Path(__file__)), 'extractor': sha256(Path(runtime_build.__file__)),
               'dependencies': sha256(Path(go_dependencies.__file__))}
    key = hashlib.sha256(json.dumps(subject, sort_keys=True).encode()).hexdigest()
    return cache / 'go-runtime-builds' / arch / key


def build(cache, output, arch, jobs, component='crictl'):
    lock = read_lock(component)
    if architecture() != arch:
        raise ValueError('Go runtime compilation requires the native target architecture')
    cache_directory(cache, arch, component)  # Enforce immutable builder identity on direct builds.
    output.mkdir(parents=True, exist_ok=False)
    source_archive = cache / 'source-inputs' / lock['source']['sha256']
    compiler = cache / 'runtime-tools' / lock['toolchains'][arch]['sha256']
    if sha256(source_archive) != lock['source']['sha256'] or sha256(compiler) != lock['toolchains'][arch]['sha256']:
        raise ValueError('Go runtime source or toolchain checksum mismatch')
    with tempfile.TemporaryDirectory(prefix='outerspace-go-runtime-') as temporary:
        work = Path(temporary)
        source, toolchain = work / 'source', work / 'go'
        runtime_build.extract(source_archive, source, directory_links=component == 'containerd')
        runtime_build.extract(compiler, toolchain)
        upstream_inputs = {n: sha256(source / n) for n in ['go.mod', 'go.sum', 'vendor/modules.txt']}
        env = {'PATH': str(toolchain / 'bin') + ':/usr/bin:/bin', 'HOME': str(work), 'LANG': 'C.UTF-8',
               'GOROOT': str(toolchain), 'GOCACHE': str(work / 'cache'), 'GOPATH': str(work / 'gopath'),
               'GOTOOLCHAIN': 'local', 'GOPROXY': 'off', 'GOSUMDB': 'off', 'GOENV': 'off',
               'CGO_ENABLED': '0', 'GOOS': 'linux', 'GOARCH': arch}
        if subprocess.check_output(['go', 'version'], env=env, text=True).strip() != 'go version ' + lock['go_version'] + ' linux/' + arch:
            raise ValueError('Go toolchain version differs from recipe')
        config = go_dependencies.read_lock(lock['dependency_lock_sha256'], component)
        proxy = work / 'proxy'
        go_dependencies.stage(config, cache / 'source-inputs', source, proxy)
        # The Go tool verifies module h1 checksums against the frozen go.sum.
        # A local proxy provides complete module archives without network access.
        vendor_env = {**env, 'GOPROXY': proxy.as_uri()}
        subprocess.run(['go', 'mod', 'vendor'], cwd=source, env=vendor_env, check=True)
        inputs = go_dependencies.build_inputs(config)
        if inputs != {n: sha256(source / n) for n in inputs}:
            raise ValueError('Offline vendoring differs from pinned Go dependency update')
        module = COMPONENTS[component]['module']
        if component == 'crictl':
            flags = '-X ' + module + '/pkg/version.Version=v' + lock['source']['version']
        else:
            flags = ('-X ' + module + '/version.Version=v' + lock['source']['version']
                     + ' -X ' + module + '/version.Revision=' + lock['source']['commit'] + '.outerspace'
                     + ' -X ' + module + '/version.Package=' + module)
        executables, commands = {}, {}
        for name in COMPONENTS[component]['binaries']:
            binary = output / name
            command = ['go', 'build', '-mod=vendor', '-trimpath', '-buildvcs=false', '-p', str(jobs)]
            tags = build_tags(component, name)
            if tags:
                command += ['-tags', ','.join(tags)]
            command += ['-ldflags', flags, '-o', str(binary), './cmd/' + name]
            subprocess.run(command, cwd=source, env=env, check=True)
            info = subprocess.check_output(['go', 'version', '-m', str(binary)], env=env, text=True)
            info = name + info[info.index(':'):]
            executables[name] = {'sha256': sha256(binary), 'go_version_m': info,
                                 'build_info': build_info(info, arch, lock, name)}
            commands[name] = command[:-2] + ['<output>/' + name, './cmd/' + name]
        if inputs != {n: sha256(source / n) for n in inputs}:
            raise ValueError('Go runtime build modified vendored dependency inputs')
        primary = executables.pop(component)
        version = subprocess.check_output([str(output / component), '--version'], text=True).strip()
        expected_version = ('crictl version v' + lock['source']['version'] if component == 'crictl' else
                            'containerd ' + module + ' v' + lock['source']['version'] + ' '
                            + lock['source']['commit'] + '.outerspace')
        if version != expected_version:
            raise ValueError('Compiled runtime reports an unexpected version')
        shutil.copyfile(source / 'LICENSE', output / 'LICENSE')
        report = {'schema': 1, 'architecture': arch, 'source': lock['source'], 'go_source': lock['go_source'],
                  'compiler_input': lock['toolchains'][arch], 'recipe_sha256': sha256(recipe_path(component)),
                  'builder_script_sha256': sha256(Path(__file__)),
                  'extraction_script_sha256': sha256(Path(runtime_build.__file__)),
                  'dependency_script_sha256': sha256(Path(go_dependencies.__file__)),
                  'dependency_lock_sha256': lock['dependency_lock_sha256'],
                  'builder_image_id': os.environ['OUTERSPACE_BUILDER_ID'],
                  'command': commands[component], 'commands': commands,
                  'source_inputs': inputs, 'upstream_source_inputs': upstream_inputs,
                  'binary_sha256': primary['sha256'], 'additional_binaries': executables,
                  'license_sha256': sha256(output / 'LICENSE'),
                  'go_version_m': primary['go_version_m'], 'build_info': primary['build_info'],
                  'reported_version': version}
        (output / 'runtime-build.json').write_text(json.dumps(report, indent=2) + '\n')
        verify(output, arch, component=component)
        print(json.dumps({'component': component, 'binary_sha256': report['binary_sha256'],
                          'go_version': primary['build_info']['go_version'],
                          'modules': len(primary['build_info']['modules'])}), flush=True)


def prepare(cache, output, arch, jobs, component='crictl'):
    directory = cache_directory(cache, arch, component)
    if directory.exists():
        if verify(directory, arch, component=component)['builder_image_id'] != os.environ['OUTERSPACE_BUILDER_ID']:
            raise ValueError('Cached Go runtime was built by another builder')
    else:
        directory.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='pending-', dir=directory.parent) as temporary:
            staging = Path(temporary) / 'result'
            build(cache, staging, arch, jobs, component)
            staging.rename(directory)
    output.mkdir(parents=True, exist_ok=True)
    for source, destination in zip(('runtime-build.json', 'LICENSE'), evidence_files(component)):
        shutil.copyfile(directory / source, output / destination)
    return directory


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['fetch', 'build', 'prepare', 'path'])
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--architecture', choices=['amd64', 'arm64'], required=True)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--component', choices=tuple(COMPONENTS), default='crictl')
    args = parser.parse_args()
    if args.action == 'fetch':
        fetch(args.cache, args.architecture, args.component)
    elif args.action == 'path':
        print(cache_directory(args.cache, args.architecture, args.component))
    elif args.output is None or args.jobs < 1:
        parser.error('Build requires --output and positive --jobs')
    elif args.action == 'build':
        build(args.cache, args.output, args.architecture, args.jobs, args.component)
    else:
        prepare(args.cache, args.output, args.architecture, args.jobs, args.component)
