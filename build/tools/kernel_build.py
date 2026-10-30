#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Build and install a source-pinned LTS kernel without tooling in the host."""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
from pathlib import PurePosixPath
import posixpath
import re
import shutil
import subprocess
import tarfile
import tempfile

from profiles import ROOT, architecture, sha256
import runtime_build

LOCK = ROOT / 'build/kernel/kernel.lock.json'
KEYRING = ROOT / 'build/kernel/release-key.gpg'
EVIDENCE_FILES = ('kernel-build.json', 'kernel.config', 'kernel-build-packages.tsv',
                  'kernel-COPYING', 'kernel-GPL-2.0', 'kernel-source.sign')


def read_lock():
    lock = json.loads(LOCK.read_text())
    if (lock['schema'] != 1 or lock['source']['version'] != lock['version']
            or lock['release'] != lock['version'] + '-outerspace'
            or set(lock['targets']) != {'amd64', 'arm64'}
            or sha256(KEYRING) != lock['keyring_sha256']):
        raise ValueError('Invalid kernel source or signing-key identity')
    for entry in lock['patches']:
        path = ROOT / entry['path']
        if (path.parent != ROOT / 'build/kernel/patches' or path.is_symlink()
                or not path.is_file() or sha256(path) != entry['sha256']):
            raise ValueError('Kernel patch differs from the reviewed source recipe')
    return lock


def apply_patches(source, lock):
    for entry in lock['patches']:
        with (ROOT / entry['path']).open('rb') as patch:
            subprocess.run(['patch', '--batch', '--fuzz=0', '-p1'], cwd=source, stdin=patch, check=True)


def fetch(cache):
    lock = read_lock()
    for entry in [lock['source'], lock['signature']]:
        runtime_build.sources.fetch(cache / 'source-inputs', entry)


def signature(cache, lock):
    archive = cache / 'source-inputs' / lock['source']['sha256']
    signed = cache / 'source-inputs' / lock['signature']['sha256']
    for path, entry in [(archive, lock['source']), (signed, lock['signature'])]:
        if path.is_symlink() or sha256(path) != entry['sha256']:
            raise ValueError('Kernel source or signature checksum differs')
    with tempfile.TemporaryDirectory(prefix='kernel-keyring-') as home:
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(['gpgv', '--homedir', home, '--keyring', str(KEYRING),
                '--status-fd', '1', str(signed), '-'], stdin=subprocess.PIPE, stdout=output,
                stderr=subprocess.STDOUT)
            try:
                with lzma.open(archive) as source:
                    shutil.copyfileobj(source, process.stdin)
                process.stdin.close()
                if process.wait():
                    raise ValueError('Kernel release signature verification failed')
                output.seek(0); result = output.read().decode()
            finally:
                if process.poll() is None:
                    process.kill(); process.wait()
    fingerprint = lock['signer_fingerprint']
    if ('[GNUPG:] VALIDSIG ' + fingerprint + ' ') not in result:
        raise ValueError('Kernel release was not signed by the pinned maintainer')
    return result


def config_values(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if line.startswith('CONFIG_') and '=' in line)


def extract_source(archive, destination):
    # Sequential validation avoids repeatedly decompressing a large xz archive
    # when resolving Linux's many internal source and device-tree aliases.
    names, links, roots = set(), set(), set()
    with tarfile.open(archive, mode='r|*') as stream:
        for member in stream:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not path.parts or str(path) in names:
                raise ValueError('Unsafe kernel source archive path')
            names.add(str(path)); roots.add(path.parts[0])
            if member.issym():
                target = posixpath.normpath(str(path.parent / member.linkname))
                if PurePosixPath(member.linkname).is_absolute() or not target.startswith(path.parts[0] + '/'):
                    raise ValueError('Kernel source link escapes its archive')
                links.add(str(path))
            elif not (member.isfile() or member.isdir()):
                raise ValueError('Unsupported kernel source archive entry')
    if len(roots) != 1 or any(str(parent) in links for name in names for parent in PurePosixPath(name).parents):
        raise ValueError('Kernel archive writes through a directory link')
    destination.mkdir()
    subprocess.run(['tar', '--extract', '--file', str(archive), '--strip-components=1',
                    '--no-same-owner', '--no-same-permissions', '--directory', str(destination)], check=True)
    for name in links:
        path = destination / PurePosixPath(*PurePosixPath(name).parts[1:])
        if not path.resolve().is_relative_to(destination.resolve()) or not path.exists():
            raise ValueError('Unresolved or escaping kernel source link')


def configure(source, build, lock, arch, env):
    target = lock['targets'][arch]
    command = ['make', '-C', str(source), 'O=' + str(build), 'ARCH=' + target['arch'], 'CC=ccache gcc']
    subprocess.run(command + [lock['config']['base']], env=env, check=True)
    config = [str(source / 'scripts/config'), '--file', str(build / '.config')]
    for option in lock['config']['enable']:
        subprocess.run(config + ['--enable', option], check=True)
    for option in lock['config']['disable']:
        subprocess.run(config + ['--disable', option], check=True)
    for option in lock['config']['modules']:
        subprocess.run(config + ['--module', option], check=True)
    for option, value in lock['config']['strings'].items():
        subprocess.run(config + ['--set-str', option, value], check=True)
    subprocess.run(command + ['olddefconfig'], env=env, check=True)
    values = config_values(build / '.config')
    # Dependencies and architecture can eliminate unavailable options. Essential
    # host capabilities must survive Kconfig resolution, never just the fragment.
    import importlib.util
    spec = importlib.util.spec_from_file_location('prepare_kernel', ROOT / 'build/tools/prepare-kernel.py')
    prepare = importlib.util.module_from_spec(spec); spec.loader.exec_module(prepare)
    required = set(prepare.REQUIRED) | {'CONFIG_EFI', 'CONFIG_BLK_DEV_INITRD', 'CONFIG_EXT4_FS',
        'CONFIG_DM_VERITY', 'CONFIG_VIRTIO_BLK', 'CONFIG_VIRTIO_NET', 'CONFIG_OVERLAY_FS',
        'CONFIG_BRIDGE_NETFILTER', 'CONFIG_NAMESPACES', 'CONFIG_MEMCG', 'CONFIG_CGROUP_PIDS',
        'CONFIG_VETH', 'CONFIG_NF_TABLES', 'CONFIG_NF_CONNTRACK'}
    if any(values.get(name) not in ('y', 'm') for name in required):
        raise ValueError('Resolved kernel configuration lacks a required host capability: ' +
                         ', '.join(sorted(n for n in required if values.get(n) not in ('y', 'm'))))
    excluded = [name for name in lock['config']['disable'] if values.get('CONFIG_' + name) in ('y', 'm')]
    if excluded:
        raise ValueError('Resolved kernel configuration enabled excluded subsystems: ' + ', '.join(excluded))
    return command


def inventory(root):
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('Kernel installation payload contains a link')
        if path.is_file():
            result[str(path.relative_to(root))] = sha256(path)
    return result


def cache_directory(cache, arch, builder):
    subject = {'lock': sha256(LOCK), 'script': sha256(Path(__file__)), 'keyring': sha256(KEYRING),
               'architecture': arch, 'builder': builder}
    key = hashlib.sha256(json.dumps(subject, sort_keys=True).encode()).hexdigest()
    return cache / 'kernel-builds' / key


def verify_receipt(directory, arch):
    lock = read_lock()
    report = json.loads((directory / 'kernel-build.json').read_text())
    expected = {'schema': 1, 'architecture': arch, 'release': lock['release'], 'source': lock['source'],
                'recipe_sha256': sha256(LOCK), 'builder_script_sha256': sha256(Path(__file__)),
                'signer_fingerprint': lock['signer_fingerprint'], 'patches': lock['patches']}
    if (any(report.get(k) != v for k, v in expected.items())
            or not re.fullmatch('sha256:[a-f0-9]{64}', report.get('builder_image_id', ''))
            or set(report.get('evidence', {})) != set(EVIDENCE_FILES) - {'kernel-build.json'}):
        raise ValueError('Kernel build receipt differs from its source recipe')
    for name, digest in report['evidence'].items():
        path = directory / name
        if path.is_symlink() or not path.is_file() or sha256(path) != digest:
            raise ValueError('Kernel build evidence is missing or modified')
    if not report.get('files') or report['evidence']['kernel-source.sign'] != lock['signature']['sha256']:
        raise ValueError('Kernel receipt lacks its files or upstream signature')
    return report


def verify(directory, arch):
    report = verify_receipt(directory, arch)
    if inventory(directory / 'root') != report['files']:
        raise ValueError('Kernel payload differs from the compiled inventory')
    return report


def export(directory, output, arch):
    verify(directory, arch)
    output.mkdir(parents=True, exist_ok=True)
    for name in EVIDENCE_FILES:
        shutil.copyfile(directory / name, output / name)


def prepare(cache, arch, builder, jobs):
    lock = read_lock(); destination = cache_directory(cache, arch, builder)
    if destination.exists():
        verify(destination, arch)
        return destination
    signature(cache, lock)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='outerspace-kernel-') as temporary:
        work = Path(temporary); source = work / 'source'; build = work / 'build'; build.mkdir()
        extract_source(cache / 'source-inputs' / lock['source']['sha256'], source)
        apply_patches(source, lock)
        env = {**os.environ, 'CCACHE_DIR': str(cache / 'kernel-ccache'), 'CCACHE_BASEDIR': str(work),
               'KBUILD_BUILD_TIMESTAMP': '1970-01-01 00:00:00 +0000',
               'KBUILD_BUILD_USER': 'outerspace', 'KBUILD_BUILD_HOST': 'builder', 'KBUILD_BUILD_VERSION': '1',
               'SOURCE_DATE_EPOCH': '0', 'KCONFIG_NOTIMESTAMP': '1'}
        command = configure(source, build, lock, arch, env)
        subprocess.run(command + ['-j' + str(jobs), lock['targets'][arch]['target'], 'modules'], env=env, check=True)
        release = subprocess.check_output(command + ['-s', 'kernelrelease'], env=env, text=True).strip()
        if release != lock['release']:
            raise ValueError('Compiled kernel release differs from the pinned version')
        result = work / 'result'; result.mkdir(); payload = result / 'root'; payload.mkdir()
        subprocess.run(command + ['modules_install', 'INSTALL_MOD_PATH=' + str(payload),
                                  'INSTALL_MOD_STRIP=1'], env=env, check=True)
        modules = payload / 'lib/modules' / release
        for name in ['build', 'source']:
            (modules / name).unlink(missing_ok=True)
        (payload / 'usr/lib').mkdir(parents=True)
        shutil.move(str(payload / 'lib/modules'), payload / 'usr/lib/modules')
        (payload / 'lib').rmdir()
        (payload / 'boot').mkdir()
        image = build / lock['targets'][arch]['image']
        shutil.copyfile(image, payload / 'usr/lib/modules' / release / 'vmlinuz')
        shutil.copyfile(image, payload / 'boot' / ('vmlinuz-' + release))
        shutil.copyfile(build / '.config', payload / 'boot' / ('config-' + release))
        shutil.copyfile(build / '.config', result / 'kernel.config')
        shutil.copyfile(source / 'COPYING', result / 'kernel-COPYING')
        shutil.copyfile(source / 'LICENSES/preferred/GPL-2.0', result / 'kernel-GPL-2.0')
        shutil.copyfile(cache / 'source-inputs' / lock['signature']['sha256'], result / 'kernel-source.sign')
        subprocess.run(['dpkg-query', '--show', '--showformat=${Package}\t${Version}\t${Architecture}\n'],
                       stdout=(result / 'kernel-build-packages.tsv').open('w'), check=True)
        receipt = {'schema': 1, 'architecture': arch, 'release': release, 'source': lock['source'],
                   'recipe_sha256': sha256(LOCK), 'builder_script_sha256': sha256(Path(__file__)),
                   'builder_image_id': builder, 'signer_fingerprint': lock['signer_fingerprint'], 'patches': lock['patches'],
                   'files': inventory(payload),
                   'evidence': {name: sha256(result / name) for name in EVIDENCE_FILES if name != 'kernel-build.json'}}
        (result / 'kernel-build.json').write_text(json.dumps(receipt, indent=2) + '\n')
        verify(result, arch)
        partial = destination.with_suffix('.partial')
        if partial.exists():
            raise ValueError('An unfinished kernel cache already exists')
        shutil.copytree(result, partial)
        partial.rename(destination)
    return destination


def install(directory, root, arch):
    report = verify(directory, arch)
    for name, digest in report['files'].items():
        target = root / name
        if target.exists() or target.is_symlink():
            raise ValueError('Kernel install would overwrite an existing payload')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(directory / 'root' / name, target)
        target.chmod(0o644)
    licenses = root / 'usr/share/licenses/linux'; licenses.mkdir(parents=True, exist_ok=True)
    for name in ['kernel-COPYING', 'kernel-GPL-2.0']:
        shutil.copyfile(directory / name, licenses / name.removeprefix('kernel-'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['fetch', 'prepare', 'path', 'export', 'install'])
    parser.add_argument('--cache', type=Path, default=Path('/cache'))
    parser.add_argument('--architecture', choices=['amd64', 'arm64'], default=architecture(os.uname().machine))
    parser.add_argument('--builder', default=os.environ.get('OUTERSPACE_KERNEL_BUILDER_ID'))
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--jobs', type=int, default=min(12, os.cpu_count() or 2))
    args = parser.parse_args()
    if args.action == 'fetch':
        fetch(args.cache)
    elif args.action == 'path':
        print(cache_directory(args.cache, args.architecture, args.builder))
    elif args.action == 'prepare':
        print(prepare(args.cache, args.architecture, args.builder, args.jobs))
    elif args.action == 'export':
        export(args.directory, args.output, args.architecture)
    else:
        install(args.directory, args.output, args.architecture)
