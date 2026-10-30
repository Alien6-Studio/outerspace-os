#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Copy the qualified disk's exact runtime bytes into the Ubuntu test fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

RUNTIMES = {'containerd': 'containerd', 'ctr': 'containerd',
            'containerd-shim-runc-v2': 'containerd', 'crictl': 'crictl', 'kubelet': 'kubelet'}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def kernel_files(kernel):
    release = kernel.get('release', '')
    files = kernel.get('files', {})
    if not re.fullmatch(r'\d+\.\d+\.\d+-outerspace', release) or not files:
        raise ValueError('Missing exact reference kernel payload')
    for name, checksum in files.items():
        if (not re.fullmatch(r'[A-Za-z0-9_./+-]+', name) or '..' in Path(name).parts
                or not (name.startswith('usr/lib/modules/' + release + '/')
                        or name in ['boot/config-' + release, 'boot/vmlinuz-' + release])
                or not re.fullmatch('[a-f0-9]{64}', checksum)):
            raise ValueError('Unsafe reference kernel payload')
    return files


def inventory(identity, evidence, components):
    if (evidence.get('identity') != identity or evidence.get('status') != 'inventoried'
            or identity['components_lock_sha256'] != digest(components)):
        raise ValueError('Reference runtimes differ from the qualified image')
    selected = [r for r in evidence['runtimes'] if r['component'] != 'dfdaemon']
    expected = {'/usr/bin/' + name: component for name, component in RUNTIMES.items()}
    if (len(selected) != len(expected)
            or {r['path']: r['component'] for r in selected} != expected
            or any(not re.fullmatch('[a-f0-9]{64}', r['sha256']) for r in selected)):
        raise ValueError('Incomplete or unsafe reference runtime inventory')
    return {'schema': 1, 'identity': identity, 'runtimes': selected}


def extract(image, evidence_directory, output, components):
    # The enclosing harness first verifies the complete packaged evidence. This
    # second binding ensures extraction uses that exact disk, even for patched
    # source builds which have no matching upstream binary download.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'build/tools'))
    from sbom import partitions
    identity = json.loads((evidence_directory / 'build-identity.json').read_text())
    evidence = json.loads((evidence_directory / 'sbom-evidence.json').read_text())
    manifest = inventory(identity, evidence, components)
    import kernel_build
    kernel = kernel_build.verify_receipt(evidence_directory, identity['architecture'])
    manifest['kernel'] = {'release': kernel['release'], 'files': kernel['files']}
    kernel_records = kernel_files(manifest['kernel'])
    if image.is_symlink() or digest(image) != identity['raw_image_sha256']:
        raise ValueError('Reference extraction requires the qualified disk')
    table = json.loads(subprocess.check_output(['sfdisk', '--json', str(image)], text=True))['partitiontable']
    layout = partitions(table, image.stat().st_size, identity['architecture'])
    output.mkdir(exist_ok=False)
    # debugfs reads a private partition copy without mounting or granting the VM
    # runner SYS_ADMIN. It never modifies the qualified disk or executes its code.
    with tempfile.TemporaryDirectory(prefix='outerspace-reference-') as temporary:
        root = Path(temporary) / 'root.ext4'
        part = layout['OOS_ROOT']
        subprocess.run(['dd', 'if=' + str(image), 'of=' + str(root), 'bs=4M',
                        'iflag=skip_bytes,count_bytes', 'skip=' + str(part['offset']),
                        'count=' + str(part['size']), 'conv=sparse', 'status=none'], check=True)
        for runtime in manifest['runtimes']:
            name = Path(runtime['path']).name
            subprocess.run(['debugfs', '-R', 'dump ' + runtime['path'] + ' ' + name, str(root)],
                           cwd=output, check=True, capture_output=True)
            target = output / name
            if target.is_symlink() or not target.is_file() or digest(target) != runtime['sha256']:
                raise ValueError('Extracted runtime differs from its qualified inventory')
            target.chmod(0o755)
        commands = []
        for name in kernel_records:
            target = output / 'kernel' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            source_name = name
            if name.startswith('boot/'):
                suffix = 'vmlinuz' if name.startswith('boot/vmlinuz-') else 'config'
                source_name = 'usr/lib/modules/' + kernel['release'] + '/' + suffix
            commands.append('dump /' + source_name + ' kernel/' + name)
        instructions = output / 'kernel-extract.commands'
        instructions.write_text('\n'.join(commands) + '\n')
        subprocess.run(['debugfs', '-f', str(instructions), str(root)], cwd=output,
                       check=True, capture_output=True)
        instructions.unlink()
        for name, checksum in kernel_records.items():
            if digest(output / 'kernel' / name) != checksum:
                raise ValueError('Extracted kernel differs from the qualified disk')
    (output / 'runtimes.json').write_text(json.dumps(manifest, indent=2) + '\n')


def install(source, root, architecture):
    manifest = json.loads((source / 'runtimes.json').read_text())
    records = manifest['runtimes']
    if (manifest.get('schema') != 1 or manifest['identity']['architecture'] != architecture
            or len(records) != len(RUNTIMES)
            or {r['path']: r['component'] for r in records}
            != {'/usr/bin/' + name: component for name, component in RUNTIMES.items()}):
        raise ValueError('Unsafe reference runtime payload')
    # Verify the complete payload before changing the disposable Ubuntu guest.
    for record in records:
        binary = source / Path(record['path']).name
        if binary.is_symlink() or not binary.is_file() or digest(binary) != record['sha256']:
            raise ValueError('Reference runtime payload checksum mismatch')
    kernel = kernel_files(manifest['kernel']) if 'kernel' in manifest else {}
    for name, checksum in kernel.items():
        path = source / 'kernel' / name
        target = root / name
        if (path.is_symlink() or not path.is_file() or digest(path) != checksum
                or target.is_symlink() or not target.resolve().is_relative_to(root.resolve())):
            raise ValueError('Reference kernel payload checksum or target differs')
    for name in kernel:
        target = root / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / 'kernel' / name, target)
        target.chmod(0o644)
    destination = root / 'usr/bin'
    destination.mkdir(parents=True, exist_ok=True)
    for record in records:
        name = Path(record['path']).name
        target = destination / name
        if target.is_symlink():
            raise ValueError('Unsafe reference runtime destination')
        shutil.copyfile(source / name, target)
        target.chmod(0o755)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    extraction = actions.add_parser('extract')
    for name in ['image', 'evidence-directory', 'output', 'components']:
        extraction.add_argument('--' + name, type=Path, required=True)
    installation = actions.add_parser('install')
    installation.add_argument('--source', type=Path, required=True)
    installation.add_argument('--root', type=Path, required=True)
    installation.add_argument('--architecture', choices=['amd64', 'arm64'], required=True)
    args = parser.parse_args()
    if args.action == 'extract':
        extract(args.image, args.evidence_directory, args.output, args.components)
    else:
        install(args.source, args.root, args.architecture)
