#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Install the digest-pinned scanner in the builder, never in the OS."""
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile


def install(lockfile, destination):
    lock = json.loads(lockfile.read_text())
    name = lock.get('name', 'syft')
    if name not in ['syft', 'grype']:
        raise ValueError('Unsupported scanner')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
    artifact = lock['artifacts'][arch]
    with tempfile.TemporaryDirectory() as directory:
        archive = Path(directory) / 'syft.tar.gz'
        subprocess.run(['curl', '-fsSL', '--proto', '=https', '--retry', '3', '--max-time', '600',
                        '-o', str(archive), artifact['url']], check=True)
        with archive.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != artifact['sha256']:
                raise ValueError('Syft archive checksum mismatch')
        with tarfile.open(archive) as tar:
            for member_name, path in [(name, destination), ('LICENSE', destination.parent / (name + '.LICENSE'))]:
                members = [m for m in tar if m.name == member_name]
                if len(members) != 1 or not members[0].isfile():
                    raise ValueError('Invalid Syft archive member: ' + member_name)
                with tar.extractfile(members[0]) as source, path.open('wb') as target:
                    shutil.copyfileobj(source, target)
                path.chmod(0o755 if member_name == name else 0o644)
    with destination.open('rb') as stream:
        binary_hash = hashlib.file_digest(stream, 'sha256').hexdigest()
    destination.with_suffix('.json').write_text(json.dumps({
        'version': lock['version'], 'architecture': arch, 'artifact': artifact,
        'binary_sha256': binary_hash}, indent=2) + '\n')


if __name__ == '__main__':
    install(Path(sys.argv[1]), Path(sys.argv[2]))
