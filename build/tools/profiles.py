#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Shared image identity for build, boot, packaging and promotion."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PROFILES = ('agent', 'inference')
HARDWARE = ('cpu', 'cpu-full-firmware')
ARCHITECTURES = ('amd64', 'arm64')
HOST_FEATURES = ['containerd', 'kubelet', 'dm-verity', 'cgroup-v2', 'apparmor', 'ebpf', 'optional-dragonfly']


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def architecture(machine=None):
    name = machine or platform.machine()
    try:
        return {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64',
                'x86-64': 'amd64', 'amd64': 'amd64'}[name]
    except KeyError:
        raise ValueError(f'Unsupported architecture: {name}') from None


def selection(profile, hardware='cpu', arch=None):
    arch = architecture(arch)
    if profile not in PROFILES or hardware not in HARDWARE:
        raise ValueError('Select PROFILE=agent|inference and HARDWARE=cpu|cpu-full-firmware')
    return {'profile': profile, 'hardware_profile': hardware, 'architecture': arch}


def image_identity(profile, hardware, arch, commit):
    if not re.fullmatch(r'[a-f0-9]{40}', commit):
        raise ValueError('Source commit must be a full Git SHA')
    return {'schema': 1, **selection(profile, hardware, arch),
            'version': (ROOT / 'VERSION').read_text().strip(), 'commit': commit,
            'components_lock_sha256': sha256(ROOT / 'src/components.lock.json'),
            'host_features': HOST_FEATURES + (['full-firmware'] if hardware == 'cpu-full-firmware' else [])}


def root_hash(uki):
    with tempfile.TemporaryDirectory() as directory:
        command_line = Path(directory) / 'cmdline'
        subprocess.run(['objcopy', '--dump-section', f'.cmdline={command_line}', str(uki),
                        str(Path(directory) / 'inspected.efi')], check=True, capture_output=True)
        values = [word.split('=', 1)[1] for word in command_line.read_bytes().rstrip(b'\0').decode().split()
                  if word.startswith('roothash=')]
    if len(values) != 1 or not re.fullmatch(r'[a-f0-9]{64}', values[0]):
        raise ValueError('Expected one SHA256 verity root hash in the UKI')
    return values[0]


def stamp(output, identity):
    result = {**identity, 'raw_image_sha256': sha256(output / 'outerspace.raw'),
              'uki_sha256': sha256(output / 'outerspace.efi'),
              'verity_root_hash': root_hash(output / 'outerspace.efi'),
              'manifest_sha256': sha256(output / 'outerspace.manifest'),
              'source_archive_sha256': sha256(output / 'outerspace-source.tar')}
    (output / 'build-identity.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def verify_identity(output, profile, hardware, commit=None):
    identity = json.loads((output / 'build-identity.json').read_text())
    expected = image_identity(profile, hardware, architecture(), commit or identity.get('commit', ''))
    if any(identity.get(key) != value for key, value in expected.items()):
        raise ValueError('Build identity does not match this profile, hardware, architecture or source')
    for key, filename in [('raw_image_sha256', 'outerspace.raw'), ('uki_sha256', 'outerspace.efi'),
                          ('manifest_sha256', 'outerspace.manifest'), ('source_archive_sha256', 'outerspace-source.tar')]:
        path = output / filename
        if path.is_symlink() or sha256(path) != identity.get(key):
            raise ValueError(f'Build identity integrity failure: {filename}')
    if root_hash(output / 'outerspace.efi') != identity.get('verity_root_hash'):
        raise ValueError('Verity root hash does not match the UKI')
    return identity


def marker(identity):
    return (f'OUTERSPACE_IMAGE_IDENTITY profile={identity["profile"]} '
            f'hardware={identity["hardware_profile"]} architecture={identity["architecture"]} '
            f'commit={identity["commit"]}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['directory', 'install', 'stamp'])
    parser.add_argument('--profile', required=True, choices=PROFILES)
    parser.add_argument('--hardware', default='cpu', choices=HARDWARE)
    parser.add_argument('--architecture', default=architecture())
    parser.add_argument('--commit')
    parser.add_argument('--root', type=Path)
    args = parser.parse_args()
    selected = selection(args.profile, args.hardware, args.architecture)
    if args.action == 'directory':
        print(f'{args.profile}-{args.hardware}-{selected["architecture"]}')
        return
    identity = image_identity(args.profile, args.hardware, args.architecture, args.commit or '')
    if args.action == 'stamp':
        stamp(args.root, identity)
    else:
        destination = args.root / 'usr/share/outerspace/image-identity.json'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(identity, indent=2) + '\n')
        with (args.root / 'usr/lib/os-release').open('a') as stream:
            stream.write(f'OUTERSPACE_PROFILE={args.profile}\nOUTERSPACE_HARDWARE_PROFILE={args.hardware}\n'
                         f'OUTERSPACE_ARCHITECTURE={selected["architecture"]}\nOUTERSPACE_SOURCE_COMMIT={args.commit}\n')


if __name__ == '__main__':
    main()
