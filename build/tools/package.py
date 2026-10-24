#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Package a verified build with its exact input identity and SHA256 inventory."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from profiles import PROFILES, HARDWARE, marker, verify_identity

ROOT = Path(__file__).resolve().parents[2]


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_boot_report(output, profile, hardware, commit):
    identity = verify_identity(output, profile, hardware, commit)
    report = json.loads((output / 'uefi-smoke.json').read_text())
    if (report.get('schema') != 2 or report.get('status') != 'passed'
            or report.get('power_cycles') != 2
            or report.get('identity') != identity
            or report.get('image_sha256') != sha256(output / 'outerspace.raw')):
        raise ValueError('UEFI evidence must bind two successful boots to this exact disk')
    content = (output / 'boot-smoke.log').read_text(errors='replace')
    required = ['OUTERSPACE_SELFTEST_OK', 'OUTERSPACE_UEFI_OK',
                'OUTERSPACE_PERSISTENCE_PREPARE_OK', 'OUTERSPACE_PERSISTENCE_VERIFY_OK']
    if 'OUTERSPACE_SELFTEST_FAIL' in content or any(marker not in content for marker in required):
        raise ValueError('Complete UEFI and persistence boot logs are required')
    for name in ['boot-smoke.log', 'boot-uefi-prepare.log', 'boot-uefi-verify.log']:
        path = output / name
        if path.is_symlink() or report.get('logs', {}).get(name) != sha256(path):
            raise ValueError('Boot evidence log integrity failure')
        if marker(identity) not in path.read_text(errors='replace'):
            raise ValueError('Boot log belongs to another profile/source')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('/out'))
    parser.add_argument('--commit', required=True)
    parser.add_argument('--profile', required=True, choices=PROFILES)
    parser.add_argument('--hardware', default='cpu', choices=HARDWARE)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.commit):
        parser.error('commit must be a full Git SHA')
    output = args.output
    log = output / 'boot-smoke.log'
    try:
        boot_report = verify_boot_report(output, args.profile, args.hardware, args.commit)
    except (ValueError, OSError) as error:
        parser.error(f'Cannot package unqualified disk: {error}')
    identity = boot_report['identity']
    arch = identity['architecture']
    version = (ROOT / 'VERSION').read_text().strip()
    bundle = output / f'outerspace-{version}-{args.profile}-{args.hardware}-{arch}'
    bundle.mkdir(exist_ok=False)
    stem = bundle / bundle.name
    subprocess.run(['zstd', '-T0', '-q', str(output / 'outerspace.raw'), '-o', str(stem) + '.raw.zst'], check=True)
    for extension in ['efi', 'manifest']:
        shutil.copyfile(output / f'outerspace.{extension}', Path(str(stem) + '.' + extension))
    shutil.copyfile(log, bundle / 'boot-smoke.log')
    shutil.copyfile(output / 'uefi-smoke.json', bundle / 'uefi-smoke.json')
    shutil.copyfile(output / 'build-identity.json', bundle / 'build-identity.json')
    for phase in ['prepare', 'verify']:
        shutil.copyfile(output / f'boot-uefi-{phase}.log', bundle / f'boot-uefi-{phase}.log')
    shutil.copyfile(ROOT / 'src/components.lock.json', bundle / 'components.lock.json')
    subprocess.run(['zstd', '-q', str(output / 'outerspace-source.tar'), '-o', str(bundle / 'source.tar.zst')], check=True)
    metadata = {'schema': 2, 'identity': identity,
                'channel': 'development' if '-dev.' in version else 'candidate',
                'boot_test': 'QEMU UEFI disk boot and state/identity persistence across two power cycles; Secure Boot disabled',
                'raw_image_sha256': boot_report['image_sha256'],
                'ubuntu_inputs': 'signed Noble repositories, not snapshot-locked',
                'manifest_sha256': sha256(output / 'outerspace.manifest'),
                'components_lock_sha256': sha256(ROOT / 'src/components.lock.json'),
                'files': {p.name: sha256(p) for p in sorted(bundle.iterdir())}}
    (bundle / 'build-metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    files = sorted(bundle.iterdir())
    (bundle / 'SHA256SUMS').write_text(''.join(f'{sha256(p)}  {p.name}\n' for p in files))
    print(bundle)


if __name__ == '__main__':
    main()
