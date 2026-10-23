#!/usr/bin/env python3
"""Package a verified build with its exact input identity and SHA256 inventory."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('/out'))
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.commit):
        parser.error('commit must be a full Git SHA')
    output = args.output
    log = output / 'boot-smoke.log'
    content = log.read_text(errors='replace')
    if 'OUTERSPACE_SELFTEST_OK' not in content or 'OUTERSPACE_SELFTEST_FAIL' in content:
        parser.error('a successful boot smoke log is required')
    arch = {'aarch64': 'arm64', 'x86_64': 'amd64'}[platform.machine()]
    version = (ROOT / 'VERSION').read_text().strip()
    bundle = output / f'outerspace-{version}-{arch}'
    bundle.mkdir(exist_ok=False)
    stem = bundle / f'outerspace-{version}-{arch}'
    subprocess.run(['zstd', '-T0', '-q', str(output / 'outerspace.raw'), '-o', str(stem) + '.raw.zst'], check=True)
    for extension in ['efi', 'manifest']:
        shutil.copyfile(output / f'outerspace.{extension}', Path(str(stem) + '.' + extension))
    shutil.copyfile(log, bundle / 'boot-smoke.log')
    shutil.copyfile(ROOT / 'components.lock.json', bundle / 'components.lock.json')
    metadata = {'schema': 1, 'version': version, 'architecture': arch, 'commit': args.commit,
                'channel': 'development' if '-dev.' in version else 'candidate',
                'boot_test': 'QEMU split kernel/initrd, not EFI boot or Secure Boot',
                'ubuntu_inputs': 'signed Noble repositories, not snapshot-locked',
                'manifest_sha256': sha256(output / 'outerspace.manifest'),
                'components_lock_sha256': sha256(ROOT / 'components.lock.json'),
                'files': {p.name: sha256(p) for p in sorted(bundle.iterdir())}}
    (bundle / 'build-metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    files = sorted(bundle.iterdir())
    (bundle / 'SHA256SUMS').write_text(''.join(f'{sha256(p)}  {p.name}\n' for p in files))
    print(bundle)


if __name__ == '__main__':
    main()
