#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Freeze previously fetched Ubuntu-signed snapshot indexes for APT."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

import apt_snapshot


def freeze(snapshot, root, output, keyring):
    if not re.fullmatch('[0-9]{8}T[0-9]{6}Z', snapshot):
        raise ValueError('Invalid snapshot identifier')
    entries = []
    releases = {}
    for suite in ('noble', 'noble-updates', 'noble-security'):
        path = root / 'dists' / suite / 'InRelease'
        subprocess.run(['gpgv', '--keyring', str(keyring), str(path)], check=True)
        data = path.read_bytes()
        apt_snapshot.release_identity(data, suite, snapshot)
        releases[suite] = hashlib.sha256(data).hexdigest()
        entries.append(('file', f'dists/{suite}/InRelease', data))
        if suite == 'noble':
            continue  # Its immutable base indexes remain available by hash.
        indexes = apt_snapshot.release_indexes(data)
        for component in ('main', 'universe'):
            for suffix in ('source/Sources.xz', 'binary-amd64/Packages.xz',
                           'binary-arm64/Packages.xz'):
                name = component + '/' + suffix
                sha, size = indexes[name]
                payload = (root / 'dists' / suite / name).read_bytes()
                if len(payload) != size or hashlib.sha256(payload).hexdigest() != sha:
                    raise ValueError('Index differs from the signed Ubuntu release: ' + name)
                entries.append(('file', f'dists/{suite}/{name}', payload))
                base = f'dists/{suite}/{name.rsplit("/", 1)[0]}'
                entries.append(('link', base + '/by-hash/SHA256/' + sha,
                                '../../' + name.rsplit('/', 1)[1]))
    with output.open('xb') as raw:
        with gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0, compresslevel=9) as zipped:
            with tarfile.open(fileobj=zipped, mode='w', format=tarfile.PAX_FORMAT) as tar:
                for kind, name, payload in sorted(entries, key=lambda entry: entry[1]):
                    member = tarfile.TarInfo(name)
                    member.mode = 0o644
                    member.uid = member.gid = member.mtime = 0
                    if kind == 'link':
                        member.type, member.linkname = tarfile.SYMTYPE, payload
                        tar.addfile(member)
                    else:
                        member.size = len(payload)
                        tar.addfile(member, io.BytesIO(payload))
    result = {'ubuntu_snapshot': snapshot,
              'snapshot_metadata_sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
              'snapshot_release_sha256': releases}
    apt_snapshot.validate(output, {**result, 'ubuntu_suites': ['noble', 'noble-updates', 'noble-security'],
                                   'ubuntu_components': ['main', 'universe']})
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', required=True)
    parser.add_argument('--index-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--keyring', type=Path, default=Path('/usr/share/keyrings/ubuntu-archive-keyring.gpg'))
    args = parser.parse_args()
    print(json.dumps(freeze(args.snapshot, args.index_root, args.output, args.keyring), indent=2))
