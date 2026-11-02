#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Validate the frozen APT index archive against its locked Ubuntu releases."""
import argparse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
from pathlib import Path
import re
import tarfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def release_indexes(data):
    lines = data.decode('utf-8').splitlines()
    try:
        start = lines.index('SHA256:') + 1
    except ValueError:
        raise ValueError('Ubuntu release has no SHA256 index') from None
    result = {}
    for line in lines[start:]:
        if not line.startswith(' '):
            break
        fields = line.split()
        if len(fields) != 3:
            raise ValueError('Invalid Ubuntu release index')
        sha, size, name = fields
        if (not re.fullmatch('[a-f0-9]{64}', sha) or not size.isdigit() or name in result):
            raise ValueError('Invalid or duplicate Ubuntu release index')
        result[name] = (sha, int(size))
    return result


def release_identity(data, suite, snapshot):
    fields = {}
    for line in data.decode('utf-8').splitlines():
        for key in ('Origin', 'Suite', 'Codename', 'Date'):
            prefix = key + ': '
            if line.startswith(prefix):
                if key in fields:
                    raise ValueError('Duplicate Ubuntu release identity')
                fields[key] = line[len(prefix):]
    if (fields.get('Origin') != 'Ubuntu' or fields.get('Suite') != suite
            or fields.get('Codename') != 'noble' or 'Date' not in fields):
        raise ValueError('Ubuntu release identity differs from the snapshot')
    try:
        release_date = parsedate_to_datetime(fields['Date'])
        snapshot_date = datetime.strptime(snapshot, '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
    except (TypeError, ValueError, OverflowError):
        raise ValueError('Invalid Ubuntu release date') from None
    if release_date.tzinfo is None or release_date > snapshot_date:
        raise ValueError('Ubuntu release is newer than the snapshot')


def validate(archive_path, lock):
    if (not re.fullmatch('[0-9]{8}T[0-9]{6}Z', lock.get('ubuntu_snapshot', ''))
            or lock.get('ubuntu_suites') != ['noble', 'noble-updates', 'noble-security']
            or lock.get('ubuntu_components') != ['main', 'universe']):
        raise ValueError('Unsupported snapshot selection')
    if digest(archive_path.read_bytes()) != lock.get('snapshot_metadata_sha256'):
        raise ValueError('APT snapshot archive differs from its lock')
    releases = lock.get('snapshot_release_sha256', {})
    if set(releases) != set(lock['ubuntu_suites']):
        raise ValueError('Missing locked Ubuntu release digest')
    expected = set()
    with tarfile.open(archive_path, 'r:gz') as tar:
        members = tar.getmembers()
        names = [item.name for item in members]
        if len(names) != len(set(names)):
            raise ValueError('Duplicate APT snapshot member')
        for suite in lock['ubuntu_suites']:
            name = f'dists/{suite}/InRelease'
            expected.add(name)
            try:
                member = tar.getmember(name)
            except KeyError:
                raise ValueError('Missing Ubuntu release') from None
            if not member.isfile():
                raise ValueError('Unsafe Ubuntu release')
            data = tar.extractfile(member).read()
            if digest(data) != releases[suite]:
                raise ValueError('Ubuntu release differs from its lock')
            release_identity(data, suite, lock['ubuntu_snapshot'])
            indexes = release_indexes(data)
            if suite == 'noble':
                continue  # Its frozen release fetches base indexes by signed hash.
            for component in lock['ubuntu_components']:
                for suffix in ('source/Sources.xz', 'binary-amd64/Packages.xz',
                               'binary-arm64/Packages.xz'):
                    path = component + '/' + suffix
                    if path not in indexes:
                        raise ValueError('Missing signed Ubuntu index')
                    sha, size = indexes[path]
                    if size <= 0:
                        raise ValueError('Empty signed Ubuntu index')
                    member_name = f'dists/{suite}/{path}'
                    link_name = f'dists/{suite}/{path.rsplit("/", 1)[0]}/by-hash/SHA256/{sha}'
                    expected.update((member_name, link_name))
                    try:
                        member, link = tar.getmember(member_name), tar.getmember(link_name)
                    except KeyError:
                        raise ValueError('Missing APT index or by-hash link') from None
                    if (not member.isfile() or member.size != size
                            or digest(tar.extractfile(member).read()) != sha
                            or not link.issym() or link.linkname != '../../' + path.rsplit('/', 1)[1]):
                        raise ValueError('APT index or by-hash link differs from the signed release')
        if set(names) != expected:
            raise ValueError('Unexpected APT snapshot archive member')
    return {'snapshot': lock['ubuntu_snapshot'], 'indexes': 12}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--lock', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.archive, json.loads(args.lock.read_text()))))
