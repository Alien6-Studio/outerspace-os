#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Preserve installed package/source identities before mkosi removes its database."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile


def paragraphs(text):
    """Parse Debian control stanzas, retaining multiline checksum/notice fields."""
    result = []
    for block in re.split(r'\n\s*\n', text.strip()):
        stanza = {}
        key = None
        for line in block.splitlines():
            if line.startswith((' ', '\t')) and key:
                stanza[key] += '\n' + line[1:]
            elif ': ' in line or line.endswith(':'):
                key, value = line.split(':', 1)
                if key in stanza:
                    raise ValueError('Duplicate Debian control field')
                stanza[key] = value.strip()
            else:
                raise ValueError('Invalid Debian control stanza')
        if stanza:
            result.append(stanza)
    return result


def source_record(stanzas, name, version, base):
    matches = [s for s in stanzas if s.get('Package') == name and s.get('Version') == version]
    # The same signed source can be present in more than one pocket.
    unique = {json.dumps(s, sort_keys=True): s for s in matches}
    if not unique:
        raise ValueError(f'Corresponding source absent from snapshot: {name}={version}')
    files = None
    for stanza in unique.values():
        directory = stanza['Directory']
        if not re.fullmatch(r'pool/[A-Za-z0-9_./+~-]+', directory) or '..' in Path(directory).parts:
            raise ValueError('Unsafe source directory')
        entries = []
        for line in stanza['Checksums-Sha256'].splitlines():
            if not line.strip():
                continue
            digest, size, filename = line.split()
            if (not re.fullmatch('[a-f0-9]{64}', digest) or Path(filename).name != filename
                    or filename in ['.', '..'] or not size.isdigit() or int(size) <= 0):
                raise ValueError('Invalid signed source checksum')
            entries.append({'name': filename, 'sha256': digest, 'size': int(size),
                            'url': base + directory + '/' + filename})
        entries.sort(key=lambda e: e['name'])
        if not entries or not any(e['name'].endswith('.dsc') for e in entries):
            raise ValueError('Missing source descriptor')
        if files is not None and entries != files:
            raise ValueError('Conflicting source inventories')
        files = entries
    return {'name': name, 'version': version, 'files': files}


def capture(root, output, lockfile):
    lock = json.loads(lockfile.read_text())
    snapshot = lock['ubuntu_snapshot']
    if not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z', snapshot):
        raise ValueError('Invalid Ubuntu snapshot')
    base = 'https://snapshot.ubuntu.com/ubuntu/' + snapshot + '/'
    format_string = '${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${db:Status-Status}\n'
    data = subprocess.check_output(['/usr/bin/dpkg-query', '--admindir=' + str(root / 'var/lib/dpkg'),
        '--show', '--showformat=' + format_string], text=True)
    packages = []
    sources = {}
    notices = {}
    ownership = {}
    for line in data.splitlines():
        name, version, architecture, source, source_version, status = line.split('\t')
        if status != 'installed':
            continue
        if not re.fullmatch('[a-z0-9][a-z0-9+.-]+', name):
            raise ValueError('Invalid installed package name')
        copyright_path = root / 'usr/share/doc' / name / 'copyright'
        resolved = copyright_path.resolve(strict=True)
        if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
            raise ValueError('Missing or unsafe copyright notice: ' + name)
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        notice_name = 'packages/' + name + '/copyright'
        notices[notice_name] = resolved
        packages.append({'type': 'deb', 'name': name, 'version': version, 'architecture': architecture,
            'source': source, 'source_version': source_version, 'notice': notice_name, 'notice_sha256': digest})
        for listing in (root / 'var/lib/dpkg/info').glob(name + '*.list'):
            if listing.name not in (name + '.list', name + ':' + architecture + '.list'):
                continue
            for filename in listing.read_text().splitlines():
                if filename.startswith(('/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/')):
                    ownership[filename] = name
        key = (source, source_version)
        if key not in sources:
            # mkosi supplies an apt-cache wrapper bound to its verified indexes.
            text = subprocess.check_output(['apt-cache', 'showsrc', '--only-source', source], text=True)
            sources[key] = source_record(paragraphs(text), source, source_version, base)
    if not packages:
        raise ValueError('Empty installed package inventory')
    for path in sorted((root / 'usr/share/common-licenses').iterdir()):
        if path.is_file() and path.resolve().is_relative_to(root.resolve()):
            notices['common-licenses/' + path.name] = path.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output / 'apt-notices.tar', 'w') as tar:
        for name, path in sorted(notices.items()):
            tar.add(path, arcname=name, recursive=False)
    record = {'schema': 1, 'snapshot': snapshot, 'inputs_lock_sha256': hashlib.sha256(lockfile.read_bytes()).hexdigest(),
              'packages': sorted(packages, key=lambda p: (p['name'], p['architecture'])),
              'sources': [sources[k] for k in sorted(sources)],
              'executable_owners': dict(sorted(ownership.items())),
              'notices_sha256': hashlib.sha256((output / 'apt-notices.tar').read_bytes()).hexdigest()}
    (output / 'apt-inputs.json').write_text(json.dumps(record, indent=2) + '\n')
    # Preserve scanner-native source names and file ownership before mkosi strips
    # dpkg metadata. This is later merged with the final disk's offline scan.
    subprocess.run(['/usr/local/bin/syft', 'scan', 'dir:' + str(root),
        '--select-catalogers', 'dpkg',
        '-o', 'syft-json=' + str(output / 'apt.sbom.syft.json')],
        env={'PATH': '/usr/bin:/bin', 'HOME': '/tmp', 'LANG': 'C.UTF-8',
             'SYFT_CHECK_FOR_APP_UPDATE': 'false'}, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--lock', type=Path, required=True)
    args = parser.parse_args()
    capture(args.root, args.output, args.lock)
