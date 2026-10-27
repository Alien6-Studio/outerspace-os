#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Compare independent builds without hiding nondeterministic image contents."""
import argparse
import hashlib
import json
from pathlib import Path

from profiles import sha256
from sbom import read_json, write_json


def differing_blocks(first, second, block_size=65536):
    result = []
    with first.open('rb') as a, second.open('rb') as b:
        offset = 0
        while True:
            x, y = a.read(block_size), b.read(block_size)
            if not x and not y:
                break
            if x != y:
                result.append({'offset': offset, 'length': max(len(x), len(y)),
                    'first_sha256': hashlib.sha256(x).hexdigest(), 'second_sha256': hashlib.sha256(y).hexdigest()})
            offset += block_size
    return result


def file_inventory(scan):
    # Syft resolves link destinations under its temporary directory source.
    # Compare those as image paths, while preserving the untouched scan evidence.
    root = scan['source']['metadata']['path'].rstrip('/')
    if scan['source']['type'] != 'directory' or not root.startswith('/') or not root:
        raise ValueError('Reproducibility requires an absolute directory scan source')
    result = {}
    for f in scan['files']:
        path = f['location']['path']
        if path in result:
            raise ValueError('Duplicate file paths in reproducibility evidence')
        metadata = dict(f.get('metadata', {}))
        link = metadata.get('linkDestination', '')
        if metadata.get('type') == 'SymbolicLink' and (link == root or link.startswith(root + '/')):
            metadata['linkDestination'] = link[len(root):] or '/'
        result[path] = {'digests': f.get('digests', []), 'metadata': metadata}
    return result


def compare(first, second):
    a, b = [read_json(p / 'build-identity.json') for p in (first, second)]
    fields = ('profile', 'hardware_profile', 'architecture', 'version', 'commit',
              'components_lock_sha256', 'source_archive_sha256')
    if any(a[k] != b[k] for k in fields):
        raise ValueError('Reproducibility requires the same profile and source inputs')
    pa, pb = [read_json(p / 'build-provenance.json') for p in (first, second)]
    if any(pa[k] != pb[k] for k in ['builder_image_id', 'builder_packages_sha256', 'inputs']):
        raise ValueError('Reproducibility requires the same immutable builder and input locks')
    ma, mb = [read_json(p / 'outerspace.manifest')['packages'] for p in (first, second)]
    if ma != mb:
        raise ValueError('Installed package input selection is not reproducible')
    scans = [read_json(p / 'sbom.syft.json') for p in (first, second)]
    files = [file_inventory(scan) for scan in scans]
    differences = [{'path': path, 'first': files[0].get(path), 'second': files[1].get(path)}
                   for path in sorted(set(files[0]) | set(files[1])) if files[0].get(path) != files[1].get(path)]
    artifacts = ('outerspace.raw', 'outerspace.efi', 'outerspace.manifest', 'apt-inputs.json',
                 'apt-notices.tar', 'source-index.json', 'corresponding-source.tar.zst')
    hashes = {name: [sha256(p / name) for p in (first, second)] for name in artifacts}
    return {'schema': 1, 'identity': a, 'second_identity': b,
            'input_selection': 'identical',
            'bit_for_bit': all(x[0] == x[1] for x in hashes.values()),
            'artifact_digests': hashes, 'filesystem_differences': differences,
            'different_binary_regions': {name: differing_blocks(first / name, second / name)
                                         for name in ['outerspace.raw', 'outerspace.efi']},
            'evidence': [{name: sha256(p / name) for name in ['build-identity.json', 'build-provenance.json',
                          'sbom.syft.json', 'sbom-evidence.json']} for p in (first, second)],
            'limits': 'File contents and recorded metadata are compared individually. Syft temporary source prefixes '
                      'in symlink destinations are normalized to image paths; raw scans are retained unchanged. '
                      'Disk/UKI hashes also cover '
                      'filesystem allocation, GPT UUIDs, filesystem timestamps and boot metadata. If only those '
                      'hashes differ, differing 64-KiB regions are reported; their metadata causes remain '
                      'unattributed. Do not claim bit-identical builds.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('first', type=Path)
    parser.add_argument('second', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.first, args.second)
    write_json(args.output, result)
    print(json.dumps({'input_selection': result['input_selection'], 'bit_for_bit': result['bit_for_bit'],
                      'differing_files': len(result['filesystem_differences'])}))
