#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Bind kernel scanner records to every compiled and installed kernel file."""
import kernel_build
from profiles import sha256

def correspondence(directory, identity, raw, index):
    report = kernel_build.verify_receipt(directory, identity['architecture'])
    source = kernel_build.read_lock()['source']
    entries = [e for e in index['entries'] if e.get('name') == 'linux' and e['sha256'] == source['sha256']]
    if len(entries) != 1 or any(entries[0].get(k) != v for k, v in source.items()):
        raise ValueError('Compiled kernel corresponding source is absent or changed')
    files = {f['location']['path']: f for f in raw['files']}
    for name, digest in report['files'].items():
        f = files.get('/' + name, {})
        if (f.get('metadata', {}).get('type') != 'RegularFile'
                or {'algorithm': 'sha256', 'value': digest} not in f.get('digests', [])):
            raise ValueError('Installed kernel differs from its build receipt: ' + name)
    module_files = {p.lstrip('/') for p, f in files.items()
                    if p.startswith('/usr/lib/modules/') and f.get('metadata', {}).get('type') == 'RegularFile'}
    if module_files != {p for p in report['files'] if p.startswith('usr/lib/modules/')}:
        raise ValueError('Unexpected or missing kernel module payload')
    return {'release': report['release'], 'version': source['version'], 'source_sha256': source['sha256'],
            'files': report['files'], 'config_sha256': report['evidence']['kernel.config'],
            'receipt_sha256': sha256(directory / 'kernel-build.json')}


def artifact(proof):
    path = '/usr/lib/modules/' + proof['release'] + '/vmlinuz'
    return {'id': 'outerspace-linux-' + proof['source_sha256'][:16], 'name': 'linux_kernel',
            'version': proof['version'], 'type': 'binary', 'foundBy': 'outerspace-verified-kernel-source',
            'locations': [{'path': path}], 'licenses': [{'value': 'GPL-2.0-only', 'type': 'declared',
                'spdxExpression': 'GPL-2.0-only', 'urls': [], 'locations': []}], 'language': '',
            'cpes': [{'cpe': 'cpe:2.3:o:linux:linux_kernel:' + proof['version'] + ':*:*:*:*:*:*:*',
                      'source': 'source-and-binary-verified'}], 'purl': 'pkg:generic/linux@' + proof['version'],
            'metadataType': 'outerspace-kernel-build',
            'metadata': {'sourceSha256': proof['source_sha256'], 'configSha256': proof['config_sha256'],
                         'binarySha256': proof['files'][path.lstrip('/')]}}

