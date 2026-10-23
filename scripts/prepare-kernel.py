#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Normalize Ubuntu ARM64 gzip kernels into EFI-loadable Image payloads."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

MAX_KERNEL_SIZE = 256 * 1024 * 1024


def normalize(data, architecture):
    if architecture not in {'arm64', 'aarch64'}:
        return data, 'unchanged'
    operation = 'unchanged'
    if data.startswith(b'\x1f\x8b'):
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
            data = compressed.read(MAX_KERNEL_SIZE + 1)
        operation = 'gzip decompression for EFI loading'
    if len(data) > MAX_KERNEL_SIZE or len(data) < 64 or data[:2] != b'MZ' or data[56:60] != b'ARMd':
        raise ValueError('Expected an ARM64 Linux Image with an EFI stub')
    pe_offset = struct.unpack_from('<I', data, 60)[0]
    if pe_offset + 6 > len(data) or data[pe_offset:pe_offset + 4] != b'PE\0\0':
        raise ValueError('ARM64 EFI kernel has no valid PE header')
    if struct.unpack_from('<H', data, pe_offset + 4)[0] != 0xaa64:
        raise ValueError('EFI kernel architecture is not ARM64')
    return data, operation


def prepare(root, architecture):
    records = []
    # mkosi selects /usr/lib/modules/*/vmlinuz, which Ubuntu may install as a
    # separate copy rather than a symlink to /boot/vmlinuz-*. Normalize both.
    kernels = sorted((root / 'usr/lib/modules').glob('*/vmlinuz')) + sorted((root / 'boot').glob('vmlinuz-*'))
    if not kernels:
        raise ValueError('No Ubuntu kernel installed under /boot')
    prepared = {}
    for path in kernels:
        if path.is_symlink() or not path.is_file():
            raise ValueError('Expected a regular Ubuntu kernel file')
        original = path.read_bytes()
        payload, operation = normalize(original, architecture)
        if payload != original:
            digest = hashlib.sha256(payload).hexdigest()
            if digest in prepared:
                path.unlink()
                path.hardlink_to(prepared[digest])
            else:
                path.write_bytes(payload)
                prepared[digest] = path
        records.append({'path': str(path.relative_to(root)), 'operation': operation,
                        'package_payload_sha256': hashlib.sha256(original).hexdigest(),
                        'efi_payload_sha256': hashlib.sha256(payload).hexdigest()})
    inventory = root / 'usr/share/outerspace/kernel-preparation.json'
    inventory.parent.mkdir(parents=True, exist_ok=True)
    inventory.write_text(json.dumps({'schema': 1, 'architecture': architecture, 'kernels': records}, indent=2) + '\n')
    for record in records:
        print(f"Kernel preparation: {record['path']}: {record['operation']}")


if __name__ == '__main__':
    prepare(Path(sys.argv[1]), sys.argv[2])
