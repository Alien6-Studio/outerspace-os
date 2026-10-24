# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Verify a retained model before reuse; fetch only when the cache is absent."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tempfile
import urllib.request


def verify(path, expected_size, expected_sha256):
    if path.is_symlink() or not path.is_file() or path.stat().st_size != expected_size:
        raise ValueError('Unexpected cached model type or size')
    with path.open('rb') as stream:
        if stream.read(4) != b'GGUF':
            raise ValueError('Cached model is not GGUF')
        stream.seek(0)
        if hashlib.file_digest(stream, 'sha256').hexdigest() != expected_sha256:
            raise ValueError('Untrusted cached model SHA256')


def stage(path, url, expected_size, expected_sha256):
    if not 4 <= expected_size < 128 * 1024**2 or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256):
        raise ValueError('Expected an immutable bounded model artifact')
    if path.exists() or path.is_symlink():
        # Init containers may run again after a node reboot. Never require DNS
        # or egress for a valid retained cache, and never repair a tampered one.
        verify(path, expected_size, expected_sha256)
        return 'verified-cache'
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='model-', suffix='.download', delete=False) as output:
            temporary = Path(output.name)
            size = 0
            with urllib.request.urlopen(url, timeout=120) as source:
                while block := source.read(1024 * 1024):
                    size += len(block)
                    if size > expected_size:
                        raise ValueError('Model download exceeded its locked size')
                    output.write(block)
        verify(temporary, expected_size, expected_sha256)
        temporary.chmod(0o444)
        temporary.replace(path)
        return 'private-source'
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--path', type=Path, required=True)
    parser.add_argument('--url', required=True)
    parser.add_argument('--bytes', dest='expected_size', type=int, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    mode = stage(args.path, args.url, args.expected_size, args.sha256)
    print(json.dumps({'source': mode, 'sha256': args.sha256, 'bytes': args.expected_size}), flush=True)


if __name__ == '__main__':
    main()
