#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 OuterSpace OS contributors
"""Skip image builds only for explicit documentation or promotion-only paths."""
import argparse
from pathlib import PurePosixPath
import re
import subprocess
import sys

DOCUMENTS = frozenset({
    'README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'CODE_OF_CONDUCT.md',
    'src/README.md', 'src/branding/README.md', 'src/cluster/README.md',
    'build/README.md', 'build/release/README.md', 'src/third_party/README.md',
    'tests/README.md', '.github/README.md',
    '.github/CODEOWNERS', '.github/pull_request_template.md',
    '.github/ISSUE_TEMPLATE/bug_report.yml',
    '.github/ISSUE_TEMPLATE/feature_request.yml',
    '.github/ISSUE_TEMPLATE/config.yml',
})

# These files verify/promote existing images or classify CI work; none builds or
# configures the OS. Contract checks remain mandatory. Any mixed runtime, policy,
# image-workflow or unknown change still requires the complete image campaign.
PROMOTION_ONLY = frozenset({
    'build/tools/attestations.py', '.github/workflows/release.yml',
    'build/tools/ci-scope.py', 'tests/unit/test_ci_scope.py',
    'tests/unit/test_supply_chain.py',
})


def documentation_only(path):
    parts = PurePosixPath(path).parts
    if not path or path.startswith('/') or '..' in parts:
        return False
    return path in DOCUMENTS or (
        path.endswith('.md') and path.startswith(('docs/', 'src/docs/', 'tests/reports/', 'tests/benchmarks/'))
    )


def requires_images(event, paths):
    # Empty, failed or unknown change inventories must never skip qualification.
    return event not in {'push', 'pull_request'} or not paths or any(
        not (documentation_only(path) or path in PROMOTION_ONLY) for path in paths
    )


def changed_paths(base, head):
    for revision in (base, head):
        if not re.fullmatch(r'[0-9a-f]{40}', revision) or revision == '0' * 40:
            raise ValueError('missing or invalid comparison SHA')
    result = subprocess.run(
        ['git', 'diff', '--no-renames', '--name-only', '-z', base, head],
        check=True, capture_output=True,
    )
    return [path.decode('utf-8', errors='strict') for path in result.stdout.split(b'\0') if path]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--event', required=True)
    parser.add_argument('--base', default='')
    parser.add_argument('--head', default='')
    args = parser.parse_args()
    paths = []
    if args.event in {'push', 'pull_request'}:
        try:
            paths = changed_paths(args.base, args.head)
        except (ValueError, UnicodeError, OSError, subprocess.CalledProcessError) as error:
            print(f'Change classification unavailable; building images: {error}', file=sys.stderr)
    images = requires_images(args.event, paths)
    print(f'images={str(images).lower()}')
    print('Full image qualification' if images else 'Documentation or promotion-only changes', file=sys.stderr)


if __name__ == '__main__':
    main()
